#Requires -Version 5.1
<#
.SYNOPSIS
    Generic harness: runs one module script from a SCRATCH copy of the repo,
    with scripted answers to every Read-Host prompt and (optionally) fake local
    account cmdlets and a stand-in nmap/tshark executable. Prints one
    machine-readable result line. Used by the tests\*.Tests.ps1 files; it never
    touches real accounts, the real firewall, or a real scanner.

.PARAMETER SpecPath
    Path to a JSON file describing the run:
      Module        module path relative to the repo, e.g. modules\Invoke-CredentialHardening.ps1
      Args          named arguments; a JSON true is passed as a switch
      Answers       key/value pairs written to config\answers.local.psd1
      Inventory     object written to logs\inventory-latest.json (optional)
      Inputs        scripted responses to Read-Host, consumed in order
      FakeLocalUsers  names for fake Get-LocalUser/Set-LocalUser/... (optional)
      DummyExes     relative paths where a stand-in "scanner" exe is built (optional)
      ExtraFiles    relative path -> content to create before the run (optional);
                    "{WORK}" in the content or path is replaced by the scratch dir
      BackdateFiles relative paths whose timestamps are set a year back, so a test can tell "recently modified" from "always been there" (optional)
      Env           environment variables to set for the run; "{WORK}" is replaced (optional)
      FakeSplunkService  $true = fake Restart-Service / Get-Service for the forwarder (optional)
      Iis           stand-in WebAdministration module (see New-IisStubModule.ps1): { Sites, AppPools, FtpLow, FtpHigh, ... }
      HyperV        fake Hyper-V + PowerShell Direct: { VMs: [{Name,State,Notes,Checkpoints}], Switches: [..] } (optional)
      SecureArgs    name -> plain text, passed to the script as a SecureString (optional)
      ReadBack      relative paths whose contents to include in the result (optional)
      ReadBackDirs  relative folders whose files are ALL included in the result (optional)
#>
param([Parameter(Mandatory)][string]$SpecPath, [Parameter(Mandatory)][string]$RepoRoot)

$ErrorActionPreference = 'Continue'
$spec = Get-Content -Raw -Path $SpecPath | ConvertFrom-Json

$global:Calls = New-Object System.Collections.Generic.List[string]
$global:Prompts = New-Object System.Collections.Generic.List[string]
$global:InputQueue = New-Object System.Collections.Generic.List[string]
foreach ($i in @($spec.Inputs)) { if ($null -ne $i) { $global:InputQueue.Add([string]$i) } }

# --- scratch copy ---------------------------------------------------------------------------------
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("modtest-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work -Force | Out-Null
foreach ($item in 'modules', 'config', 'configs', 'lab') { if (Test-Path (Join-Path $RepoRoot $item)) { Copy-Item -Path (Join-Path $RepoRoot $item) -Destination (Join-Path $work $item) -Recurse -Force } }
Copy-Item -Path (Join-Path $RepoRoot 'Invoke-CCDCToolkit.ps1') -Destination (Join-Path $work 'Invoke-CCDCToolkit.ps1') -Force
New-Item -ItemType Directory -Path (Join-Path $work 'logs') -Force | Out-Null

if ($spec.Answers) {
    $lines = @('@{')
    foreach ($p in $spec.Answers.PSObject.Properties) { $lines += "    $($p.Name) = '$($p.Value)'" }
    $lines += '}'
    Set-Content -Path (Join-Path $work 'config\answers.local.psd1') -Value $lines -Encoding UTF8
}
if ($spec.Inventory) {
    $spec.Inventory | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $work 'logs\inventory-latest.json') -Encoding UTF8
}

if ($spec.ExtraFiles) {
    foreach ($p in $spec.ExtraFiles.PSObject.Properties) {
        $target = Join-Path $work ($p.Name.Replace('{WORK}', $work))
        New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
        Set-Content -Path $target -Value ([string]$p.Value).Replace('{WORK}', $work) -Encoding UTF8
    }
}
if ($spec.BackdateFiles) {
    $old = (Get-Date).AddDays(-365)
    foreach ($rel in @($spec.BackdateFiles | Where-Object { $_ })) {
        $target = Join-Path $work $rel
        if (Test-Path -LiteralPath $target) {
            (Get-Item -LiteralPath $target).LastWriteTime = $old
            (Get-Item -LiteralPath $target).CreationTime = $old
        }
    }
}
if ($spec.Env) {
    foreach ($p in $spec.Env.PSObject.Properties) { [Environment]::SetEnvironmentVariable($p.Name, ([string]$p.Value).Replace('{WORK}', $work), 'Process') }
}

# --- stand-in scanner exe (records its arguments; creates the files a real one would) -------------
if ($spec.DummyExes) {
    $src = @'
using System;
using System.IO;
public static class P {
    public static int Main(string[] a) {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        File.AppendAllText(Path.Combine(dir, "args.log"), string.Join("\n", a) + "\n---\n");
        for (int i = 0; i < a.Length; i++) {
            bool hasNext = i + 1 < a.Length;
            if (a[i] == "--script-args-file" && hasNext) File.WriteAllText(Path.Combine(dir, "script-args-content.log"), File.ReadAllText(a[i + 1]));
            if (a[i] == "-oN" && hasNext) File.WriteAllText(a[i + 1], "Nmap scan report for test\n445/tcp open microsoft-ds\n4444/tcp open krb524\n");
            if (a[i] == "-oX" && hasNext) File.WriteAllText(a[i + 1], "<nmaprun/>");
            if (a[i] == "-w" && hasNext) File.WriteAllText(a[i + 1], "pcap");
            if (a[i] == "-D") Console.WriteLine("1. \\Device\\NPF_{TEST} (Dummy)");
        }
        return 0;
    }
}
'@
    foreach ($rel in @($spec.DummyExes)) {
        $exe = Join-Path $work $rel
        New-Item -ItemType Directory -Path (Split-Path $exe -Parent) -Force | Out-Null
        Add-Type -TypeDefinition $src -OutputAssembly $exe -OutputType ConsoleApplication
    }
}

# --- fakes --------------------------------------------------------------------------------------------
function global:Read-Host {
    param([Parameter(Position = 0)]$Prompt, [switch]$AsSecureString)
    $global:Prompts.Add("$Prompt")
    if ($global:InputQueue.Count -eq 0) { return $null }
    $v = $global:InputQueue[0]; $global:InputQueue.RemoveAt(0)
    if ($AsSecureString) { return (ConvertTo-SecureString -String $v -AsPlainText -Force) }
    return $v
}
function global:Start-Sleep { param($Seconds) }

if ($spec.HyperV) {
    # Pre-load the real modules so the fakes below (global functions) are not shadowed by an auto-load later.
    Import-Module Hyper-V -ErrorAction SilentlyContinue
    $global:VMs = [ordered]@{}
    foreach ($v in @($spec.HyperV.VMs)) {
        $global:VMs[$v.Name] = [pscustomobject]@{ Name = $v.Name; State = $v.State; Notes = [string]$v.Notes; Checkpoints = @($v.Checkpoints | Where-Object { $_ }); Dvds = 0 }
    }
    $global:Switches = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($spec.HyperV.Switches)) { if ($s) { $global:Switches.Add([string]$s) } }
    $global:ScriptRuns = @{}

    function global:Get-VM { param($Name, $ErrorAction) if ($Name) { if ($global:VMs.Contains($Name)) { return $global:VMs[$Name] } else { return $null } } return @($global:VMs.Values) }
    function global:Get-VMSwitch { param($Name, $ErrorAction) if ($global:Switches -contains $Name) { return [pscustomobject]@{ Name = $Name; SwitchType = 'Private' } } return $null }
    function global:New-VMSwitch { param($Name, $SwitchType) $global:Switches.Add($Name); $global:Calls.Add("New-VMSwitch|$Name|$SwitchType") }
    function global:Remove-VMSwitch { param($Name, [switch]$Force) [void]$global:Switches.Remove($Name); $global:Calls.Add("Remove-VMSwitch|$Name") }
    function global:New-VHD { param($Path, $SizeBytes, [switch]$Dynamic) $global:Calls.Add("New-VHD|$(Split-Path $Path -Leaf)|$SizeBytes") }
    function global:New-VM {
        param($Name, $Generation, $MemoryStartupBytes, $VHDPath, $SwitchName, $Path)
        $global:VMs[$Name] = [pscustomobject]@{ Name = $Name; State = 'Off'; Notes = ''; Checkpoints = @(); Dvds = 0 }
        $global:Calls.Add("New-VM|$Name|gen$Generation|$MemoryStartupBytes|$SwitchName")
        return $global:VMs[$Name]
    }
    function global:Set-VMMemory { param($VMName, $DynamicMemoryEnabled, $MinimumBytes, $StartupBytes, $MaximumBytes) $global:Calls.Add("Set-VMMemory|$VMName|$DynamicMemoryEnabled|$MinimumBytes|$StartupBytes|$MaximumBytes") }
    function global:Set-VMProcessor { param($VMName, $Count) $global:Calls.Add("Set-VMProcessor|$VMName|$Count") }
    function global:Set-VM { param($Name, $Notes, $AutomaticCheckpointsEnabled, $CheckpointType, $AutomaticStopAction) if ($Notes) { $global:VMs[$Name].Notes = $Notes }; $global:Calls.Add("Set-VM|$Name|$CheckpointType|$AutomaticStopAction|autocp=$AutomaticCheckpointsEnabled") }
    # -Passthru returns the drive that was just added, carrying its Path.
    # The real builder uses that to pick the boot device, instead of
    # indexing into Get-VMDvdDrive and hoping it lands on the install
    # media rather than the answer-file disc.
    function global:Add-VMDvdDrive {
        param($VMName, $Path, [switch]$Passthru)
        $global:VMs[$VMName].Dvds++
        $global:Calls.Add("Add-VMDvdDrive|$VMName|$(Split-Path $Path -Leaf)")
        if ($Passthru) { return [pscustomobject]@{ VMName = $VMName; Path = $Path } }
    }
    function global:Get-VMDvdDrive { param($VMName) for ($i = 1; $i -le $global:VMs[$VMName].Dvds; $i++) { [pscustomobject]@{ VMName = $VMName; Index = $i } } }
    function global:Remove-VMDvdDrive { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Drive) process { $global:Calls.Add("Remove-VMDvdDrive|$($Drive.VMName)"); $global:VMs[$Drive.VMName].Dvds = 0 } }
    function global:Get-VMHardDiskDrive { param($VMName) [pscustomobject]@{ VMName = $VMName } }
    function global:Set-VMFirmware {
        param($VMName, $EnableSecureBoot, $SecureBootTemplate, $BootOrder)
        # Count only a boot order that was actually passed: @($null).Count
        # is 1, so an unbound -BootOrder would otherwise be recorded as one
        # phantom boot device.
        $bootCount = 0
        if ($PSBoundParameters.ContainsKey('BootOrder')) { $bootCount = @($BootOrder).Count }
        $global:Calls.Add("Set-VMFirmware|$VMName|$EnableSecureBoot|$SecureBootTemplate|bootdevices=$bootCount")
        # Only touch the stored boot order when one was actually passed.
        # The real cmdlet leaves it alone otherwise, and a fake that wiped
        # it made a later Secure Boot call look like it had erased the
        # boot order -- a bug in the harness, not in the thing under test.
        if ($PSBoundParameters.ContainsKey('BootOrder')) {
            $global:VMs[$VMName] | Add-Member -NotePropertyName BootOrder -NotePropertyValue @($BootOrder) -Force
        }
    }
    function global:Get-VMFirmware {
        param($VMName)
        $set = @()
        if ($global:VMs[$VMName].PSObject.Properties['BootOrder']) { $set = @($global:VMs[$VMName].BootOrder) }
        [pscustomobject]@{ BootOrder = @($set | ForEach-Object { [pscustomobject]@{ Device = $_ } }) }
    }
    function global:Set-VMKeyProtector { param($VMName, [switch]$NewLocalKeyProtector) $global:Calls.Add("Set-VMKeyProtector|$VMName") }
    function global:Enable-VMTPM { param($VMName) $global:Calls.Add("Enable-VMTPM|$VMName") }
    function global:Connect-VMNetworkAdapter { param($VMName, $SwitchName) $global:VMs[$VMName] | Add-Member -NotePropertyName SwitchName -NotePropertyValue $SwitchName -Force; $global:Calls.Add("Connect-VMNetworkAdapter|$VMName|$SwitchName") }
    function global:Get-VMNetworkAdapter { param($VMName) [pscustomobject]@{ VMName = $VMName; Name = 'Network Adapter'; SwitchName = $global:VMs[$VMName].SwitchName } }
    function global:Export-VM { param($Name, $Path) $global:Calls.Add("Export-VM|$Name|$Path") }
    function global:Import-VM {
        # Test fixtures lay the fake .vmcx under <MigrationPath>\<VMName>\Virtual
        # Machines\<guid>.vmcx -- the same shape the real Export-VM/Import-VM use
        # -- so the VM name comes from the path, same as the real cmdlet reads it
        # from the file's own content. The fake .vmcx's CONTENT (set via the
        # spec's ExtraFiles) is just the switch name that VM "remembers" being
        # on, so this can simulate the real behaviour of reconnecting by switch
        # NAME only when a switch with that name already exists.
        param($Path, [switch]$Copy, [switch]$GenerateNewId, $VirtualMachinePath, $VhdDestinationPath)
        $name = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $Path))
        $remembered = if (Test-Path -LiteralPath $Path) { (Get-Content -LiteralPath $Path -Raw).Trim() } else { $null }
        $connected = if ($remembered -and ($global:Switches -contains $remembered)) { $remembered } else { $null }
        $global:VMs[$name] = [pscustomobject]@{ Name = $name; State = 'Off'; Notes = ''; Checkpoints = @(); Dvds = 0; SwitchName = $connected }
        $global:Calls.Add("Import-VM|$name|copy=$Copy|newid=$GenerateNewId|switch=$connected")
        return $global:VMs[$name]
    }
    function global:Start-VM { param($Name, $ErrorAction) $global:VMs[$Name].State = 'Running'; $global:Calls.Add("Start-VM|$Name") }
    function global:Stop-VM { param($Name, [switch]$Force, [switch]$TurnOff) $global:VMs[$Name].State = 'Off'; $global:Calls.Add("Stop-VM|$Name|$(if ($TurnOff) { 'TurnOff' } else { 'Shutdown' })") }
    function global:Remove-VM { param($Name, [switch]$Force) $global:VMs.Remove($Name); $global:Calls.Add("Remove-VM|$Name") }
    function global:Checkpoint-VM { param($Name, $SnapshotName) $global:VMs[$Name].Checkpoints += $SnapshotName; $global:Calls.Add("Checkpoint-VM|$Name|$SnapshotName") }
    function global:Get-VMSnapshot { param($VMName, $Name, $ErrorAction) foreach ($c in @($global:VMs[$VMName].Checkpoints)) { if (-not $Name -or $c -eq $Name) { [pscustomobject]@{ VMName = $VMName; Name = $c } } } }
    function global:Remove-VMSnapshot { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Checkpoint) process { $global:Calls.Add("Remove-VMCheckpoint|$($Checkpoint.VMName)|$($Checkpoint.Name)"); $vm = $global:VMs[$Checkpoint.VMName]; $vm.Checkpoints = @($vm.Checkpoints | Where-Object { $_ -ne $Checkpoint.Name }) } }
    # (the script calls the *-VMCheckpoint aliases; they resolve to these)
    function global:Restore-VMSnapshot { param($VMName, $Name, $Confirm) $global:Calls.Add("Restore-VMCheckpoint|$VMName|$Name") }

    # keyboard wake-up (Msvm_Keyboard): only the Hyper-V namespace is faked, everything else is the real Get-CimInstance
    function global:Get-CimInstance {
        [CmdletBinding()] param($Namespace, $ClassName, $Filter)
        if ($Namespace -like '*virtualization*') {
            if ($ClassName -eq 'Msvm_ComputerSystem') { return [pscustomobject]@{ Name = 'GUID-OF-VM'; ElementName = 'vm' } }
            return [pscustomobject]@{ Kind = 'keyboard'; Filter = $Filter }
        }
        & (Get-Command Get-CimInstance -CommandType Cmdlet) @PSBoundParameters
    }
    function global:Invoke-CimMethod { param($InputObject, $MethodName, $Arguments) $global:Calls.Add("CimMethod|$MethodName|key=$($Arguments.keyCode)"); }

    # PowerShell Direct
    function global:New-PSSession { param($VMName, $Credential) $global:Calls.Add("New-PSSession|$VMName|$($Credential.UserName)"); [pscustomobject]@{ VMName = $VMName } }
    function global:Remove-PSSession { param($Session, $ErrorAction) }
    function global:Copy-Item {
        [CmdletBinding()] param([string[]]$Path, [string[]]$LiteralPath, [string]$Destination, [switch]$Recurse, [switch]$Force, $ToSession)
        if ($ToSession) { $global:Calls.Add("Copy-ToSession|$($ToSession.VMName)|$Destination"); return }
        & (Get-Command Copy-Item -CommandType Cmdlet) @PSBoundParameters
    }
    function global:Invoke-Command {
        param($VMName, $Session, $Credential, $ScriptBlock, $ArgumentList, $ErrorAction)
        if ($VMName) {
            if ("$ScriptBlock" -match 'Restart-Computer') { $global:Calls.Add("Restart|$VMName"); return }
            if ($global:VMs.Contains($VMName) -and $global:VMs[$VMName].State -eq 'Running') { return $true }
            throw 'A remote session might have ended.'
        }
        if ($ArgumentList -and "$($ArgumentList[0])" -like '*.ps1') {
            $script = "$($ArgumentList[0])"; $plain = $ArgumentList[1]; $secure = @($ArgumentList[2])
            $key = "$($Session.VMName)|$script"
            $n = 1 + [int]$global:ScriptRuns[$key]; $global:ScriptRuns[$key] = $n
            $global:Calls.Add("GuestScript|$($Session.VMName)|$script|run$n|plain=$((@($plain.Keys) | Sort-Object) -join ',')|dns=$($plain['DnsServer'])|secure=$($secure -join ',')")
            # First run of each script asks for a restart; the second finishes.
            if ($n -eq 1) { if ($script -like '*DC*') { 'REBOOTING' } else { 'REBOOT_NEEDED' } } else { 'DONE' }
            return
        }
    }
}
if ($spec.Iis) {
    # "{WORK}" inside the IIS spec (site physical paths) points at the scratch copy.
    $iisSpec = (($spec.Iis | ConvertTo-Json -Depth 8).Replace('{WORK}', $work.Replace('\', '\\'))) | ConvertFrom-Json
    & (Join-Path $PSScriptRoot 'New-IisStubModule.ps1') -Root (Join-Path $work 'stubmodules') -Spec $iisSpec
}
if ($spec.FakeSplunkService) {
    function global:Restart-Service { param($Name, $ErrorAction) $global:Calls.Add("Restart-Service|$Name") }
    function global:Get-Service { param($Name, $ErrorAction) [pscustomobject]@{ Name = 'SplunkForwarder'; Status = 'Running' } }
}
if ($spec.FakeLocalUsers) {
    $global:FakeUsers = @($spec.FakeLocalUsers)
    function global:Get-LocalUser { param($Name, $ErrorAction) foreach ($n in $global:FakeUsers) { [pscustomobject]@{ Name = $n; Enabled = $true } } }
    function global:Set-LocalUser { param($Name, $Password, $ErrorAction) $global:Calls.Add("Set-LocalUser|$Name") }
}

# --- run ----------------------------------------------------------------------------------------------
$argHash = @{}
if ($spec.Args) {
    foreach ($p in $spec.Args.PSObject.Properties) {
        $v = $p.Value
        if ($v -is [string]) { $v = $v.Replace('{WORK}', $work) }
        $argHash[$p.Name] = $(if ($v -is [bool] -and $v) { [switch]::Present } else { $v })
    }
}
if ($spec.SecureArgs) { foreach ($p in $spec.SecureArgs.PSObject.Properties) { $argHash[$p.Name] = ConvertTo-SecureString -String ([string]$p.Value) -AsPlainText -Force } }
$script = Join-Path $work $spec.Module
try { & $script @argHash } catch { Write-Host "SCRIPT-THREW: $($_.Exception.Message)" }

# --- report --------------------------------------------------------------------------------------------
$read = @{}
foreach ($rel in @($spec.ReadBack | Where-Object { $_ })) {
    $path = Join-Path $work $rel
    if (Test-Path -LiteralPath $path -PathType Leaf) { $read[$rel] = [string](Get-Content -LiteralPath $path -Raw) } else { $read[$rel] = $null }
}
foreach ($rel in @($spec.ReadBackDirs | Where-Object { $_ })) {
    $dir = Join-Path $work $rel
    if (Test-Path -LiteralPath $dir) {
        foreach ($f in (Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
            $read["$rel\$($f.Name)"] = [string](Get-Content -LiteralPath $f.FullName -Raw)
        }
    }
}
$files = @(Get-ChildItem -Path $work -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName.Substring($work.Length + 1) })
$iis = $null
if ($spec.Iis) {
    $iis = [pscustomobject]@{
        Sites = @($global:IisSites.Values | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; DirectoryBrowsing = $_.DirectoryBrowsing; XPoweredBy = $_.XPoweredBy
                               FtpAnonymous = $_.FtpAnonymous; DeniedExtensions = @($_.DeniedExtensions) }
        })
        RemoveServerHeader = $global:IisRemoveServerHeader
    }
}
$hv = $null
if ($spec.HyperV) {
    $hv = [pscustomobject]@{
        VMs      = @($global:VMs.Values | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = $_.State; Notes = $_.Notes; Checkpoints = @($_.Checkpoints); Dvds = $_.Dvds } })
        Switches = @($global:Switches)
    }
}
$result = [pscustomobject]@{
    Iis       = $iis
    HyperV    = $hv
    WorkDir   = $work
    Calls     = @($global:Calls)
    Prompts   = @($global:Prompts)
    InputsLeft = $global:InputQueue.Count
    Files     = $files
    ReadBack  = $read
}
'@@RESULT@@' + ($result | ConvertTo-Json -Compress -Depth 6)
