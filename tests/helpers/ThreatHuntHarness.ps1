#Requires -Version 5.1
<#
.SYNOPSIS
    Test harness for modules\Invoke-ThreatHunt.ps1. Runs the REAL script in a
    scratch copy of the repo against fake system data that simulates red team
    already being present (a rogue Domain Admins member, a backdoor local
    admin, an unsigned service in a Temp path, a listener on a known C2 port).
    Used by tests\ThreatHunt.Tests.ps1.

.PARAMETER Pass
    1 = first pass (no prior state); 2 = second pass, in the same -WorkDir,
    after new red-team activity appears (a new Domain Admin, a new service,
    a new scheduled task, a new local account).
#>
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)][string]$WorkDir,
    [Parameter(Mandatory)][ValidateSet(1, 2)][int]$Pass,
    # Simulates a domain controller, where Get-LocalGroupMember does not
    # work at all. Observed on the lab DC (Server 2019): it fails with
    # "Group Administrators was not found", which took the whole
    # local-admin check out on the one box where it matters most.
    [switch]$AsDomainController,
    # Red team has been here and switched the defences off: update tasks
    # disabled, Defender weakened, an SSH server installed, the Security
    # log cleared. Every item is one a real enumeration log recorded.
    [switch]$Tampered,
    # Unelevated Get-MpPreference, which reports a message instead of the
    # exclusion list and used to read as three exclusions.
    [switch]$DefenderUnreadable
)

$ErrorActionPreference = 'Continue'
$global:Pass = $Pass
$global:Work = $WorkDir

# --- one-time scratch copy (pass 1 creates it; pass 2 reuses it so state persists) ------------
if (-not (Test-Path (Join-Path $WorkDir 'modules'))) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    foreach ($item in 'modules', 'config', 'configs') { Copy-Item -Path (Join-Path $RepoRoot $item) -Destination (Join-Path $WorkDir $item) -Recurse -Force }
    # A made-up tool name appended to the copy of the shipped names file, so the
    # test can prove the file is really loaded without this script itself ever
    # containing a real offensive-tool name (antivirus reacts to those in script text).
    Add-Content -Path (Join-Path $WorkDir 'configs\threat-hunt\known-tool-names.txt') -Value 'customtool'
    New-Item -ItemType Directory -Path (Join-Path $WorkDir 'logs') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $WorkDir 'Temp') -Force | Out-Null
    Set-Content -Path (Join-Path $WorkDir 'Temp\evil.exe') -Value 'not a real binary' -Encoding ASCII
}
$env:TEMP = Join-Path $WorkDir 'Temp'
$env:USERPROFILE = $WorkDir     # so the Downloads scan looks at the scratch dir, not a real profile

# --- fakes (global, so they shadow any real cmdlet) ---------------------------------------------
function global:Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.test'; DistinguishedName = 'DC=corp,DC=test' } }
function global:Get-ADGroupMember {
    param($Identity, $ErrorAction)
    $names = switch ($Identity) {
        'Domain Admins' { @('Administrator', 'rogueadmin') }
        # BUILTIN\Administrators as it is read on a domain controller.
        'Administrators' { @('Administrator', 'dcbackdoor') }
        default { @('Administrator') }
    }
    if ($global:Pass -eq 2 -and $Identity -eq 'Domain Admins') { $names += 'newguy' }
    $names | ForEach-Object { [pscustomobject]@{ SamAccountName = $_ } }
}
function global:Get-ADUser {
    param($Filter, $Properties, $ErrorAction)
    $u = @([pscustomobject]@{ SamAccountName = 'alice'; Created = (Get-Date).AddDays(-30) })
    if ($global:Pass -eq 2) { $u += [pscustomobject]@{ SamAccountName = 'freshaccount'; Created = (Get-Date) } }
    $u
}
function global:Get-GPO {
    param([switch]$All, $ErrorAction)
    [pscustomobject]@{ DisplayName = 'Default Domain Policy'; ModificationTime = [datetime]'2026-01-01T10:00:00' }
    if ($global:Pass -eq 2) { [pscustomobject]@{ DisplayName = 'Default Domain Policy'; ModificationTime = (Get-Date) } }
}
function global:Get-DnsServerResourceRecord {
    param($ZoneName, $ErrorAction)
    [pscustomobject]@{ HostName = 'www'; RecordType = 'A'; RecordData = '10.10.10.20' }
    if ($global:Pass -eq 2) { [pscustomobject]@{ HostName = 'evil'; RecordType = 'A'; RecordData = '10.10.10.99' } }
}
function global:Get-DhcpServerv4Scope {
    param($ErrorAction)
    [pscustomobject]@{ ScopeId = [ipaddress]'10.10.10.0' }
}
function global:Get-DhcpServerv4Reservation {
    param($ScopeId, $ErrorAction)
    [pscustomobject]@{ IPAddress = '10.10.10.50'; ClientId = '00-11-22-33-44-55'; Name = 'printer' }
    if ($global:Pass -eq 2) { [pscustomobject]@{ IPAddress = '10.10.10.99'; ClientId = 'AA-BB-CC-DD-EE-FF'; Name = 'rogue' } }
}
$global:IsDc = [bool]$AsDomainController
$global:Tampered = [bool]$Tampered
$global:DefenderUnreadable = [bool]$DefenderUnreadable
function global:Get-LocalGroupMember {
    param($Group, $ErrorAction)
    if ($global:IsDc) { throw 'Group Administrators was not found.' }
    $m = @("$env:COMPUTERNAME\Administrator", "$env:COMPUTERNAME\backdoor")
    if ($global:Pass -eq 2) { $m += "$env:COMPUTERNAME\sneaky" }
    $m | ForEach-Object { [pscustomobject]@{ Name = $_ } }
}
function global:Get-LocalUser {
    param($ErrorAction)
    $n = @('Administrator', 'backdoor')
    if ($global:Pass -eq 2) { $n += 'newlocal' }
    $n | ForEach-Object { [pscustomobject]@{ Name = $_ } }
}
function global:Get-Process {
    param([int]$Id, $ErrorAction)
    if ($Id) { return [pscustomobject]@{ ProcessName = 'listener'; Id = $Id } }
    [pscustomobject]@{ ProcessName = 'explorer'; Id = 100; Path = 'C:\Windows\explorer.exe' }
    [pscustomobject]@{ ProcessName = 'updater'; Id = 200; Path = (Join-Path $global:Work 'Temp\updater.exe') }
    [pscustomobject]@{ ProcessName = 'customtool'; Id = 201; Path = 'C:\Windows\System32\customtool.exe' }
}
function global:Get-NetTCPConnection {
    param($State, $ErrorAction)
    [pscustomobject]@{ LocalPort = 445; OwningProcess = 4 }
    [pscustomobject]@{ LocalPort = 4444; OwningProcess = 300 }
}
function global:Get-ScheduledTask {
    param($ErrorAction)
    [pscustomobject]@{ TaskPath = '\Microsoft\Windows\'; TaskName = 'Defrag'; State = 'Ready' }
    if ($global:Pass -eq 2) { [pscustomobject]@{ TaskPath = '\'; TaskName = 'PersistTask'; State = 'Ready' } }
    if ($global:Tampered) {
        # What a previous round's web server actually looked like: the
        # update tasks switched off so the box stays exploitable.
        [pscustomobject]@{ TaskPath = '\Microsoft\Windows\UpdateOrchestrator\'; TaskName = 'Schedule Scan'; State = 'Disabled' }
    }
}
function global:Get-MpPreference {
    param($ErrorAction)
    if ($global:Tampered) {
        return [pscustomobject]@{
            DisableRealtimeMonitoring = $true; DisableBehaviorMonitoring = $false; DisableScriptScanning = $false
            ExclusionPath = @('C:\Users\Public'); ExclusionProcess = @(); ExclusionExtension = @()
        }
    }
    if ($global:DefenderUnreadable) {
        # Exactly what an unelevated Get-MpPreference returns: a message
        # in place of the list, not an error.
        return [pscustomobject]@{
            DisableRealtimeMonitoring = $false; DisableBehaviorMonitoring = $false; DisableScriptScanning = $false
            ExclusionPath = @('N/A: Must be an administrator to view exclusions')
            ExclusionProcess = @('N/A: Must be an administrator to view exclusions')
            ExclusionExtension = @('N/A: Must be an administrator to view exclusions')
        }
    }
    return [pscustomobject]@{
        DisableRealtimeMonitoring = $false; DisableBehaviorMonitoring = $false; DisableScriptScanning = $false
        ExclusionPath = @(); ExclusionProcess = @(); ExclusionExtension = @()
    }
}
function global:Get-ItemProperty {
    param($Path, $ErrorAction)
    $o = [pscustomobject]@{ PSPath = 'x'; PSParentPath = 'x'; OneDrive = 'C:\Windows\onedrive.exe' }
    if ($global:Pass -eq 2) { $o | Add-Member -NotePropertyName 'Beacon' -NotePropertyValue 'C:\Users\Public\b.exe' }
    $o
}
function global:Get-WinEvent {
    param($FilterHashtable, $MaxEvents, $ErrorAction)
    if ($global:Tampered -and $FilterHashtable -and $FilterHashtable['Id'] -eq 1102) {
        # Event 1102 is "the Security log was cleared", and it is the one
        # an attacker generates on the way out.
        return [pscustomobject]@{ TimeCreated = (Get-Date).AddMinutes(-5) }
    }
}
function global:Get-CimInstance {
    # $Filter is declared on purpose. Without it, a non-advanced function
    # swallows -Filter into $args and returns EVERY service, so a lookup
    # for one named service matches whatever is in the list -- which is
    # exactly how the OpenSSH check first appeared to find sshd here.
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_ComputerSystem') {
        # DomainRole 5 = primary domain controller, 3 = member server.
        return [pscustomobject]@{ DomainRole = $(if ($global:IsDc) { 5 } else { 3 }) }
    }
    if ($ClassName -ne 'Win32_Service') { return }

    if ($Filter) {
        if ($Filter -notmatch "Name='([^']+)'") { return }
        $wanted = $Matches[1]
        if ($global:Tampered) {
            if ($wanted -eq 'wuauserv') { return [pscustomobject]@{ Name = 'wuauserv'; StartMode = 'Disabled'; State = 'Stopped' } }
            if ($wanted -eq 'sshd') { return [pscustomobject]@{ Name = 'sshd'; StartMode = 'Auto'; State = 'Running' } }
        }
        return
    }
    [pscustomobject]@{ Name = 'Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe' }
    [pscustomobject]@{ Name = 'Dhcp'; PathName = '"C:\Windows\System32\svchost.exe" -k LocalServiceNetworkRestricted' }
    [pscustomobject]@{ Name = 'GhostSvc'; PathName = 'C:\does\not\exist.exe' }
    [pscustomobject]@{ Name = 'EvilSvc'; PathName = ('"' + (Join-Path $global:Work 'Temp\evil.exe') + '" -k x') }
    if ($global:Pass -eq 2) { [pscustomobject]@{ Name = 'Evil2'; PathName = ('"' + (Join-Path $global:Work 'Temp\evil.exe') + '"') } }
}
function global:Get-AuthenticodeSignature {
    param($FilePath, $LiteralPath, $ErrorAction)
    $p = if ($LiteralPath) { $LiteralPath } else { $FilePath }
    [pscustomobject]@{ Status = $(if ($p -like '*\Windows\*') { 'Valid' } else { 'NotSigned' }) }
}

# --- run the real module ------------------------------------------------------------------------
& (Join-Path $WorkDir 'modules\Invoke-ThreatHunt.ps1')
'@@DONE@@'
