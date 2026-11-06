#Requires -Version 5.1
<#
.SYNOPSIS
    Test harness for modules\Invoke-FirewallBaseline.ps1. Runs the REAL module
    script against fake firewall / scheduled-task cmdlets, in a scratch copy of
    the repo, and prints one machine-readable result line. Used by
    tests\Firewall.Tests.ps1; safe to run by hand too -- it never touches this
    machine's real firewall or scheduled tasks.

.DESCRIPTION
    The fakes are defined as GLOBAL functions after the real NetSecurity and
    ScheduledTasks modules are pre-loaded. Order matters: if a real module
    auto-loads later it would otherwise shadow a fake with the real cmdlet
    (which, on an unelevated box, fails with "Access is denied").

    Everything the module needs (answers, inventory) is seeded in the scratch
    copy, so nothing here prompts.

.PARAMETER Scenario
    happy           everything succeeds
    ftp-ok          like happy, but an FTPPassive scored entry exists
    regfail         registering the safety-net task fails
    wrongprincipal  the task registers, but as a non-SYSTEM user
    regfail-allow   registration fails and -AllowNoSafetyNet is passed
    whatif          -WhatIf
    skipblock       -SkipDefaultBlock
    selfcheckfail   a rule silently lands with the wrong port (self-check must catch it)
    fullblackout    -FullBlackout: block first with zero rules, "run" credential
                    hardening (Start-Process is faked -- recorded, never really
                    launched), then add rules and self-check
    fullblackout-regfail  -FullBlackout where the safety net fails to arm: must
                    refuse to enter the blackout at all and never call Start-Process
#>
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)][ValidateSet('happy', 'ftp-ok', 'regfail', 'wrongprincipal', 'regfail-allow', 'whatif', 'skipblock', 'selfcheckfail', 'icmpfail', 'no-icmp', 'no-inventory', 'no-scored', 'fullblackout', 'fullblackout-regfail')]
    [string]$Scenario
)

$ErrorActionPreference = 'Continue'
Import-Module NetSecurity, ScheduledTasks -ErrorAction SilentlyContinue

$global:Scenario = $Scenario
$global:Calls = New-Object System.Collections.Generic.List[string]
$global:Rules = [ordered]@{}
$global:Tasks = @{}
$global:Profiles = @(
    [pscustomobject]@{ Name = 'Domain'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' },
    [pscustomobject]@{ Name = 'Private'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' },
    [pscustomobject]@{ Name = 'Public'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' })

# A pre-existing built-in-style rule, so rule enumeration has something real to walk past.
$global:Rules['File and Printer Sharing (NB-Session-In)'] = [pscustomobject]@{
    Name = 'FPS-NB'; DisplayName = 'File and Printer Sharing (NB-Session-In)'; Direction = 'Inbound'
    Enabled = 'True'; Action = 'Allow'; _Protocol = 'TCP'; _LocalPort = '139'; _Remote = 'Any'
}

function global:Get-NetFirewallRule {
    param([string]$DisplayName)
    if ($DisplayName) { if ($global:Rules.Contains($DisplayName)) { return $global:Rules[$DisplayName] } else { return $null } }
    return @($global:Rules.Values)
}
function global:Get-NetFirewallProfile { param([switch]$All) return $global:Profiles }
function global:New-NetFirewallRule {
    param($DisplayName, $Direction, $Protocol, $LocalPort, $Action, $RemoteAddress, $IcmpType, $ErrorAction)
    $remote = if ($RemoteAddress) { $RemoteAddress } else { 'Any' }
    # IcmpType is the last field so the fixed indexes the port-rule tests use stay put.
    $global:Calls.Add("New-NetFirewallRule|$DisplayName|$Protocol|$LocalPort|$remote|$IcmpType")
    $recordedPort = "$LocalPort"
    if ($global:Scenario -eq 'selfcheckfail' -and "$LocalPort" -eq '53' -and $Protocol -eq 'UDP') { $recordedPort = '5353' }  # silently wrong
    # A ping rule that gets created but comes back disabled -- the failure mode
    # that leaves a box looking hardened while it has stopped answering the
    # scoring engine.
    $enabled = 'True'
    if ($global:Scenario -eq 'icmpfail' -and $Protocol -eq 'ICMPv4') { $enabled = 'False' }
    $global:Rules[$DisplayName] = [pscustomobject]@{
        Name = $DisplayName; DisplayName = $DisplayName; Direction = $Direction; Enabled = $enabled; Action = $Action
        _Protocol = $Protocol; _LocalPort = $recordedPort; _Remote = $remote
    }
}
function global:Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule, $ErrorAction) [pscustomobject]@{ Protocol = $AssociatedNetFirewallRule._Protocol; LocalPort = $AssociatedNetFirewallRule._LocalPort } }
function global:Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule, $ErrorAction) [pscustomobject]@{ RemoteAddress = $AssociatedNetFirewallRule._Remote } }
function global:Set-NetFirewallProfile {
    param([switch]$All, $DefaultInboundAction, $DefaultOutboundAction, $ErrorAction)
    $global:Calls.Add("Set-NetFirewallProfile|$DefaultInboundAction")
    foreach ($p in $global:Profiles) { $p.DefaultInboundAction = $DefaultInboundAction }
}
function global:Disable-NetFirewallRule { param($Name, $ErrorAction) $global:Calls.Add("Disable-NetFirewallRule|$Name") }

function global:Register-ScheduledTask {
    param($TaskName, $Action, $Trigger, $Principal, $Settings, [switch]$Force, $ErrorAction)
    if ($global:Scenario -like 'regfail*' -or $global:Scenario -eq 'fullblackout-regfail') { throw 'Access is denied (simulated registration failure)' }
    $uid = $Principal.UserId
    $lvl = "$($Principal.RunLevel)"
    if ($global:Scenario -eq 'wrongprincipal') { $uid = 'someuser'; $lvl = 'Limited' }
    $global:Calls.Add("Register-ScheduledTask|$TaskName|$($Principal.UserId)|$($Principal.RunLevel)|$($Principal.LogonType)|$($Action.Execute)")
    $global:Tasks[$TaskName] = [pscustomobject]@{ TaskName = $TaskName; State = 'Ready'; Principal = [pscustomobject]@{ UserId = $uid; RunLevel = $lvl } }
}
function global:Get-ScheduledTask { param($TaskName, $ErrorAction) if ($global:Tasks.ContainsKey($TaskName)) { return $global:Tasks[$TaskName] } throw "task $TaskName not found" }
function global:Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction) $global:Calls.Add("Unregister-ScheduledTask|$TaskName"); $global:Tasks.Remove($TaskName) }
function global:Start-Sleep { param($Seconds) }   # nothing to wait for in a test
function global:Start-Process {
    # -FullBlackout launches Invoke-CredentialHardening.ps1 in its own
    # process and waits for it. Never actually spawn it from a test --
    # just record that it was asked for, with enough of the call to check
    # it really is credential hardening and really did -Wait.
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$NoNewWindow)
    $argText = ($ArgumentList -join ' ')
    $global:Calls.Add("Start-Process|$FilePath|$argText|Wait=$Wait")
}

# --- scratch copy of the repo + seeded config -------------------------------------------------
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("fwtest-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work -Force | Out-Null
foreach ($item in 'modules', 'config', 'configs') { Copy-Item -Path (Join-Path $RepoRoot $item) -Destination (Join-Path $work $item) -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $work 'logs') -Force | Out-Null

$h = $env:COMPUTERNAME
$scored = @("${h}:DNS", "${h}:LDAP", "${h}:NTP", "${h}:CustomApp", "${h}:FTP", 'OTHERHOST:HTTP')
if ($Scenario -eq 'ftp-ok') { $scored += "${h}:FTPPassive" }

$answers = New-Object System.Collections.Generic.List[string]
$answers.Add('@{')
$answers.Add("    AdminSubnet = '10.10.10.0/24'")
$answers.Add("    ArtifactPrefix = 'Test'")
$answers.Add("    Port_CustomApp = '8443,udp:5060,50000-50100'")
$answers.Add("    Port_FTPPassive = '50000-50100'")
# The 'no-inventory' scenario is the one that matters here: the answer
# file carries ScoredServices and no inventory-latest.json exists, which
# is exactly the state a box is in when the firewall baseline is run
# before discovery. It used to produce management rules and nothing else.
if ($Scenario -eq 'no-inventory') {
    $answers.Add("    ScoredServices = '$($scored -join ',')'")
}
$answers.Add('}')
Set-Content -Path (Join-Path $work 'config\answers.local.psd1') -Value $answers.ToArray() -Encoding UTF8

if ($Scenario -notin 'no-inventory', 'no-scored') {
    $inv = [pscustomobject]@{ Timestamp = (Get-Date).ToString('o'); DomainJoined = $false; ScoredServices = $scored }
    $inv | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $work 'logs\inventory-latest.json') -Encoding UTF8
}

# --- run the real module ----------------------------------------------------------------------
$fw = Join-Path $work 'modules\Invoke-FirewallBaseline.ps1'
switch ($Scenario) {
    'whatif' { & $fw -WhatIf }
    'skipblock' { & $fw -SkipDefaultBlock }
    'regfail-allow' { & $fw -AllowNoSafetyNet }
    'no-icmp' { & $fw -NoIcmpEcho }
    'fullblackout' { & $fw -FullBlackout }
    'fullblackout-regfail' { & $fw -FullBlackout }
    default { & $fw }
}

$result = [pscustomobject]@{
    WorkDir        = $work
    Calls          = @($global:Calls)
    DefaultInbound = @($global:Profiles | ForEach-Object { $_.DefaultInboundAction } | Select-Object -Unique)
    TasksLeft      = $global:Tasks.Count
}
'@@RESULT@@' + ($result | ConvertTo-Json -Compress -Depth 4)
