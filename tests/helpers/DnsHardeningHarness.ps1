#Requires -Version 5.1
<#
.SYNOPSIS
    Test harness for modules\Invoke-DnsHardening.ps1. Runs the REAL module
    script against fake DnsServer cmdlets, in a scratch copy of the repo,
    and prints one machine-readable result line. Used by
    tests\DnsHardening.Tests.ps1; never touches this machine's real DNS
    configuration (there usually isn't one to touch, but the module would
    try if the real cmdlets were reachable).

.DESCRIPTION
    Same shape as tests\helpers\FirewallHarness.ps1: fakes defined as
    GLOBAL functions, a scratch copy of modules/config/configs, seeded
    answers, then the real script runs against the fakes.

.PARAMETER Scenario
    happy              a vulnerable zone (open transfers, AD-integrated
                        zone with nonsecure dynamic update, weak cache);
                        run with the three safe switches
    audit-only         no switches passed -- must change nothing at all
    already-secure     zone already NoTransfer/Secure, cache already
                        hardened -- the fix switches must make zero Set- calls
    filebacked-update  a file-backed zone with nonsecure dynamic update --
                        must be reported, never auto-changed
    recursion-off      -DisableRecursion passed explicitly
    recursion-untouched the three safe switches, recursion ON -- must
                        NEVER call Set-DnsServerRecursion
    no-dnsserver       Get-DnsServerZone doesn't exist (every non-DNS box)
                        -- must do nothing and not error
    whatif             the three safe switches + -WhatIf -- zero real Set- calls
#>
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)][ValidateSet('happy', 'audit-only', 'already-secure', 'filebacked-update', 'recursion-off', 'recursion-untouched', 'no-dnsserver', 'whatif')]
    [string]$Scenario
)

$ErrorActionPreference = 'Continue'
$global:Scenario = $Scenario
$global:Calls = New-Object System.Collections.Generic.List[string]

# One AD-integrated zone with issues the "safe three" switches should fix,
# unless the scenario says otherwise.
function script:Get-ZoneSet {
    switch ($global:Scenario) {
        'already-secure' {
            @(
                [pscustomobject]@{ ZoneName = 'lab.local'; ZoneType = 'Primary'; IsDsIntegrated = $true; DynamicUpdate = 'Secure'; SecureSecondaries = 'NoTransfer'; ZoneFile = $null; IsAutoCreated = $false }
            )
        }
        'filebacked-update' {
            @(
                [pscustomobject]@{ ZoneName = 'legacy.local'; ZoneType = 'Primary'; IsDsIntegrated = $false; DynamicUpdate = 'NonsecureAndSecure'; SecureSecondaries = 'NoTransfer'; ZoneFile = 'legacy.local.dns'; IsAutoCreated = $false }
            )
        }
        default {
            @(
                [pscustomobject]@{ ZoneName = 'lab.local'; ZoneType = 'Primary'; IsDsIntegrated = $true; DynamicUpdate = 'NonsecureAndSecure'; SecureSecondaries = 'TransferAnyServer'; ZoneFile = $null; IsAutoCreated = $false }
            )
        }
    }
}

if ($Scenario -ne 'no-dnsserver') {
    function global:Get-DnsServerZone { param($ErrorAction) Get-ZoneSet }
    # Recursion is reported ON in every scenario. 'recursion-off' passes
    # -DisableRecursion and needs it ON first to actually exercise the
    # disable path; 'recursion-untouched' needs it ON to prove the three
    # safe switches never touch it regardless.
    function global:Get-DnsServerRecursion { param($ErrorAction) [pscustomobject]@{ Enable = $true } }
    function global:Get-DnsServerForwarder { param($ErrorAction) [pscustomobject]@{ IPAddress = @('8.8.8.8') } }
    function global:Get-DnsServerCache {
        param($ErrorAction)
        if ($global:Scenario -eq 'already-secure') { [pscustomobject]@{ LockingPercent = 100; EnablePollutionProtection = $true } }
        else { [pscustomobject]@{ LockingPercent = 50; EnablePollutionProtection = $false } }
    }
    function global:Get-DnsServerRootHint { param($ErrorAction) @(1..13) }
    function global:Get-DnsServerResourceRecord { param($ZoneName, $ErrorAction) @() }
    function global:Set-DnsServerPrimaryZone {
        param($Name, $SecureSecondaries, $DynamicUpdate, $ErrorAction)
        $global:Calls.Add("Set-DnsServerPrimaryZone|$Name|$SecureSecondaries|$DynamicUpdate")
    }
    function global:Set-DnsServerCache {
        param($LockingPercent, $PollutionProtection, $ErrorAction)
        $global:Calls.Add("Set-DnsServerCache|$LockingPercent|$PollutionProtection")
    }
    function global:Set-DnsServerRecursion {
        param($Enable, $ErrorAction)
        $global:Calls.Add("Set-DnsServerRecursion|$Enable")
    }
}
# If $Scenario -eq 'no-dnsserver', none of the above are defined, so
# Get-Command -Name Get-DnsServerZone correctly finds nothing -- exactly
# the state every non-DNS-server box is actually in.

# --- scratch copy of the repo + seeded config -------------------------------------------------
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("dnstest-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work -Force | Out-Null
foreach ($item in 'modules', 'config', 'configs') { Copy-Item -Path (Join-Path $RepoRoot $item) -Destination (Join-Path $work $item) -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $work 'logs') -Force | Out-Null
Set-Content -Path (Join-Path $work 'config\answers.local.psd1') -Value "@{ SubnetCidr = '10.10.10.0/24' }" -Encoding UTF8

# --- run the real module ----------------------------------------------------------------------
$dns = Join-Path $work 'modules\Invoke-DnsHardening.ps1'
switch ($Scenario) {
    'audit-only' { & $dns }
    'no-dnsserver' { & $dns -SecureZoneTransfers -SecureDynamicUpdates -HardenCache }
    'recursion-off' { & $dns -DisableRecursion }
    'recursion-untouched' { & $dns -SecureZoneTransfers -SecureDynamicUpdates -HardenCache }
    'whatif' { & $dns -SecureZoneTransfers -SecureDynamicUpdates -HardenCache -WhatIf }
    default { & $dns -SecureZoneTransfers -SecureDynamicUpdates -HardenCache }
}

$result = [pscustomobject]@{ WorkDir = $work; Calls = @($global:Calls) }
'@@RESULT@@' + ($result | ConvertTo-Json -Compress -Depth 4)
