#Requires -Version 5.1
# Regression tests for modules\Invoke-DnsHardening.ps1. DNS is a scored
# service AND the thing every other service depends on to be found, so this
# runs the real script in a child Windows PowerShell 5.1 process against
# fake DnsServer cmdlets; see tests\helpers\DnsHardeningHarness.ps1. Nothing
# here touches real DNS. Pure-function coverage for the verdict helpers
# (Get-CcdcDnsZoneTransferVerdict, Get-CcdcDnsDynamicUpdateVerdict, etc.)
# already lives in tests\Logic.Tests.ps1 -- this file is about whether the
# ORCHESTRATION makes the right calls, in the right order, and never more
# than it was asked to. Windows only.
#
#   Invoke-Pester .\tests\DnsHardening.Tests.ps1

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:Harness = Join-Path $PSScriptRoot 'helpers\DnsHardeningHarness.ps1'
$script:Engine = $null
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($env:OS -eq 'Windows_NT' -and (Test-Path $ps51)) { $script:Engine = $ps51 }

function script:Invoke-Scenario {
    param([string]$Name)
    $lines = & $script:Engine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Harness -RepoRoot $script:RepoRoot -Scenario $Name 2>&1 | ForEach-Object { "$_" }
    $resultLine = $lines | Where-Object { $_ -like '@@RESULT@@*' } | Select-Object -Last 1
    $result = $null
    if ($resultLine) { $result = $resultLine.Substring(10) | ConvertFrom-Json }
    if ($result -and $result.WorkDir -and (Test-Path $result.WorkDir)) { Remove-Item -Path $result.WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    [pscustomobject]@{
        Log       = @($lines | Where-Object { $_ -notlike '@@RESULT@@*' })
        Calls     = @($result.Calls)
        HasResult = [bool]$result
    }
}

function script:Test-LogHas { param($Run, [string]$Pattern) (@($Run.Log | Where-Object { $_ -match $Pattern }).Count -gt 0) }
function script:Get-CallsLike { param($Run, [string]$Pattern) @($Run.Calls | Where-Object { $_ -like $Pattern }) }

Describe 'Invoke-DnsHardening: audit only (no switches)' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'audit-only' } }

    It 'runs to completion under Windows PowerShell 5.1' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'changes absolutely nothing -- no Set- calls of any kind' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-*').Count | Should Be 0
    }
    It 'reports the open zone transfer as a finding' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run 'ANY server can pull this entire zone' | Should Be $true
    }
    It 'tells the operator nothing was changed and names the safe three' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run 'Nothing was changed.*SecureZoneTransfers.*SecureDynamicUpdates.*HardenCache' | Should Be $true
    }
}

Describe 'Invoke-DnsHardening: the safe three on a vulnerable AD-integrated zone' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'happy' } }

    It 'runs to completion' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'backs up the zone list and the cache settings before changing anything' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run "Backed up 'dns-zones-before'" | Should Be $true
        Test-LogHas $script:Run "Backed up 'dns-cache-before'" | Should Be $true
    }
    It 'refuses zone transfers on the vulnerable zone' {
        if (-not $script:Engine) { return }
        $calls = Get-CallsLike $script:Run 'Set-DnsServerPrimaryZone|lab.local|NoTransfer|*'
        $calls.Count | Should Be 1
    }
    It 'sets the AD-integrated zone to Secure dynamic updates' {
        if (-not $script:Engine) { return }
        $calls = Get-CallsLike $script:Run 'Set-DnsServerPrimaryZone|lab.local|*|Secure'
        $calls.Count | Should Be 1
    }
    It 'hardens the cache to 100% locking with pollution protection on' {
        if (-not $script:Engine) { return }
        $calls = Get-CallsLike $script:Run 'Set-DnsServerCache|100|True'
        $calls.Count | Should Be 1
    }
    It 'never touches recursion -- -DisableRecursion was not asked for' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-DnsServerRecursion|*').Count | Should Be 0
    }
}

Describe 'Invoke-DnsHardening: zone already secure' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'already-secure' } }

    It 'runs to completion' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'makes zero Set- calls -- nothing needed changing' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-*').Count | Should Be 0
    }
    It 'reports the cache as already hardened rather than re-applying it' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run 'cache was already hardened' | Should Be $true
    }
}

Describe 'Invoke-DnsHardening: file-backed zone with nonsecure dynamic update' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'filebacked-update' } }

    It 'runs to completion' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'does NOT change the file-backed zone -- Secure is not available and None would break registration' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-DnsServerPrimaryZone|legacy.local|*').Count | Should Be 0
    }
    It 'warns that the zone needs a deliberate decision instead of silently picking one' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run 'legacy\.local was NOT changed.*file-backed' | Should Be $true
    }
}

Describe 'Invoke-DnsHardening: -DisableRecursion, explicitly asked for' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'recursion-off' } }

    It 'runs to completion' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'turns recursion off when explicitly asked' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-DnsServerRecursion|False').Count | Should Be 1
    }
    It 'warns that this can break external lookups and cost the scored DNS check' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run 'Turning recursion OFF.*DNS is scored' | Should Be $true
    }
}

Describe 'Invoke-DnsHardening: recursion is never touched unless explicitly asked' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'recursion-untouched' } }

    It 'runs to completion' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'makes zero Set-DnsServerRecursion calls, even though recursion is on, because -DisableRecursion was not passed' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-DnsServerRecursion|*').Count | Should Be 0
    }
    It 'still fixes the other vulnerable settings' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-DnsServerPrimaryZone|*').Count | Should BeGreaterThan 0
    }
}

Describe 'Invoke-DnsHardening: no DnsServer module on this box' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'no-dnsserver' } }

    It 'runs to completion without erroring' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'makes zero calls of any kind' {
        if (-not $script:Engine) { return }
        $script:Run.Calls.Count | Should Be 0
    }
    It 'says plainly that there is nothing to do here' {
        if (-not $script:Engine) { return }
        Test-LogHas $script:Run "isn't installed on this box" | Should Be $true
    }
}

Describe 'Invoke-DnsHardening: -WhatIf' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'whatif' } }

    It 'runs to completion' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'makes zero real Set- calls despite asking for all three safe changes' {
        if (-not $script:Engine) { return }
        @(Get-CallsLike $script:Run 'Set-*').Count | Should Be 0
    }
}
