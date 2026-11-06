#Requires -Version 5.1
# Tests for modules\Invoke-CredentialHardening.ps1 -- especially the gate that
# stops a real run when ProtectedAccounts is empty. Runs the real script in a
# child Windows PowerShell 5.1 process with FAKE local-account cmdlets (nothing
# real is ever reset) and scripted answers. Windows only.
#
#   Invoke-Pester .\tests\CredentialHardening.Tests.ps1

. (Join-Path $PSScriptRoot 'helpers\HarnessClient.ps1')

function script:Get-SetCalls { param($Run) @($Run.Calls | Where-Object { $_ -like 'Set-LocalUser|*' } | ForEach-Object { $_.Split('|')[1] }) }

Describe 'Invoke-CredentialHardening: empty ProtectedAccounts gate' {
    It 'CANCELS a real run when the operator does not confirm, and changes nothing' {
        # Read-Host answers, in order: ProtectedAccounts prompt (blank), then the gate ("no")
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'bob'); Inputs = @('', 'no') }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Get-SetCalls $run).Count | Should Be 0
        (Test-HarnessLog $run 'Cancelled -- nothing was changed') | Should Be $true
        (@($run.Files | Where-Object { $_ -like 'logs\credentials_*.csv' }).Count) | Should Be 0
    }
    It 'proceeds only after the operator types NONE, and rotates every non-excluded account' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'bob'); Inputs = @('', 'NONE') }
        if (-not $run) { return }
        ((Get-SetCalls $run) -join ',') | Should Be 'alice,bob'
        (@($run.Files | Where-Object { $_ -like 'logs\credentials_*.csv' -and $_ -notlike '*_pcr.csv' }).Count) | Should Be 1
    }
    It 'accepts -AcknowledgeNoProtectedAccounts instead of the prompt' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice'); Inputs = @(''); Args = @{ AcknowledgeNoProtectedAccounts = $true } }
        if (-not $run) { return }
        ((Get-SetCalls $run) -join ',') | Should Be 'alice'
        (@($run.Prompts | Where-Object { $_ -match 'Type NONE' }).Count) | Should Be 0
    }
    It 'does not prompt at all, and skips the protected account, when ProtectedAccounts is set' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'svc_scored'); Answers = @{ ProtectedAccounts = 'svc_scored' }; Inputs = @() }
        if (-not $run) { return }
        ((Get-SetCalls $run) -join ',') | Should Be 'alice'
        (@($run.Prompts | Where-Object { $_ -match 'Type NONE' }).Count) | Should Be 0
    }
    It 'protected-account matching is case-insensitive' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'SVC_Scored'); Answers = @{ ProtectedAccounts = 'svc_scored' }; Inputs = @() }
        if (-not $run) { return }
        ((Get-SetCalls $run) -join ',') | Should Be 'alice'
    }
    It '-WhatIf never asks for confirmation and never changes anything' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'bob'); Inputs = @(''); Args = @{ WhatIf = $true } }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Get-SetCalls $run).Count | Should Be 0
        (@($run.Prompts | Where-Object { $_ -match 'Type NONE' }).Count) | Should Be 0
    }
    It 'also writes a headerless username,password PCR file alongside the credential sheet (for a Quotient-style scoring portal)' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'bob'); Inputs = @('', 'NONE'); ReadBackDirs = @('logs') }
        if (-not $run) { return }
        $pcr = @($run.ReadBack.PSObject.Properties | Where-Object { $_.Name -like 'logs\credentials_*_pcr.csv' })
        $pcr.Count | Should Be 1
        $lines = @(("$($pcr[0].Value)" -split "`r?`n") | Where-Object { $_ })
        $lines.Count | Should Be 2
        foreach ($l in $lines) { $l | Should Match '^(alice|bob),\S{20}$' }
    }
    It 'writes no PCR file when the run is cancelled and nothing was rotated' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice', 'bob'); Inputs = @('', 'no') }
        if (-not $run) { return }
        (@($run.Files | Where-Object { $_ -like 'logs\credentials_*_pcr.csv' }).Count) | Should Be 0
    }
    It 'never writes a generated password into the session log' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-CredentialHardening.ps1'; FakeLocalUsers = @('alice'); Inputs = @('', 'NONE'); ReadBackDirs = @('logs') }
        if (-not $run) { return }
        $csv = @($run.ReadBack.PSObject.Properties | Where-Object { $_.Name -like 'logs\credentials_*.csv' -and $_.Name -notlike '*_pcr.csv' })
        $csv.Count | Should Be 1
        $pw = ($csv[0].Value | ConvertFrom-Csv | Select-Object -First 1).Password
        $pw.Length | Should Be 20
        $logs = @($run.ReadBack.PSObject.Properties | Where-Object { $_.Name -like 'logs\session_*.log' })
        foreach ($l in $logs) { ([string]$l.Value).Contains($pw) | Should Be $false }
    }
}
