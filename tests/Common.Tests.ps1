#Requires -Version 5.1
# Tests for the shared scaffolding in modules\Common.psm1: answer precedence,
# password generation, the trimmed prompt helper, the sensitive-folder ACL,
# and the target-context banner. Run from the repo root: Invoke-Pester .\tests

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

Describe 'Get-CcdcAnswer precedence: -Value > answer file > prompt' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ccdc-test-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path (Join-Path $script:Tmp 'config') -Force | Out-Null
        Set-Content -Path (Join-Path $script:Tmp 'config\answers.local.psd1') -Value "@{ DomainName = 'from-file.local'; EmptyOne = '' }" -Encoding UTF8
        Import-CcdcAnswers -RootPath $script:Tmp | Out-Null
    }

    It 'an explicit -Value wins over the file' {
        (Get-CcdcAnswer -Key 'DomainName' -Prompt 'x' -Value 'explicit.local') | Should Be 'explicit.local'
    }
    It 'the answer file wins over prompting' {
        (Get-CcdcAnswer -Key 'DomainName' -Prompt 'x') | Should Be 'from-file.local'
    }
    It 'a blank answer in the file falls through to the prompt default' {
        Mock Read-Host { '' } -ModuleName Common
        (Get-CcdcAnswer -Key 'EmptyOne' -Prompt 'x' -Default 'dflt') | Should Be 'dflt'
    }
    It 'a missing key prompts, and typed input is returned' {
        Mock Read-Host { 'typed-value' } -ModuleName Common
        (Get-CcdcAnswer -Key 'NotThere' -Prompt 'x') | Should Be 'typed-value'
    }
}

Describe 'New-CcdcRandomPassword' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'defaults to 20 characters and honors -Length' {
        (New-CcdcRandomPassword).Length | Should Be 20
        (New-CcdcRandomPassword -Length 32).Length | Should Be 32
    }
    It 'always has upper, lower, digit and symbol, and never an ambiguous or KEY=VALUE-unsafe character' {
        $bad = New-Object System.Collections.Generic.List[string]
        1..300 | ForEach-Object {
            $p = New-CcdcRandomPassword
            if ($p -cnotmatch '[A-Z]') { $bad.Add("no upper: $p") }
            if ($p -cnotmatch '[a-z]') { $bad.Add("no lower: $p") }
            if ($p -notmatch '\d') { $bad.Add("no digit: $p") }
            if ($p -notmatch '[!@#%^&*\-_+]') { $bad.Add("no symbol: $p") }
            if ($p -cmatch '[IOl01="]') { $bad.Add("ambiguous/unsafe char: $p") }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'does not repeat' {
        $set = @{}
        1..200 | ForEach-Object { $set[(New-CcdcRandomPassword)] = 1 }
        $set.Count | Should Be 200
    }
}

Describe 'Read-CcdcInput' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'trims stray whitespace' {
        Mock Read-Host { '  web01  ' } -ModuleName Common
        (Read-CcdcInput -Prompt 'Which host') | Should Be 'web01'
    }
    It 'turns a $null (stdin ran out) into an empty string instead of crashing' {
        Mock Read-Host { $null } -ModuleName Common
        (Read-CcdcInput -Prompt 'Which host') | Should Be ''
    }
    It 'works with no prompt text (for callers that print their own)' {
        Mock Read-Host { ' YES ' } -ModuleName Common
        (Read-CcdcInput) | Should Be 'YES'
    }
}

Describe 'sessions and backups' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ccdc-test-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Session = Start-CcdcSession -RootPath $script:Tmp
    }
    AfterAll { Stop-CcdcSession }

    It 'creates the timestamped log and backup folders under the given root' {
        (Test-Path $script:Session.BackupRoot) | Should Be $true
        $script:Session.BackupRoot | Should Match 'logs\\backups\\\d{4}-\d{2}-\d{2}_\d{6}$'
    }
    It 'Backup-CcdcState writes a Clixml file that round-trips' {
        $path = Backup-CcdcState -Name 'unit test/backup' -Data ([pscustomobject]@{ A = 1; B = 'two' })
        (Test-Path $path) | Should Be $true
        (Split-Path -Leaf $path) | Should Be 'unit_test_backup.xml'
        $back = Import-Clixml -Path $path
        $back.B | Should Be 'two'
    }
    It 'Invoke-CcdcSafe records success and failure without throwing' {
        $ok = Invoke-CcdcSafe -Target 't' -Action 'works' -ScriptBlock { 42 }
        $ok.Success | Should Be $true
        $ok.Value | Should Be 42
        $bad = Invoke-CcdcSafe -Target 't' -Action 'breaks' -ScriptBlock { throw 'boom' }
        $bad.Success | Should Be $false
        $bad.Detail | Should Be 'boom'
        Show-CcdcSummary
    }
    It 'Invoke-CcdcSafe wraps a collection result so it is not unrolled' {
        $r = Invoke-CcdcSafe -Target 't' -Action 'list' -ScriptBlock { 1, 2, 3 }
        @($r.Value).Count | Should Be 3
        Show-CcdcSummary
    }
}

Describe 'Protect-CcdcSensitiveFolder (Windows ACLs)' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $script:IsWin = ($env:OS -eq 'Windows_NT')
        $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) ("ccdc-acl-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        if ($script:IsWin) { Protect-CcdcSensitiveFolder -Path $script:Dir }
    }

    It 'stops inheriting and keeps only Administrators, SYSTEM and the current user' {
        if (-not $script:IsWin) { return }
        $acl = Get-Acl -Path $script:Dir
        $acl.AreAccessRulesProtected | Should Be $true
        $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })
        ($sids -contains 'S-1-5-32-544') | Should Be $true    # Administrators
        ($sids -contains 'S-1-5-18') | Should Be $true        # SYSTEM
        ($sids -contains 'S-1-5-32-545') | Should Be $false   # Users
        ($sids -contains 'S-1-1-0') | Should Be $false        # Everyone
        ($sids -contains 'S-1-5-11') | Should Be $false       # Authenticated Users
    }
    It 'is harmless on a path that does not exist' {
        { Protect-CcdcSensitiveFolder -Path (Join-Path $script:Dir 'nope') } | Should Not Throw
    }
}

Describe 'elevation and target context' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'Test-CcdcElevated answers true, false, or null (unknown) -- never throws' {
        $e = Test-CcdcElevated
        ($null -eq $e -or $e -is [bool]) | Should Be $true
    }
    It 'Show-CcdcTargetContext reports the local host and never throws' {
        $ctx = Show-CcdcTargetContext -RootPath ([System.IO.Path]::GetTempPath()) 6>$null
        if ($env:COMPUTERNAME) { $ctx.Host | Should Be $env:COMPUTERNAME }
        ($ctx.PSObject.Properties.Name -contains 'Domain') | Should Be $true
    }
    It 'stays quiet when the menu already showed it' {
        $env:CCDC_TARGET_SHOWN = '1'
        try {
            $ctx = Show-CcdcTargetContext -RootPath ([System.IO.Path]::GetTempPath()) -SkipIfShownByMenu 6>$null
            $ctx | Should BeNullOrEmpty
        } finally { $env:CCDC_TARGET_SHOWN = $null }
    }
}
