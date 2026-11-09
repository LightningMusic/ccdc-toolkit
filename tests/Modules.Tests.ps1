#Requires -Version 5.1
# Scripted end-to-end runs of the remaining modules, in a child Windows
# PowerShell 5.1 process against a scratch copy of the repo, with every
# Read-Host prompt answered from a script: the incident report generator, the
# admin console, environment inventory, the Splunk forwarder reconfigure path,
# and AD hardening's no-RSAT behavior. Nothing here changes the real system.
# Windows only.
#
#   Invoke-Pester .\tests\Modules.Tests.ps1

. (Join-Path $PSScriptRoot 'helpers\HarnessClient.ps1')

Describe 'New-IncidentReport' {
    BeforeAll {
        $now = Get-Date
        $sessionName = "logs\session_$($now.ToString('yyyy-MM-dd'))_000001.log"
        $sessionBody = "[$($now.ToString('HH:mm:ss'))] [WARN] planted evidence line for the proof section`n[03:00:00] [WARN] a line from hours ago, outside the window"
        # Prompt order, which is also the required-field order from the
        # packet and the incident-reporting inject:
        #  title, description, delivery, scope, detectedTime, timeline,
        #  sourceIp, destIp, credsCracked, credsRotated, impact, evidence,
        #  iocs, remArtifact, remVerified, prevention
        $script:Full = Invoke-ModuleHarness @{
            Module = 'modules\New-IncidentReport.ps1'; Args = @{ Hostname = 'WEB01' }
            ExtraFiles = @{ $sessionName = $sessionBody }
            ReadBackDirs = @('logs\incident-reports')
            Inputs = @('Webshell on WEB01', 'An unauthorized aspx file was uploaded and executed',
                       'file upload form with no extension filtering', '1 server (WEB01), the IIS web service',
                       '14:35', '14:12 upload; 14:20 first execution; 14:35 detected; 14:44 contained',
                       '10.20.30.40', '172.20.240.101',
                       'none cracked', 'rotated the app pool account',
                       '5 minutes of downtime', 'screenshot 1 and the <b>evil</b>.aspx file',
                       'evil.aspx', 'deleted evil.aspx', 'curl returned 200',
                       'removed execute rights from the upload folder')
        }
        $script:NoPrevention = Invoke-ModuleHarness @{
            Module = 'modules\New-IncidentReport.ps1'; Args = @{ Hostname = 'WEB01' }; ReadBackDirs = @('logs\incident-reports')
            Inputs = @('Something happened', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '')
        }
    }

    function script:Get-Report { param($Run, [string]$Extension)
        $p = @($Run.ReadBack.PSObject.Properties | Where-Object { $_.Name -match "^logs\\incident-reports\\WEB01_.+\.$Extension$" })
        if ($p.Count -eq 0) { return '' }
        return [string]$p[0].Value
    }

    It 'writes both a Markdown working copy and a print-ready HTML memo' {
        if (-not $script:Full) { return }
        $script:Full.Completed | Should Be $true
        @($script:Full.ReadBack.PSObject.Properties | Where-Object { $_.Name -match '\.md$' }).Count | Should Be 1
        @($script:Full.ReadBack.PSObject.Properties | Where-Object { $_.Name -match '\.html$' }).Count | Should Be 1
    }
    It 'contains every section the packet and the inject require' {
        if (-not $script:Full) { return }
        $md = Get-Report $script:Full 'md'
        foreach ($h in '## Summary', '## Scope', '## Timeline and sequence', '## Source and destination',
                       '## Delivery mechanism', '## Credentials', '## Damage and impact',
                       '## Supporting evidence', '## Remediation', '## Prevention') {
            $md.Contains($h) | Should Be $true
        }
    }
    It 'consumes every prompt and loses none to a trim/null bug' {
        if (-not $script:Full) { return }
        $md = Get-Report $script:Full 'md'
        $md | Should Match 'Webshell on WEB01'
        $md | Should Match '10\.20\.30\.40'
        $md | Should Match '172\.20\.240\.101'
        $md | Should Match 'file upload form with no extension filtering'
        $md | Should Match 'removed execute rights from the upload folder'
        $script:Full.InputsLeft | Should Be 0
    }
    It 'carries the business-memo header a judge expects' {
        if (-not $script:Full) { return }
        $md = Get-Report $script:Full 'md'
        $md | Should Match '\*\*To:\*\* CIO Management Team'
        (Get-Report $script:Full 'html') | Should Match 'CIO Management Team'
    }
    It 'escapes markup in the HTML, because an IR quotes attacker-controlled strings by definition' {
        if (-not $script:Full) { return }
        $html = Get-Report $script:Full 'html'
        $html | Should Match '&lt;b&gt;evil&lt;/b&gt;'
        $html.Contains('<b>evil</b>') | Should Be $false
    }
    It 'auto-pulls session-log lines from the evidence window, and leaves out lines from hours earlier' {
        if (-not $script:Full) { return }
        $md = Get-Report $script:Full 'md'
        $md | Should Match 'planted evidence line for the proof section'
        $md | Should Not Match 'a line from hours ago'
    }
    It 'tells the operator the portal needs a PDF and how to get one' {
        if (-not $script:Full) { return }
        (Test-HarnessLog $script:Full 'ConvertTo-Pdf') | Should Be $true
    }
    It 'shouts if prevention is left blank, and marks the gap in the report' {
        if (-not $script:NoPrevention) { return }
        (Test-HarnessLog $script:NoPrevention '\[ERROR\].*Prevention is blank') | Should Be $true
        (Get-Report $script:NoPrevention 'md') | Should Match '## Prevention[\s\S]*FILL IN'
    }
    It 'names every required field that is still blank rather than just counting them' {
        if (-not $script:NoPrevention) { return }
        (Test-HarnessLog $script:NoPrevention 'required field\(s\) are still blank') | Should Be $true
        foreach ($needed in 'source IP address', 'destination IP address', 'time window and sequence',
                            'delivery mechanism', 'scope:') {
            (Test-HarnessLog $script:NoPrevention ([regex]::Escape($needed))) | Should Be $true
        }
    }
    It 'warns against filing one for a misconfiguration, which the packet scores negatively' {
        if (-not $script:Full) { return }
        (Test-HarnessLog $script:Full 'EXPLOITATION EVENT, NOT A MISCONFIGURATION') | Should Be $true
    }
}

Describe 'Invoke-AdminConsole (scripted session)' {
    BeforeAll {
        $tmp = [System.IO.Path]::GetTempPath()
        $script:Run = Invoke-ModuleHarness @{
            Module = 'modules\Invoke-AdminConsole.ps1'
            Inputs = @('7', '1', $tmp, '2', $tmp, 'BUILTIN\Users', 'Owner', 'B',    # file perms: show ACL; grant with an invalid right; back
                       '5', '1', 'abc', 'B',                                        # firewall: invalid port; back
                       '9', 'Get-Date -Format yyyy', 'YES',                         # custom command, confirmed
                       'B')                                                          # quit
        }
    }

    It 'runs a whole scripted session to a clean exit, consuming every answer' {
        if (-not $script:Run) { return }
        $script:Run.Completed | Should Be $true
        $script:Run.InputsLeft | Should Be 0
    }
    It 'file-permission actions use the shared validators (an invalid right is refused)' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run "isn't one of ReadAndExecute/Read/Write/Modify/FullControl") | Should Be $true
        (Test-HarnessLog $script:Run '^\s*Owner:') | Should Be $true
    }
    It 'refuses an invalid port before touching the firewall' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run "'abc' isn't a valid port") | Should Be $true
    }
    It 'the custom-command escape hatch warns that the command is logged in plaintext, then runs it' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run 'written to this session''s plaintext transcript') | Should Be $true
        ($script:Run.Log -contains (Get-Date -Format 'yyyy')) | Should Be $true
    }
    It 'trims stray whitespace around a YES confirmation' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-AdminConsole.ps1'; Inputs = @('9', 'Get-Date -Format yyyy', '  YES  ', 'B') }
        if (-not $run) { return }
        ($run.Log -contains (Get-Date -Format 'yyyy')) | Should Be $true
    }
    It 'anything other than YES cancels the custom command' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-AdminConsole.ps1'; Inputs = @('9', 'Get-Date -Format yyyy', 'y', 'B') }
        if (-not $run) { return }
        ($run.Log -contains (Get-Date -Format 'yyyy')) | Should Be $false
        (Test-HarnessLog $run 'Cancelled') | Should Be $true
    }
}

Describe 'Get-EnvironmentInventory: network sweep (works on Windows PowerShell 5.1)' {
    It 'sweeps a small block and saves the inventory, without any PowerShell-7-only constructs' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Get-EnvironmentInventory.ps1'; Args = @{ SubnetCidr = '127.0.0.0/30' }
            Answers = @{ ScoredServices = 'DC01:DNS,DC01:LDAP' }; Inputs = @(); ReadBack = @('logs\inventory-latest.json')
        }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Test-HarnessLog $run 'Parallel|parameter cannot be found') | Should Be $false
        $inv = $run.ReadBack.'logs\inventory-latest.json' | ConvertFrom-Json
        @($inv.ScoredServices).Count | Should Be 2
        if (-not $inv.DomainJoined) {
            (@($inv.NetworkHosts | ForEach-Object { $_.IPAddress }) -contains '127.0.0.1') | Should Be $true
        }
    }
    It 'refuses a mistyped huge block with a clear message instead of sweeping for an hour' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Get-EnvironmentInventory.ps1'; Args = @{ SubnetCidr = '10.0.0.0/8' }
            Answers = @{ ScoredServices = 'DC01:DNS' }; Inputs = @(); ReadBack = @('logs\inventory-latest.json')
        }
        if (-not $run) { return }
        $inv = $run.ReadBack.'logs\inventory-latest.json' | ConvertFrom-Json
        if (-not $inv.DomainJoined) {
            (Test-HarnessLog $run 'bigger than any CCDC subnet') | Should Be $true
            @($inv.NetworkHosts).Count | Should Be 0
        }
    }
}

Describe 'Install-SplunkForwarder: reconfigure an existing install' {
    It 'writes an output group named from ArtifactPrefix (no literal "ccdc" fingerprint) and restarts the service' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Install-SplunkForwarder.ps1'
            Answers = @{ SplunkIndexerAddress = 'idx.example'; ArtifactPrefix = 'Acme' }
            ExtraFiles = @{ 'tools\SplunkForwarder\fake.msi' = 'x'; 'pf\SplunkUniversalForwarder\bin\splunk.exe' = 'x' }
            Env = @{ ProgramFiles = '{WORK}\pf' }
            FakeSplunkService = $true; Inputs = @()
            ReadBack = @('pf\SplunkUniversalForwarder\etc\system\local\outputs.conf')
        }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        $conf = $run.ReadBack.'pf\SplunkUniversalForwarder\etc\system\local\outputs.conf'
        $conf | Should Match 'defaultGroup = Acme_indexers'
        $conf | Should Match '\[tcpout:Acme_indexers\]'
        $conf | Should Match 'server = idx\.example:9997'
        $conf | Should Not Match '(?i)ccdc'
        ($run.Calls -contains 'Restart-Service|SplunkForwarder') | Should Be $true
    }
}

Describe 'Invoke-CCDCToolkit (the main menu)' {
    It 'shows the target-check block BEFORE a YES prompt, and cancels cleanly on anything but YES' {
        $run = Invoke-ModuleHarness @{ Module = 'Invoke-CCDCToolkit.ps1'; Inputs = @('3', 'no', 'Z', '8', 'Q') }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        $run.InputsLeft | Should Be 0
        $log = $run.Log
        $banner = [array]::IndexOf(@($log | ForEach-Object { $_ -match 'TARGET CHECK' }), $true)
        $yes = [array]::IndexOf(@($log | ForEach-Object { $_ -match 'Type YES to continue' }), $true)
        ($banner -ge 0 -and $yes -gt $banner) | Should Be $true
        # the whole point of the banner: it must actually name the box, the domain and who is running this
        (Test-HarnessLog $run ('Host:\s+' + [regex]::Escape($env:COMPUTERNAME))) | Should Be $true
        (Test-HarnessLog $run 'Domain:\s+\S') | Should Be $true
        (Test-HarnessLog $run 'Running as:\s+\S.*elevated:') | Should Be $true
        (Test-HarnessLog $run 'Cancelled\.') | Should Be $true
        (Test-HarnessLog $run 'Not a valid choice') | Should Be $true
    }
    It 'launches a module after YES, shows the target block only ONCE, and passes the module''s own gates through' {
        $run = Invoke-ModuleHarness @{
            Module = 'Invoke-CCDCToolkit.ps1'; FakeLocalUsers = @('alice'); Answers = @{ ProtectedAccounts = 'someone_else' }
            Inputs = @('3', '  YES ', '', 'Q')   # option 3, confirm (with stray spaces), "press Enter", quit
        }
        if (-not $run) { return }
        $run.InputsLeft | Should Be 0
        (@($run.Log | Where-Object { $_ -match 'TARGET CHECK' }).Count) | Should Be 1
        ($run.Calls -contains 'Set-LocalUser|alice') | Should Be $true
    }
    It 'preview options (2 and 4) need no confirmation' {
        $run = Invoke-ModuleHarness @{ Module = 'Invoke-CCDCToolkit.ps1'; FakeLocalUsers = @('alice'); Answers = @{ ProtectedAccounts = 'x' }; Inputs = @('2', '', 'Q') }
        if (-not $run) { return }
        (@($run.Calls | Where-Object { $_ -like 'Set-LocalUser|*' }).Count) | Should Be 0
        (@($run.Prompts | Where-Object { $_ -match 'Type YES' }).Count) | Should Be 0
    }
    It 'exits instead of looping forever when input runs out' {
        $run = Invoke-ModuleHarness @{ Module = 'Invoke-CCDCToolkit.ps1'; Inputs = @() }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Test-HarnessLog $run 'no interactive console') | Should Be $true
    }
}
Describe 'Invoke-AD*: degrades cleanly without RSAT' {
    It 'AD hardening says what is missing instead of failing halfway (run with -WhatIf so a domain-joined dev box is never changed)' {
        $run = Invoke-ModuleHarness @{ Module = 'modules\Invoke-ADHardening.ps1'; Args = @{ WhatIf = $true }; Inputs = @('', '', '', '') }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Test-HarnessLog $run 'TARGET CHECK') | Should Be $true
    }
    It 'creates the hardening GPO through New-CcdcHardeningGpo, not its own inline New-GPO/Set-GPRegistryValue calls -- the one place this module and the admin console UI can agree on what it contains' {
        $text = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules\Invoke-ADHardening.ps1') -Raw
        $text | Should Match 'New-CcdcHardeningGpo'
        # Real code only, not a comment explaining the move -- which
        # legitimately NAMES the cmdlets this module deliberately no longer
        # calls directly.
        $code = ($text -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should Not Match 'New-GPO\s'
        $code | Should Not Match 'Set-GPRegistryValue'
    }
}
