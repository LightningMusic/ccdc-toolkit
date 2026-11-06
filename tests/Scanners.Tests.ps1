#Requires -Version 5.1
# Tests for the nmap and tshark wrappers (modules\Invoke-NetworkRecon.ps1 and
# modules\Invoke-PacketCapture.ps1), using a tiny STAND-IN executable that
# records the arguments it was given -- so the "credential never touches the
# command line" fix can be checked end to end, without nmap installed.
# Child Windows PowerShell 5.1 process, scratch repo copy. Windows only.
#
#   Invoke-Pester .\tests\Scanners.Tests.ps1

. (Join-Path $PSScriptRoot 'helpers\HarnessClient.ps1')

$script:Pw = 'Zx9-unique-secret-Q7'

Describe 'Invoke-NetworkRecon: credentialed scan' {
    BeforeAll {
        $script:Run = Invoke-ModuleHarness @{
            Module    = 'modules\Invoke-NetworkRecon.ps1'
            Args      = @{ Target = '10.10.10.5'; ScanProfile = 'Quick'; SmbUsername = 'svc_scan'; Hostname = 'SOMEHOST' }
            Inputs    = @($script:Pw)
            DummyExes = @('tools\nmap\nmap.exe')
            ReadBack  = @('tools\nmap\args.log', 'tools\nmap\script-args-content.log')
            ReadBackDirs = @('logs')
            Inventory = @{ Timestamp = (Get-Date).ToString('o'); DomainJoined = $false; ScoredServices = @('SOMEHOST:SMB') }
        }
    }

    It 'runs the scanner' {
        if (-not $script:Run) { return }
        $script:Run.Completed | Should Be $true
        ($script:Run.Files -contains 'tools\nmap\args.log') | Should Be $true
    }
    It 'passes the credential via --script-args-file, NEVER on the command line' {
        if (-not $script:Run) { return }
        $argLines = @((($script:Run.ReadBack.'tools\nmap\args.log' -split "---")[0] -split "`r?`n") | Where-Object { $_ })
        ($argLines -contains '--script-args-file') | Should Be $true
        (($argLines -join ' ').Contains($script:Pw)) | Should Be $false
        (($argLines -join ' ') -match 'smbpass|smbuser') | Should Be $false
        (($argLines -join ' ') -match '--script-args ') | Should Be $false
    }
    It 'the credential file the scanner read had the credentials in it (so the scan is genuinely credentialed)' {
        if (-not $script:Run) { return }
        $content = "$($script:Run.ReadBack.'tools\nmap\script-args-content.log')".Trim()
        $content | Should Be "smbuser=svc_scan,smbpass=$($script:Pw)"
    }
    It 'deletes the temporary credential file afterwards' {
        if (-not $script:Run) { return }
        $argLines = @((($script:Run.ReadBack.'tools\nmap\args.log' -split "---")[0] -split "`r?`n") | Where-Object { $_ })
        $i = [array]::IndexOf($argLines, '--script-args-file')
        $tmp = $argLines[$i + 1]
        (Test-Path $tmp) | Should Be $false
        # neutral name: a bare GUID, nothing greppable like "nmap" or "ccdc"
        (Split-Path $tmp -Leaf) | Should Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$'
    }
    It 'never writes the password into any log or transcript' {
        if (-not $script:Run) { return }
        $everything = ($script:Run.Log -join "`n") + ($script:Run.ReadBack.PSObject.Properties | Where-Object { $_.Name -like 'logs\*' } | ForEach-Object { [string]$_.Value }) -join "`n"
        $everything.Contains($script:Pw) | Should Be $false
    }
    It 'flags an open port nobody expected (4444), and not the scored SMB port (445)' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run '\[WARN\].*4444/tcp open') | Should Be $true
        (Test-HarnessLog $script:Run '\[WARN\].*445/tcp open') | Should Be $false
    }
}

Describe 'Invoke-NetworkRecon: -WhatIf with credentials' {
    It 'shows the command, but never asks for a password, never writes a file, and never runs the scanner' {
        $run = Invoke-ModuleHarness @{
            Module    = 'modules\Invoke-NetworkRecon.ps1'
            Args      = @{ Target = '10.10.10.5'; SmbUsername = 'svc_scan'; WhatIf = $true }
            Inputs    = @($script:Pw)
            DummyExes = @('tools\nmap\nmap.exe')
        }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Test-HarnessLog $run 'About to run: nmap') | Should Be $true
        (@($run.Prompts | Where-Object { $_ -match 'SMB password' }).Count) | Should Be 0
        ($run.Files -contains 'tools\nmap\args.log') | Should Be $false
        $run.InputsLeft | Should Be 1
    }
}

Describe 'Invoke-NetworkRecon: no credentials' {
    It 'does not prompt for a password and passes no script-args at all' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Invoke-NetworkRecon.ps1'; Args = @{ Target = '10.10.10.5'; ScanProfile = 'Vuln' }
            DummyExes = @('tools\nmap\nmap.exe'); ReadBack = @('tools\nmap\args.log'); Inputs = @()
        }
        if (-not $run) { return }
        (@($run.Prompts | Where-Object { $_ -match 'SMB password' }).Count) | Should Be 0
        $argLines = $run.ReadBack.'tools\nmap\args.log'
        $argLines | Should Match '--script'
        $argLines | Should Not Match 'script-args'
    }
}

Describe 'Invoke-PacketCapture' {
    It 'builds the tshark command from the parameters and saves a timestamped capture' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Invoke-PacketCapture.ps1'; Args = @{ DurationSeconds = 5; Interface = '1'; CaptureFilter = 'host 10.10.10.5' }
            DummyExes = @('tools\Wireshark\tshark.exe'); ReadBack = @('tools\Wireshark\args.log'); Inputs = @()
        }
        if (-not $run) { return }
        $run.Completed | Should Be $true
        $argLines = @((($run.ReadBack.'tools\Wireshark\args.log' -split "---")[0] -split "`r?`n") | Where-Object { $_ })
        (($argLines[0..3]) -join ' ') | Should Be '-i 1 -a duration:5'
        ($argLines -contains '-f') | Should Be $true
        ($argLines -contains 'host 10.10.10.5') | Should Be $true
        (@($run.Files | Where-Object { $_ -match '^logs\\captures\\.+_\d{4}-\d{2}-\d{2}_\d{6}\.pcapng$' }).Count) | Should Be 1
        (Test-HarnessLog $run 'Capture saved') | Should Be $true
    }
    It 'asks which interface when none is given' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Invoke-PacketCapture.ps1'; Args = @{ DurationSeconds = 5 }
            DummyExes = @('tools\Wireshark\tshark.exe'); Inputs = @('1')
        }
        if (-not $run) { return }
        (@($run.Prompts | Where-Object { $_ -match 'Interface number or name' }).Count) | Should Be 1
        (Test-HarnessLog $run 'Capture saved') | Should Be $true
    }
    It '-WhatIf captures nothing' {
        $run = Invoke-ModuleHarness @{
            Module = 'modules\Invoke-PacketCapture.ps1'; Args = @{ DurationSeconds = 5; Interface = '1'; WhatIf = $true }
            DummyExes = @('tools\Wireshark\tshark.exe'); Inputs = @()
        }
        if (-not $run) { return }
        ($run.Files -contains 'tools\Wireshark\args.log') | Should Be $false
    }
}
