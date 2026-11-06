#Requires -Version 5.1
# End-to-end tests for modules\Invoke-IISHardening.ps1. The real script runs in
# a child Windows PowerShell 5.1 process against a stand-in WebAdministration
# module (tests\helpers\New-IisStubModule.ps1) and real files on disk, so the
# web-shell hunt is exercised for real. No IIS needed. Windows only.
#
#   Invoke-Pester .\tests\IISHardening.Tests.ps1

. (Join-Path $PSScriptRoot 'helpers\HarnessClient.ps1')

# A small web site on disk: one ordinary page, one image, and a planted shell in
# an uploads folder. "{WORK}" is replaced with the scratch folder by the harness.
$script:SiteFiles = @{
    'wwwroot\index.html'          = '<html><body>hello</body></html>'
    'wwwroot\default.aspx'        = '<%@ Page Language="C#" %><h1>App</h1>'
    'wwwroot\images\logo.png'     = 'not really a png'
    'wwwroot\uploads\readme.txt'  = 'uploads go here'
    'wwwroot\uploads\images.aspx' = '<% var p = System.Diagnostics.Process.Start("cmd.exe /c " + Request.Form["c"]); %>'
    'ftproot\welcome.txt'         = 'lab ftp'
    'ftproot\update.exe'          = 'MZ not really'
}

function script:New-IisSpec {
    param(
        [hashtable]$ExtraArgs = @{},
        [bool]$DirectoryBrowsing = $true,
        [bool]$XPoweredBy = $true,
        [bool]$FtpAnonymous = $true,
        [object[]]$FtpAuthz = @(@{ users = '*'; roles = ''; permissions = '3' }),
        [int]$FtpLow = 50000,
        [int]$FtpHigh = 50100,
        [bool]$ServerHeaderUnsupported = $false,
        [bool]$BackupFails = $false,
        [object[]]$AppPools = @(@{ Name = 'DefaultAppPool'; IdentityType = 'ApplicationPoolIdentity' }),
        [object[]]$Sites
    )
    if (-not $PSBoundParameters.ContainsKey('Sites')) {
        $Sites = @(
            @{ Name = 'Default Web Site'; PhysicalPath = '{WORK}\wwwroot'; DirectoryBrowsing = $DirectoryBrowsing; XPoweredBy = $XPoweredBy
               Bindings = @(@{ protocol = 'http'; bindingInformation = '*:80:' }, @{ protocol = 'https'; bindingInformation = '*:443:' }) },
            @{ Name = 'LabFTP'; PhysicalPath = '{WORK}\ftproot'; FtpAnonymous = $FtpAnonymous; FtpAuthz = $FtpAuthz
               Bindings = @(@{ protocol = 'ftp'; bindingInformation = '*:21:' }) }
        )
    }
    $labArgs = @{ SinceTime = '2026-06-01 00:00:00' }
    foreach ($k in $ExtraArgs.Keys) { $labArgs[$k] = $ExtraArgs[$k] }
    @{
        Module = 'modules\Invoke-IISHardening.ps1'
        Args = $labArgs
        Answers = @{ ArtifactPrefix = 'Test' }
        Inputs = @()
        ExtraFiles = $script:SiteFiles
        # Everything except the planted shell has been there since the site was published.
        BackdateFiles = @('wwwroot\index.html', 'wwwroot\default.aspx', 'wwwroot\images\logo.png', 'wwwroot\uploads\readme.txt', 'ftproot\welcome.txt')
        Iis = @{
            Sites = $Sites; AppPools = $AppPools; FtpLow = $FtpLow; FtpHigh = $FtpHigh
            ServerHeaderUnsupported = $ServerHeaderUnsupported; BackupFails = $BackupFails; RemoveServerHeader = $false
        }
    }
}
function script:Get-CallsLike { param($Run, [string]$Pattern) @($Run.Calls | Where-Object { $_ -match $Pattern }) }
function script:Get-Site { param($Run, [string]$Name) @($Run.Iis.Sites | Where-Object { $_.Name -eq $Name })[0] }

Describe 'Invoke-IISHardening: the read-only audit' {
    BeforeAll { if ($script:HarnessEngine) { $script:Run = Invoke-ModuleHarness (New-IisSpec -ExtraArgs @{ ReportOnly = $true }) } }

    It 'runs to completion and lists the sites it found' {
        if (-not $script:Run) { return }
        $script:Run.Completed | Should Be $true
        (Test-HarnessLog $script:Run 'Default Web Site') | Should Be $true
        (Test-HarnessLog $script:Run 'LabFTP') | Should Be $true
    }
    It 'finds the planted shell in the uploads folder and says why' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run 'images\.aspx') | Should Be $true
        (Test-HarnessLog $script:Run 'EXECUTABLE FILE IN AN UPLOAD') | Should Be $true
        (Test-HarnessLog $script:Run 'CONTENT LOOKS LIKE A SHELL') | Should Be $true
    }
    It 'does not flag the ordinary page or the static files' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run 'logo\.png') | Should Be $false
        (Test-HarnessLog $script:Run 'index\.html') | Should Be $false
        (Test-HarnessLog $script:Run 'default\.aspx') | Should Be $false
    }
    It 'prints the answer-file lines, including the FTP passive range' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run ':HTTP,') | Should Be $true
        (Test-HarnessLog $script:Run ':FTPPassive') | Should Be $true
        (Test-HarnessLog $script:Run "Port_FTPPassive = '50000-50100'") | Should Be $true
    }
    It 'reports anonymous FTP and a rule that lets everyone write' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run 'allows ANONYMOUS logins') | Should Be $true
        (Test-HarnessLog $script:Run "users='\*'.*WRITE") | Should Be $true
    }
    It 'notices the executable-looking file sitting in the FTP root' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run 'update\.exe') | Should Be $true
    }
    It 'changes NOTHING at all, and takes no backup it does not need' {
        if (-not $script:Run) { return }
        (Get-CallsLike $script:Run '^(Set-|Remove-|Deny-|Backup-)').Count | Should Be 0
        (Get-Site $script:Run 'Default Web Site').DirectoryBrowsing | Should Be $true
        (Get-Site $script:Run 'LabFTP').FtpAnonymous | Should Be $true
        (Test-HarnessLog $script:Run 'nothing was changed') | Should Be $true
    }
}

Describe 'Invoke-IISHardening: the default hardening pass' {
    BeforeAll { if ($script:HarnessEngine) { $script:Run = Invoke-ModuleHarness (New-IisSpec) } }

    It 'takes an IIS configuration backup BEFORE it changes anything, and says how to undo it' {
        if (-not $script:Run) { return }
        $backup = [array]::IndexOf($script:Run.Calls, (Get-CallsLike $script:Run '^Backup-WebConfiguration\|' | Select-Object -First 1))
        $firstChange = [array]::IndexOf($script:Run.Calls, (Get-CallsLike $script:Run '^(Set-|Remove-|Deny-)' | Select-Object -First 1))
        ($backup -ge 0 -and $firstChange -gt $backup) | Should Be $true
        (Test-HarnessLog $script:Run "Restore-WebConfiguration -Name 'Test-iis-") | Should Be $true
    }
    It 'turns directory browsing off' {
        if (-not $script:Run) { return }
        (Get-CallsLike $script:Run '^Set-DirectoryBrowsing\|Default Web Site\|False$').Count | Should Be 1
        (Get-Site $script:Run 'Default Web Site').DirectoryBrowsing | Should Be $false
    }
    It 'removes the X-Powered-By header and suppresses the Server header' {
        if (-not $script:Run) { return }
        (Get-CallsLike $script:Run '^Remove-XPoweredBy\|Default Web Site$').Count | Should Be 1
        (Get-CallsLike $script:Run '^Set-RemoveServerHeader\|True$').Count | Should Be 1
        $script:Run.Iis.RemoveServerHeader | Should Be $true
    }
    It 'leaves the two changes that can break a scored service alone unless asked' {
        if (-not $script:Run) { return }
        (Get-CallsLike $script:Run '^Deny-Extension\|').Count | Should Be 0
        (Get-CallsLike $script:Run '^Set-FtpAnonymous\|').Count | Should Be 0
        (Get-Site $script:Run 'LabFTP').FtpAnonymous | Should Be $true
    }
    It 'still does the whole read-only audit on the way through' {
        if (-not $script:Run) { return }
        (Test-HarnessLog $script:Run 'CONTENT LOOKS LIKE A SHELL') | Should Be $true
        (Test-HarnessLog $script:Run 'Port_FTPPassive') | Should Be $true
    }
}

Describe 'Invoke-IISHardening: -WhatIf' {
    It 'audits, says what it would change, and changes nothing' {
        $run = Invoke-ModuleHarness (New-IisSpec -ExtraArgs @{ WhatIf = $true })
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Test-HarnessLog $run 'CONTENT LOOKS LIKE A SHELL') | Should Be $true
        (Get-CallsLike $run '^(Set-|Remove-|Deny-|Backup-)').Count | Should Be 0
        (Get-Site $run 'Default Web Site').DirectoryBrowsing | Should Be $true
    }
}

Describe 'Invoke-IISHardening: it will not change what it cannot undo' {
    It 'makes no changes when the IIS configuration backup fails' {
        $run = Invoke-ModuleHarness (New-IisSpec -BackupFails $true)
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Get-CallsLike $run '^(Set-|Remove-|Deny-)').Count | Should Be 0
        (Test-HarnessLog $run "doesn't change IIS settings it can't undo") | Should Be $true
        (Get-Site $run 'Default Web Site').DirectoryBrowsing | Should Be $true
    }
}

Describe 'Invoke-IISHardening: the opt-in changes' {
    It '-BlockRiskyExtensions denies the listed extensions and warns first' {
        $run = Invoke-ModuleHarness (New-IisSpec -ExtraArgs @{ BlockRiskyExtensions = $true; RiskyExtensions = @('.php', '.jsp') })
        if (-not $run) { return }
        (Get-CallsLike $run '^Deny-Extension\|Default Web Site\|\.php$').Count | Should Be 1
        (Get-CallsLike $run '^Deny-Extension\|Default Web Site\|\.jsp$').Count | Should Be 1
        (Test-HarnessLog $run 'most likely to break a real site') | Should Be $true
    }
    It '-DisableAnonymousFtp turns anonymous off and says what that could cost' {
        $run = Invoke-ModuleHarness (New-IisSpec -ExtraArgs @{ DisableAnonymousFtp = $true })
        if (-not $run) { return }
        (Get-CallsLike $run '^Set-FtpAnonymous\|LabFTP\|False$').Count | Should Be 1
        (Get-Site $run 'LabFTP').FtpAnonymous | Should Be $false
        (Test-HarnessLog $run 'If your packet scores an anonymous login') | Should Be $true
    }
    It '-KeepDirectoryBrowsing leaves it on' {
        $run = Invoke-ModuleHarness (New-IisSpec -ExtraArgs @{ KeepDirectoryBrowsing = $true })
        if (-not $run) { return }
        (Get-CallsLike $run '^Set-DirectoryBrowsing\|').Count | Should Be 0
        (Get-Site $run 'Default Web Site').DirectoryBrowsing | Should Be $true
    }
    It '-SkipWebShellHunt skips the hunt but still does the rest' {
        $run = Invoke-ModuleHarness (New-IisSpec -ExtraArgs @{ SkipWebShellHunt = $true })
        if (-not $run) { return }
        (Test-HarnessLog $run 'CONTENT LOOKS LIKE A SHELL') | Should Be $false
        (Get-CallsLike $run '^Set-DirectoryBrowsing\|').Count | Should Be 1
    }
}

Describe 'Invoke-IISHardening: quieter environments' {
    It 'says so and stops when IIS is not installed' {
        $spec = New-IisSpec
        $spec.Remove('Iis')
        $run = Invoke-ModuleHarness $spec
        if (-not $run) { return }
        $run.Completed | Should Be $true
        (Test-HarnessLog $run "IIS isn't installed") | Should Be $true
        (Get-CallsLike $run '^(Set-|Remove-|Deny-|Backup-)').Count | Should Be 0
    }
    It 'reports rather than fails when this IIS is too old to suppress the Server header' {
        $run = Invoke-ModuleHarness (New-IisSpec -ServerHeaderUnsupported $true)
        if (-not $run) { return }
        (Test-HarnessLog $run "doesn't support suppressing the Server header") | Should Be $true
        (Get-CallsLike $run '^Set-DirectoryBrowsing\|').Count | Should Be 1   # the rest still happened
    }
    It 'does not touch directory browsing that is already off' {
        $run = Invoke-ModuleHarness (New-IisSpec -DirectoryBrowsing $false)
        if (-not $run) { return }
        (Get-CallsLike $run '^Set-DirectoryBrowsing\|').Count | Should Be 0
        (Test-HarnessLog $run 'already off') | Should Be $true
    }
    It 'warns loudly about an application pool running as LocalSystem' {
        $run = Invoke-ModuleHarness (New-IisSpec -AppPools @(@{ Name = 'DefaultAppPool'; IdentityType = 'LocalSystem' }))
        if (-not $run) { return }
        (Test-HarnessLog $run '\[ERROR\].*runs as LocalSystem') | Should Be $true
    }
    It 'warns that a 0-0 passive range means 16,000 ports, and says so in the answer-file line' {
        $run = Invoke-ModuleHarness (New-IisSpec -FtpLow 0 -FtpHigh 0)
        if (-not $run) { return }
        (Test-HarnessLog $run "use the Windows ephemeral range") | Should Be $true
        (Test-HarnessLog $run "Port_FTPPassive = '49152-65535'") | Should Be $true
    }
    It 'does not flag an FTP rule that only lets a named account write' {
        $run = Invoke-ModuleHarness (New-IisSpec -FtpAuthz @(@{ users = 'svc_ftp'; roles = ''; permissions = '3' }))
        if (-not $run) { return }
        (Test-HarnessLog $run 'WRITE\.') | Should Be $false
    }
}
