#Requires -Version 5.1
# Unit tests for the IIS/FTP helpers in modules\CcdcLogic.ps1 (the pure part of
# Invoke-IISHardening.ps1). No IIS needed; runs anywhere.
#
#   Invoke-Pester .\tests\IISLogic.Tests.ps1

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

Describe 'Test-CcdcExecutableWebExtension' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'recognises what a web server would run' {
        foreach ($n in 'shell.aspx', 'a.asp', 'x.ashx', 'b.php', 'c.jsp', 'd.cfm', 'e.exe', 'f.dll', 'g.ps1') {
            (Test-CcdcExecutableWebExtension -FileName $n) | Should Be $true
        }
    }
    It 'counts web.config, because it can add handlers and modules' {
        (Test-CcdcExecutableWebExtension -FileName 'web.config') | Should Be $true
    }
    It 'leaves ordinary static content alone' {
        foreach ($n in 'index.html', 'logo.png', 'site.css', 'app.js', 'readme.txt', 'report.pdf') {
            (Test-CcdcExecutableWebExtension -FileName $n) | Should Be $false
        }
    }
    It 'is case-insensitive and safe on odd input' {
        (Test-CcdcExecutableWebExtension -FileName 'SHELL.ASPX') | Should Be $true
        (Test-CcdcExecutableWebExtension -FileName 'noextension') | Should Be $false
        (Test-CcdcExecutableWebExtension -FileName '') | Should Be $false
        (Test-CcdcExecutableWebExtension -FileName $null) | Should Be $false
    }
}

Describe 'Get-CcdcWebShellFlags' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $script:Cutoff = [datetime]'2026-06-01T12:00:00'
        $script:Old = [datetime]'2026-01-01T09:00:00'
        $script:New = [datetime]'2026-06-01T13:00:00'
    }

    It 'never flags a static file, whatever else is true about it' {
        $f = @(Get-CcdcWebShellFlags -FileName 'logo.png' -RelativePath 'uploads\logo.png' -LastWriteTime $script:New -ReferenceTime $script:Cutoff -ContentIndicators @('eval('))
        $f.Count | Should Be 0
    }
    It 'flags an executable file modified after the cutoff' {
        $f = @(Get-CcdcWebShellFlags -FileName 'a.aspx' -RelativePath 'a.aspx' -LastWriteTime $script:New -ReferenceTime $script:Cutoff)
        ($f -contains 'RECENTLY MODIFIED') | Should Be $true
    }
    It 'does not flag an executable file older than the cutoff as recent' {
        $f = @(Get-CcdcWebShellFlags -FileName 'a.aspx' -RelativePath 'a.aspx' -LastWriteTime $script:Old -ReferenceTime $script:Cutoff)
        ($f -contains 'RECENTLY MODIFIED') | Should Be $false
    }
    It 'flags an executable file sitting in a folder meant for uploads' {
        foreach ($p in 'uploads\x.aspx', 'upload\x.aspx', 'files\x.php', 'images/x.aspx', 'a\b\userfiles\x.aspx') {
            $f = @(Get-CcdcWebShellFlags -FileName 'x.aspx' -RelativePath $p -LastWriteTime $script:Old -ReferenceTime $script:Cutoff)
            ($f -contains 'EXECUTABLE FILE IN AN UPLOAD/CONTENT FOLDER') | Should Be $true
        }
    }
    It 'does not flag the normal application folders as upload folders' {
        $f = @(Get-CcdcWebShellFlags -FileName 'default.aspx' -RelativePath 'app\default.aspx' -LastWriteTime $script:Old -ReferenceTime $script:Cutoff)
        ($f -contains 'EXECUTABLE FILE IN AN UPLOAD/CONTENT FOLDER') | Should Be $false
    }
    It 'reports each content indicator that was found, naming it' {
        $f = @(Get-CcdcWebShellFlags -FileName 'a.aspx' -RelativePath 'a.aspx' -LastWriteTime $script:Old -ReferenceTime $script:Cutoff -ContentIndicators @('eval(', 'WScript.Shell'))
        ($f -contains 'CONTENT LOOKS LIKE A SHELL: eval(') | Should Be $true
        ($f -contains 'CONTENT LOOKS LIKE A SHELL: WScript.Shell') | Should Be $true
    }
    It 'flags a file much newer than the rest of the site' {
        $f = @(Get-CcdcWebShellFlags -FileName 'a.aspx' -RelativePath 'a.aspx' -LastWriteTime $script:New -ReferenceTime $script:New.AddDays(1) -SiteBaselineTime $script:Old)
        ($f -contains 'MUCH NEWER THAN THE REST OF THE SITE') | Should Be $true
    }
    It 'does not use the age comparison when the site was published all at once' {
        $f = @(Get-CcdcWebShellFlags -FileName 'a.aspx' -RelativePath 'a.aspx' -LastWriteTime $script:Old.AddDays(1) -ReferenceTime $script:Cutoff -SiteBaselineTime $script:Old)
        ($f -contains 'MUCH NEWER THAN THE REST OF THE SITE') | Should Be $false
    }
    It 'says nothing about an ordinary, old, untouched application page' {
        $f = @(Get-CcdcWebShellFlags -FileName 'default.aspx' -RelativePath 'default.aspx' -LastWriteTime $script:Old -ReferenceTime $script:Cutoff -SiteBaselineTime $script:Old -ContentIndicators @())
        $f.Count | Should Be 0
    }
    It 'is safe with nothing supplied' {
        { Get-CcdcWebShellFlags -FileName 'a.aspx' } | Should Not Throw
    }
}

Describe 'Test-CcdcRiskyFtpAuthorization' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'flags everyone-can-write and anonymous-can-write' {
        (Test-CcdcRiskyFtpAuthorization -Users '*' -Permissions '3') | Should Be $true   # read+write
        (Test-CcdcRiskyFtpAuthorization -Users '*' -Permissions '2') | Should Be $true   # write
        (Test-CcdcRiskyFtpAuthorization -Users '?' -Permissions '2') | Should Be $true   # anonymous
        (Test-CcdcRiskyFtpAuthorization -Users '' -Roles '*' -Permissions '3') | Should Be $true
    }
    It 'accepts the word form as well as the number' {
        (Test-CcdcRiskyFtpAuthorization -Users '*' -Permissions 'Read, Write') | Should Be $true
        (Test-CcdcRiskyFtpAuthorization -Users '*' -Permissions 'Read') | Should Be $false
    }
    It 'does not flag everyone-can-only-read' {
        (Test-CcdcRiskyFtpAuthorization -Users '*' -Permissions '1') | Should Be $false
    }
    It 'does not flag a named account that can write' {
        (Test-CcdcRiskyFtpAuthorization -Users 'svc_ftp' -Permissions '3') | Should Be $false
        (Test-CcdcRiskyFtpAuthorization -Users 'LAB\svc_ftp' -Permissions 'Write') | Should Be $false
    }
}

Describe 'Get-CcdcIisAnswerSuggestion' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'turns standard bindings into the well-known service names' {
        $b = @([pscustomobject]@{ Protocol = 'http'; Port = '80' }, [pscustomobject]@{ Protocol = 'https'; Port = '443' })
        $s = Get-CcdcIisAnswerSuggestion -HostName 'LABWEB' -Bindings $b
        $s.ScoredServices | Should Be 'LABWEB:HTTP,LABWEB:HTTPS'
        @($s.ExtraLines).Count | Should Be 0
    }
    It 'gives a non-standard port its own name and Port_ line' {
        $b = @([pscustomobject]@{ Protocol = 'http'; Port = '8080' })
        $s = Get-CcdcIisAnswerSuggestion -HostName 'LABWEB' -Bindings $b
        $s.ScoredServices | Should Be 'LABWEB:HTTP8080'
        ($s.ExtraLines -join '') | Should Be "Port_HTTP8080 = '8080'"
    }
    It 'adds the FTP passive range, which is the piece people miss' {
        $b = @([pscustomobject]@{ Protocol = 'ftp'; Port = '21' })
        $s = Get-CcdcIisAnswerSuggestion -HostName 'LABFTP' -Bindings $b -FtpPassiveRange '50000-50100'
        $s.ScoredServices | Should Be 'LABFTP:FTP,LABFTP:FTPPassive'
        ($s.ExtraLines -join '') | Should Be "Port_FTPPassive = '50000-50100'"
    }
    It 'expands the 0-0 range to the real Windows ephemeral range' {
        $s = Get-CcdcIisAnswerSuggestion -HostName 'LABFTP' -Bindings @([pscustomobject]@{ Protocol = 'ftp'; Port = '21' }) -FtpPassiveRange '0-0'
        ($s.ExtraLines -join '') | Should Be "Port_FTPPassive = '49152-65535'"
    }
    It 'does not repeat a service when two sites share a protocol and port' {
        $b = @([pscustomobject]@{ Protocol = 'http'; Port = '80' }, [pscustomobject]@{ Protocol = 'http'; Port = '80' })
        (Get-CcdcIisAnswerSuggestion -HostName 'W' -Bindings $b).ScoredServices | Should Be 'W:HTTP'
    }
    It 'ignores protocols the firewall module does not handle, and empty input' {
        $b = @([pscustomobject]@{ Protocol = 'net.tcp'; Port = '808' })
        (Get-CcdcIisAnswerSuggestion -HostName 'W' -Bindings $b).ScoredServices | Should Be ''
        (Get-CcdcIisAnswerSuggestion -HostName 'W' -Bindings @()).ScoredServices | Should Be ''
    }
    It 'produces something the firewall module can actually consume' {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $b = @([pscustomobject]@{ Protocol = 'http'; Port = '80' }, [pscustomobject]@{ Protocol = 'ftp'; Port = '21' })
        $s = Get-CcdcIisAnswerSuggestion -HostName 'LABFTP' -Bindings $b -FtpPassiveRange '50000-50100'
        $forHost = @(Get-CcdcScoredServicesForHost -ScoredServices ($s.ScoredServices -split ',') -HostName 'LABFTP')
        ($forHost -contains 'HTTP') | Should Be $true
        ($forHost -contains 'FTPPassive') | Should Be $true
        # HTTP and FTP are known; FTPPassive needs its Port_ line, which is supplied.
        @(Get-CcdcServiceRuleSpecs -ServiceName 'HTTP').Count | Should BeGreaterThan 0
        @(Get-CcdcServiceRuleSpecs -ServiceName 'FTPPassive').Count | Should Be 0
        $parsed = ConvertFrom-CcdcPortSpec -Spec '50000-50100'
        @($parsed.Specs).Count | Should Be 1
        $parsed.Specs[0].Port | Should Be '50000-50100'
    }
}

Describe 'the shipped web-shell indicator file' {
    It 'exists, parses, and has no regex-looking entries (matching is plain text)' {
        $file = Join-Path $script:RepoRoot 'configs\iis\webshell-indicators.txt'
        (Test-Path $file) | Should Be $true
        $entries = @(Get-Content $file | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
        $entries.Count | Should BeGreaterThan 20
        foreach ($e in $entries) { $e.Length | Should BeGreaterThan 2 }
    }
}
