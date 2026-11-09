#Requires -Version 5.1
# Unit tests for the pure helpers in modules\CcdcLogic.ps1 (exported through
# modules\Common.psm1). No AD, firewall, admin rights, or network needed --
# run from the repo root with:   Invoke-Pester .\tests
#
# Written in the classic Pester syntax ("Should Be", not "Should -Be") because
# that is what ships inside Windows PowerShell 5.1 (Pester 3.4) and also runs
# on newer Pester, so no install is needed on a locked-down box.

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

Describe 'service -> port tables' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'DNS is TCP and UDP 53' {
        ((Resolve-CcdcServicePorts -ServiceName 'DNS') -join ',') | Should Be '53'
        ((Resolve-CcdcServicePorts -ServiceName 'DNS' -Protocol UDP) -join ',') | Should Be '53'
    }
    It 'is case-insensitive and trims' {
        ((Resolve-CcdcServicePorts -ServiceName '  dns ') -join ',') | Should Be '53'
    }
    It 'NTP and DHCP are UDP-only (DHCP used to be mapped to TCP by mistake)' {
        @(Resolve-CcdcServicePorts -ServiceName 'NTP').Count | Should Be 0
        ((Resolve-CcdcServicePorts -ServiceName 'NTP' -Protocol UDP) -join ',') | Should Be '123'
        @(Resolve-CcdcServicePorts -ServiceName 'DHCP').Count | Should Be 0
        ((Resolve-CcdcServicePorts -ServiceName 'DHCP' -Protocol UDP) -join ',') | Should Be '67,68'
    }
    It 'returns nothing for unknown or empty names' {
        @(Resolve-CcdcServicePorts -ServiceName 'CustomApp').Count | Should Be 0
        @(Resolve-CcdcServicePorts -ServiceName '').Count | Should Be 0
        @(Resolve-CcdcServicePorts -ServiceName $null).Count | Should Be 0
    }
    It 'Get-CcdcServiceRuleSpecs returns both protocols for DNS and only UDP for NTP' {
        $dns = @(Get-CcdcServiceRuleSpecs -ServiceName 'DNS' | ForEach-Object { "$($_.Protocol)/$($_.Port)" })
        ($dns -contains 'TCP/53') | Should Be $true
        ($dns -contains 'UDP/53') | Should Be $true
        $ntp = @(Get-CcdcServiceRuleSpecs -ServiceName 'NTP' | ForEach-Object { "$($_.Protocol)/$($_.Port)" })
        ($ntp -join ',') | Should Be 'UDP/123'
    }
    It 'Get-CcdcServiceRuleSpecs is EMPTY only for a service it does not know' {
        @(Get-CcdcServiceRuleSpecs -ServiceName 'CustomApp').Count | Should Be 0
        @(Get-CcdcServiceRuleSpecs -ServiceName 'LDAP').Count | Should BeGreaterThan 0
    }
}

Describe 'Get-CcdcScoredServicesForHost' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'keeps only this host (case-insensitive) and bare entries' {
        $list = @('DC01:DNS', 'dc01:LDAP', 'WEB01:HTTP', 'NTP')
        $r = @(Get-CcdcScoredServicesForHost -ScoredServices $list -HostName 'DC01')
        ($r -join ',') | Should Be 'DNS,LDAP,NTP'
    }
    It 'trims whitespace around names' {
        $r = @(Get-CcdcScoredServicesForHost -ScoredServices @(' DC01 : DNS ') -HostName 'DC01')
        ($r -join ',') | Should Be 'DNS'
    }
    It 'is null- and empty-safe' {
        @(Get-CcdcScoredServicesForHost -ScoredServices $null -HostName 'DC01').Count | Should Be 0
        @(Get-CcdcScoredServicesForHost -ScoredServices @('', $null) -HostName 'DC01').Count | Should Be 0
    }
    It 'returns nothing for a host with no entries' {
        @(Get-CcdcScoredServicesForHost -ScoredServices @('DC01:DNS') -HostName 'WEB01').Count | Should Be 0
    }
}

Describe 'port validation and custom port specs' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'Test-CcdcValidPort accepts 1-65535 only' {
        (Test-CcdcValidPort '1') | Should Be $true
        (Test-CcdcValidPort '65535') | Should Be $true
        (Test-CcdcValidPort '0') | Should Be $false
        (Test-CcdcValidPort '65536') | Should Be $false
        (Test-CcdcValidPort '99999999999') | Should Be $false
        (Test-CcdcValidPort 'abc') | Should Be $false
        (Test-CcdcValidPort '') | Should Be $false
    }
    It 'parses a single port, a list, and a range' {
        $r = ConvertFrom-CcdcPortSpec -Spec '8443, 9443, 50000-50100'
        (($r.Specs | ForEach-Object { "$($_.Protocol)/$($_.Port)" }) -join ',') | Should Be 'TCP/8443,TCP/9443,TCP/50000-50100'
        @($r.Invalid).Count | Should Be 0
    }
    It 'honors udp:/tcp: prefixes and the default protocol' {
        $r = ConvertFrom-CcdcPortSpec -Spec 'udp:5060,tcp:5061,5062'
        (($r.Specs | ForEach-Object { "$($_.Protocol)/$($_.Port)" }) -join ',') | Should Be 'UDP/5060,TCP/5061,TCP/5062'
        $u = ConvertFrom-CcdcPortSpec -Spec '5060' -DefaultProtocol UDP
        "$($u.Specs[0].Protocol)/$($u.Specs[0].Port)" | Should Be 'UDP/5060'
    }
    It 'reports what it could not parse instead of guessing' {
        $r = ConvertFrom-CcdcPortSpec -Spec '80, 0, 99999, 80-20, abc, 1-2-3, 20-20'
        (($r.Specs | ForEach-Object { $_.Port }) -join ',') | Should Be '80'
        (($r.Invalid) -join '|') | Should Be '0|99999|80-20|abc|1-2-3|20-20'
    }
    It 'treats blank input as nothing to allow' {
        $r = ConvertFrom-CcdcPortSpec -Spec ''
        @($r.Specs).Count | Should Be 0
        @($r.Invalid).Count | Should Be 0
    }
    It 'validates IPv4 text and file-system rights' {
        (Test-CcdcValidIPv4 '10.10.10.5') | Should Be $true
        (Test-CcdcValidIPv4 '256.1.1.1') | Should Be $false
        (Test-CcdcValidIPv4 '1.2.3') | Should Be $false
        (Test-CcdcValidFileSystemRight 'Modify') | Should Be $true
        (Test-CcdcValidFileSystemRight 'Owner') | Should Be $false
    }
}

Describe 'Get-CcdcCidrAddresses' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'expands a /24 to 254 hosts, skipping network and broadcast' {
        $r = Get-CcdcCidrAddresses -Cidr '10.10.10.0/24'
        $r.Valid | Should Be $true
        @($r.Addresses).Count | Should Be 254
        $r.Addresses[0] | Should Be '10.10.10.1'
        $r.Addresses[-1] | Should Be '10.10.10.254'
    }
    It 'aligns a host address inside the block to the real network (/27)' {
        $r = Get-CcdcCidrAddresses -Cidr '192.168.1.77/27'
        @($r.Addresses).Count | Should Be 30
        $r.Addresses[0] | Should Be '192.168.1.65'
        $r.Addresses[-1] | Should Be '192.168.1.94'
    }
    It 'handles /31 (both addresses) and /32 (one address)' {
        (@((Get-CcdcCidrAddresses -Cidr '10.10.10.4/31').Addresses) -join ',') | Should Be '10.10.10.4,10.10.10.5'
        (@((Get-CcdcCidrAddresses -Cidr '10.10.10.9/32').Addresses) -join ',') | Should Be '10.10.10.9'
    }
    It 'crosses an octet boundary correctly (/23)' {
        $r = Get-CcdcCidrAddresses -Cidr '10.10.10.0/23'
        @($r.Addresses).Count | Should Be 510
        $r.Addresses[-1] | Should Be '10.10.11.254'
    }
    It 'refuses a huge block and says why' {
        $r = Get-CcdcCidrAddresses -Cidr '10.0.0.0/8'
        $r.Valid | Should Be $false
        $r.Message | Should Match 'bigger than any CCDC subnet'
    }
    It 'caps the number of addresses and notes the truncation' {
        $r = Get-CcdcCidrAddresses -Cidr '10.10.0.0/22' -MaxHosts 100
        $r.Valid | Should Be $true
        @($r.Addresses).Count | Should Be 100
        $r.Message | Should Match 'only the first 100'
    }
    It 'rejects garbage without throwing (including empty and null)' {
        (Get-CcdcCidrAddresses -Cidr '300.1.1.1/24').Valid | Should Be $false
        (Get-CcdcCidrAddresses -Cidr '10.10.10.0/33').Valid | Should Be $false
        (Get-CcdcCidrAddresses -Cidr 'not a cidr').Valid | Should Be $false
        (Get-CcdcCidrAddresses -Cidr '').Valid | Should Be $false
        (Get-CcdcCidrAddresses -Cidr $null).Valid | Should Be $false
    }
}

Describe 'Invoke-CcdcPingSweep (works on Windows PowerShell 5.1)' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'finds loopback and reports nothing for an empty list' {
        $alive = @(Invoke-CcdcPingSweep -Addresses @('127.0.0.1') -TimeoutMs 1500)
        ($alive -contains '127.0.0.1') | Should Be $true
        @(Invoke-CcdcPingSweep -Addresses @()).Count | Should Be 0
    }
    It 'does not report an address in the unroutable documentation range' {
        $alive = @(Invoke-CcdcPingSweep -Addresses @('192.0.2.1') -TimeoutMs 400)
        ($alive -contains '192.0.2.1') | Should Be $false
    }
}

Describe 'threat-hunt helpers' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'Get-CcdcNewItems returns only what is new, case-insensitively' {
        $r = @(Get-CcdcNewItems -Previous @('a', 'B') -Current @('A', 'b', 'c'))
        ($r -join ',') | Should Be 'c'
    }
    It 'Get-CcdcNewItems is null- and empty-safe (everything is new against nothing)' {
        (@(Get-CcdcNewItems -Previous $null -Current @('x', '', $null, 'y')) -join ',') | Should Be 'x,y'
        @(Get-CcdcNewItems -Previous @('x') -Current $null).Count | Should Be 0
    }
    It 'Get-CcdcServiceExePath strips arguments from quoted and unquoted paths' {
        Get-CcdcServiceExePath -PathName '"C:\Program Files\App\svc.exe" -k netsvcs' | Should Be 'C:\Program Files\App\svc.exe'
        Get-CcdcServiceExePath -PathName 'C:\Windows\system32\svchost.exe -k netsvcs' | Should Be 'C:\Windows\system32\svchost.exe'
        Get-CcdcServiceExePath -PathName '' | Should Be ''
        Get-CcdcServiceExePath -PathName $null | Should Be ''
    }
    It 'Test-CcdcSuspiciousPath matches the default staging locations' {
        $pats = @('\\Temp\\', '\\Downloads\\', '\\ProgramData\\(?!Microsoft)', '\\Users\\Public\\')
        (Test-CcdcSuspiciousPath -Path 'C:\Users\bob\AppData\Local\Temp\x.exe' -Patterns $pats) | Should Be $true
        (Test-CcdcSuspiciousPath -Path 'C:\ProgramData\Evil\a.exe' -Patterns $pats) | Should Be $true
        (Test-CcdcSuspiciousPath -Path 'C:\ProgramData\Microsoft\Windows Defender\a.exe' -Patterns $pats) | Should Be $false
        (Test-CcdcSuspiciousPath -Path 'C:\Windows\System32\cmd.exe' -Patterns $pats) | Should Be $false
        (Test-CcdcSuspiciousPath -Path '' -Patterns $pats) | Should Be $false
    }
}

Describe 'Test-CcdcStaleAccount' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $now = [datetime]'2026-06-01T12:00:00'
    }

    It 'never-logged-in enabled accounts are stale' {
        (Test-CcdcStaleAccount -Enabled $true -SamAccountName 'u1' -LastLogonDate $null -Now $now -StaleDaysThreshold 90 -ExcludedNames @()) | Should Be $true
    }
    It 'old logons are stale, recent ones are not' {
        (Test-CcdcStaleAccount -Enabled $true -SamAccountName 'u1' -LastLogonDate ([datetime]'2026-01-01') -Now $now -StaleDaysThreshold 90 -ExcludedNames @()) | Should Be $true
        (Test-CcdcStaleAccount -Enabled $true -SamAccountName 'u1' -LastLogonDate ([datetime]'2026-05-20') -Now $now -StaleDaysThreshold 90 -ExcludedNames @()) | Should Be $false
    }
    It 'disabled and excluded accounts are never candidates' {
        (Test-CcdcStaleAccount -Enabled $false -SamAccountName 'u1' -LastLogonDate $null -Now $now -StaleDaysThreshold 90 -ExcludedNames @()) | Should Be $false
        (Test-CcdcStaleAccount -Enabled $true -SamAccountName 'svc_scored' -LastLogonDate $null -Now $now -StaleDaysThreshold 90 -ExcludedNames @('svc_scored')) | Should Be $false
    }
}

Describe 'incident-report evidence windows' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $center = [datetime]'2026-06-01T14:00:00'
    }

    It 'log lines: keeps lines inside the window, drops outside and non-level lines' {
        $lines = @(
            '[13:40:00] [WARN] inside (20 min before)',
            '[14:30:00] [ERROR] exactly on the edge',
            '[14:30:01] [WARN] one second past the edge',
            '[09:00:00] [WARN] far outside',
            '[14:00:00] [INFO] wrong level',
            'not a log line at all'
        )
        $r = @(Get-CcdcLogLinesNearTime -Lines $lines -FileDate ([datetime]'2026-06-01') -CenterTime $center -WindowMinutes 30)
        $r.Count | Should Be 2
        ($r[0] -match 'inside') | Should Be $true
        ($r[1] -match 'edge') | Should Be $true
    }
    It 'log lines: anchors to the FILE date, not today' {
        $lines = @('[14:00:00] [OK] same clock time, different day')
        @(Get-CcdcLogLinesNearTime -Lines $lines -FileDate ([datetime]'2026-05-31') -CenterTime $center -WindowMinutes 30).Count | Should Be 0
    }
    It 'backup folders: parses yyyy-MM-dd_HHmmss names and applies the window' {
        $r = @(Get-CcdcBackupFoldersNearTime -FolderNames @('2026-06-01_135500', '2026-06-01_090000', 'garbage') -CenterTime $center -WindowMinutes 30)
        ($r -join ',') | Should Be '2026-06-01_135500'
    }
    It 'capture files: extracts the embedded timestamp from <host>_<stamp>.pcapng' {
        $r = @(Get-CcdcCaptureFilesNearTime -FileNames @('WEB01_2026-06-01_140500.pcapng', 'WEB01_2026-06-01_060000.pcapng', 'notes.txt') -CenterTime $center -WindowMinutes 30)
        ($r -join ',') | Should Be 'WEB01_2026-06-01_140500.pcapng'
    }
    It 'Test-CcdcAnyNonBlank ignores empty and whitespace-only answers' {
        (Test-CcdcAnyNonBlank -Values @('', '  ', $null)) | Should Be $false
        (Test-CcdcAnyNonBlank -Values @('', 'fixed it')) | Should Be $true
        (Test-CcdcAnyNonBlank -Values $null) | Should Be $false
    }
}

Describe 'external-tool argument builders' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'nmap: profiles map to the documented flags, output flags and target last' {
        $q = @(Get-CcdcNmapArgs -ScanProfileName 'Quick' -TargetHost '10.10.10.5' -OutputBase 'C:\o\scan')
        ($q -join ' ') | Should Be '-T4 -F -oN C:\o\scan.txt -oX C:\o\scan.xml 10.10.10.5'
        $f = @(Get-CcdcNmapArgs -ScanProfileName 'Full' -TargetHost 'h' -OutputBase 'o')
        ($f[0..1] -join ' ') | Should Be '-T4 -p-'
        $v = @(Get-CcdcNmapArgs -ScanProfileName 'Vuln' -TargetHost 'h' -OutputBase 'o')
        ($v -join ' ') | Should Match '--script default,vuln'
        $v[-1] | Should Be 'h'
    }
    It 'nmap: an SMB credential is passed as a FILE path, never on the command line' {
        $a = @(Get-CcdcNmapArgs -ScanProfileName 'Quick' -TargetHost 'h' -OutputBase 'o' -SmbUser 'svc' -ScriptArgsFilePath 'C:\t\abc.tmp')
        ($a -contains '--script-args-file') | Should Be $true
        ($a -contains 'C:\t\abc.tmp') | Should Be $true
        (($a -join ' ') -match 'smbpass|smbuser|--script-args ') | Should Be $false
    }
    It 'nmap: no credential means no script-args flags at all' {
        $a = @(Get-CcdcNmapArgs -ScanProfileName 'Quick' -TargetHost 'h' -OutputBase 'o')
        (($a -join ' ') -match 'script-args') | Should Be $false
    }
    It 'nmap: unexpected-open-port check' {
        (Test-CcdcUnexpectedOpenPort -Port 4444 -ExpectedPorts @(80, 443)) | Should Be $true
        (Test-CcdcUnexpectedOpenPort -Port 443 -ExpectedPorts @(80, 443)) | Should Be $false
    }
    It 'tshark: duration, interface, output, and an optional filter' {
        ((Get-CcdcTsharkArgs -Duration 30 -Iface '2' -Filter '' -OutputPath 'c.pcapng') -join ' ') | Should Be '-i 2 -a duration:30 -w c.pcapng'
        ((Get-CcdcTsharkArgs -Duration 30 -Iface '2' -Filter 'host 10.10.10.5' -OutputPath 'c.pcapng') -join '|') | Should Be '-i|2|-a|duration:30|-w|c.pcapng|-f|host 10.10.10.5'
    }
}

Describe 'name tampering: the attack that renames a file so a reference stops resolving' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'flags a trailing space -- the reported attack, and invisible in Explorer' {
        $f = @(Get-CcdcNameTamperFlag -Name 'acme.com.dns ')
        $f.Count | Should Be 1
        ($f -join ';') | Should Match 'ends with whitespace'
    }
    It 'flags a leading space and a trailing tab too' {
        (@(Get-CcdcNameTamperFlag -Name ' acme.com.dns') -join ';') | Should Match 'starts with whitespace'
        (@(Get-CcdcNameTamperFlag -Name "acme.com.dns`t") -join ';') | Should Match 'ends with whitespace'
    }
    It 'flags a trailing dot, which Windows also silently tolerates' {
        (@(Get-CcdcNameTamperFlag -Name 'acme.com.dns.') -join ';') | Should Match 'ends with a dot'
    }
    It 'flags a double space in the middle' {
        (@(Get-CcdcNameTamperFlag -Name 'my  zone.dns') -join ';') | Should Match 'double space'
    }
    It 'flags a homoglyph and names the code point' {
        # Cyrillic small a (U+0430) standing in for ASCII a
        $name = 'd' + [char]0x0430 + 'tabase.dns'
        $f = (@(Get-CcdcNameTamperFlag -Name $name) -join ';')
        $f | Should Match 'non-ASCII'
        $f | Should Match 'U\+0430'
    }
    It 'flags a right-to-left override separately, because the displayed name lies' {
        $name = 'invoice' + [char]0x202E + 'cod.exe'
        (@(Get-CcdcNameTamperFlag -Name $name) -join ';') | Should Match 'text-direction override'
    }
    It 'flags a double extension ending in an executable one' {
        (@(Get-CcdcNameTamperFlag -Name 'report.pdf.exe') -join ';') | Should Match 'double extension'
    }
    It 'stays quiet on ordinary names, including ones with single spaces and dots' {
        foreach ($ok in @('acme.com.dns', 'web.config', 'My Report 2026.docx', 'index.html', 'a.b.c.dns')) {
            @(Get-CcdcNameTamperFlag -Name $ok).Count | Should Be 0
        }
    }
    It 'is null and empty safe' {
        @(Get-CcdcNameTamperFlag -Name '').Count | Should Be 0
        @(Get-CcdcNameTamperFlag -Name $null).Count | Should Be 0
    }
}

Describe 'baseline diffing' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    function script:P { param($k, $v) [pscustomobject]@{ Key = $k; Value = $v } }

    It 'separates added, removed and changed' {
        $base = @((P 'a' '1'), (P 'b' '2'), (P 'c' '3'))
        $now = @((P 'a' '1'), (P 'b' 'CHANGED'), (P 'd' '4'))
        $d = Compare-CcdcBaselineSet -Baseline $base -Current $now
        @($d.Added).Count | Should Be 1
        @($d.Added)[0].Key | Should Be 'd'
        @($d.Removed).Count | Should Be 1
        @($d.Removed)[0].Key | Should Be 'c'
        @($d.Changed).Count | Should Be 1
        @($d.Changed)[0].Was | Should Be '2'
        @($d.Changed)[0].Now | Should Be 'CHANGED'
        $d.DriftCount | Should Be 3
    }
    It 'reports no drift when nothing moved' {
        $set = @((P 'a' '1'), (P 'b' '2'))
        (Compare-CcdcBaselineSet -Baseline $set -Current $set).DriftCount | Should Be 0
    }
    It 'matches keys case-insensitively (Windows paths and account names are)' {
        $d = Compare-CcdcBaselineSet -Baseline @((P 'C:\Temp\A.TXT' 'h')) -Current @((P 'c:\temp\a.txt' 'h'))
        $d.DriftCount | Should Be 0
    }
    It 'treats a case-only value change as a change, not a match' {
        $d = Compare-CcdcBaselineSet -Baseline @((P 'k' 'Running')) -Current @((P 'k' 'running'))
        @($d.Changed).Count | Should Be 1
    }
    It 'counts unique keys, so duplicate keys cannot silently hide a change' {
        # This is why firewall rules are keyed on display name AND rule id:
        # 272 rules collapsed to 170 unique display names in a real run.
        $d = Compare-CcdcBaselineSet -Baseline @((P 'dup' '1'), (P 'dup' '2')) -Current @((P 'dup' '2'))
        $d.BaselineSize | Should Be 1
        $d.DriftCount | Should Be 0
    }
    It 'survives empty and null inputs on either side' {
        (Compare-CcdcBaselineSet -Baseline @() -Current @()).DriftCount | Should Be 0
        @((Compare-CcdcBaselineSet -Baseline @() -Current @((P 'a' '1'))).Added).Count | Should Be 1
        @((Compare-CcdcBaselineSet -Baseline @((P 'a' '1')) -Current @()).Removed).Count | Should Be 1
        (Compare-CcdcBaselineSet -Baseline $null -Current $null).DriftCount | Should Be 0
    }
    It 'ignores entries with no key rather than crashing on them' {
        $d = Compare-CcdcBaselineSet -Baseline @((P '' 'x'), (P 'a' '1')) -Current @((P 'a' '1'))
        $d.DriftCount | Should Be 0
    }
}

Describe 'baseline area verdicts' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    function script:Drift { param($added = 0, $removed = 0, $changed = 0)
        [pscustomobject]@{
            Added = @(1..$added | Where-Object { $added -gt 0 })
            Removed = @(1..$removed | Where-Object { $removed -gt 0 })
            Changed = @(1..$changed | Where-Object { $changed -gt 0 })
            DriftCount = $added + $removed + $changed
            BaselineSize = 10
            CurrentSize = 10
        }
    }

    It 'says OK when an area matches' {
        (Get-CcdcBaselineAreaVerdict -Area 'Services' -Diff (Drift)).Level | Should Be 'OK'
    }
    It 'escalates high-stakes areas to ERROR on any drift at all' {
        foreach ($a in 'DnsZoneFiles', 'DnsZones', 'DhcpScopes', 'DhcpScopeOptions', 'DhcpAuthorizedServers', 'LocalAdministrators', 'Services', 'ScheduledTasks') {
            (Get-CcdcBaselineAreaVerdict -Area $a -Diff (Drift -added 1)).Level | Should Be 'ERROR'
        }
    }
    It 'keeps ordinary areas at WARN so real alarms stay meaningful' {
        foreach ($a in 'WatchedFiles', 'ListeningPorts', 'Hotfixes', 'FirewallRules') {
            (Get-CcdcBaselineAreaVerdict -Area $a -Diff (Drift -changed 3)).Level | Should Be 'WARN'
        }
    }
    It 'tells you to look for a rename when a DNS zone file goes missing' {
        $v = Get-CcdcBaselineAreaVerdict -Area 'DnsZoneFiles' -Diff (Drift -removed 1)
        $v.Message | Should Match 'renamed file'
    }
    It 'handles a null diff without throwing' {
        (Get-CcdcBaselineAreaVerdict -Area 'Services' -Diff $null).Level | Should Be 'INFO'
    }
}

Describe 'DNS zone transfers' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'flags transfers to any server, which copies the whole zone in one request' {
        (Get-CcdcDnsZoneTransferVerdict -SecureSecondaries 'TransferAnyServer').Vulnerable | Should Be $true
    }
    It 'accepts NoTransfer and the two restricted settings' {
        foreach ($s in 'NoTransfer', 'TransferToZoneNameServer', 'TransferToSecureServers') {
            (Get-CcdcDnsZoneTransferVerdict -SecureSecondaries $s).Vulnerable | Should Be $false
        }
    }
    It 'treats an unreadable setting as untested, not safe' {
        $v = Get-CcdcDnsZoneTransferVerdict -SecureSecondaries ''
        $v.Vulnerable | Should Be $true
        $v.Detail | Should Match 'untested'
    }
}

Describe 'DNS dynamic updates' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'flags nonsecure updates, which let an unauthenticated host rewrite records' {
        (Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate 'NonsecureAndSecure' -IsDsIntegrated $true).Vulnerable | Should Be $true
    }
    It 'targets Secure on an AD-integrated zone, and says it is safe to apply' {
        $v = Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate 'NonsecureAndSecure' -IsDsIntegrated $true
        $v.Target | Should Be 'Secure'
        $v.SafeToChange | Should Be $true
    }
    It 'targets None on a FILE-BACKED zone, and refuses to call it safe' {
        # The trap: Secure requires AD integration and the cmdlet rejects
        # it on a file-backed zone, so a script that sets Secure everywhere
        # fails on exactly the zones that need attention. None is the only
        # secure value there, and it stops clients registering at all.
        $v = Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate 'NonsecureAndSecure' -IsDsIntegrated $false
        $v.Target | Should Be 'None'
        $v.SafeToChange | Should Be $false
        $v.Detail | Should Match 'file-backed'
    }
    It 'accepts None and Secure as already safe' {
        foreach ($m in 'None', 'Secure') {
            (Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate $m -IsDsIntegrated $true).Vulnerable | Should Be $false
        }
    }
    It 'treats an unreadable mode as untested, not safe' {
        (Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate '' -IsDsIntegrated $true).Vulnerable | Should Be $true
    }
}

Describe 'suspicious DNS records' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'flags a wildcard record' {
        (@(Get-CcdcSuspiciousDnsRecordFlag -HostName '*' -RecordType 'A' -TtlSeconds 3600) -join ';') | Should Match 'wildcard'
        (@(Get-CcdcSuspiciousDnsRecordFlag -HostName '*.sub' -RecordType 'A' -TtlSeconds 3600) -join ';') | Should Match 'wildcard'
    }
    It 'flags the record types used to carry data out' {
        foreach ($t in 'TXT', 'NULL', 'HINFO') {
            @(Get-CcdcSuspiciousDnsRecordFlag -HostName 'x' -RecordType $t -TtlSeconds 3600).Count | Should Be 1
        }
    }
    It 'flags a TTL under a minute' {
        (@(Get-CcdcSuspiciousDnsRecordFlag -HostName 'x' -RecordType 'A' -TtlSeconds 30) -join ';') | Should Match 'TTL of 30s'
    }
    It 'flags an A record pointing off the expected subnet' {
        $f = @(Get-CcdcSuspiciousDnsRecordFlag -HostName 'web' -RecordType 'A' -TtlSeconds 3600 -RecordData '8.8.8.8' -ExpectedSubnetPrefix '10.10.10.')
        ($f -join ';') | Should Match 'outside 10\.10\.10\.'
    }
    It 'leaves ordinary records alone' {
        foreach ($t in 'A', 'AAAA', 'SRV', 'NS', 'SOA', 'CNAME', 'PTR') {
            @(Get-CcdcSuspiciousDnsRecordFlag -HostName 'host' -RecordType $t -TtlSeconds 3600 -RecordData '10.10.10.5' -ExpectedSubnetPrefix '10.10.10.').Count | Should Be 0
        }
    }
    It 'does not flag an off-subnet address when no subnet was given' {
        @(Get-CcdcSuspiciousDnsRecordFlag -HostName 'web' -RecordType 'A' -TtlSeconds 3600 -RecordData '8.8.8.8').Count | Should Be 0
    }
    It 'reports every reason a record is interesting, not just the first' {
        $f = @(Get-CcdcSuspiciousDnsRecordFlag -HostName '*' -RecordType 'TXT' -TtlSeconds 10)
        $f.Count | Should Be 3
    }
}

Describe 'Get-CcdcDnsRecordDataText (rendering what a DNS record actually points at)' {
    BeforeAll {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        # A real Get-DnsServerResourceRecord result's .RecordData is a
        # CimInstance; a PSCustomObject with the same property names goes
        # through the exact same .PSObject.Properties code path (that
        # adapter works identically for both), so this is a faithful stand-in
        # without needing a live DNS server to build a real CimInstance.
    }

    It 'found on the real lab DC: a CimInstance''s own ToString() is just its class name, never the address' {
        # This is what the bug actually looked like before the fix -- an
        # object whose only usable signal is the IPv4Address property, and
        # whose ToString() returns nothing but its own type name.
        $fake = [pscustomobject]@{ IPv4Address = '10.10.10.99' }
        $fake.PSObject.TypeNames.Insert(0, 'DnsServerResourceRecordA')
        Get-CcdcDnsRecordDataText -RecordData $fake | Should Be '10.10.10.99'
    }
    It 'reads the right property for each common record type' {
        (Get-CcdcDnsRecordDataText -RecordData ([pscustomobject]@{ IPv6Address = 'fe80::1' })) | Should Be 'fe80::1'
        (Get-CcdcDnsRecordDataText -RecordData ([pscustomobject]@{ HostNameAlias = 'web.lab.local.' })) | Should Be 'web.lab.local.'
        (Get-CcdcDnsRecordDataText -RecordData ([pscustomobject]@{ DescriptiveText = 'v=spf1 -all' })) | Should Be 'v=spf1 -all'
        (Get-CcdcDnsRecordDataText -RecordData ([pscustomobject]@{ MailExchange = 'mail.lab.local.' })) | Should Be 'mail.lab.local.'
    }
    It 'prefers the known payload property over an unrelated extra property' {
        $fake = [pscustomobject]@{ IPv4Address = '10.10.10.5'; RecordClass = 'IN' }
        Get-CcdcDnsRecordDataText -RecordData $fake | Should Be '10.10.10.5'
    }
    It 'falls back to other non-empty properties, sorted, for a record type with no known payload property' {
        # Order must be stable across calls -- CIM does not guarantee
        # enumeration order, and an unstable rendering would make an
        # UNCHANGED record look "new" on every single diff pass.
        $fake = [pscustomobject]@{ Zebra = 'z-value'; Alpha = 'a-value' }
        Get-CcdcDnsRecordDataText -RecordData $fake | Should Be 'a-value z-value'
    }
    It 'never throws on $null, and calls it unknown rather than guessing' {
        Get-CcdcDnsRecordDataText -RecordData $null | Should Be 'unknown'
    }
    It 'calls an object with nothing readable on it unknown, not its bare type name' {
        Get-CcdcDnsRecordDataText -RecordData ([pscustomobject]@{}) | Should Be 'unknown'
    }
    It 'renders a plain string value as itself' {
        Get-CcdcDnsRecordDataText -RecordData '10.10.10.1' | Should Be '10.10.10.1'
    }
}

Describe 'accounts that must never have their password rotated' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'refuses computer accounts, which is how a member server loses its domain trust' {
        # Found on the real lab DC: Get-LocalUser there returns DIRECTORY
        # objects, so the preview queued LABDC$ and LABFTP$ for a reset.
        foreach ($n in 'LABDC$', 'LABFTP$', 'WEB01$', 'A$') {
            (Test-CcdcRotatableAccountName -Name $n) | Should Be $false
        }
    }
    It 'allows ordinary user accounts, including ones with odd characters' {
        foreach ($n in 'alice', 'svc_web', 'it.admin', 'bob-2', 'a') {
            (Test-CcdcRotatableAccountName -Name $n) | Should Be $true
        }
    }
    It 'never queues the same DC account twice, which would reset it to two different passwords' {
        # The real lab DC preview said:
        #   10 account(s) queued: alice, bob, carol, olduser, itadmin,
        #                         alice, bob, carol, olduser, itadmin
        # For real that resets each account twice; the password recorded for
        # the team is then the FIRST one, and the account has the second.
        $cand = @()
        foreach ($n in 'alice', 'bob', 'carol', 'olduser', 'itadmin') { $cand += [pscustomobject]@{ Name = $n; Scope = 'Local' } }
        foreach ($n in 'alice', 'bob', 'carol', 'olduser', 'itadmin') { $cand += [pscustomobject]@{ Name = $n; Scope = 'Domain' } }
        $kept = @(Select-CcdcCredentialTarget -Candidate $cand -IsDomainController $true)
        $kept.Count | Should Be 5
        # The DOMAIN entry is the one that survives: a DC has no local SAM.
        (@($kept | Where-Object { $_.Scope -eq 'Local' }).Count) | Should Be 0
        (($kept.Name) -join ',') | Should Be 'alice,bob,carol,olduser,itadmin'
    }
    It 'keeps BOTH on a member server, where LABWEB\alice and LAB\alice are different people' {
        $cand = @(
            [pscustomobject]@{ Name = 'alice'; Scope = 'Local' },
            [pscustomobject]@{ Name = 'alice'; Scope = 'Domain' }
        )
        $kept = @(Select-CcdcCredentialTarget -Candidate $cand -IsDomainController $false)
        $kept.Count | Should Be 2
    }
    It 'collapses an exact duplicate in one scope on any box, since that is one principal' {
        $cand = @(
            [pscustomobject]@{ Name = 'alice'; Scope = 'Local' },
            [pscustomobject]@{ Name = 'ALICE'; Scope = 'Local' }
        )
        (@(Select-CcdcCredentialTarget -Candidate $cand -IsDomainController $false)).Count | Should Be 1
    }
    It 'keeps a DC local account that has no directory twin, rather than silently dropping it' {
        $cand = @(
            [pscustomobject]@{ Name = 'onlylocal'; Scope = 'Local' },
            [pscustomobject]@{ Name = 'indir'; Scope = 'Domain' }
        )
        (@(Select-CcdcCredentialTarget -Candidate $cand -IsDomainController $true)).Count | Should Be 2
    }
    It 'survives an empty or null candidate list rather than throwing mid-run' {
        (@(Select-CcdcCredentialTarget -Candidate @() -IsDomainController $true)).Count | Should Be 0
        (@(Select-CcdcCredentialTarget -Candidate $null -IsDomainController $true)).Count | Should Be 0
    }
    It 'is not fooled by a dollar sign anywhere but the end' {
        (Test-CcdcRotatableAccountName -Name 'we$ird') | Should Be $true
        (Test-CcdcRotatableAccountName -Name '$admin') | Should Be $true
    }
    It 'trims before deciding, so a stray space cannot smuggle one through' {
        (Test-CcdcRotatableAccountName -Name 'LABDC$ ') | Should Be $false
    }
    It 'treats empty and null as not rotatable rather than throwing' {
        (Test-CcdcRotatableAccountName -Name '') | Should Be $false
        (Test-CcdcRotatableAccountName -Name $null) | Should Be $false
        (Test-CcdcRotatableAccountName -Name '   ') | Should Be $false
    }
}

Describe 'known-exposure audit: which checks apply to which box' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'Any applies everywhere' {
        foreach ($r in 'DC', 'Member', 'Client') {
            (Test-CcdcExposureApplies -Applies 'Any' -HostRole $r) | Should Be $true
        }
    }
    It 'DC-only checks stay off a web server and a workstation' {
        (Test-CcdcExposureApplies -Applies 'DC' -HostRole 'DC') | Should Be $true
        (Test-CcdcExposureApplies -Applies 'DC' -HostRole 'Member') | Should Be $false
        (Test-CcdcExposureApplies -Applies 'DC' -HostRole 'Client') | Should Be $false
    }
    It 'Server means any non-client' {
        (Test-CcdcExposureApplies -Applies 'Server' -HostRole 'DC') | Should Be $true
        (Test-CcdcExposureApplies -Applies 'Server' -HostRole 'Member') | Should Be $true
        (Test-CcdcExposureApplies -Applies 'Server' -HostRole 'Client') | Should Be $false
    }
    It 'an entry with no Applies value is never run, rather than run everywhere' {
        (Test-CcdcExposureApplies -Applies '' -HostRole 'DC') | Should Be $false
        (Test-CcdcExposureApplies -Applies $null -HostRole 'DC') | Should Be $false
    }
}

Describe 'unquoted service paths' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'flags an unquoted path with a space outside Windows' {
        (Test-CcdcUnquotedServicePath -PathName 'C:\Program Files\My App\svc.exe') | Should Be $true
    }
    It 'ignores a quoted path, however many spaces it has' {
        (Test-CcdcUnquotedServicePath -PathName '"C:\Program Files\My App\svc.exe"') | Should Be $false
        (Test-CcdcUnquotedServicePath -PathName '"C:\Program Files\My App\svc.exe" -k netsvcs') | Should Be $false
    }
    It 'ignores a path with no spaces' {
        (Test-CcdcUnquotedServicePath -PathName 'C:\Apps\svc.exe') | Should Be $false
    }
    It 'ignores anything under the Windows directory' {
        # Otherwise every box reports a pile of Microsoft services, and an
        # attacker who can write there has already won.
        (Test-CcdcUnquotedServicePath -PathName 'C:\Windows\My Thing\svc.exe') | Should Be $false
        (Test-CcdcUnquotedServicePath -PathName 'c:\windows\system32\Some Service\x.exe') | Should Be $false
    }
    It 'looks only at the image path, not at arguments after it' {
        # Arguments cannot be hijacked; only the path Windows resolves can.
        (Test-CcdcUnquotedServicePath -PathName 'C:\Apps\svc.exe -config "C:\Program Files\x.ini"') | Should Be $false
    }
    It 'ignores a bare command with no drive-letter path' {
        (Test-CcdcUnquotedServicePath -PathName 'svchost.exe -k netsvcs') | Should Be $false
    }
    It 'is empty and null safe' {
        (Test-CcdcUnquotedServicePath -PathName '') | Should Be $false
        (Test-CcdcUnquotedServicePath -PathName $null) | Should Be $false
    }
}

Describe 'LmCompatibilityLevel' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'calls levels 0-2 vulnerable: this box SENDS crackable responses' {
        foreach ($n in 0, 1, 2) { (Get-CcdcLmCompatibilityVerdict -Level $n).Vulnerable | Should Be $true }
    }
    It 'calls 3 and 4 vulnerable too: it still ACCEPTS NTLMv1 as a server' {
        foreach ($n in 3, 4) { (Get-CcdcLmCompatibilityVerdict -Level $n).Vulnerable | Should Be $true }
    }
    It 'only 5 is clean' {
        (Get-CcdcLmCompatibilityVerdict -Level 5).Vulnerable | Should Be $false
    }
    It 'treats "not set" as unknown-and-risky, not as safe' {
        # The default differs by Windows version, so unset is not an answer.
        $v = Get-CcdcLmCompatibilityVerdict -Level $null
        $v.Vulnerable | Should Be $true
        $v.State | Should Be 'not set'
    }
    It 'handles a non-numeric value without throwing' {
        (Get-CcdcLmCompatibilityVerdict -Level 'banana').Vulnerable | Should Be $true
    }
}

Describe 'ms-DS-MachineAccountQuota' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'the default of 10 is the precondition for sAMAccountName spoofing' {
        (Get-CcdcMachineAccountQuotaVerdict -Quota 10).Vulnerable | Should Be $true
    }
    It 'even 1 is enough for the attack' {
        (Get-CcdcMachineAccountQuotaVerdict -Quota 1).Vulnerable | Should Be $true
    }
    It 'zero closes it' {
        (Get-CcdcMachineAccountQuotaVerdict -Quota 0).Vulnerable | Should Be $false
    }
    It 'unreadable is not clean' {
        (Get-CcdcMachineAccountQuotaVerdict -Quota $null).Vulnerable | Should Be $true
        (Get-CcdcMachineAccountQuotaVerdict -Quota 'x').Vulnerable | Should Be $true
    }
}

Describe 'exposure summary' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    function script:F { param($sev, $vuln, $state = 'x') [pscustomobject]@{ Severity = $sev; Vulnerable = $vuln; State = $state } }

    It 'counts by severity, only for findings that are actually present' {
        $s = Get-CcdcExposureSummary -Findings @((F 'Critical' $true), (F 'High' $true), (F 'High' $false), (F 'Medium' $true))
        $s.Checked | Should Be 4
        $s.Vulnerable | Should Be 3
        $s.Critical | Should Be 1
        $s.High | Should Be 1
        $s.Medium | Should Be 1
    }
    It 'says plainly when nothing was found' {
        (Get-CcdcExposureSummary -Findings @((F 'High' $false))).Message | Should Match 'none are present'
    }
    It 'distinguishes "nothing found" from "nothing checked"' {
        (Get-CcdcExposureSummary -Findings @()).Message | Should Match 'Nothing was checked'
    }
    It 'counts untested checks separately so they are not mistaken for clean' {
        $s = Get-CcdcExposureSummary -Findings @((F 'High' $false 'unknown'), (F 'High' $false 'ok'))
        $s.Unknown | Should Be 1
        $s.Vulnerable | Should Be 0
    }
}

Describe 'module launch arguments (the window Modules tab)' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'builds a clean list when the module has no extra arguments' {
        # The real bug: most module entries have no Args key, @($null) is a
        # one-element array holding $null, and Start-Process then refuses
        # the whole call. Eleven of thirteen buttons did nothing.
        $a = @(Get-CcdcModuleLaunchArgs -ScriptPath 'C:\toolkit\modules\Install-Sysmon.ps1' -ExtraArgs $null)
        @($a | Where-Object { $null -eq $_ }).Count | Should Be 0
        $a[-1] | Should Be '"C:\toolkit\modules\Install-Sysmon.ps1"'
        ($a -contains '-NoExit') | Should Be $true
        ($a -contains '-NoProfile') | Should Be $true
    }
    It 'appends extra arguments when there are some' {
        $a = @(Get-CcdcModuleLaunchArgs -ScriptPath 'C:\x\Invoke-FirewallBaseline.ps1' -ExtraArgs @('-WhatIf'))
        $a[-1] | Should Be '-WhatIf'
        ($a -join ' ') | Should Match '"C:\\x\\Invoke-FirewallBaseline\.ps1" -WhatIf'
    }
    It 'drops nulls and blanks hiding among real arguments' {
        $a = @(Get-CcdcModuleLaunchArgs -ScriptPath 'C:\x\m.ps1' -ExtraArgs @('-WhatIf', $null, '', '   ', '-Verbose'))
        @($a | Where-Object { $null -eq $_ -or "$_".Trim() -eq '' }).Count | Should Be 0
        ($a[-2] + ' ' + $a[-1]) | Should Be '-WhatIf -Verbose'
    }
    It 'quotes the script path so a repo under a path with spaces still launches' {
        $a = @(Get-CcdcModuleLaunchArgs -ScriptPath 'C:\Program Files\ccdc\m.ps1')
        ($a -contains '"C:\Program Files\ccdc\m.ps1"') | Should Be $true
    }
    It 'never returns an empty or null-bearing list, whatever it is handed' {
        foreach ($extra in @($null, @(), @($null), @('', $null))) {
            $a = @(Get-CcdcModuleLaunchArgs -ScriptPath 'C:\x\m.ps1' -ExtraArgs $extra)
            $a.Count | Should Be 6
            @($a | Where-Object { $null -eq $_ }).Count | Should Be 0
        }
    }
}

Describe 'net localgroup parsing (the last-resort way to read Administrators)' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    $script:NetOut = @(
        'Alias name     Administrators',
        'Comment        Administrators have complete and unrestricted access',
        '',
        'Members',
        '',
        '-------------------------------------------------------------------------------',
        'Administrator',
        'LAB\Domain Admins',
        'LAB\itadmin',
        'The command completed successfully.',
        ''
    )

    It 'returns only the members, not the header block' {
        $m = @(ConvertFrom-CcdcNetLocalGroupOutput -Lines $script:NetOut)
        $m.Count | Should Be 3
        ($m -join ',') | Should Be 'Administrator,LAB\Domain Admins,LAB\itadmin'
    }
    It 'stops at the completion line instead of swallowing it as a member' {
        (@(ConvertFrom-CcdcNetLocalGroupOutput -Lines $script:NetOut) -contains 'The command completed successfully.') | Should Be $false
    }
    It 'ignores the header even when it contains a word like Members' {
        (@(ConvertFrom-CcdcNetLocalGroupOutput -Lines $script:NetOut) -contains 'Members') | Should Be $false
    }
    It 'returns nothing when there is no dashed rule at all (unexpected output)' {
        @(ConvertFrom-CcdcNetLocalGroupOutput -Lines @('Alias name  Administrators', 'System error 1376 has occurred.')).Count | Should Be 0
    }
    It 'is empty and null safe' {
        @(ConvertFrom-CcdcNetLocalGroupOutput -Lines @()).Count | Should Be 0
        @(ConvertFrom-CcdcNetLocalGroupOutput -Lines $null).Count | Should Be 0
        @(ConvertFrom-CcdcNetLocalGroupOutput -Lines @($null, '----------', 'Administrator')).Count | Should Be 1
    }
    It 'handles a group with no members (the rule, then the completion line)' {
        @(ConvertFrom-CcdcNetLocalGroupOutput -Lines @('Members', '----------', 'The command completed successfully.')).Count | Should Be 0
    }
}

Describe 'patch status verdict' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'calls out a pending reboot before anything else' {
        $c = Get-CcdcPatchStatusVerdict -NewestHotfixDate (Get-Date) -RebootPending $true
        $c.Status | Should Be 'Warn'
        $c.Value | Should Match 'Reboot pending'
    }
    It 'is Bad at six months behind, Warn at two, Good when current' {
        $now = Get-Date '2026-09-28'
        (Get-CcdcPatchStatusVerdict -NewestHotfixDate $now.AddDays(-200) -RebootPending $false -Now $now).Status | Should Be 'Bad'
        (Get-CcdcPatchStatusVerdict -NewestHotfixDate $now.AddDays(-75) -RebootPending $false -Now $now).Status | Should Be 'Warn'
        (Get-CcdcPatchStatusVerdict -NewestHotfixDate $now.AddDays(-5) -RebootPending $false -Now $now).Status | Should Be 'Good'
    }
    It 'says Unknown rather than Good when there is no update history at all' {
        (Get-CcdcPatchStatusVerdict -NewestHotfixDate ([datetime]::MinValue) -RebootPending $false).Status | Should Be 'Unknown'
    }
}
