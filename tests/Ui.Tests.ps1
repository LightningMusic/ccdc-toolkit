#Requires -Version 5.1
# Tests for the toolkit window (ui\). A GUI cannot be clicked from a test, but
# the things that actually break one can all be checked: the layout parses, every
# control the script looks up exists, the background work scripts (which are
# strings, so the normal parse check never sees them) are valid PowerShell, the
# module buttons point at scripts that exist, and the health rules behind the
# dashboard behave.
#
#   Invoke-Pester .\tests\Ui.Tests.ps1

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:UiScript = Join-Path $script:RepoRoot 'ui\Start-CcdcConsole.ps1'
$script:UiXaml = Join-Path $script:RepoRoot 'ui\CcdcConsole.xaml'

function script:Get-UiAst {
    $tok = $null; $err = $null
    return [System.Management.Automation.Language.Parser]::ParseFile($script:UiScript, [ref]$tok, [ref]$err)
}
function script:Get-UiStringVariable {
    <#
        The CONTENTS of a "$script:Name = @'...'@" assignment, taken from the
        syntax tree rather than by trimming the text. That matters: if the
        trimming ever failed you would be handed "@'...'@" and parsing that
        succeeds trivially as a string literal, so a syntax error inside the
        work script would sail through the test that exists to catch it.
        Returns $null if it is not a plain string assignment.
    #>
    param([string]$Name)
    $ast = Get-UiAst
    $assign = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -eq "script:$Name" }, $true) | Select-Object -First 1
    if (-not $assign) { return $null }
    $str = $assign.Right.Find({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
    if (-not $str) { return $null }
    return $str.Value
}
function script:Get-UiSwitchCaseText {
    # The body of one case of the switch inside a named work script, so a test
    # can check a rule holds in EVERY branch rather than just somewhere in the file.
    param([string]$VariableName, [string]$CaseLabel)
    $body = Get-UiStringVariable -Name $VariableName
    if (-not $body) { return $null }
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($body, [ref]$tok, [ref]$err)
    foreach ($sw in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)) {
        # Clauses are Tuple<ExpressionAst, StatementBlockAst>: Item1 is the label, Item2 the body.
        foreach ($clause in $sw.Clauses) {
            if ("$($clause.Item1.Extent.Text)".Trim("'", '"') -eq $CaseLabel) { return $clause.Item2.Extent.Text }
        }
    }
    return $null
}
function script:Get-DeclaredControlNames {
    $ast = Get-UiAst
    $assign = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -eq 'script:ControlNames' }, $true) | Select-Object -First 1
    if (-not $assign) { return @() }
    return @([regex]::Matches($assign.Right.Extent.Text, "'([A-Za-z0-9_]+)'") | ForEach-Object { $_.Groups[1].Value })
}

Describe 'the window layout' {
    It 'is valid XAML that WPF can actually load, and every named control comes back findable' {
        if ($env:OS -ne 'Windows_NT') { return }
        # WPF needs a single-threaded apartment, and the test host may not be one,
        # so load it inside an STA runspace rather than on this thread.
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'STA'
        $rs.ThreadOptions = 'ReuseThread'
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript({
            param($XamlPath, $Names)
            try {
                Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
            } catch { return 'SKIP: WPF not available here' }
            try {
                $reader = New-Object System.Xml.XmlNodeReader ([xml](Get-Content -LiteralPath $XamlPath -Raw))
                $w = [Windows.Markup.XamlReader]::Load($reader)
            } catch { return "LOAD FAILED: $($_.Exception.Message)" }
            $missing = @($Names | Where-Object { -not $w.FindName($_) })
            if ($missing.Count -gt 0) { return "NOT FINDABLE: $($missing -join ', ')" }
            return 'OK'
        }).AddArgument($script:UiXaml).AddArgument((Get-DeclaredControlNames))
        $out = $ps.Invoke()
        $errors = @($ps.Streams.Error | ForEach-Object { "$($_.Exception.Message)" })
        $ps.Dispose(); $rs.Close(); $rs.Dispose()
        ($errors -join '; ') | Should Be ''
        $verdict = "$(@($out) | Select-Object -Last 1)"
        if ($verdict -like 'SKIP:*') { return }
        $verdict | Should Be 'OK'
    }
    It 'is well-formed XML with a Window root' {
        $xml = [xml](Get-Content -LiteralPath $script:UiXaml -Raw)
        $xml.DocumentElement.LocalName | Should Be 'Window'
    }
}

Describe 'the window actually starts' {
    # The test that matters most, and the one that was missing: everything below
    # only checks the window's PARTS. The first real outing failed at runtime --
    # a string-format call that throws the moment it runs -- and no amount of
    # static checking would have caught it. This runs the real script end to end
    # (layout, controls, wiring, one live health check) and stops short of
    # showing the window, against a scratch copy so it writes its logs there.
    BeforeAll {
        $script:SelfTestOutput = $null
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ($env:OS -eq 'Windows_NT' -and (Test-Path $ps51)) {
            $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("uitest-" + [guid]::NewGuid())
            New-Item -ItemType Directory -Path $script:Work -Force | Out-Null
            foreach ($item in 'modules', 'ui', 'config', 'configs') {
                Copy-Item -Path (Join-Path $script:RepoRoot $item) -Destination (Join-Path $script:Work $item) -Recurse -Force
            }
            $target = Join-Path $script:Work 'ui\Start-CcdcConsole.ps1'
            $job = Start-Job -ScriptBlock {
                param($Exe, $Script)
                & $Exe -STA -NoProfile -ExecutionPolicy Bypass -File $Script -SelfTest -NoRelaunch 2>&1 | ForEach-Object { "$_" }
            } -ArgumentList $ps51, $target
            if (Wait-Job $job -Timeout 180) { $script:SelfTestOutput = @(Receive-Job $job) }
            else { Stop-Job $job; $script:SelfTestOutput = @('TIMED OUT: the self-test did not finish within 180 seconds') }
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    AfterAll { if ($script:Work) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'builds the whole window and completes a health check without throwing' {
        if ($null -eq $script:SelfTestOutput) { return }
        $verdict = @($script:SelfTestOutput | Where-Object { $_ -match 'SELFTEST (OK|FAILED)|TIMED OUT' }) -join ' | '
        # On failure the script prints the exception and where it came from, so
        # put that in the test output rather than just "expected OK".
        $detail = @($script:SelfTestOutput | Where-Object { $_ -match 'SELFTEST FAILED|^\s+\w+Exception|^\s+at |TIMED OUT' }) -join ' / '
        "$verdict$(if ($verdict -notmatch 'SELFTEST OK') { "  --  $detail" })" | Should Match 'SELFTEST OK'
    }
    It 'produces health cards rather than an empty dashboard' {
        if ($null -eq $script:SelfTestOutput) { return }
        $line = @($script:SelfTestOutput | Where-Object { $_ -like 'Cards shown:*' }) | Select-Object -First 1
        $line | Should Match 'Cards shown: [1-9]'
    }
    It 'logs no errors on a clean startup' {
        if ($null -eq $script:SelfTestOutput) { return }
        $errors = @($script:SelfTestOutput | Where-Object { $_ -match '\[ERROR\]' })
        ($errors -join ' | ') | Should Be ''
    }
}

Describe 'the script and the layout agree about control names' {
    It 'declares at least the controls it needs' {
        (Get-DeclaredControlNames).Count | Should BeGreaterThan 20
    }
    It 'every control the script declares really exists in the XAML' {
        $xamlText = Get-Content -LiteralPath $script:UiXaml -Raw
        $inXaml = @([regex]::Matches($xamlText, 'x:Name\s*=\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        $missing = @(Get-DeclaredControlNames | Where-Object { $inXaml -notcontains $_ })
        ($missing -join ', ') | Should Be ''
    }
    It 'every control the script USES ($ui.Something) is one it declared, so a typo cannot make a dead button' {
        $declared = Get-DeclaredControlNames
        $text = Get-Content -LiteralPath $script:UiScript -Raw
        $used = @([regex]::Matches($text, '\$ui\.([A-Za-z0-9_]+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $undeclared = @($used | Where-Object { $declared -notcontains $_ })
        ($undeclared -join ', ') | Should Be ''
    }
}

Describe 'the background work scripts' {
    It 'are valid PowerShell (they live in strings, so the repo-wide parse check never sees them)' {
        $bad = @()
        foreach ($name in 'WorkRefresh', 'WorkAccounts', 'WorkAccountAction', 'WorkDns', 'WorkDnsRecordAction', 'WorkDnsHarden', 'WorkTasks', 'WorkTaskAction', 'WorkFirewall', 'WorkFirewallAction', 'WorkServices', 'WorkServiceAction') {
            $body = Get-UiStringVariable -Name $name
            if (-not $body) { $bad += "$name : not found, or not a plain string assignment"; continue }
            if ($body -match "^@'") { $bad += "$name : the here-string markers were not stripped, so this check would pass on anything"; continue }
            $tok = $null; $err = $null
            [void][System.Management.Automation.Language.Parser]::ParseInput($body, [ref]$tok, [ref]$err)
            if ($err.Count -gt 0) { $bad += "$name line $($err[0].Extent.StartLineNumber): $($err[0].Message)" }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'each take the repo root and an argument hashtable, so Start-UiWork can call them all the same way' {
        foreach ($name in 'WorkRefresh', 'WorkAccounts', 'WorkAccountAction', 'WorkDns', 'WorkDnsRecordAction', 'WorkDnsHarden', 'WorkTasks', 'WorkTaskAction', 'WorkFirewall', 'WorkFirewallAction', 'WorkServices', 'WorkServiceAction') {
            $text = Get-UiStringVariable -Name $name
            $text | Should Match 'param\(\$RepoRoot, \$Arg\)'
        }
    }
    It 'each import the shared module, since they run in a runspace of their own' {
        foreach ($name in 'WorkRefresh', 'WorkAccounts', 'WorkAccountAction', 'WorkDns', 'WorkDnsRecordAction', 'WorkDnsHarden', 'WorkTasks', 'WorkTaskAction', 'WorkFirewall', 'WorkFirewallAction', 'WorkServices', 'WorkServiceAction') {
            $text = Get-UiStringVariable -Name $name
            $text | Should Match 'Import-Module'
            $text | Should Match 'Common\.psm1'
        }
    }
    It 'never prompt: a Read-Host in a background runspace would hang with nothing on screen to answer' {
        foreach ($name in 'WorkRefresh', 'WorkAccounts', 'WorkAccountAction', 'WorkDns', 'WorkDnsRecordAction', 'WorkDnsHarden', 'WorkTasks', 'WorkTaskAction', 'WorkFirewall', 'WorkFirewallAction', 'WorkServices', 'WorkServiceAction') {
            (Get-UiStringVariable -Name $name) | Should Not Match 'Read-Host'
        }
        # Get-CcdcAnswer falls back to Read-Host when a value is missing, so the
        # UI reads the answer file directly instead.
        foreach ($name in 'WorkRefresh', 'WorkAccountAction', 'WorkDns') {
            (Get-UiStringVariable -Name $name) | Should Not Match 'Get-CcdcAnswer'
        }
    }
    It 'back up before they change an account -- in EVERY branch that changes one, not just somewhere in the file' {
        foreach ($case in 'Reset', 'Disable', 'AddToGroup', 'RemoveFromGroup') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkAccountAction' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            # Both paths through the branch (Active Directory and local) have to back up.
            $backups = @([regex]::Matches($branch, 'Backup-CcdcState')).Count
            $adOrLocalPaths = @([regex]::Matches($branch, 'if \(\$isAd\)')).Count
            if ($adOrLocalPaths -gt 0) { $backups | Should BeGreaterThan 1 } else { $backups | Should BeGreaterThan 0 }
        }
    }
    It 'removing someone from a group passes -Confirm:$false on both paths -- Remove-ADGroupMember and Remove-LocalGroupMember both prompt by default, and nothing is watching this background runspace to answer that prompt' {
        $branch = Get-UiSwitchCaseText -VariableName 'WorkAccountAction' -CaseLabel 'RemoveFromGroup'
        $branch | Should Match 'Remove-ADGroupMember[^\n]*-Confirm:\$false'
        $branch | Should Match 'Remove-LocalGroupMember[^\n]*-Confirm:\$false'
    }
    It 'back up before they change a service' {
        (Get-UiStringVariable -Name 'WorkServiceAction') | Should Match 'Backup-CcdcState'
    }
    It 'back up before they add or remove a DNS record -- in both branches' {
        foreach ($case in 'Add', 'Remove') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkDnsRecordAction' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            $branch | Should Match 'Backup-CcdcState'
        }
    }
    It 'back up before every DNS hardening change -- in every branch, not just somewhere in the file' {
        foreach ($case in 'SecureZoneTransfers', 'SecureDynamicUpdates', 'HardenCache') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkDnsHarden' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            $branch | Should Match 'Backup-CcdcState'
        }
    }
    It 'the DNS hardening work script calls the SAME verdict functions Invoke-DnsHardening.ps1 uses, so the UI and the module cannot quietly disagree about what counts as secure' {
        $text = Get-UiStringVariable -Name 'WorkDnsHarden'
        $text | Should Match 'Get-CcdcDnsZoneTransferVerdict'
        $text | Should Match 'Get-CcdcDnsDynamicUpdateVerdict'
    }
    It 'DNS record removal matches on the EXACT record (by its rendered data), not just by name and type -- a zone can hold more than one record with the same name' {
        $branch = Get-UiSwitchCaseText -VariableName 'WorkDnsRecordAction' -CaseLabel 'Remove'
        $branch | Should Match 'Get-CcdcDnsRecordDataText'
        $branch | Should Match 'Where-Object'
    }
    It 'back up before they add or remove a DHCP reservation -- in both branches' {
        foreach ($case in 'Add', 'Remove') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkDhcpReservationAction' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            $branch | Should Match 'Backup-CcdcState'
        }
    }
    It 'back up before a GPO link changes -- Link and Unlink, each on its own' {
        foreach ($case in 'Link', 'Unlink') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkGpoLinkAction' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            $branch | Should Match 'Backup-CcdcState'
        }
    }
    It 'creating the hardening GPO calls the SAME shared function Invoke-ADHardening.ps1 uses, so the window and that module cannot quietly disagree about what the GPO contains' {
        $text = Get-UiStringVariable -Name 'WorkGpoCreate'
        $text | Should Match 'New-CcdcHardeningGpo'
        # Real code only, not an explanatory comment that happens to NAME the
        # cmdlets it deliberately avoids calling -- strip comment lines first.
        $code = ($text -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should Not Match 'New-GPO\b'
        $code | Should Not Match 'Set-GPRegistryValue'
    }
    It 'back up before every scheduled-task change -- Enable, Disable and Delete, each on its own' {
        foreach ($case in 'Enable', 'Disable', 'Delete') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkTaskAction' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            $branch | Should Match 'Backup-CcdcState'
        }
    }
    It 'flags a scheduled task whose action runs from an unusual location, the same way the Services tab flags a service' {
        (Get-UiStringVariable -Name 'WorkTasks') | Should Match 'Test-CcdcSuspiciousPath'
    }
    It 'back up before every firewall-rule change -- Add, Enable, Disable and Remove, each on its own' {
        foreach ($case in 'Add', 'Enable', 'Disable', 'Remove') {
            $branch = Get-UiSwitchCaseText -VariableName 'WorkFirewallAction' -CaseLabel $case
            "$case : $(if ($branch) { 'found' } else { 'MISSING' })" | Should Be "$case : found"
            $branch | Should Match 'Backup-CcdcState'
        }
    }
    It 'validates a new firewall rule''s port and remote address with the toolkit''s OWN pure checks, not a hand-rolled regex that could disagree with them' {
        $text = Get-Content -LiteralPath $script:UiScript -Raw
        $text | Should Match 'Test-CcdcValidPort'
        $text | Should Match 'Test-CcdcValidIPv4'
    }
    It 'never pipes a firewall rule through Get-NetFirewallPortFilter/-AddressFilter one at a time -- that is a separate CIM query PER RULE' {
        # Found for real by this window's own self-test: on a normal
        # Windows box carrying 500-700+ firewall rules, the per-rule form
        # ($r | Get-NetFirewallPortFilter) took over 90 seconds and made
        # "List rules" look like the window had hung. Bulk-fetch every
        # filter once and join by InstanceID instead -- under a second for
        # the same box, verified against the slow form on real rules
        # before being trusted.
        $text = Get-UiStringVariable -Name 'WorkFirewall'
        $text | Should Not Match '\|\s*Get-NetFirewallPortFilter'
        $text | Should Not Match '\|\s*Get-NetFirewallAddressFilter'
        $text | Should Match 'InstanceID'
    }
    It 'the default-block sweep stays out of the quick-rule tab -- that change needs its own safety net, not a background-runspace button' {
        # Invoke-FirewallBaseline.ps1's dead-man-switch sequencing has no
        # equivalent here on purpose. If this module name ever appears
        # inside the Firewall work scripts, someone tried to shortcut that
        # safety net from a single button -- which is exactly the one
        # mistake this UI must never make quietly.
        foreach ($name in 'WorkFirewall', 'WorkFirewallAction') {
            (Get-UiStringVariable -Name $name) | Should Not Match 'Invoke-FirewallBaseline'
            (Get-UiStringVariable -Name $name) | Should Not Match 'DefaultInboundAction'
        }
    }
}

Describe 'the module buttons' {
    It 'all point at a module that exists' {
        $text = Get-Content -LiteralPath $script:UiScript -Raw
        $scripts = @([regex]::Matches($text, "Script\s*=\s*'([^']+\.ps1)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $scripts.Count | Should BeGreaterThan 10
        $missing = @($scripts | Where-Object { -not (Test-Path (Join-Path $script:RepoRoot "modules\$_")) })
        ($missing -join ', ') | Should Be ''
    }
    It 'mark the read-only ones, and do not mark the ones that change the machine' {
        $text = Get-Content -LiteralPath $script:UiScript -Raw
        $text | Should Match "Name = 'Environment discovery';[^}]*ReadOnly = \`$true"
        $text | Should Match "Name = 'IIS / FTP audit';[^}]*ReadOnly = \`$true"
        # The firewall baseline changes real state, so it must not claim otherwise.
        $text | Should Not Match "Name = 'Firewall baseline';[^}]*ReadOnly"
        $text | Should Not Match "Name = 'AD hardening';[^}]*ReadOnly"
    }
}

Describe 'health verdicts behind the dashboard' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'firewall: all Block is good, a mix is a warning, none is bad, nothing is unknown' {
        (Get-CcdcFirewallVerdict -DefaultInboundActions @('Block', 'Block', 'Block')).Status | Should Be 'Good'
        (Get-CcdcFirewallVerdict -DefaultInboundActions @('Block', 'Allow', 'Block')).Status | Should Be 'Warn'
        (Get-CcdcFirewallVerdict -DefaultInboundActions @('Allow', 'Allow')).Status | Should Be 'Bad'
        (Get-CcdcFirewallVerdict -DefaultInboundActions @()).Status | Should Be 'Unknown'
    }
    It 'services: running is good, stopped is bad, and a missing optional one is only a warning' {
        (Get-CcdcServiceVerdict -Title 'Sysmon' -Status 'Running').Status | Should Be 'Good'
        (Get-CcdcServiceVerdict -Title 'Sysmon' -Status 'Stopped').Status | Should Be 'Bad'
        (Get-CcdcServiceVerdict -Title 'Sysmon' -Status $null).Status | Should Be 'Bad'
        (Get-CcdcServiceVerdict -Title 'Splunk forwarder' -Status $null -Optional).Status | Should Be 'Warn'
    }
    It 'failed logons: thresholds, and unknown is never reported as fine' {
        (Get-CcdcFailedLogonVerdict -Count 0).Status | Should Be 'Good'
        (Get-CcdcFailedLogonVerdict -Count 6).Status | Should Be 'Warn'
        (Get-CcdcFailedLogonVerdict -Count 60).Status | Should Be 'Bad'
        (Get-CcdcFailedLogonVerdict -Count $null).Status | Should Be 'Unknown'
    }
    It 'listening ports: a well-known remote-access port is bad on sight' {
        (Get-CcdcC2PortVerdict -ListeningPorts @(80, 443, 3389)).Status | Should Be 'Good'
        (Get-CcdcC2PortVerdict -ListeningPorts @(80, 4444)).Status | Should Be 'Bad'
        (Get-CcdcC2PortVerdict -ListeningPorts @(2222)).Status | Should Be 'Bad'
        (Get-CcdcC2PortVerdict -ListeningPorts $null).Status | Should Be 'Unknown'
    }
    It 'protected accounts: empty is a warning, because that is the common own-goal' {
        (Get-CcdcProtectedAccountsVerdict -Count 0).Status | Should Be 'Warn'
        (Get-CcdcProtectedAccountsVerdict -Count 3).Status | Should Be 'Good'
    }
    It 'inventory: never run and stale are both warnings' {
        (Get-CcdcInventoryVerdict -AgeMinutes $null).Status | Should Be 'Warn'
        (Get-CcdcInventoryVerdict -AgeMinutes 500).Status | Should Be 'Warn'
        (Get-CcdcInventoryVerdict -AgeMinutes 10).Status | Should Be 'Good'
    }
    It 'overall health is the worst card present, so nothing hides behind an average' {
        $c = { param($s) New-CcdcHealthCard -Title 't' -Status $s }
        (Get-CcdcOverallHealth -Cards @((& $c Good), (& $c Good))) | Should Be 'Good'
        (Get-CcdcOverallHealth -Cards @((& $c Good), (& $c Warn))) | Should Be 'Warn'
        (Get-CcdcOverallHealth -Cards @((& $c Warn), (& $c Bad))) | Should Be 'Bad'
        (Get-CcdcOverallHealth -Cards @((& $c Good), (& $c Unknown))) | Should Be 'Unknown'
        (Get-CcdcOverallHealth -Cards @()) | Should Be 'Unknown'
    }
    It 'every verdict says what it means, not just a status' {
        foreach ($card in @((Get-CcdcFirewallVerdict -DefaultInboundActions @('Allow')),
                            (Get-CcdcFailedLogonVerdict -Count 60),
                            (Get-CcdcC2PortVerdict -ListeningPorts @(4444)),
                            (Get-CcdcProtectedAccountsVerdict -Count 0))) {
            $card.Detail.Length | Should BeGreaterThan 30
            $card.Value | Should Not Be ''
        }
    }
}

Describe 'Get-CcdcScoredServiceStatus' {
    BeforeAll { Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force }

    It 'says Up when the port is listening and Down when it is not' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('WEB01:HTTP', 'WEB01:HTTPS') -HostName 'WEB01' -ListeningTcp @(80) -ListeningUdp @())
        $http = $rows | Where-Object { $_.Service -eq 'HTTP' }
        $https = $rows | Where-Object { $_.Service -eq 'HTTPS' }
        $http.Status | Should Be 'Up'
        $https.Status | Should Be 'Down'
        $https.Detail | Should Match 'losing points'
    }
    It 'checks UDP against UDP, not TCP -- DNS answers on both and only one may be up' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('DC01:DNS') -HostName 'DC01' -ListeningTcp @(53) -ListeningUdp @())
        $udp = $rows | Where-Object { $_.Protocol -eq 'UDP' }
        $tcp = $rows | Where-Object { $_.Protocol -eq 'TCP' }
        $tcp.Status | Should Be 'Up'
        $udp.Status | Should Be 'Down'
    }
    It 'ignores services that belong to another host' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('OTHER:HTTP') -HostName 'WEB01' -ListeningTcp @() -ListeningUdp @())
        $rows.Count | Should Be 0
    }
    It 'uses a custom Port_ entry for a service the built-in table does not know' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('APP01:CustomApp') -HostName 'APP01' -CustomPorts @{ CustomApp = '8443' } -ListeningTcp @(8443) -ListeningUdp @())
        $rows.Count | Should Be 1
        $rows[0].Status | Should Be 'Up'
        $rows[0].Port | Should Be '8443'
    }
    It 'says so, rather than guessing, when no port is known for a service' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('APP01:Mystery') -HostName 'APP01' -ListeningTcp @() -ListeningUdp @())
        $rows[0].Status | Should Be 'Unknown'
        $rows[0].Detail | Should Match 'Port_Mystery'
    }
    It 'does not call an idle FTP passive range Down -- those ports only open during a transfer' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('FTP01:FTPPassive') -HostName 'FTP01' -CustomPorts @{ FTPPassive = '50000-50100' } -ListeningTcp @() -ListeningUdp @())
        $rows[0].Status | Should Be 'Unknown'
        $rows[0].Detail | Should Match 'only in use during a transfer'
    }
    It 'reports nothing when the ports could not be listed, instead of claiming everything is down' {
        $rows = @(Get-CcdcScoredServiceStatus -ScoredServices @('WEB01:HTTP') -HostName 'WEB01' -ListeningTcp $null -ListeningUdp $null)
        $rows[0].Status | Should Be 'Unknown'
    }
}
