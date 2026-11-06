#Requires -Version 5.1
# Regression tests for modules\Invoke-FirewallBaseline.ps1 -- the riskiest module.
# Each scenario runs the real script in a child Windows PowerShell 5.1 process
# (the engine the competition boxes actually run) against fake firewall and
# scheduled-task cmdlets; see tests\helpers\FirewallHarness.ps1. Nothing here
# touches the real firewall. Windows only.
#
#   Invoke-Pester .\tests\Firewall.Tests.ps1

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:Harness = Join-Path $PSScriptRoot 'helpers\FirewallHarness.ps1'
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
        Log            = @($lines | Where-Object { $_ -notlike '@@RESULT@@*' })
        Calls          = @($result.Calls)
        DefaultInbound = @($result.DefaultInbound)
        TasksLeft      = $result.TasksLeft
        HasResult      = [bool]$result
    }
}

function script:Get-RuleCalls { param($Run) @($Run.Calls | Where-Object { $_ -like 'New-NetFirewallRule|*' } | ForEach-Object { $p = $_.Split('|'); [pscustomobject]@{ Name = $p[1]; Proto = $p[2]; Port = $p[3]; Remote = $p[4] } }) }
function script:Test-LogHas { param($Run, [string]$Pattern) (@($Run.Log | Where-Object { $_ -match $Pattern }).Count -gt 0) }

Describe 'Invoke-FirewallBaseline: happy path' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'happy' } }

    It 'runs to completion under Windows PowerShell 5.1' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'creates TCP and UDP rules as each service needs (DNS both, NTP UDP-only)' {
        if (-not $script:Engine) { return }
        $r = @(Get-RuleCalls $script:Run | ForEach-Object { "$($_.Proto)/$($_.Port)" })
        ($r -contains 'TCP/53') | Should Be $true
        ($r -contains 'UDP/53') | Should Be $true
        ($r -contains 'UDP/123') | Should Be $true
        ($r -contains 'TCP/123') | Should Be $false
        ($r -contains 'UDP/389') | Should Be $true
    }
    It 'supports custom ports: single, UDP-prefixed, and a range' {
        if (-not $script:Engine) { return }
        $r = @(Get-RuleCalls $script:Run | ForEach-Object { "$($_.Proto)/$($_.Port)" })
        ($r -contains 'TCP/8443') | Should Be $true
        ($r -contains 'UDP/5060') | Should Be $true
        ($r -contains 'TCP/50000-50100') | Should Be $true
    }
    It 'scopes ONLY management ports to the admin subnet; scored ports stay unrestricted' {
        if (-not $script:Engine) { return }
        $rules = Get-RuleCalls $script:Run
        foreach ($m in @($rules | Where-Object { $_.Port -in '3389', '5985', '5986' })) { $m.Remote | Should Be '10.10.10.0/24' }
        foreach ($s in @($rules | Where-Object { $_.Port -notin '3389', '5985', '5986' })) { $s.Remote | Should Be 'Any' }
    }
    It 'arms the safety net as SYSTEM with the highest run level, using the full path to Windows PowerShell' {
        if (-not $script:Engine) { return }
        $reg = @($script:Run.Calls | Where-Object { $_ -like 'Register-ScheduledTask|*' })
        $reg.Count | Should Be 1
        $p = $reg[0].Split('|')
        $p[2] | Should Be 'SYSTEM'
        $p[3] | Should Be 'Highest'
        $p[4] | Should Be 'ServiceAccount'
        $p[5] | Should Match 'System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$'
    }
    It 'registers the safety net BEFORE it flips the default action to Block' {
        if (-not $script:Engine) { return }
        $reg = [array]::IndexOf($script:Run.Calls, ($script:Run.Calls | Where-Object { $_ -like 'Register-ScheduledTask|*' } | Select-Object -First 1))
        $blk = [array]::IndexOf($script:Run.Calls, ($script:Run.Calls | Where-Object { $_ -like 'Set-NetFirewallProfile|Block' } | Select-Object -First 1))
        ($reg -ge 0 -and $blk -gt $reg) | Should Be $true
    }
    It 'ends with the default inbound action Block and the safety net disarmed' {
        if (-not $script:Engine) { return }
        ($script:Run.DefaultInbound -join ',') | Should Be 'Block'
        $script:Run.TasksLeft | Should Be 0
        (Test-LogHas $script:Run 'Self-check passed') | Should Be $true
    }
    It 'warns that FTP passive ports are not covered when FTP is scored without an FTPPassive entry' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'FTP is scored on this host.*Passive') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: FTP passive range configured' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'ftp-ok' } }
    It 'does not warn when an FTPPassive entry is listed' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'FTP is scored on this host.*Passive') | Should Be $false
        $script:Run.HasResult | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: the safety net cannot be armed' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'regfail' } }

    It 'refuses to switch the default action to Block' {
        if (-not $script:Engine) { return }
        (@($script:Run.Calls | Where-Object { $_ -like 'Set-NetFirewallProfile|*' }).Count) | Should Be 0
        ($script:Run.DefaultInbound -join ',') | Should Be 'Allow'
    }
    It 'still leaves the allow rules in place and says why it stopped' {
        if (-not $script:Engine) { return }
        (Get-RuleCalls $script:Run).Count | Should BeGreaterThan 5
        (Test-LogHas $script:Run 'NOT switched to Block') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: the safety net registers as the wrong identity' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'wrongprincipal' } }

    It 'refuses to switch to Block and removes the misconfigured task instead of leaving it behind' {
        if (-not $script:Engine) { return }
        ($script:Run.DefaultInbound -join ',') | Should Be 'Allow'
        $script:Run.TasksLeft | Should Be 0
        (Test-LogHas $script:Run 'not SYSTEM') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: -AllowNoSafetyNet' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'regfail-allow' } }

    It 'proceeds to Block only when explicitly told to, and warns loudly' {
        if (-not $script:Engine) { return }
        ($script:Run.DefaultInbound -join ',') | Should Be 'Block'
        (Test-LogHas $script:Run 'safety net is NOT armed') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: -WhatIf' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'whatif' } }

    It 'changes nothing: no rules, no task, no profile change' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
        (@($script:Run.Calls | Where-Object { $_ -match '^(New-NetFirewallRule|Set-NetFirewallProfile|Register-ScheduledTask|Unregister-ScheduledTask|Disable-NetFirewallRule)\|' }).Count) | Should Be 0
        ($script:Run.DefaultInbound -join ',') | Should Be 'Allow'
    }
    It 'does not report false self-check failures for rules it never created' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run '\[ERROR\]') | Should Be $false
    }
}

Describe 'Invoke-FirewallBaseline: -SkipDefaultBlock' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'skipblock' } }

    It 'adds the allow rules but touches neither the safety net nor the default action' {
        if (-not $script:Engine) { return }
        (Get-RuleCalls $script:Run).Count | Should BeGreaterThan 5
        (@($script:Run.Calls | Where-Object { $_ -match '^(Set-NetFirewallProfile|Register-ScheduledTask)\|' }).Count) | Should Be 0
        ($script:Run.DefaultInbound -join ',') | Should Be 'Allow'
    }
}

Describe 'Invoke-FirewallBaseline: self-check catches a rule that landed wrong' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'selfcheckfail' } }

    It 'reports the scored failure and does NOT disarm the safety net' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'SCORED rule\(s\) failed self-check: UDP/53') | Should Be $true
        (Test-LogHas $script:Run 'NOT removing the safety net') | Should Be $true
        $script:Run.TasksLeft | Should Be 1
        (@($script:Run.Calls | Where-Object { $_ -like 'Unregister-ScheduledTask|*' }).Count) | Should Be 0
    }
}

# ---------------------------------------------------------------------------
# Ping. The 2026 Midwest team packet says the scoring engine relies on ICMP
# and to keep it up on every device except the Palo Alto core port. Flipping
# the default inbound action to Block silently kills it, because Windows
# Server ships its built-in echo-request rule disabled -- so the rule has to
# be ours, it has to be created before the flip, and the self-check has to
# treat it as seriously as a scored port.
# ---------------------------------------------------------------------------
function script:Get-IcmpCalls { param($Run) @($Run.Calls | Where-Object { $_ -like 'New-NetFirewallRule|*|ICMPv4|*' }) }

Describe 'Invoke-FirewallBaseline: ping keeps answering' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'happy' } }

    It 'creates exactly one inbound ICMPv4 echo-request allow rule' {
        if (-not $script:Engine) { return }
        # Re-wrapped at the call site: PowerShell unrolls a single-element
        # array on the way out of a function, and .Count on the bare string
        # is also 1, so the assertion would pass while [0] handed back a char.
        $icmp = @(Get-IcmpCalls $script:Run)
        $icmp.Count | Should Be 1
        $p = $icmp[0].Split('|')
        $p[5] | Should Be '8'          # echo request only, not every ICMP type
    }
    It 'never scopes the ping rule to a source address' {
        # We do not know the scoring engine's source IP; guessing it wrong
        # costs the uptime points the rule exists to protect.
        if (-not $script:Engine) { return }
        @(Get-IcmpCalls $script:Run)[0].Split('|')[4] | Should Be 'Any'
    }
    It 'creates the ping rule BEFORE flipping the default action to Block' {
        if (-not $script:Engine) { return }
        $icmpIdx = [array]::IndexOf($script:Run.Calls, ((Get-IcmpCalls $script:Run) | Select-Object -First 1))
        $blkIdx = [array]::IndexOf($script:Run.Calls, ($script:Run.Calls | Where-Object { $_ -like 'Set-NetFirewallProfile|Block' } | Select-Object -First 1))
        ($icmpIdx -ge 0 -and $blkIdx -gt $icmpIdx) | Should Be $true
    }
    It 'says so in the self-check line' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'Self-check passed.*ping still answers') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: the ping rule did not take' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'icmpfail' } }

    It 'fails the self-check at ERROR and keeps the safety net armed' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'stopped answering ping') | Should Be $true
        (Test-LogHas $script:Run 'Self-check passed') | Should Be $false
        (Test-LogHas $script:Run 'NOT removing the safety net') | Should Be $true
        $script:Run.TasksLeft | Should Be 1
    }
}

Describe 'Invoke-FirewallBaseline: no inventory, but the answer file has ScoredServices' {
    # The state a box is in when the firewall baseline runs before
    # discovery does. This used to produce management rules and nothing
    # else, silently, while the values sat in config\answers.local.psd1 --
    # a quiet no-op that looks exactly like "the tool did nothing".
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'no-inventory' } }

    It 'still opens the scored ports, from the answer file' {
        if (-not $script:Engine) { return }
        $r = @(Get-RuleCalls $script:Run | ForEach-Object { "$($_.Proto)/$($_.Port)" })
        ($r -contains 'TCP/53') | Should Be $true
        ($r -contains 'UDP/53') | Should Be $true
        ($r -contains 'UDP/123') | Should Be $true
        ($r -contains 'TCP/8443') | Should Be $true
    }
    It 'says where it got the list, so nobody thinks discovery ran' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'ScoredServices list from your answer file') | Should Be $true
    }
    It 'still reaches default-block and disarms the safety net' {
        if (-not $script:Engine) { return }
        ($script:Run.DefaultInbound -join ',') | Should Be 'Block'
        $script:Run.TasksLeft | Should Be 0
    }
}

Describe 'Invoke-FirewallBaseline: no scored services anywhere' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'no-scored' } }

    It 'says plainly that it has nothing to protect, and how to fix that' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'nothing to protect') | Should Be $true
        (Test-LogHas $script:Run 'run discovery \(menu 1\)') | Should Be $true
    }
    It 'creates no scored-port rules at all' {
        if (-not $script:Engine) { return }
        $r = @(Get-RuleCalls $script:Run | ForEach-Object { "$($_.Proto)/$($_.Port)" })
        ($r -contains 'TCP/53') | Should Be $false
    }
}

Describe 'Invoke-FirewallBaseline: -NoIcmpEcho' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'no-icmp' } }

    It 'creates no ping rule, warns why that is risky, and still passes its self-check' {
        if (-not $script:Engine) { return }
        (Get-IcmpCalls $script:Run).Count | Should Be 0
        (Test-LogHas $script:Run 'stop answering ping') | Should Be $true
        (Test-LogHas $script:Run 'Self-check passed') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: -FullBlackout' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'fullblackout' } }

    It 'blocks BEFORE any allow rule exists -- the point of a real blackout' {
        if (-not $script:Engine) { return }
        $blk = [array]::IndexOf($script:Run.Calls, ($script:Run.Calls | Where-Object { $_ -like 'Set-NetFirewallProfile|Block' } | Select-Object -First 1))
        $firstRule = [array]::IndexOf($script:Run.Calls, ($script:Run.Calls | Where-Object { $_ -like 'New-NetFirewallRule|*' } | Select-Object -First 1))
        ($blk -ge 0) | Should Be $true
        ($firstRule -lt 0 -or $firstRule -gt $blk) | Should Be $true
    }
    It 'launches credential hardening (via Start-Process -Wait) during the blackout, before any rule exists' {
        if (-not $script:Engine) { return }
        $launch = @($script:Run.Calls | Where-Object { $_ -like 'Start-Process|*' })
        $launch.Count | Should Be 1
        $launch[0] | Should Match 'Invoke-CredentialHardening\.ps1'
        $launch[0] | Should Match 'Wait=True'
        # Forced, not optional: this child process gets a fresh console with
        # nobody at it. Without this flag, an empty ProtectedAccounts list
        # would sit at Read-Host forever -- box stuck in full deny-all with
        # no snapshot/revert on competition day.
        $launch[0] | Should Match 'AcknowledgeNoProtectedAccounts'
        $launchIdx = [array]::IndexOf($script:Run.Calls, $launch[0])
        $firstRule = [array]::IndexOf($script:Run.Calls, ($script:Run.Calls | Where-Object { $_ -like 'New-NetFirewallRule|*' } | Select-Object -First 1))
        ($firstRule -lt 0 -or $firstRule -gt $launchIdx) | Should Be $true
    }
    It 'still ends with every scored rule present, Block, and the safety net disarmed -- same end state as the default path' {
        if (-not $script:Engine) { return }
        $r = @(Get-RuleCalls $script:Run | ForEach-Object { "$($_.Proto)/$($_.Port)" })
        ($r -contains 'TCP/53') | Should Be $true
        ($script:Run.DefaultInbound -join ',') | Should Be 'Block'
        $script:Run.TasksLeft | Should Be 0
        (Test-LogHas $script:Run 'Self-check passed') | Should Be $true
    }
    It 'warns loudly that this will cut an RDP/WinRM session before doing anything' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'BLACKOUT ACTIVE') | Should Be $true
    }
}

Describe 'Invoke-FirewallBaseline: -FullBlackout when the safety net cannot be armed' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-Scenario 'fullblackout-regfail' } }

    It 'refuses to enter the blackout at all -- a deny-all with no way back is worse than not running' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Run 'Could not enter the blackout safely') | Should Be $true
        (@($script:Run.Calls | Where-Object { $_ -like 'Set-NetFirewallProfile|Block' })).Count | Should Be 0
    }
    It 'never launches credential hardening if the blackout itself was refused' {
        if (-not $script:Engine) { return }
        (@($script:Run.Calls | Where-Object { $_ -like 'Start-Process|*' })).Count | Should Be 0
    }
    It 'creates no allow rules either -- stops completely, changes nothing' {
        if (-not $script:Engine) { return }
        (@($script:Run.Calls | Where-Object { $_ -like 'New-NetFirewallRule|*' })).Count | Should Be 0
    }
}
