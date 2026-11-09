#Requires -Version 5.1
# Regression tests for modules\Invoke-ThreatHunt.ps1's first-pass behavior: a
# first run must NOT quietly treat whatever is already on the box as clean.
# Runs the real script in a child Windows PowerShell 5.1 process against fake
# system data that simulates red team already being present (see
# tests\helpers\ThreatHuntHarness.ps1). Read-only; Windows only.
#
#   Invoke-Pester .\tests\ThreatHunt.Tests.ps1

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:Harness = Join-Path $PSScriptRoot 'helpers\ThreatHuntHarness.ps1'
$script:Engine = $null
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($env:OS -eq 'Windows_NT' -and (Test-Path $ps51)) { $script:Engine = $ps51 }

function script:Invoke-HuntHarness {
    param([string]$WorkDir, [int]$Pass, [switch]$AsDomainController, [switch]$Tampered, [switch]$DefenderUnreadable)
    $harnessArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:Harness,
                     '-RepoRoot', $script:RepoRoot, '-WorkDir', $WorkDir, '-Pass', $Pass)
    if ($AsDomainController) { $harnessArgs += '-AsDomainController' }
    if ($Tampered) { $harnessArgs += '-Tampered' }
    if ($DefenderUnreadable) { $harnessArgs += '-DefenderUnreadable' }
    @(& $script:Engine @harnessArgs 2>&1 | ForEach-Object { "$_" })
}
function script:Test-LogHas { param($Lines, [string]$Pattern) (@($Lines | Where-Object { $_ -match $Pattern }).Count -gt 0) }

Describe 'Invoke-ThreatHunt: first pass with red team already present' {
    BeforeAll {
        if ($script:Engine) {
            $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("hunttest-" + [guid]::NewGuid())
            $script:Pass1 = Invoke-HuntHarness -WorkDir $script:Work -Pass 1
        }
    }
    AfterAll { if ($script:Work) { Remove-Item -Path $script:Work -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'finishes cleanly under Windows PowerShell 5.1' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 '@@DONE@@') | Should Be $true
    }
    It 'says plainly that the first pass is UNVERIFIED, not clean' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 'UNVERIFIED, not confirmed clean') | Should Be $true
    }
    It 'surfaces the rogue Domain Admins member at ERROR level on pass 1' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 '\[ERROR\].*UNVERIFIED.*Domain Admins members.*rogueadmin') | Should Be $true
    }
    It 'surfaces the backdoor administrator on pass 1' {
        # "Administrators group", not "local Administrators group": on a
        # domain controller this membership comes from the directory, not
        # from a local SAM, and calling it local was misleading on the one
        # box where it matters most.
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 '\[ERROR\].*UNVERIFIED.*Administrators group members.*backdoor') | Should Be $true
    }
    It 'flags the unsigned service in a Temp path IN THE CONSOLE PREVIEW, not just in the file' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 'FLAGGED by the path/signature checks.*EvilSvc.*SUSPICIOUS PATH') | Should Be $true
        (Test-LogHas $script:Pass1 'EvilSvc.*UNSIGNED/INVALID SIGNATURE') | Should Be $true
    }
    It 'does not bury the console in one log line per service signature check' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 'check service binary signature') | Should Be $false
    }
    It 'writes the full baseline to disk with flagged services FIRST' {
        if (-not $script:Engine) { return }
        $file = Join-Path $script:Work 'logs\threat-hunt-initial-baseline\services.txt'
        (Test-Path $file) | Should Be $true
        $first = @(Get-Content $file)[0]
        $first | Should Match '^EvilSvc'
        $all = (Get-Content $file) -join "`n"
        $all | Should Match 'Spooler'
        $all | Should Match 'GhostSvc'
    }
    It 'loads the known-tool names from the data file (a processes by NAME is flagged even from a normal path)' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 'Watching for \d+ known offensive-tool process name') | Should Be $true
        (Test-LogHas $script:Pass1 'Suspicious process: customtool') | Should Be $true
        (Test-LogHas $script:Pass1 'Suspicious process: updater') | Should Be $true
    }
    It 'baselines GPOs and DNS records too, so pre-planted changes there are not silently trusted' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 'UNVERIFIED.*GPOs \(name \+ modification time\) already present') | Should Be $true
        (Test-LogHas $script:Pass1 'UNVERIFIED.*DNS zone records already present') | Should Be $true
    }
    It 'baselines DHCP reservations too, so a pre-planted rogue reservation is not silently trusted' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 'UNVERIFIED.*DHCP reservations already present') | Should Be $true
    }
    It 'still flags the known default C2 port every pass' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass1 '\[ERROR\].*known default C2 port: 4444') | Should Be $true
    }
    It 'writes state so the next pass can diff' {
        if (-not $script:Engine) { return }
        (Test-Path (Join-Path $script:Work 'logs\threat-hunt-state.json')) | Should Be $true
    }
}

Describe 'Invoke-ThreatHunt: second pass shows only what changed' {
    BeforeAll {
        if ($script:Engine) {
            $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("hunttest-" + [guid]::NewGuid())
            $null = Invoke-HuntHarness -WorkDir $script:Work -Pass 1
            $script:Pass2 = Invoke-HuntHarness -WorkDir $script:Work -Pass 2
        }
    }
    AfterAll { if ($script:Work) { Remove-Item -Path $script:Work -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'does not repeat the first-pass baseline dump' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass2 'UNVERIFIED') | Should Be $false
    }
    It 'reports the NEW Domain Admins member, and not the pre-existing rogue one' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass2 'Domain Admins gained a new member since last check: newguy') | Should Be $true
        (Test-LogHas $script:Pass2 'Domain Admins gained a new member since last check: rogueadmin') | Should Be $false
    }
    It 'reports the new service (with its flags), account, task, Run key, GPO change and DNS record' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass2 'New service since last check: Evil2 \[SUSPICIOUS PATH, UNSIGNED') | Should Be $true
        (Test-LogHas $script:Pass2 'Administrators group gained a new member since last check: .*sneaky') | Should Be $true
        (Test-LogHas $script:Pass2 'New local account since last check: newlocal') | Should Be $true
        (Test-LogHas $script:Pass2 'New scheduled task since last check: \\PersistTask') | Should Be $true
        (Test-LogHas $script:Pass2 'New Run-key persistence entry since last check: .*Beacon') | Should Be $true
        (Test-LogHas $script:Pass2 'GPO created or modified since last check: Default Domain Policy') | Should Be $true
        (Test-LogHas $script:Pass2 'DNS record added or changed since last check: evil') | Should Be $true
        (Test-LogHas $script:Pass2 'DHCP reservation added or changed since last check: 10.10.10.99 AA-BB-CC-DD-EE-FF rogue') | Should Be $true
    }
    It 'keeps flagging the C2 port even though it is no longer new' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:Pass2 '\[ERROR\].*known default C2 port: 4444') | Should Be $true
        (Test-LogHas $script:Pass2 'New listening port since last check: 4444') | Should Be $false
    }
}

Describe 'Invoke-ThreatHunt: red team switched the defences off' {
    # Every item here is one a real enumeration log from a previous round
    # recorded: update tasks disabled, Defender weakened, an SSH server on
    # a Windows box, the Security log cleared. None of them appear as a
    # NEW anything, so the diff-based checks cannot see them.
    BeforeAll {
        if ($script:Engine) {
            $script:TWork = Join-Path ([System.IO.Path]::GetTempPath()) ("hunttest-tamper-" + [guid]::NewGuid())
            $script:TPass = Invoke-HuntHarness -WorkDir $script:TWork -Pass 1 -Tampered
        }
    }
    AfterAll {
        if ($script:TWork -and (Test-Path -LiteralPath $script:TWork)) { [System.IO.Directory]::Delete($script:TWork, $true) }
    }

    It 'notices Windows Update being switched off, which no diff would catch' {
        if (-not $script:Engine) { return }
        # Asserted against the "switched off" line specifically, not just
        # against the task name appearing somewhere: the generic task dump
        # lists every task including this one, so a looser match passes
        # even with the update check deleted.
        (Test-LogHas $script:TPass '\[ERROR\].*Windows Update has been switched off.*task .*UpdateOrchestrator') | Should Be $true
        (Test-LogHas $script:TPass '\[ERROR\].*Windows Update has been switched off.*service wuauserv is Disabled') | Should Be $true
    }
    It 'notices Defender being weakened, and names the exclusion' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:TPass '\[ERROR\].*Defender has been weakened') | Should Be $true
        (Test-LogHas $script:TPass 'real-time monitoring is OFF') | Should Be $true
        (Test-LogHas $script:TPass 'C:\\Users\\Public') | Should Be $true
    }
    It 'notices an SSH server on a Windows box' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:TPass 'OpenSSH is present on this Windows box') | Should Be $true
    }
    It 'notices that the Security log was cleared' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:TPass '\[ERROR\].*Security event log has been CLEARED') | Should Be $true
    }
}

Describe 'Invoke-ThreatHunt: Defender exclusions cannot be read unelevated' {
    # Get-MpPreference does not fail unelevated -- it returns the string
    # "N/A: Must be an administrator to view exclusions" in each exclusion
    # property. Read literally that is three exclusions, and the check
    # fired a red alert on every non-elevated run until this was fixed.
    BeforeAll {
        if ($script:Engine) {
            $script:UWork = Join-Path ([System.IO.Path]::GetTempPath()) ("hunttest-unread-" + [guid]::NewGuid())
            $script:UPass = Invoke-HuntHarness -WorkDir $script:UWork -Pass 1 -DefenderUnreadable
        }
    }
    AfterAll {
        if ($script:UWork -and (Test-Path -LiteralPath $script:UWork)) { [System.IO.Directory]::Delete($script:UWork, $true) }
    }

    It 'does not report the "must be an administrator" message as an exclusion' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:UPass 'Defender has been weakened') | Should Be $false
        (Test-LogHas $script:UPass 'Must be an administrator to view exclusions') | Should Be $false
    }
    It 'says the exclusion list is untested rather than clean' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:UPass 'EXCLUSION list could not be read') | Should Be $true
        (Test-LogHas $script:UPass 'no exclusions are configured') | Should Be $false
    }
}

Describe 'Invoke-ThreatHunt: on a domain controller' {
    # Get-LocalGroupMember fails outright on a DC ("Group Administrators was
    # not found"), which is exactly where this check matters most. The real
    # run on the lab DC lost the whole membership check to that one call.
    BeforeAll {
        if ($script:Engine) {
            $script:DcWork = Join-Path ([System.IO.Path]::GetTempPath()) ("hunttest-dc-" + [guid]::NewGuid())
            $script:DcPass = Invoke-HuntHarness -WorkDir $script:DcWork -Pass 1 -AsDomainController
        }
    }
    AfterAll {
        if ($script:DcWork -and (Test-Path -LiteralPath $script:DcWork)) {
            [System.IO.Directory]::Delete($script:DcWork, $true)
        }
    }

    It 'still reads the Administrators group, via the directory' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:DcPass 'UNVERIFIED.*Administrators group members.*dcbackdoor') | Should Be $true
    }
    It 'no longer reports the membership check as a failure' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:DcPass 'Group Administrators was not found') | Should Be $false
        (Test-LogHas $script:DcPass 'audit group membership : FAILED') | Should Be $false
    }
    It 'finishes with nothing in the failure summary' {
        if (-not $script:Engine) { return }
        (Test-LogHas $script:DcPass '@@DONE@@') | Should Be $true
        (Test-LogHas $script:DcPass 'Failures \(fix these first\)') | Should Be $false
    }
}
