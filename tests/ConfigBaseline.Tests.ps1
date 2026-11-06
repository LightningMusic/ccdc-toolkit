#Requires -Version 5.1
# Tests for modules\Invoke-ConfigBaseline.ps1 -- the "what should this box
# look like, and what does it look like now" module.
#
# Each scenario runs the real module twice (capture, then verify) in a child
# Windows PowerShell 5.1 process against a scratch copy of the repo and a
# throwaway watched folder; see tests\helpers\BaselineHarness.ps1. Nothing
# here changes anything on this machine. Windows only.
#
#   Invoke-Pester .\tests\ConfigBaseline.Tests.ps1

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:Harness = Join-Path $PSScriptRoot 'helpers\BaselineHarness.ps1'
$script:Engine = $null
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($env:OS -eq 'Windows_NT' -and (Test-Path $ps51)) { $script:Engine = $ps51 }

function script:Invoke-BaselineScenario {
    param([string]$Name)
    $lines = & $script:Engine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Harness -RepoRoot $script:RepoRoot -Scenario $Name 2>&1 | ForEach-Object { "$_" }
    $resultLine = $lines | Where-Object { $_ -like '@@RESULT@@*' } | Select-Object -Last 1
    $result = $null
    if ($resultLine) { $result = $resultLine.Substring(10) | ConvertFrom-Json }
    if ($result -and $result.WorkDir -and (Test-Path $result.WorkDir)) {
        Remove-Item -Path $result.WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    [pscustomobject]@{
        HasResult  = [bool]$result
        Capture    = @($result.CaptureLog)
        Verify     = @($result.VerifyLog)
        Reports    = @($result.Reports)
        ReportText = (@($result.Reports) -join "`n")
    }
}
function script:Test-VerifyHas { param($Run, [string]$Pattern) (@($Run.Verify | Where-Object { $_ -match $Pattern }).Count -gt 0) }

Describe 'Invoke-ConfigBaseline: capture then verify with nothing changed' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'clean' } }

    It 'runs both passes to completion under Windows PowerShell 5.1' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
    }
    It 'captures the areas it says it captures' {
        if (-not $script:Engine) { return }
        foreach ($area in 'Services', 'ScheduledTasks', 'LocalAdministrators', 'ListeningPorts', 'FirewallRules', 'Hotfixes', 'WatchedFiles') {
            (@($script:Run.Capture | Where-Object { $_ -match $area }).Count -gt 0) | Should Be $true
        }
    }
    It 'reports the watched files as matching, not as drift' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'WatchedFiles : matches the baseline') | Should Be $true
    }
    It 'shows no drift in any of the high-stakes areas' {
        # Deliberately not asserting the "Everything matches the baseline"
        # summary line: on a live workstation a listening port can change
        # owning process between the two runs all by itself (mDNS on 5353
        # moves between svchost and whatever desktop app grabbed it), and a
        # test that fails for that reason teaches nothing. The areas below
        # do not move on their own.
        if (-not $script:Engine) { return }
        foreach ($area in 'DnsZones', 'DnsZoneFiles', 'LocalAdministrators', 'Services', 'ScheduledTasks', 'WatchedFiles', 'FirewallRules') {
            (Test-VerifyHas $script:Run "$area : matches the baseline") | Should Be $true
        }
        (Test-VerifyHas $script:Run 'Name check: nothing odd') | Should Be $true
    }
    It 'writes a drift report either way' {
        if (-not $script:Engine) { return }
        $script:Run.Reports.Count | Should Be 1
        $script:Run.ReportText | Should Match 'Configuration drift report'
    }
    It 'changes nothing: no ACTION line proposes a modification' {
        if (-not $script:Engine) { return }
        # Every Invoke-CcdcSafe action in this module is a read. If one
        # ever starts writing, this catches it.
        foreach ($l in @($script:Run.Capture + $script:Run.Verify | Where-Object { $_ -match '\[ACTION\]' })) {
            ($l -match 'read|list|count|enumerate|hash|check') | Should Be $true
        }
    }
}

Describe 'Invoke-ConfigBaseline: a file renamed with a trailing space' {
    # The attack a returning competitor described: AD went down because a
    # file DNS loads was renamed with a space on the end.
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'trailing-space' } }

    It 'reports the old name missing and the new one added' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'WatchedFiles : .*added.*missing') | Should Be $true
    }
    It 'flags the name itself, not just the file count' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'Name check: 1 name\(s\) look deliberately altered') | Should Be $true
        (Test-VerifyHas $script:Run 'ends with whitespace') | Should Be $true
    }
    It 'prints the name in brackets so the trailing space is actually visible' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run '\[site\.conf \]') | Should Be $true
    }
    It 'puts the finding in the written report too' {
        if (-not $script:Engine) { return }
        $script:Run.ReportText | Should Match 'Names that look deliberately altered'
    }
}

Describe 'Invoke-ConfigBaseline: a homoglyph in a filename' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'homoglyph' } }

    It 'flags the non-ASCII character and names its code point' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'non-ASCII') | Should Be $true
        (Test-VerifyHas $script:Run 'U\+0430') | Should Be $true
    }
}

Describe 'Invoke-ConfigBaseline: file contents changed underneath us' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'content-change' } }

    It 'detects the change by hash, with the same name on both sides' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'WatchedFiles : 1 changed') | Should Be $true
        (Test-VerifyHas $script:Run 'index\.html') | Should Be $true
    }
    It 'does not cry tampering when only the contents moved' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'Name check: nothing odd') | Should Be $true
    }
}

Describe 'Invoke-ConfigBaseline: contents changed without changing the file size' {
    # Proves the comparison is a content hash and not a size check. A
    # size-only baseline passes every other test in this file, so without
    # this one the hashing could quietly stop working.
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'same-size-change' } }

    It 'still detects the change' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'WatchedFiles : 1 changed') | Should Be $true
        (Test-VerifyHas $script:Run 'index\.html') | Should Be $true
    }
    It 'shows a hash on both sides of the diff, not a size' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'was: [0-9A-F]{64}') | Should Be $true
        (Test-VerifyHas $script:Run 'now: [0-9A-F]{64}') | Should Be $true
    }
}

Describe 'Invoke-ConfigBaseline: a file appeared, and a file vanished' {
    BeforeAll {
        if ($script:Engine) {
            $script:New = Invoke-BaselineScenario 'new-file'
            $script:Gone = Invoke-BaselineScenario 'deleted-file'
        }
    }

    It 'reports a new file as added' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:New 'WatchedFiles : 1 added') | Should Be $true
        (Test-VerifyHas $script:New 'shell\.aspx') | Should Be $true
    }
    It 'reports a deleted file as missing' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Gone 'WatchedFiles : 1 missing') | Should Be $true
    }
}

Describe 'Invoke-ConfigBaseline: it finds this box content roots by itself' {
    # The first real run on the lab FTP server captured "WatchedFiles: 0" --
    # a successful baseline of a content server that fingerprinted none of
    # its content, because nobody had set BaselineWatchPaths. Auto-discovery
    # runs by default now, so it needs coverage: no dev box has IIS, so
    # without the harness faking Get-Website this path never executes.
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'auto-watch' } }

    It 'watches the IIS site root and the FTP root without being told to' {
        # Asserted against the CAPTURE log: discovery happens there, and
        # deliberately not at verify time.
        if (-not $script:Engine) { return }
        (@($script:Run.Capture | Where-Object { $_ -match 'Watching .*wwwroot.* automatically' }).Count -gt 0) | Should Be $true
        (@($script:Run.Capture | Where-Object { $_ -match 'Watching .*ftproot.* automatically' }).Count -gt 0) | Should Be $true
    }
    It 'actually fingerprints what it found, rather than just naming it' {
        if (-not $script:Engine) { return }
        (@($script:Run.Capture | Where-Object { $_ -match 'WatchedFiles\s+0 item' }).Count) | Should Be 0
    }
    It 'catches a defacement in a folder nobody configured' {
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'WatchedFiles : 1 changed') | Should Be $true
        (Test-VerifyHas $script:Run 'default\.htm') | Should Be $true
    }
}

Describe 'Invoke-ConfigBaseline: -NoAutoWatch' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'auto-watch-off' } }

    It 'watches nothing automatically when told not to' {
        if (-not $script:Engine) { return }
        (@($script:Run.Capture | Where-Object { $_ -match 'automatically' }).Count) | Should Be 0
        (@($script:Run.Capture | Where-Object { $_ -match 'WatchedFiles\s+0 item' }).Count) | Should Be 1
    }
    It 'does not then discover paths at verify time and call them drift' {
        # A baseline captured with -NoAutoWatch knows about no files. If
        # verify went looking on its own, every file it found would be
        # reported as newly added -- drift that is really just the two
        # runs having looked at different folders.
        if (-not $script:Engine) { return }
        (Test-VerifyHas $script:Run 'WatchedFiles : matches the baseline') | Should Be $true
        (Test-VerifyHas $script:Run 'automatically') | Should Be $false
    }
}

Describe 'Invoke-ConfigBaseline: verify with no baseline captured' {
    BeforeAll { if ($script:Engine) { $script:Run = Invoke-BaselineScenario 'no-baseline' } }

    It 'refuses clearly and says what to do instead of comparing against nothing' {
        if (-not $script:Engine) { return }
        $script:Run.HasResult | Should Be $true
        (Test-VerifyHas $script:Run 'Action Capture') | Should Be $true
    }
}
