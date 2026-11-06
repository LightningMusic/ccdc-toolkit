#Requires -Version 5.1
<#
.SYNOPSIS
    The "what's happening on this box right now that I should know about"
    tool — plain-English background threat hunting, read-only.

.DESCRIPTION
    This is the module the whole toolkit was originally supposed to include
    for "permanent troubleshooting": something that periodically looks for
    the signs of red-team activity the CCDC research (and later, an actual
    past regional's Windows Lead reference material) calls out again and
    again, and tells you in one plain-English line per finding what it saw
    — not a raw event log dump you have to squint at mid-round.

    This module NEVER changes anything. No backup step, because there's
    nothing to back up — every check here is read-only. That also means
    it's safe to run as often as you want, including from a second window
    while other modules are doing real work.

    Two kinds of checks:
      - DIFF-BASED (only reports what's NEW since the last pass): Domain
        Admins / Enterprise Admins / local Administrators membership, local
        accounts, listening TCP ports, scheduled tasks, services, registry
        Run/RunOnce persistence entries, GPO modification times, and DNS
        zone records (the last two per an ATCC coach's field manual's own
        AD-audit advice — a changed GPO can be a persistence mechanism,
        and a changed DNS record can redirect traffic). The first time you
        ever run this, there's nothing to diff against yet — but that does
        NOT mean the box gets assumed clean. You have to assume red team
        could already be in by the time you get a console open, so the
        first pass dumps everything each diffed check finds as an
        UNVERIFIED one-time baseline instead of silently swallowing it: a
        short WARN/ERROR preview per category in the console, plus the
        full list written to logs\threat-hunt-initial-baseline\<category>.txt
        so nothing's lost to console scroll on the noisier categories
        (services, DNS records can run into the hundreds). Services
        specifically also get the suspicious-path/signature check run
        against every one of them on this first pass, not just
        newly-appeared ones, for the same reason. Every pass AFTER the
        first goes back to only flagging what changed since the last one,
        which is what's actually usable during a live round (nobody has
        time to re-read a full account list every 15 minutes looking for
        the one new name) — but that first, unverified dump is the one
        chance to catch something already planted before this tool ever
        ran, so actually read it once.
      - ALWAYS-ON (re-reported every single pass, not diffed): suspicious
        processes (running from Temp/AppData/Downloads-type paths, or
        matching a list of known offensive-tool process names), known
        default C2 listener ports if currently listening (4444/2222 by
        default — flagged every pass even if they aren't new, since
        they're suspicious on sight, not just on arrival), recently
        dropped/modified files in common staging locations, and a summary
        of recent Security-log logon activity. These stay visible every
        pass on purpose — if something red team planted is still sitting
        there, you want to be reminded, not just alerted once and then
        have it go quiet if you missed the first line.

    State (what "last pass" looked like) is tracked in
    logs\threat-hunt-state.json — gitignored like everything else under
    logs\, and irrelevant to anyone reading the public source.

    Every individual check degrades gracefully and independently: if a
    cmdlet isn't available (not domain-joined, RSAT missing, older
    PowerShell without Get-LocalUser, whatever), that ONE check is skipped
    with a plain INFO line and everything else still runs.

.PARAMETER LookbackMinutes
    On the very first pass (no baseline yet), how far back to look for
    "recent" activity that doesn't have a diff to compare against — new AD
    accounts, recently dropped files, and logon-log activity. Default 20.
    Ignored on every pass after the first (those use "since the last
    pass" instead, which is always more precise).

.PARAMETER Continuous
    Keep running passes in a loop instead of doing one and exiting, waiting
    -IntervalMinutes between each. Ctrl+C to stop. Meant for a dedicated
    window you leave open, NOT for running through the main menu (which
    would otherwise hang waiting for a loop that never returns) — call this
    script directly for continuous mode.

.PARAMETER IntervalMinutes
    How long to wait between passes in -Continuous mode. Default 10,
    matching the "check every 10-15 minutes" cadence the CCDC research
    consistently recommends.

.PARAMETER SuspiciousPathPatterns
    Regex fragments matched against process paths, service paths, and file
    locations to flag as worth a second look. Has a sensible generic
    default (Temp, AppData\Local\Temp, Downloads, non-Microsoft
    ProgramData, Users\Public) — override if your environment's layout
    differs.

.PARAMETER KnownToolNames
    Process names (lowercase, no .exe) that are always flagged if seen
    running, regardless of path. By default these come from
    configs\threat-hunt\known-tool-names.txt (one name per line; edit that
    file to extend the list -- it's a first pass at common offensive-security
    tooling, not exhaustive). Pass names here to override the file for one run.

    The list lives in a data file, not in this script, on purpose: antivirus
    (Windows Defender's AMSI scan) reacts to well-known offensive tool names
    appearing in script source, and this script was blocked as "malicious
    content" once on a first run because its own indicator list looked like
    the real thing.

.PARAMETER KnownToolNamesPath
    Use a different names file than the default one under configs\threat-hunt\.

.PARAMETER AlwaysFlagPorts
    Listening TCP ports flagged EVERY pass, not just when they're new —
    per an ATCC coach's field manual, ports like 4444 and 2222 are common
    enough default C2 listener ports that they're worth a standing flag
    regardless of new-or-not. Defaults to 4444 and 2222.

.EXAMPLE
    .\Invoke-ThreatHunt.ps1
    One pass: establishes a baseline the first time, diffs against the
    last pass every time after.

.EXAMPLE
    .\Invoke-ThreatHunt.ps1 -Continuous -IntervalMinutes 10
    Runs in a loop in its own window until you Ctrl+C it.
#>
[CmdletBinding()]
param(
    [int]$LookbackMinutes = 20,
    [switch]$Continuous,
    [int]$IntervalMinutes = 10,
    [string[]]$SuspiciousPathPatterns = @(
        '\\Temp\\',
        '\\AppData\\Local\\Temp\\',
        '\\Downloads\\',
        '\\ProgramData\\(?!Microsoft)',
        '\\Users\\Public\\'
    ),
    [string[]]$KnownToolNames,
    [string]$KnownToolNamesPath,
    [int[]]$AlwaysFlagPorts = @(4444, 2222)
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Threat-hunt watcher starting. Read-only — this never changes anything on the box, it only looks and reports."

# Known offensive-tool process names: an explicit -KnownToolNames wins, then a
# names file (default: configs\threat-hunt\known-tool-names.txt), then a tiny
# built-in fallback so the check still does something if the file is missing.
# (The list is a data file, not script source -- see .PARAMETER KnownToolNames.)
if (-not $PSBoundParameters.ContainsKey('KnownToolNames')) {
    if (-not $KnownToolNamesPath) {
        $KnownToolNamesPath = Join-Path (Join-Path (Join-Path $session.RootPath 'configs') 'threat-hunt') 'known-tool-names.txt'
    }
    $KnownToolNames = @()
    if (Test-Path -LiteralPath $KnownToolNamesPath) {
        $KnownToolNames = @(Get-Content -LiteralPath $KnownToolNamesPath |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Where-Object { $_ -and -not $_.StartsWith('#') })
    } else {
        Write-CcdcLog -Level WARN -Message "Tool-name list not found at $KnownToolNamesPath -- using a minimal built-in fallback. Restore configs\threat-hunt\known-tool-names.txt for the full list."
        $KnownToolNames = @('nc', 'ncat', 'netcat', 'psexec', 'psexec64', 'procdump')
    }
    Write-CcdcLog -Level INFO -Message "Watching for $($KnownToolNames.Count) known offensive-tool process name(s)."
}

$statePath = Join-Path $session.LogRoot 'threat-hunt-state.json'

# ---------------------------------------------------------------------------
# The pure logic this module uses (diffing what's new since the last pass,
# stripping a service's arguments to its executable path, matching
# suspicious-path patterns) lives in modules\CcdcLogic.ps1 and is covered by
# tests\. What's below is the one helper that also writes to disk/console.
# ---------------------------------------------------------------------------

function Write-CcdcInitialBaseline {
    <#
    .SYNOPSIS
        The first pass has nothing to diff against, so a diffed check's
        "if ($PreviousState) {...}" block used to just do nothing at all
        -- whatever was already there got folded silently into the
        baseline and would NEVER be flagged, even if it was red team's
        own persistence planted before this ever ran. You have to assume
        that's possible, not assume a first run means a clean box.

        Instead: log one short WARN with a preview, and write the full
        current list to disk under logs\threat-hunt-initial-baseline\ so
        nothing is lost to console scroll -- without dumping potentially
        hundreds of DNS records or services straight into the console,
        which would just bury the one line that actually matters. This
        only runs once, on the pass that has no prior state; every pass
        after that goes back to normal new-since-last-check diffing.

        -Highlight is for categories where each item gets its own
        suspicious/unsigned check (services): pass the subset that was
        flagged. Flagged items go FIRST in the file and are what the
        console preview shows, so a couple of hundred ordinary services
        can't bury the ones that matter. Omit it for categories with no
        per-item check.
    #>
    param(
        [string]$Label,
        [string[]]$Items,
        [string]$BaselineDir,
        [string]$Level = 'WARN',
        [string[]]$Highlight
    )
    $itemList = @($Items | Where-Object { $_ })
    if ($itemList.Count -eq 0) { return }

    $hasHighlightCheck = $PSBoundParameters.ContainsKey('Highlight')
    $highlightList = @($Highlight | Where-Object { $_ })
    $orderedList = if ($hasHighlightCheck -and $highlightList.Count -gt 0) {
        @($highlightList) + @($itemList | Where-Object { $highlightList -notcontains $_ })
    } else {
        $itemList
    }

    $outPath = $null
    try {
        if (-not (Test-Path -Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }
        $safeLabel = ($Label -replace '[^a-zA-Z0-9_\-]', '_')
        $outPath = Join-Path $BaselineDir "$safeLabel.txt"
        $orderedList | Out-File -FilePath $outPath -Encoding utf8
    } catch {
        Write-CcdcLog -Level WARN -Message "Couldn't write the initial-baseline file for '$Label' ($($_.Exception.Message)) -- showing what fits below instead."
    }

    $fileNote = if ($outPath) { " Full list: $outPath" } else { '' }
    if ($hasHighlightCheck) {
        if ($highlightList.Count -gt 0) {
            $preview = ($highlightList | Select-Object -First 8) -join '; '
            $more = if ($highlightList.Count -gt 8) { " (+$($highlightList.Count - 8) more flagged)" } else { '' }
            Write-CcdcLog -Level $Level -Message "First pass -- no prior scan to diff against, so this is UNVERIFIED, not confirmed clean: $($itemList.Count) $Label already present, $($highlightList.Count) FLAGGED by the path/signature checks: $preview$more.$fileNote"
        } else {
            Write-CcdcLog -Level INFO -Message "First pass -- no prior scan to diff against, so this is UNVERIFIED, not confirmed clean: $($itemList.Count) $Label already present; none were flagged by the path/signature checks.$fileNote"
        }
        return
    }

    $preview = ($itemList | Select-Object -First 5) -join '; '
    $more = if ($itemList.Count -gt 5) { " (+$($itemList.Count - 5) more)" } else { '' }
    Write-CcdcLog -Level $Level -Message "First pass -- no prior scan to diff against, so this is UNVERIFIED, not confirmed clean: $($itemList.Count) $Label already present. $preview$more$fileNote"
}



function Invoke-HuntPass {
    param(
        $PreviousState,
        [datetime]$SinceUtc
    )

    $current = [ordered]@{
        RunUtc              = (Get-Date).ToUniversalTime().ToString('o')
        DomainAdmins        = @()
        EnterpriseAdmins    = @()
        LocalAdministrators = @()
        LocalAccounts       = @()
        ListeningPorts      = @()
        ScheduledTasks      = @()
        Services            = @()
        RunKeyEntries       = @()
        GpoModTimes         = @()
        DnsRecords          = @()
        WmiSubscriptions    = @()
        PowerShellProfiles  = @()
        StartupFolderItems  = @()
    }
    # Where first-pass "here's everything, unverified" dumps land (see
    # Write-CcdcInitialBaseline) -- only ever written to on the pass that
    # has no $PreviousState.
    $baselineDir = Join-Path $session.LogRoot 'threat-hunt-initial-baseline'

    Write-Host ""
    Write-Host "---- Threat-hunt pass: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ----" -ForegroundColor Cyan

    # -- Privileged AD group membership + new domain accounts -----------
    if (Get-Command -Name Get-ADGroupMember -ErrorAction SilentlyContinue) {
        $daOutcome = Invoke-CcdcSafe -Target 'Domain Admins' -Action 'audit group membership' -ScriptBlock {
            Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction Stop | ForEach-Object { $_.SamAccountName }
        }
        if ($daOutcome.Success) {
            $current.DomainAdmins = @($daOutcome.Value)
            if ($PreviousState) {
                $newMembers = Get-CcdcNewItems -Previous $PreviousState.DomainAdmins -Current $current.DomainAdmins
                foreach ($m in $newMembers) {
                    Write-CcdcLog -Level ERROR -Message "Domain Admins gained a new member since last check: $m. Verify this was your team."
                }
            } else {
                Write-CcdcInitialBaseline -Label 'Domain Admins members' -Items $current.DomainAdmins -BaselineDir $baselineDir -Level ERROR
            }
        }

        $eaOutcome = Invoke-CcdcSafe -Target 'Enterprise Admins' -Action 'audit group membership' -ScriptBlock {
            Get-ADGroupMember -Identity 'Enterprise Admins' -ErrorAction Stop | ForEach-Object { $_.SamAccountName }
        }
        if ($eaOutcome.Success) {
            $current.EnterpriseAdmins = @($eaOutcome.Value)
            if ($PreviousState) {
                $newMembers = Get-CcdcNewItems -Previous $PreviousState.EnterpriseAdmins -Current $current.EnterpriseAdmins
                foreach ($m in $newMembers) {
                    Write-CcdcLog -Level ERROR -Message "Enterprise Admins gained a new member since last check: $m. Verify this was your team."
                }
            } else {
                Write-CcdcInitialBaseline -Label 'Enterprise Admins members' -Items $current.EnterpriseAdmins -BaselineDir $baselineDir -Level ERROR
            }
        }

        $newUsersOutcome = Invoke-CcdcSafe -Target 'AD users' -Action 'check for newly created domain accounts' -ScriptBlock {
            $localSince = $SinceUtc.ToLocalTime()
            Get-ADUser -Filter * -Properties Created -ErrorAction Stop |
                Where-Object { $_.Created -gt $localSince } |
                ForEach-Object { "$($_.SamAccountName) (created $($_.Created))" }
        }
        if ($newUsersOutcome.Success) {
            foreach ($u in @($newUsersOutcome.Value)) {
                Write-CcdcLog -Level WARN -Message "New domain account since last check: $u"
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-ADGroupMember not available — skipping AD privileged-group checks (not domain-joined, or RSAT missing)."
    }

    # -- Administrators group + local accounts ---------------------------
    # Routed through Get-CcdcAdministratorsMember rather than calling
    # Get-LocalGroupMember directly: that cmdlet fails outright on a domain
    # controller ("Group Administrators was not found"), which is exactly
    # where this check matters most.
    $laOutcome = Invoke-CcdcSafe -Target 'Administrators group' -Action 'audit group membership' -ScriptBlock {
        $r = Get-CcdcAdministratorsMember
        if (-not $r.Success) { throw $r.Message }
        $r.Members
    }
    if ($laOutcome.Success) {
        $current.LocalAdministrators = @($laOutcome.Value)
        if ($PreviousState) {
            $newMembers = Get-CcdcNewItems -Previous $PreviousState.LocalAdministrators -Current $current.LocalAdministrators
            foreach ($m in $newMembers) {
                Write-CcdcLog -Level ERROR -Message "Administrators group gained a new member since last check: $m. Verify this was your team."
            }
        } else {
            Write-CcdcInitialBaseline -Label 'Administrators group members' -Items $current.LocalAdministrators -BaselineDir $baselineDir -Level ERROR
        }
    }

    if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
        $luOutcome = Invoke-CcdcSafe -Target 'local accounts' -Action 'list local user accounts' -ScriptBlock {
            Get-LocalUser -ErrorAction Stop | ForEach-Object { $_.Name }
        }
        if ($luOutcome.Success) {
            $current.LocalAccounts = @($luOutcome.Value)
            if ($PreviousState) {
                $newAccts = Get-CcdcNewItems -Previous $PreviousState.LocalAccounts -Current $current.LocalAccounts
                foreach ($a in $newAccts) {
                    Write-CcdcLog -Level WARN -Message "New local account since last check: $a"
                }
            } else {
                Write-CcdcInitialBaseline -Label 'local accounts' -Items $current.LocalAccounts -BaselineDir $baselineDir
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-LocalUser not available — skipping local account check."
    }

    # -- Suspicious processes (always re-reported, never diffed) --------
    if (Get-Command -Name Get-Process -ErrorAction SilentlyContinue) {
        $procOutcome = Invoke-CcdcSafe -Target 'processes' -Action 'scan for suspicious processes' -ScriptBlock {
            Get-Process -ErrorAction Stop | Where-Object {
                (Test-CcdcSuspiciousPath -Path $_.Path -Patterns $SuspiciousPathPatterns) -or
                ($KnownToolNames -contains $_.ProcessName.ToLowerInvariant())
            } | ForEach-Object {
                $loc = if ($_.Path) { " - $($_.Path)" } else { '' }
                "$($_.ProcessName) (PID $($_.Id))$loc"
            }
        }
        if ($procOutcome.Success) {
            $hits = @($procOutcome.Value)
            if ($hits.Count -gt 0) {
                foreach ($p in $hits) { Write-CcdcLog -Level WARN -Message "Suspicious process: $p" }
            } else {
                Write-CcdcLog -Level OK -Message "No processes matched the suspicious-path / known-tool-name checks."
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-Process not available — skipping process check."
    }

    # -- Listening TCP ports (diffed) ------------------------------------
    if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $portOutcome = Invoke-CcdcSafe -Target 'network' -Action 'list listening TCP ports' -ScriptBlock {
            Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
                $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { 'unknown' }
                "$($_.LocalPort)/tcp ($procName)"
            } | Sort-Object -Unique
        }
        if ($portOutcome.Success) {
            $current.ListeningPorts = @($portOutcome.Value)
            if ($PreviousState) {
                $newPorts = Get-CcdcNewItems -Previous $PreviousState.ListeningPorts -Current $current.ListeningPorts
                foreach ($p in $newPorts) {
                    Write-CcdcLog -Level WARN -Message "New listening port since last check: $p — if that's not a service you just started on purpose, look closer."
                }
            } else {
                Write-CcdcInitialBaseline -Label 'listening TCP ports' -Items $current.ListeningPorts -BaselineDir $baselineDir
            }
            # Always-on, not diffed: a handful of ports are common enough
            # default C2 listeners that they're worth flagging on sight
            # every pass, not just the pass they first appear on.
            foreach ($flagPort in $AlwaysFlagPorts) {
                $hits = @($current.ListeningPorts | Where-Object { $_ -match "^$flagPort/tcp" })
                foreach ($h in $hits) {
                    Write-CcdcLog -Level ERROR -Message "Listening on a known default C2 port: $h — not yours. Investigate now."
                }
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-NetTCPConnection not available — skipping listening-port check."
    }

    # -- Scheduled tasks (diffed) -----------------------------------------
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $taskOutcome = Invoke-CcdcSafe -Target 'scheduled tasks' -Action 'list scheduled tasks' -ScriptBlock {
            Get-ScheduledTask -ErrorAction Stop | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }
        }
        if ($taskOutcome.Success) {
            $current.ScheduledTasks = @($taskOutcome.Value)
            if ($PreviousState) {
                $newTasks = Get-CcdcNewItems -Previous $PreviousState.ScheduledTasks -Current $current.ScheduledTasks
                foreach ($t in $newTasks) {
                    Write-CcdcLog -Level WARN -Message "New scheduled task since last check: $t"
                }
            } else {
                Write-CcdcInitialBaseline -Label 'scheduled tasks' -Items $current.ScheduledTasks -BaselineDir $baselineDir
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-ScheduledTask not available — skipping scheduled-task check."
    }

    # -- Services (diffed, flags a suspicious path on the new ones) -----
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        $svcOutcome = Invoke-CcdcSafe -Target 'services' -Action 'list Windows services' -ScriptBlock {
            Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
                ForEach-Object { [pscustomobject]@{ Name = $_.Name; PathName = $_.PathName } }
        }
        if ($svcOutcome.Success) {
            $svcList = @($svcOutcome.Value)
            $current.Services = @($svcList | ForEach-Object { $_.Name })
            # On a normal pass, only NEWLY-appeared services get the
            # suspicious-path/signature check (an expensive scan to repeat
            # every 10 minutes, and most of a box's normal software lives
            # outside \Windows\ too). On the very first pass there's no
            # "new" to compare against, but skipping the check entirely
            # would mean a service red team planted before this ever ran
            # gets a permanent pass -- so the first pass checks EVERY
            # currently-installed service instead, once, as the tradeoff
            # for that one-time unverified baseline.
            $svcNamesToCheck = if ($PreviousState) {
                Get-CcdcNewItems -Previous $PreviousState.Services -Current $current.Services
            } else {
                $current.Services
            }
            $baselineSvcFindings = New-Object System.Collections.Generic.List[string]
            $baselineSvcFlagged = New-Object System.Collections.Generic.List[string]
            $svcNamesToCheck = @($svcNamesToCheck | Where-Object { $_ })
            if (-not $PreviousState) {
                Write-CcdcLog -Level INFO -Message "First pass: checking the path and signature of all $($svcNamesToCheck.Count) installed services' binaries (this can take a minute)..."
            }
            $haveSigCheck = [bool](Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue)
            foreach ($n in $svcNamesToCheck) {
                $svc = $svcList | Where-Object { $_.Name -eq $n } | Select-Object -First 1
                $flags = New-Object System.Collections.Generic.List[string]
                if (Test-CcdcSuspiciousPath -Path $svc.PathName -Patterns $SuspiciousPathPatterns) { $flags.Add('SUSPICIOUS PATH') }
                # A binary path pulled from a service's PathName can carry
                # arguments after it (e.g. "C:\app\svc.exe -x"), so strip
                # to the executable before checking. This is a plain
                # try/catch rather than Invoke-CcdcSafe on purpose: on the
                # first pass it runs once per installed service (a couple
                # hundred), and Invoke-CcdcSafe would print two log lines
                # and add a scoreboard entry for every one of them.
                if ($svc.PathName -and $haveSigCheck) {
                    $exePath = Get-CcdcServiceExePath -PathName $svc.PathName
                    if ($exePath -and (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) {
                        try {
                            $sigStatus = (Get-AuthenticodeSignature -LiteralPath $exePath -ErrorAction Stop).Status
                            if ($sigStatus -ne 'Valid') { $flags.Add("UNSIGNED/INVALID SIGNATURE ($sigStatus)") }
                        } catch {
                            $flags.Add('SIGNATURE CHECK FAILED')
                        }
                    }
                }
                $flagText = if ($flags.Count -gt 0) { " [$($flags -join ', ')]" } else { '' }
                $loc = if ($svc.PathName) { " - $($svc.PathName)" } else { '' }
                if ($PreviousState) {
                    Write-CcdcLog -Level WARN -Message "New service since last check: $n$flagText$loc"
                } else {
                    $baselineSvcFindings.Add("$n$flagText$loc")
                    if ($flags.Count -gt 0) { $baselineSvcFlagged.Add("$n$flagText$loc") }
                }
            }
            if (-not $PreviousState) {
                Write-CcdcInitialBaseline -Label 'services' -Items $baselineSvcFindings -BaselineDir $baselineDir -Highlight $baselineSvcFlagged.ToArray()
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-CimInstance not available — skipping service check."
    }

    # -- Registry Run/RunOnce persistence (diffed) ------------------------
    # A classic, specifically named persistence spot (per an ATCC coach's
    # field manual's own Windows hunt-loop command:
    # reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run).
    # Test-Path on an HKLM:/HKCU: path returns $false (not a throw) on a
    # box where that key/hive doesn't exist, so this degrades safely on
    # its own without needing a separate "is this Windows" guard.
    if (Get-Command -Name Get-ItemProperty -ErrorAction SilentlyContinue) {
        $runKeyOutcome = Invoke-CcdcSafe -Target 'registry Run keys' -Action 'list Run/RunOnce persistence entries' -ScriptBlock {
            $regPaths = @(
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
            )
            $found = New-Object System.Collections.Generic.List[string]
            foreach ($regPath in $regPaths) {
                if (Test-Path -Path $regPath -ErrorAction SilentlyContinue) {
                    $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($props) {
                        foreach ($prop in $props.PSObject.Properties) {
                            # Skip PowerShell's own bookkeeping properties
                            # (PSPath, PSParentPath, etc.) — not real values.
                            if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$') {
                                $found.Add("$regPath\$($prop.Name) = $($prop.Value)")
                            }
                        }
                    }
                }
            }
            return $found
        }
        if ($runKeyOutcome.Success) {
            $current.RunKeyEntries = @($runKeyOutcome.Value)
            if ($PreviousState) {
                $newEntries = Get-CcdcNewItems -Previous $PreviousState.RunKeyEntries -Current $current.RunKeyEntries
                foreach ($e in $newEntries) {
                    Write-CcdcLog -Level WARN -Message "New Run-key persistence entry since last check: $e"
                }
            } else {
                Write-CcdcInitialBaseline -Label 'registry Run-key persistence entries' -Items $current.RunKeyEntries -BaselineDir $baselineDir
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-ItemProperty not available — skipping Run-key persistence check."
    }

    # -- Startup folders (diffed) -----------------------------------------
    # The Run keys above are only half of the autostart story; anything
    # dropped in a Startup folder runs at logon without touching the
    # registry at all.
    $startupOutcome = Invoke-CcdcSafe -Target 'Startup folders' -Action 'list startup items' -ScriptBlock {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($sf in @(
                (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),
                (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
            )) {
            if (-not (Test-Path -LiteralPath $sf)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $sf -File -Force -ErrorAction SilentlyContinue)) {
                $found.Add("$($f.FullName) (modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))")
            }
        }
        return $found
    }
    if ($startupOutcome.Success) {
        $current.StartupFolderItems = @($startupOutcome.Value)
        if ($PreviousState) {
            foreach ($e in (Get-CcdcNewItems -Previous $PreviousState.StartupFolderItems -Current $current.StartupFolderItems)) {
                Write-CcdcLog -Level WARN -Message "New or changed Startup folder item since last check: $e"
            }
        } else {
            Write-CcdcInitialBaseline -Label 'Startup folder items' -Items $current.StartupFolderItems -BaselineDir $baselineDir
        }
    }

    # -- WMI event subscriptions (diffed) ---------------------------------
    # Fileless persistence: a filter (when to fire) bound to a consumer
    # (what to run), both living in the WMI repository. Nothing appears in
    # Run keys, services or scheduled tasks, so a check that covers only
    # those misses it entirely. A clean Windows box normally has NO
    # subscriptions outside the BVTFilter/SCM defaults, which is what
    # makes this worth looking at: almost anything here is worth reading.
    if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
        $wmiOutcome = Invoke-CcdcSafe -Target 'WMI event subscriptions' -Action 'list filters, consumers and bindings' -ScriptBlock {
            $found = New-Object System.Collections.Generic.List[string]
            foreach ($f in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue)) {
                $found.Add("Filter: $($f.Name) -> $($f.Query)")
            }
            foreach ($c in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue)) {
                # CommandLineTemplate / ScriptText are where the payload
                # lives, and only exist on the consumer subclasses that
                # actually run something.
                $what = ''
                if ($c.PSObject.Properties['CommandLineTemplate']) { $what = $c.CommandLineTemplate }
                elseif ($c.PSObject.Properties['ScriptText']) { $what = $c.ScriptText }
                elseif ($c.PSObject.Properties['ExecutablePath']) { $what = $c.ExecutablePath }
                $found.Add("Consumer: $($c.Name) [$($c.CimClass.CimClassName)] -> $what")
            }
            foreach ($b in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)) {
                $found.Add("Binding: $($b.Filter) => $($b.Consumer)")
            }
            return $found
        }
        if ($wmiOutcome.Success) {
            $current.WmiSubscriptions = @($wmiOutcome.Value)
            if ($PreviousState) {
                foreach ($e in (Get-CcdcNewItems -Previous $PreviousState.WmiSubscriptions -Current $current.WmiSubscriptions)) {
                    Write-CcdcLog -Level ERROR -Message "New WMI event subscription since last check: $e. This is a persistence mechanism that leaves nothing in Run keys, services or scheduled tasks -- read it before removing it."
                }
            } else {
                Write-CcdcInitialBaseline -Label 'WMI event subscriptions' -Items $current.WmiSubscriptions -BaselineDir $baselineDir -Level ERROR
            }
        }
    }

    # -- PowerShell profiles (diffed) -------------------------------------
    # A profile script runs on every PowerShell start, including yours.
    # These files do not exist on a default install, so the presence of
    # one at all is the finding; the hash catches a change to one that is
    # legitimately there.
    $profileOutcome = Invoke-CcdcSafe -Target 'PowerShell profiles' -Action 'check the four profile paths' -ScriptBlock {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($p in @(
                $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost,
                $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost
            )) {
            if (-not $p) { continue }
            if (Test-Path -LiteralPath $p) {
                $h = Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction SilentlyContinue
                $hash = if ($h) { $h.Hash.Substring(0, 16) } else { 'unreadable' }
                $found.Add("$p (sha256 starts $hash)")
            }
        }
        return $found
    }
    if ($profileOutcome.Success) {
        $current.PowerShellProfiles = @($profileOutcome.Value)
        if ($PreviousState) {
            foreach ($e in (Get-CcdcNewItems -Previous $PreviousState.PowerShellProfiles -Current $current.PowerShellProfiles)) {
                Write-CcdcLog -Level ERROR -Message "PowerShell profile appeared or changed since last check: $e. A profile script runs on every PowerShell start, including the ones you open."
            }
        } elseif ($current.PowerShellProfiles.Count -gt 0) {
            Write-CcdcInitialBaseline -Label 'PowerShell profile scripts present' -Items $current.PowerShellProfiles -BaselineDir $baselineDir -Level ERROR
        } else {
            Write-CcdcLog -Level OK -Message "No PowerShell profile scripts exist on this box, which is the default state and the one you want."
        }
    }

    # -- Tampering with the defences themselves (NOT diffed) --------------
    # Reported every pass, regardless of whether it changed, because these
    # are absolute conditions: Windows Update being switched off is bad on
    # pass one and still bad on pass ten, and a diff would mention it once
    # and then go quiet.
    #
    # Every item here comes from a real enumeration log of a previous
    # round rather than from a list of things that sound plausible. The
    # pattern is consistent: red team does not only plant things, it also
    # turns off what would have evicted them.

    # Windows Update left disabled so the box stays exploitable. The
    # enumeration log recorded exactly this: "Scan for updates tasks are
    # disabled". A disabled Microsoft task never appears as a NEW task, so
    # the diff-based checks above cannot see it.
    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $updOutcome = Invoke-CcdcSafe -Target 'Windows Update' -Action 'check that update tasks and the service are not switched off' -ScriptBlock {
            $found = New-Object System.Collections.Generic.List[string]
            foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                        $_.TaskPath -like '\Microsoft\Windows\UpdateOrchestrator\*' -or
                        $_.TaskPath -like '\Microsoft\Windows\WindowsUpdate\*'
                    })) {
                if ($t.State -eq 'Disabled') { $found.Add("task $($t.TaskPath)$($t.TaskName)") }
            }
            foreach ($svcName in 'wuauserv', 'UsoSvc') {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
                if ($svc -and $svc.StartMode -eq 'Disabled') { $found.Add("service $svcName is Disabled") }
            }
            return $found
        }
        if ($updOutcome.Success) {
            $disabled = @($updOutcome.Value)
            if ($disabled.Count -gt 0) {
                Write-CcdcLog -Level ERROR -Message "Windows Update has been switched off here ($($disabled.Count) item(s)): $($disabled -join '; '). Nobody disables patching by accident -- this keeps the box exploitable, and it is how a previous round's web server was left."
            } else {
                Write-CcdcLog -Level OK -Message "Windows Update tasks and services are not disabled."
            }
        }
    }

    # Defender turned off, or told to ignore a folder. An exclusion is the
    # quieter move: everything still looks healthy while one directory is
    # a free-fire zone.
    if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
        $defOutcome = Invoke-CcdcSafe -Target 'Microsoft Defender' -Action 'check for disabled protection and exclusions' -ScriptBlock {
            $notes = New-Object System.Collections.Generic.List[string]
            $pref = Get-MpPreference -ErrorAction Stop
            if ($pref.DisableRealtimeMonitoring) { $notes.Add('real-time monitoring is OFF') }
            if ($pref.DisableBehaviorMonitoring) { $notes.Add('behaviour monitoring is OFF') }
            if ($pref.DisableScriptScanning) { $notes.Add('script scanning is OFF') }

            # Unelevated, Get-MpPreference does not fail -- it returns the
            # STRING "N/A: Must be an administrator to view exclusions" in
            # each exclusion property. Taken at face value that reads as
            # three exclusions and fires a red alert on every non-elevated
            # run. A threat hunt that cries wolf gets ignored, so an
            # unreadable value is reported as unreadable.
            $blocked = $false
            foreach ($pair in @(
                    @{ Label = 'path'; Values = $pref.ExclusionPath },
                    @{ Label = 'process'; Values = $pref.ExclusionProcess },
                    @{ Label = 'extension'; Values = $pref.ExclusionExtension })) {
                foreach ($p in @($pair.Values)) {
                    if (-not $p) { continue }
                    if ("$p" -match '^N/A:' -or "$p" -match 'Must be an administrator') { $blocked = $true; continue }
                    $notes.Add("$($pair.Label) exclusion: $p")
                }
            }
            if ($blocked) { $notes.Add('@@UNREADABLE@@') }
            return $notes
        }
        if ($defOutcome.Success) {
            $all = @($defOutcome.Value)
            $unreadable = ($all -contains '@@UNREADABLE@@')
            $notes = @($all | Where-Object { $_ -ne '@@UNREADABLE@@' })
            if ($notes.Count -gt 0) {
                Write-CcdcLog -Level ERROR -Message "Microsoft Defender has been weakened here: $($notes -join '; '). An exclusion you did not add is somebody telling the antivirus where not to look."
            } elseif ($unreadable) {
                Write-CcdcLog -Level WARN -Message "Defender's protection switches look on, but its EXCLUSION list could not be read without elevation -- that part is untested, not clean. Re-run elevated to see it."
            } else {
                Write-CcdcLog -Level OK -Message "Defender's protections are on and no exclusions are configured."
            }
        }
    }

    # OpenSSH on Windows. A previous round's Server 2022 had an SSH agent
    # running on it, which is not something a Windows file server needs and
    # is a tidy way back in that nothing else on this box would flag.
    $sshOutcome = Invoke-CcdcSafe -Target 'OpenSSH' -Action 'check for an SSH server on a Windows box' -ScriptBlock {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($n in 'sshd', 'ssh-agent') {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
            if ($svc) { $found.Add("$n is installed (state $($svc.State), start $($svc.StartMode))") }
        }
        return $found
    }
    if ($sshOutcome.Success) {
        $ssh = @($sshOutcome.Value)
        if ($ssh.Count -gt 0) {
            Write-CcdcLog -Level WARN -Message "OpenSSH is present on this Windows box: $($ssh -join '; '). If your team did not put it there, it is remote access nobody asked for -- find out which before removing it."
        }
    }

    # A cleared Security log is not a configuration state, it is an event,
    # and it is the one an attacker generates on the way out.
    $clearOutcome = Invoke-CcdcSafe -Target 'Security log' -Action 'check whether the event log has been cleared' -ScriptBlock {
        @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 5 -ErrorAction SilentlyContinue |
                ForEach-Object { "cleared at $($_.TimeCreated)" })
    }
    if ($clearOutcome.Success) {
        $cleared = @($clearOutcome.Value)
        if ($cleared.Count -gt 0) {
            Write-CcdcLog -Level ERROR -Message "The Security event log has been CLEARED ($($cleared -join '; ')). That is event 1102, and it is deliberate -- treat everything before that timestamp as unavailable and say so in the incident report."
        }
    }

    # -- GPO modification times (diffed) ----------------------------------
    # A changed GPO can be a persistence mechanism, per an ATCC coach's
    # field manual's own AD-audit advice. Diffing on "name + mod time" as
    # one combined string means any change to an EXISTING GPO's mod time
    # shows up as a "new" entry too, not just brand-new GPOs.
    if (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue) {
        $gpoOutcome = Invoke-CcdcSafe -Target 'GPOs' -Action 'list GPO modification times' -ScriptBlock {
            Get-GPO -All -ErrorAction Stop | ForEach-Object {
                "$($_.DisplayName) @ $($_.ModificationTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
        }
        if ($gpoOutcome.Success) {
            $current.GpoModTimes = @($gpoOutcome.Value)
            if ($PreviousState) {
                $newGpoStates = Get-CcdcNewItems -Previous $PreviousState.GpoModTimes -Current $current.GpoModTimes
                foreach ($g in $newGpoStates) {
                    Write-CcdcLog -Level WARN -Message "GPO created or modified since last check: $g"
                }
            } else {
                Write-CcdcInitialBaseline -Label 'GPOs (name + modification time)' -Items $current.GpoModTimes -BaselineDir $baselineDir
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-GPO not available — skipping GPO modification-time check (needs the GroupPolicy module)."
    }

    # -- DNS records (diffed) ----------------------------------------------
    # Auto-detects the domain zone via Get-ADDomain rather than prompting
    # for one, to keep this module's "zero answer-file setup" property —
    # skips cleanly if not domain-joined or the DnsServer module (only on
    # a box with the DNS Server role) isn't present.
    if ((Get-Command -Name Get-DnsServerResourceRecord -ErrorAction SilentlyContinue) -and
        (Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue)) {
        $dnsOutcome = Invoke-CcdcSafe -Target 'DNS records' -Action 'list DNS zone records' -ScriptBlock {
            $zoneName = (Get-ADDomain -ErrorAction Stop).DNSRoot
            Get-DnsServerResourceRecord -ZoneName $zoneName -ErrorAction Stop | ForEach-Object {
                # RecordData.ToString() returns the CIM class name, never
                # what the record points at -- see Get-CcdcDnsRecordDataText.
                $dataStr = Get-CcdcDnsRecordDataText -RecordData $_.RecordData
                "$($_.HostName) $($_.RecordType) $dataStr"
            }
        }
        if ($dnsOutcome.Success) {
            $current.DnsRecords = @($dnsOutcome.Value)
            if ($PreviousState) {
                $newRecords = Get-CcdcNewItems -Previous $PreviousState.DnsRecords -Current $current.DnsRecords
                foreach ($r in $newRecords) {
                    Write-CcdcLog -Level WARN -Message "DNS record added or changed since last check: $r"
                }
            } else {
                Write-CcdcInitialBaseline -Label 'DNS zone records' -Items $current.DnsRecords -BaselineDir $baselineDir
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-DnsServerResourceRecord or Get-ADDomain not available — skipping DNS record check (needs the DnsServer module, usually only present on a DNS server)."
    }

    # -- Recently dropped/modified files in common staging locations ----
    $rootsToScan = @(
        $env:TEMP,
        $(if ($env:SystemRoot) { Join-Path $env:SystemRoot 'Temp' }),
        $(if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Downloads' }),
        'C:\Users\Public'
    ) | Where-Object { $_ -and (Test-Path -Path $_ -ErrorAction SilentlyContinue) } | Select-Object -Unique

    if ($rootsToScan.Count -gt 0) {
        $fileOutcome = Invoke-CcdcSafe -Target 'filesystem' -Action 'scan for recently dropped files' -ScriptBlock {
            $localSince = $SinceUtc.ToLocalTime()
            $found = New-Object System.Collections.Generic.List[string]
            foreach ($root in $rootsToScan) {
                Get-ChildItem -Path $root -File -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                    Where-Object { $_.CreationTime -gt $localSince -or $_.LastWriteTime -gt $localSince } |
                    Select-Object -First 20 |
                    ForEach-Object { $found.Add($_.FullName) }
            }
            return $found
        }
        if ($fileOutcome.Success) {
            $files = @($fileOutcome.Value)
            foreach ($f in ($files | Select-Object -First 20)) {
                Write-CcdcLog -Level WARN -Message "Recently dropped/modified file: $f"
            }
            if ($files.Count -gt 20) {
                Write-CcdcLog -Level WARN -Message "...and $($files.Count - 20) more (truncated for readability — check $($rootsToScan -join ', ') directly for the full list)."
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "No common staging locations (Temp/Downloads/Public) found to scan on this box."
    }

    # -- Event log summary (best-effort; needs logon auditing enabled) --
    if (Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue) {
        $logOutcome = Invoke-CcdcSafe -Target 'Security log' -Action 'summarize recent logon activity' -ScriptBlock {
            $localSince = $SinceUtc.ToLocalTime()
            $failed = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $localSince } -ErrorAction SilentlyContinue)
            $success = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $localSince } -ErrorAction SilentlyContinue)
            [pscustomobject]@{ FailedCount = $failed.Count; SuccessCount = $success.Count }
        }
        if ($logOutcome.Success -and $logOutcome.Value) {
            $r = $logOutcome.Value
            if ($r.FailedCount -gt 0) {
                Write-CcdcLog -Level WARN -Message "$($r.FailedCount) failed logon attempt(s) (event 4625) since last check."
            }
            Write-CcdcLog -Level INFO -Message "$($r.SuccessCount) successful logon(s) (event 4624) since last check."
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Get-WinEvent not available — skipping Security log summary."
    }

    return $current
}

# ---------------------------------------------------------------------------
# Load previous state, run pass(es), save state.
# ---------------------------------------------------------------------------
function Get-CcdcPreviousState {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { return $null }
    try {
        return Get-Content -Path $Path -Raw | ConvertFrom-Json
    } catch {
        Write-CcdcLog -Level WARN -Message "Found $Path but couldn't parse it ($($_.Exception.Message)) — treating this as a fresh baseline."
        return $null
    }
}

function Save-CcdcState {
    param($State, [string]$Path)
    try {
        $State | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
    } catch {
        Write-CcdcLog -Level WARN -Message "Couldn't save threat-hunt state to $Path ($($_.Exception.Message)) — next pass will re-baseline instead of diffing against this one."
    }
}

try {
    if ($Continuous) {
        Write-CcdcLog -Level INFO -Message "Continuous mode: one pass every $IntervalMinutes minute(s). Ctrl+C to stop."
        $previousState = Get-CcdcPreviousState -Path $statePath
        while ($true) {
            $sinceUtc = if ($previousState) { [datetime]$previousState.RunUtc } else { (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes) }
            if (-not $previousState) {
                Write-CcdcLog -Level WARN -Message "No previous scan found — this pass establishes a baseline. That does NOT mean the box is assumed clean: everything diff-based checks find gets dumped below as an unverified first look (don't assume red team wasn't already here before this ran), and the NEXT pass onward will only show what's changed since."
            }
            $currentState = Invoke-HuntPass -PreviousState $previousState -SinceUtc $sinceUtc
            Save-CcdcState -State $currentState -Path $statePath
            $previousState = $currentState
            Show-CcdcSummary
            Start-Sleep -Seconds ($IntervalMinutes * 60)
        }
    } else {
        $previousState = Get-CcdcPreviousState -Path $statePath
        $sinceUtc = if ($previousState) { [datetime]$previousState.RunUtc } else { (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes) }
        if (-not $previousState) {
            Write-CcdcLog -Level WARN -Message "No previous scan found — this pass establishes a baseline (and checks the last $LookbackMinutes minute(s) for new accounts/files/logons). That does NOT mean the box is assumed clean: everything diff-based checks find (admins, ports, tasks, services, Run keys, GPOs, DNS) gets dumped below as an unverified first look — don't assume red team wasn't already here before this ran. Run this again later to start seeing what's actually changed."
        }
        $currentState = Invoke-HuntPass -PreviousState $previousState -SinceUtc $sinceUtc
        Save-CcdcState -State $currentState -Path $statePath
        Show-CcdcSummary
    }
} finally {
    Stop-CcdcSession
}
