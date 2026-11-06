#Requires -Version 5.1
<#
.SYNOPSIS
    Bundles the evidence that's actually hard to reconstruct later into one
    timestamped folder: recent Security/System/Sysmon event logs, a live
    TCP connection snapshot, and the Splunk Universal Forwarder's own local
    logs (if it's installed here) — so a box can be scrubbed, rebuilt, or
    handed off without losing what it had seen.

.DESCRIPTION
    There is no snapshot/revert during the round, and Splunk itself is a
    separate box someone else administers — if THIS host gets scrubbed, or
    the forwarder stops shipping and nobody notices for a while, whatever
    this host's own logs knew goes with it unless it was pulled off first.
    This does that pull: a read-only, point-in-time export of what this one
    host currently has, written to logs\evidence\<host>_<timestamp>\
    (gitignored, same as everything else under logs\) so it survives the
    host being rebuilt and is ready to hand off (the team packet requires
    data/log deliverables go out through the team's NextCloud).

    Three things get collected, each independently best-effort — one
    failing (e.g. Sysmon not installed) does not stop the others:

      Event logs    Security, System, and Microsoft-Windows-Sysmon/
                    Operational if present, each exported natively as
                    .evtx (wevtutil, filtered to the last -HoursBack) so
                    they open straight in Event Viewer on another machine —
                    not reconstructed from a text dump, which loses fields.
      TCP snapshot  Every current TCP connection, joined with the owning
                    process name, as a CSV. Not a packet capture (see
                    Invoke-PacketCapture.ps1 for that) — this is "what was
                    this host talking to RIGHT NOW," useful on its own and
                    useful to tell a capture where to point.
      Splunk logs   splunkd.log and metrics.log from the Universal
                    Forwarder's own install here, if one is installed — the
                    fastest way to tell whether the forwarder itself is
                    healthy and actually shipping, separately from whether
                    the indexer received anything.

    New-IncidentReport.ps1 automatically looks here too, the same way it
    already looks at session logs, state backups and packet captures, so
    an evidence pull taken near an incident shows up without being
    attached by hand.

.PARAMETER HoursBack
    How far back to export event logs from. Default 4.

.PARAMETER Hostname
    Label used in the output folder name. Defaults to the current computer
    name.

.PARAMETER Zip
    Also produce a single .zip alongside the folder — convenient for a
    one-file upload/hand-off. Off by default; the folder itself is already
    fine to hand off as-is.

.EXAMPLE
    .\Invoke-EvidenceCollection.ps1
    Pulls the last 4 hours of event logs, a TCP snapshot, and Splunk's own
    logs if present.

.EXAMPLE
    .\Invoke-EvidenceCollection.ps1 -HoursBack 12 -Zip
    Wider window, plus a .zip ready to upload.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 168)]
    [int]$HoursBack = 4,
    [string]$Hostname = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { (hostname) }),
    [switch]$Zip
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Evidence collection starting -- read-only, nothing on this host changes. Pulling the last $HoursBack hour(s) of event logs, a live TCP snapshot, and the Splunk forwarder's own logs if it's here."
Assert-CcdcElevated -Because "reading the Security event log needs admin rights (or Event Log Readers membership)"

try {

$safeHost = ($Hostname -replace '[^a-zA-Z0-9_\-]', '_')
$fileStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$evidenceDir = Join-Path (Join-Path $session.LogRoot 'evidence') "$safeHost`_$fileStamp"
if ($PSCmdlet.ShouldProcess($evidenceDir, 'Create evidence folder and collect into it')) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
} else {
    Write-CcdcLog -Level INFO -Message "-WhatIf: would create $evidenceDir and collect into it."
}

# ---------------------------------------------------------------------------
# Event logs — native .evtx export, filtered to the time window, so they
# open directly in Event Viewer elsewhere rather than being reconstructed
# from a text dump that drops fields.
# ---------------------------------------------------------------------------
$msBack = [int64]$HoursBack * 3600000
$timeQuery = "*[System[TimeCreated[timediff(@SystemTime) <= $msBack]]]"
$logsToExport = @('Security', 'System')
if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) {
    $logsToExport += 'Microsoft-Windows-Sysmon/Operational'
}

foreach ($logName in $logsToExport) {
    $safeLogName = ($logName -replace '[\\/]', '_')
    $outPath = Join-Path $evidenceDir "$safeLogName.evtx"
    if ($PSCmdlet.ShouldProcess($logName, "Export last $HoursBack hour(s) to $outPath")) {
        $exportOutcome = Invoke-CcdcSafe -Target $logName -Action "export event log (last $HoursBack hour(s))" -ScriptBlock {
            $wevtutilArgs = @('epl', $logName, $outPath, "/q:$timeQuery", '/ow:true')
            & wevtutil.exe @wevtutilArgs 2>&1
            if ($LASTEXITCODE -ne 0) { throw "wevtutil exited ${LASTEXITCODE}: $($wevtutilArgs -join ' ')" }
        }
        if ($exportOutcome.Success -and (Test-Path -LiteralPath $outPath)) {
            $count = (Get-Item -LiteralPath $outPath).Length
            Write-CcdcLog -Level OK -Message "$logName -> $outPath ($([math]::Round($count / 1KB, 1)) KB)."
        }
    }
}

# ---------------------------------------------------------------------------
# TCP connection snapshot — what this host is talking to right now, with
# the owning process name, not just the PID.
# ---------------------------------------------------------------------------
$tcpPath = Join-Path $evidenceDir 'tcp-connections.csv'
if ($PSCmdlet.ShouldProcess('TCP connections', "Snapshot to $tcpPath")) {
    $tcpOutcome = Invoke-CcdcSafe -Target 'TCP connections' -Action 'snapshot live TCP connections' -ScriptBlock {
        $procNames = @{}
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procNames[$p.Id] = $p.ProcessName }
        Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = $_.State
                ProcessId     = $_.OwningProcess
                ProcessName   = $procNames[[int]$_.OwningProcess]
            }
        }
    }
    if ($tcpOutcome.Success) {
        $rows = @($tcpOutcome.Value)
        $rows | Export-Csv -Path $tcpPath -NoTypeInformation
        Write-CcdcLog -Level OK -Message "TCP snapshot -> $tcpPath ($($rows.Count) connection(s))."
    }
}

# ---------------------------------------------------------------------------
# Splunk Universal Forwarder's own logs, if installed here. Graceful no-op
# if it isn't -- this box may simply not be the one running it.
# ---------------------------------------------------------------------------
$splunkLogDir = Join-Path ${env:ProgramFiles} 'SplunkUniversalForwarder\var\log\splunk'
if (Test-Path -LiteralPath $splunkLogDir) {
    $splunkOutDir = Join-Path $evidenceDir 'splunk'
    $wanted = @('splunkd.log', 'metrics.log')
    $copied = 0
    foreach ($name in $wanted) {
        $src = Join-Path $splunkLogDir $name
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if ($PSCmdlet.ShouldProcess($src, "Copy to $splunkOutDir")) {
            if (-not (Test-Path -LiteralPath $splunkOutDir)) { New-Item -ItemType Directory -Path $splunkOutDir -Force | Out-Null }
            $copyOutcome = Invoke-CcdcSafe -Target $src -Action 'copy Splunk forwarder log' -ScriptBlock {
                Copy-Item -LiteralPath $src -Destination (Join-Path $splunkOutDir $name) -Force -ErrorAction Stop
            }
            if ($copyOutcome.Success) { $copied++ }
        }
    }
    if ($copied -gt 0) {
        Write-CcdcLog -Level OK -Message "Splunk forwarder's own logs ($copied file(s)) -> $splunkOutDir. splunkd.log's last lines are the fastest way to tell whether it's actually shipping -- look for repeated connection/SSL errors to the indexer."
    } else {
        Write-CcdcLog -Level INFO -Message "Splunk Universal Forwarder is installed here, but neither splunkd.log nor metrics.log was found at $splunkLogDir -- nothing to copy."
    }
} else {
    Write-CcdcLog -Level INFO -Message "No Splunk Universal Forwarder found at $splunkLogDir -- not installed on this host, nothing to collect."
}

# ---------------------------------------------------------------------------
# Optional zip for a one-file hand-off.
# ---------------------------------------------------------------------------
if ($Zip -and (Test-Path -LiteralPath $evidenceDir)) {
    $zipPath = "$evidenceDir.zip"
    if ($PSCmdlet.ShouldProcess($evidenceDir, "Compress to $zipPath")) {
        $zipOutcome = Invoke-CcdcSafe -Target $evidenceDir -Action 'compress evidence folder' -ScriptBlock {
            Compress-Archive -Path (Join-Path $evidenceDir '*') -DestinationPath $zipPath -Force -ErrorAction Stop
        }
        if ($zipOutcome.Success) { Write-CcdcLog -Level OK -Message "Zipped -> $zipPath" }
    }
}

Write-CcdcLog -Level OK -Message "Evidence collection done: $evidenceDir"

} finally {
    Show-CcdcSummary
    Stop-CcdcSession
}
