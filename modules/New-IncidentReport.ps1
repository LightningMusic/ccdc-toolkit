#Requires -Version 5.1
<#
.SYNOPSIS
    Walks you through an incident report containing every field the
    competition actually requires, pulls in whatever evidence this
    toolkit's own logs already hold for that time window, and writes it
    out as both Markdown and a print-ready business memo you can turn
    into the PDF the scoring portal demands.

.DESCRIPTION
    Incident reports are 10-20% of the total score, and they are how you
    get points back after red team gets in. Two documents define what one
    has to contain, and this asks for all of it:

      The team packet: "Incident reports must contain a description of
      what occurred (including source and destination IP addresses,
      timelines of activity, passwords cracked, etc), a discussion of what
      was affected, and a remediation plan." Scored on clarity,
      thoroughness and accuracy.

      The incident-reporting inject: a clear description; the scope (how
      many systems, applications and services were impacted); the time
      window and sequence; identification of the source; the delivery
      mechanism; damage or monetary impact; remediation methods; and
      supporting evidence. Timeliness of reporting is itself a factor.

    Two more rules from the packet shape the output:

      REPORT EXPLOITATION, NOT MISCONFIGURATION. A finding that a service
      was configured badly is not an incident. Reports are explicitly
      scored on exploitation events, and the packet warns that frivolous,
      unnecessary or excessive communication can be scored NEGATIVELY. If
      nothing was exploited, do not file.

      WRITE IT AS A BUSINESS MEMO. Inject guidance is explicit that the
      reader is management, not an engineer, that business form and
      content are part of the score, and that a judge reading many reports
      rewards one that surfaces the key facts immediately.

    NOTE ON AI, WHICH IS NOT A SIDE ISSUE: the competition's own inject
    guidance states that using AI tools to generate inject responses
    results in ZERO POINTS. This module is a form and a formatter. It
    prompts you, records what you type, attaches evidence this toolkit
    logged, and lays it out. It does not write your report, and you should
    not let anything else write it either.

    WHAT IT GATHERS FOR YOU
    Given roughly when the incident happened, it searches this session's
    transcripts for WARN/ERROR/ACTION lines in a window around that time,
    lists state backups (Backup-CcdcState snapshots) from the same window,
    lists packet captures from around then too, and lists evidence pulls
    (Invoke-EvidenceCollection.ps1's event logs/TCP snapshot/Splunk logs)
    from around then as well. Running Invoke-ThreatHunt.ps1 or
    Invoke-ConfigBaseline.ps1 -Action Verify first gives it materially
    more to find.

    OUTPUT
      logs\incident-reports\<host>_<stamp>.md    working copy, easy to edit
      logs\incident-reports\<host>_<stamp>.html  print-ready memo

    Turn the HTML into the required PDF with prep\ConvertTo-Pdf.ps1, or by
    opening it in a browser and printing to PDF. The HTML is styled for
    paper: the on-screen colours drop out and it prints on letter/A4
    without a horizontal scrollbar.

.PARAMETER Hostname
    Which host this incident is about. Defaults to the current computer.

.PARAMETER IncidentTime
    When the incident happened (or was first noticed). Centres the
    evidence search. Defaults to now.

.PARAMETER EvidenceWindowMinutes
    How far either side of -IncidentTime to search. Default 30.

.PARAMETER TeamNumber
    Your team number, for the memo header. Read from the answer file key
    TeamNumber if present.

.PARAMETER Author
    Who is signing the memo. Read from the answer file key ReportAuthor.

.EXAMPLE
    .\New-IncidentReport.ps1
    Walks through every required field using "now" as the incident time.

.EXAMPLE
    .\New-IncidentReport.ps1 -Hostname WEB01 -IncidentTime "14:32"
    Centres the automatic evidence search on 14:32 today for WEB01.
#>
[CmdletBinding()]
param(
    [string]$Hostname = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { (hostname) }),
    [datetime]$IncidentTime = (Get-Date),
    [int]$EvidenceWindowMinutes = 30,
    [string]$TeamNumber,
    [string]$Author
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Incident report generator starting for '$Hostname' around $($IncidentTime.ToString('yyyy-MM-dd HH:mm:ss'))."

$answers = Import-CcdcAnswers
if (-not $TeamNumber -and $answers -and $answers.ContainsKey('TeamNumber')) { $TeamNumber = [string]$answers['TeamNumber'] }
if (-not $Author -and $answers -and $answers.ContainsKey('ReportAuthor')) { $Author = [string]$answers['ReportAuthor'] }

# ---------------------------------------------------------------------------
# Auto-gather: session log lines, backups, captures and evidence pulls near
# the incident time.
# The pure time-window matching lives in modules\CcdcLogic.ps1.
# ---------------------------------------------------------------------------

$autoEvidence = New-Object System.Collections.Generic.List[string]

$logFilesOutcome = Invoke-CcdcSafe -Target 'logs' -Action 'search session logs for evidence near the incident time' -ScriptBlock {
    $files = Get-ChildItem -Path $session.LogRoot -Filter 'session_*.log' -File -ErrorAction SilentlyContinue
    $results = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        if ($f.BaseName -match 'session_(?<date>\d{4}-\d{2}-\d{2})_\d{6}') {
            $fileDate = [datetime]::ParseExact($Matches.date, 'yyyy-MM-dd', $null)
            $lines = Get-Content -Path $f.FullName -ErrorAction SilentlyContinue
            $near = Get-CcdcLogLinesNearTime -Lines $lines -FileDate $fileDate -CenterTime $IncidentTime -WindowMinutes $EvidenceWindowMinutes
            foreach ($l in $near) { $results.Add($l) }
        }
    }
    return $results
}
if ($logFilesOutcome.Success) {
    foreach ($l in @($logFilesOutcome.Value)) { $autoEvidence.Add($l) }
}

$backupHits = @()
$backupRootOutcome = Invoke-CcdcSafe -Target 'backups' -Action 'find state backups near the incident time' -ScriptBlock {
    $backupRoot = Join-Path $session.LogRoot 'backups'
    if (-not (Test-Path -Path $backupRoot)) { return @() }
    $names = Get-ChildItem -Path $backupRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    Get-CcdcBackupFoldersNearTime -FolderNames $names -CenterTime $IncidentTime -WindowMinutes $EvidenceWindowMinutes
}
if ($backupRootOutcome.Success) { $backupHits = @($backupRootOutcome.Value) }

$captureHits = @()
$captureRootOutcome = Invoke-CcdcSafe -Target 'captures' -Action 'find packet captures near the incident time' -ScriptBlock {
    $captureRoot = Join-Path $session.LogRoot 'captures'
    if (-not (Test-Path -Path $captureRoot)) { return @() }
    $names = Get-ChildItem -Path $captureRoot -Filter '*.pcapng' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    Get-CcdcCaptureFilesNearTime -FileNames $names -CenterTime $IncidentTime -WindowMinutes $EvidenceWindowMinutes
}
if ($captureRootOutcome.Success) { $captureHits = @($captureRootOutcome.Value) }

$evidenceHits = @()
$evidenceRootOutcome = Invoke-CcdcSafe -Target 'evidence' -Action 'find evidence-collection pulls near the incident time' -ScriptBlock {
    $evidenceRoot = Join-Path $session.LogRoot 'evidence'
    if (-not (Test-Path -Path $evidenceRoot)) { return @() }
    $names = Get-ChildItem -Path $evidenceRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    Get-CcdcEvidenceFoldersNearTime -FolderNames $names -CenterTime $IncidentTime -WindowMinutes $EvidenceWindowMinutes
}
if ($evidenceRootOutcome.Success) { $evidenceHits = @($evidenceRootOutcome.Value) }

if ($autoEvidence.Count -gt 0) {
    Write-CcdcLog -Level OK -Message "Found $($autoEvidence.Count) log line(s) within $EvidenceWindowMinutes minute(s) of the incident time -- offered below as a starting point."
} else {
    Write-CcdcLog -Level INFO -Message "No matching log lines found in that window -- normal if this is the first thing run today, or if the incident predates this toolkit's logs."
}
if ($backupHits.Count -gt 0) {
    Write-CcdcLog -Level OK -Message "Found $($backupHits.Count) state backup folder(s) from around that time."
}
if ($captureHits.Count -gt 0) {
    Write-CcdcLog -Level OK -Message "Found $($captureHits.Count) packet capture(s) from around that time."
}
if ($evidenceHits.Count -gt 0) {
    Write-CcdcLog -Level OK -Message "Found $($evidenceHits.Count) evidence-collection pull(s) (event logs/TCP snapshot/Splunk logs) from around that time."
}

# ---------------------------------------------------------------------------
# Interactive gather. Fresh one-off operational input, so Read-CcdcInput
# rather than Get-CcdcAnswer (see docs/ARCHITECTURE.md on that distinction).
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "==================== INCIDENT REPORT ====================" -ForegroundColor Cyan
Write-Host "Every field below is named in the team packet or the incident-" -ForegroundColor Cyan
Write-Host "reporting inject as required content. Short and factual beats" -ForegroundColor Cyan
Write-Host "polished -- you can tighten wording before you submit." -ForegroundColor Cyan
Write-Host ""
Write-Host "FILE THIS FOR AN EXPLOITATION EVENT, NOT A MISCONFIGURATION." -ForegroundColor Yellow
Write-Host "The packet scores IRs on exploitation, and says frivolous or" -ForegroundColor Yellow
Write-Host "excessive reporting can be scored NEGATIVELY. If red team did" -ForegroundColor Yellow
Write-Host "not actually do something, close this and fix the config instead." -ForegroundColor Yellow
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

$title = Read-CcdcInput 'One-line subject for the memo (e.g. "Unauthorized administrator account created on WEB01")'

Write-Host ""
Write-Host "-- WHAT HAPPENED --" -ForegroundColor Yellow
$description = Read-CcdcInput 'Clear description of the attack or incident, in plain business language'
$delivery = Read-CcdcInput 'Delivery mechanism -- how did they get in? (stolen credential, web shell upload, unpatched service, existing backdoor...)'

Write-Host ""
Write-Host "-- SCOPE -- how far did it reach?" -ForegroundColor Yellow
$scope = Read-CcdcInput 'Which systems, applications and services were impacted (name them, and say how many)'

Write-Host ""
Write-Host "-- TIMELINE -- the sequence, with times" -ForegroundColor Yellow
Write-Host "Incident time on record: $($IncidentTime.ToString('yyyy-MM-dd HH:mm:ss'))"
$detectedTime = Read-CcdcInput 'When did YOU notice it, if different (blank = same)'
$timeline = Read-CcdcInput 'Sequence of activity: first observed -> what they did -> when contained. Semicolons are fine'

Write-Host ""
Write-Host "-- SOURCE AND DESTINATION -- named in the packet as required" -ForegroundColor Yellow
$sourceIp = Read-CcdcInput 'Source IP address(es) the activity came from'
$destIp = Read-CcdcInput 'Destination IP address(es)/host(s) that were targeted'

Write-Host ""
Write-Host "-- CREDENTIALS -- the packet asks specifically about passwords cracked" -ForegroundColor Yellow
$credsCracked = Read-CcdcInput 'Any passwords cracked or accounts compromised? Name the accounts, never the passwords'
$credsRotated = Read-CcdcInput 'Which credentials did you rotate in response?'

Write-Host ""
Write-Host "-- IMPACT -- damage, downtime, business effect" -ForegroundColor Yellow
$impact = Read-CcdcInput 'Include downtime duration if a scored service was affected, and data exposure if any'

Write-Host ""
Write-Host "-- EVIDENCE --" -ForegroundColor Yellow
if ($autoEvidence.Count -gt 0) {
    Write-Host "Auto-found log lines from around this time (all of them go in the report):"
    foreach ($l in ($autoEvidence | Select-Object -First 10)) { Write-Host "  $l" }
    if ($autoEvidence.Count -gt 10) { Write-Host "  ...and $($autoEvidence.Count - 10) more, included in the file." }
}
$evidence = Read-CcdcInput 'Additional evidence -- event IDs, file paths, screenshots you captured, packet capture names'
$iocs = Read-CcdcInput 'Indicators of compromise -- IPs, filenames, process/account names (comma-separated)'

Write-Host ""
Write-Host "-- REMEDIATION --" -ForegroundColor Yellow
$remArtifact = Read-CcdcInput 'What did you remove or undo? (account, file, task, service -- be specific)'
$remVerified = Read-CcdcInput 'How did you confirm the fix held and the service is back?'

Write-Host ""
Write-Host "-- PREVENTION -- how this vector is closed for good" -ForegroundColor Red
Write-Host "Per an ATCC coach's field manual this section is worth as much as" -ForegroundColor Red
Write-Host "the rest combined -- they WILL try the same way in again." -ForegroundColor Red
$prevention = Read-CcdcInput 'What specifically changed so this exact vector cannot be used again'

# ---------------------------------------------------------------------------
# Completeness check against the required field list.
# ---------------------------------------------------------------------------

$fields = @{
    Description = $description
    Scope       = $scope
    Timeline    = $timeline
    SourceIp    = $sourceIp
    DestIp      = $destIp
    Delivery    = $delivery
    Impact      = $impact
    Evidence    = $(if ($evidence) { $evidence } elseif ($autoEvidence.Count -gt 0) { 'auto-gathered log lines' } else { '' })
    Remediation = $(if ($remArtifact) { $remArtifact } else { $remVerified })
    Prevention  = $prevention
}
$gaps = @(Get-CcdcIncidentReportGap -Fields $fields)
if ($gaps.Count -gt 0) {
    Write-CcdcLog -Level WARN -Message "$($gaps.Count) required field(s) are still blank. Reports are scored on thoroughness, so fill these in before submitting:"
    foreach ($g in $gaps) { Write-CcdcLog -Level WARN -Message "  - $($g.Needs)" }
} else {
    Write-CcdcLog -Level OK -Message "Every required field has something in it."
}
if (-not (Test-CcdcAnyNonBlank -Values @($prevention))) {
    Write-CcdcLog -Level ERROR -Message "Prevention is blank. Per your team's rubric it is worth as much as all the other sections combined -- go back and fill in at least what you actually changed."
}

# ---------------------------------------------------------------------------
# Render. Markdown to work from, HTML to print.
# ---------------------------------------------------------------------------

$reportDir = Join-Path $session.LogRoot 'incident-reports'
if (-not (Test-Path -Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }

$safeHost = ($Hostname -replace '[^a-zA-Z0-9_\-]', '_')
$fileStamp = $IncidentTime.ToString('yyyy-MM-dd_HHmmss')
$stem = Join-Path $reportDir "$safeHost`_$fileStamp"
$counter = 1
while ((Test-Path -Path "$stem.md") -or (Test-Path -Path "$stem.html")) {
    $stem = Join-Path $reportDir "$safeHost`_$fileStamp`_$counter"
    $counter++
}
$reportPath = "$stem.md"
$htmlPath = "$stem.html"

function Get-Field { param([string]$Value, [string]$Placeholder = '[FILL IN BEFORE SUBMITTING]')
    if (Test-CcdcAnyNonBlank -Values @($Value)) { return $Value }
    return $Placeholder
}

$detectedDisplay = if ($detectedTime) { $detectedTime } else { $IncidentTime.ToString('yyyy-MM-dd HH:mm:ss') }
$teamDisplay = if ($TeamNumber) { "Team $TeamNumber" } else { '[team number]' }
$authorDisplay = if ($Author) { $Author } else { '[your name]' }
$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$evidenceLines = New-Object System.Collections.Generic.List[string]
foreach ($l in $autoEvidence) { $evidenceLines.Add($l) }
foreach ($b in $backupHits) { $evidenceLines.Add("State snapshot: logs/backups/$b/") }
foreach ($c in $captureHits) { $evidenceLines.Add("Packet capture: logs/captures/$c") }
foreach ($e in $evidenceHits) { $evidenceLines.Add("Evidence pull (event logs/TCP snapshot/Splunk logs): logs/evidence/$e/") }

$evidenceMd = if ($evidenceLines.Count -gt 0) {
    ($evidenceLines | ForEach-Object { "- ``$_``" }) -join "`n"
} else {
    '- [FILL IN: no evidence was auto-gathered for this window]'
}

$md = @"
# Incident Report -- $(Get-Field $title '[subject]')

**To:** CIO Management Team
**From:** $teamDisplay
**Prepared by:** $authorDisplay
**Date:** $generated
**Affected host:** $Hostname

## Summary

$(Get-Field $description)

## Scope

$(Get-Field $scope)

## Timeline and sequence

- Incident time: $($IncidentTime.ToString('yyyy-MM-dd HH:mm:ss'))
- Detected: $detectedDisplay
- Sequence: $(Get-Field $timeline)

## Source and destination

- Source IP(s): $(Get-Field $sourceIp)
- Destination IP(s)/host(s): $(Get-Field $destIp)

## Delivery mechanism

$(Get-Field $delivery)

## Credentials

- Passwords cracked / accounts compromised: $(Get-Field $credsCracked '[none identified]')
- Credentials rotated in response: $(Get-Field $credsRotated)

## Damage and impact

$(Get-Field $impact)

## Supporting evidence

$evidenceMd

**Additional evidence:** $(Get-Field $evidence '[none beyond the above]')

**Indicators of compromise:** $(Get-Field $iocs '[none identified yet]')

## Remediation

- Removed / undone: $(Get-Field $remArtifact)
- Fix verified by: $(Get-Field $remVerified)

## Prevention

*Worth as much as the rest of the report combined -- be specific about what is closed for good, not just what was cleaned up.*

$(Get-Field $prevention)
"@

$writeOutcome = Invoke-CcdcSafe -Target $reportPath -Action 'write incident report (Markdown)' -ScriptBlock {
    $md | Set-Content -Path $reportPath -Encoding UTF8 -ErrorAction Stop
}
if ($writeOutcome.Success) { Write-CcdcLog -Level OK -Message "Markdown written: $reportPath" }

# --- HTML memo -------------------------------------------------------------
# Every interpolated value goes through ConvertTo-CcdcHtmlText: an incident
# report quotes attacker-controlled strings by definition, and a filename
# containing a tag should render as text, not as markup.

function Get-HtmlPara { param([string]$Value, [string]$Placeholder = '[FILL IN BEFORE SUBMITTING]')
    $text = Get-Field -Value $Value -Placeholder $Placeholder
    $escaped = ConvertTo-CcdcHtmlText -Text $text
    return '<p>' + $escaped + '</p>'
}

$evidenceHtml = if ($evidenceLines.Count -gt 0) {
    ($evidenceLines | ForEach-Object { '<li><code>' + (ConvertTo-CcdcHtmlText -Text $_) + '</code></li>' }) -join "`n"
} else {
    '<li>[FILL IN: no evidence was auto-gathered for this window]</li>'
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Incident Report - $(ConvertTo-CcdcHtmlText -Text (Get-Field $title '[subject]'))</title>
<style>
  /* Deliberately plain. This is read by a judge, on paper or as a PDF,
     alongside many others. Nothing here is decorative. */
  body { font-family: Georgia, 'Times New Roman', serif; font-size: 11pt;
         line-height: 1.45; color: #111; max-width: 7.2in; margin: 0.6in auto;
         padding: 0 16px; }
  h1 { font-size: 16pt; margin: 0 0 4px 0; }
  h2 { font-size: 12pt; margin: 20px 0 6px 0; border-bottom: 1px solid #999;
       padding-bottom: 3px; }
  .memo-head { border: 1px solid #333; padding: 10px 12px; margin-bottom: 18px; }
  .memo-head div { margin: 2px 0; }
  .label { display: inline-block; min-width: 110px; font-weight: bold; }
  code { font-family: Consolas, 'Courier New', monospace; font-size: 9.5pt;
         word-break: break-all; }
  ul { margin: 6px 0 6px 18px; padding: 0; }
  li { margin: 2px 0; }
  .note { font-style: italic; color: #444; font-size: 10pt; }
  @media print {
    body { margin: 0; max-width: none; font-size: 10.5pt; }
    h2 { page-break-after: avoid; }
    .memo-head { border-color: #000; }
  }
</style>
</head>
<body>

<h1>Incident Report</h1>

<div class="memo-head">
  <div><span class="label">To:</span> CIO Management Team</div>
  <div><span class="label">From:</span> $(ConvertTo-CcdcHtmlText -Text $teamDisplay)</div>
  <div><span class="label">Prepared by:</span> $(ConvertTo-CcdcHtmlText -Text $authorDisplay)</div>
  <div><span class="label">Date:</span> $(ConvertTo-CcdcHtmlText -Text $generated)</div>
  <div><span class="label">Affected host:</span> $(ConvertTo-CcdcHtmlText -Text $Hostname)</div>
  <div><span class="label">Subject:</span> $(ConvertTo-CcdcHtmlText -Text (Get-Field $title '[subject]'))</div>
</div>

<h2>Summary</h2>
$(Get-HtmlPara $description)

<h2>Scope</h2>
$(Get-HtmlPara $scope)

<h2>Timeline and sequence</h2>
<ul>
  <li><strong>Incident time:</strong> $(ConvertTo-CcdcHtmlText -Text $IncidentTime.ToString('yyyy-MM-dd HH:mm:ss'))</li>
  <li><strong>Detected:</strong> $(ConvertTo-CcdcHtmlText -Text $detectedDisplay)</li>
</ul>
$(Get-HtmlPara $timeline)

<h2>Source and destination</h2>
<ul>
  <li><strong>Source IP(s):</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $sourceIp))</li>
  <li><strong>Destination IP(s) / host(s):</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $destIp))</li>
</ul>

<h2>Delivery mechanism</h2>
$(Get-HtmlPara $delivery)

<h2>Credentials</h2>
<ul>
  <li><strong>Passwords cracked / accounts compromised:</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $credsCracked '[none identified]'))</li>
  <li><strong>Credentials rotated in response:</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $credsRotated))</li>
</ul>

<h2>Damage and impact</h2>
$(Get-HtmlPara $impact)

<h2>Supporting evidence</h2>
<ul>
$evidenceHtml
</ul>
$(Get-HtmlPara $evidence '[none beyond the above]')
<p><strong>Indicators of compromise:</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $iocs '[none identified yet]'))</p>

<h2>Remediation</h2>
<ul>
  <li><strong>Removed / undone:</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $remArtifact))</li>
  <li><strong>Fix verified by:</strong> $(ConvertTo-CcdcHtmlText -Text (Get-Field $remVerified))</li>
</ul>

<h2>Prevention</h2>
$(Get-HtmlPara $prevention)

</body>
</html>
"@

$htmlOutcome = Invoke-CcdcSafe -Target $htmlPath -Action 'write incident report (print-ready HTML)' -ScriptBlock {
    $html | Set-Content -Path $htmlPath -Encoding UTF8 -ErrorAction Stop
}
if ($htmlOutcome.Success) { Write-CcdcLog -Level OK -Message "Print-ready memo written: $htmlPath" }

Write-Host ""
Write-Host "The scoring portal requires a PDF. Two ways to get one:" -ForegroundColor Yellow
Write-Host "  1. prep\ConvertTo-Pdf.ps1 -Path '$htmlPath'" -ForegroundColor Yellow
Write-Host "  2. Open the .html in a browser, Print, choose 'Microsoft Print to PDF'." -ForegroundColor Yellow
Write-Host ""
Write-Host "Read it through before you submit. Judges score clarity and business" -ForegroundColor Yellow
Write-Host "form, and the words in it should be yours." -ForegroundColor Yellow

Show-CcdcSummary
Stop-CcdcSession
