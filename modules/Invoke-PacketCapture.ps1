#Requires -Version 5.1
<#
.SYNOPSIS
    Grabs a short, timestamped packet capture as evidence — the automatable
    half of Wireshark. Wireshark itself is a GUI a person drives; this
    wraps its CLI companion, tshark, for "capture N seconds around this
    incident" on demand.

.DESCRIPTION
    Wireshark wasn't something to script directly — it's built for a human
    to click through interactively, which doesn't fit this toolkit's
    pattern of small, non-interactive-by-default actions. tshark (installed
    alongside Wireshark, or standalone) is the part that does, and a short
    capture saved with a timestamp is exactly the kind of proof-with-a-
    visible-timestamp an ATCC coach's field manual says to grab BEFORE you
    clean anything up when you catch red team.

    Looks for tools\Wireshark\tshark.exe first (stage it there ahead of
    time — see docs/PREP-SHEET.md), then falls back to tshark on PATH.
    Capturing needs Npcap (or WinPcap) installed separately — this checks
    for it and tells you plainly if it's missing rather than failing with
    a raw tshark error.

    Saves to logs\captures\<hostname>_<timestamp>.pcapng (gitignored, same
    as everything else under logs\), plus a quick protocol-hierarchy
    summary alongside it (tshark -q -z io,phs) so you get a fast read
    without opening the capture in Wireshark at all. New-IncidentReport.ps1
    automatically looks here too, the same way it already looks at session
    logs and state backups, so a capture taken near an incident shows up
    as evidence without you having to remember to attach it by hand.

.PARAMETER DurationSeconds
    How long to capture. Default 60. Keep this short and deliberate —
    this is evidence for one specific window, not a standing capture.

.PARAMETER CaptureFilter
    Optional BPF capture filter (tshark -f syntax), e.g. "host 10.10.10.5"
    to scope to one suspect IP. Blank captures everything on the chosen
    interface.

.PARAMETER Interface
    Which interface to capture on. If not given, lists what tshark sees
    (tshark -D) and prompts you to pick one — fresh, one-off operational
    input, so this uses Read-Host directly rather than Get-CcdcAnswer.

.PARAMETER Hostname
    Label used in the output filename. Defaults to the current computer
    name.

.EXAMPLE
    .\Invoke-PacketCapture.ps1
    Prompts for an interface, captures 60 seconds of everything on it.

.EXAMPLE
    .\Invoke-PacketCapture.ps1 -DurationSeconds 120 -CaptureFilter "host 10.10.10.5"
    Two-minute capture scoped to one suspect IP.

.EXAMPLE
    .\Invoke-PacketCapture.ps1 -WhatIf
    Shows the exact tshark command that would run without executing it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 3600)]
    [int]$DurationSeconds = 60,
    [string]$CaptureFilter = '',
    [string]$Interface,
    [string]$Hostname = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { (hostname) })
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Packet capture starting. Grab evidence with a visible timestamp BEFORE cleaning anything up -- that's the rule an ATCC coach's field manual gives for catching red team."
Assert-CcdcElevated -Because "capturing packets (Npcap/WinPcap need admin rights to open an interface)"

# Whole body wrapped in try/finally so Show-CcdcSummary/Stop-CcdcSession
# always run and the transcript closes cleanly even if something below
# fails in an unexpected way -- same reasoning as Invoke-NetworkRecon.ps1,
# which is where this was first found to matter.
try {


# ---------------------------------------------------------------------------
# Resolve the tshark binary — local tools folder first, then PATH.
# ---------------------------------------------------------------------------
$tsharkPath = $null
$stagedTshark = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\Wireshark\tshark.exe'
if (Test-Path -Path $stagedTshark -ErrorAction SilentlyContinue) {
    $tsharkPath = $stagedTshark
} elseif (Get-Command -Name tshark -ErrorAction SilentlyContinue) {
    $tsharkPath = (Get-Command -Name tshark).Source
}

if (-not $tsharkPath) {
    Write-CcdcLog -Level ERROR -Message "tshark not found -- stage Wireshark's install at tools\Wireshark\tshark.exe (see docs/PREP-SHEET.md) or install it and make sure it's on PATH. Nothing was captured."
    return
}

if (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
    $sig = Get-AuthenticodeSignature -FilePath $tsharkPath
    if ($sig.Status -ne 'Valid') {
        Write-CcdcLog -Level WARN -Message "$tsharkPath doesn't have a valid Authenticode signature (status: $($sig.Status)). The official Wireshark Windows build is signed -- if this came from anywhere other than wireshark.org directly, verify it before trusting it."
    } else {
        Write-CcdcLog -Level OK -Message "tshark binary signature status: Valid (signer: $($sig.SignerCertificate.Subject))."
    }
} else {
    Write-CcdcLog -Level WARN -Message "Get-AuthenticodeSignature isn't available here -- proceeding without verifying the tshark binary's signature."
}

# ---------------------------------------------------------------------------
# Resolve capture interface.
# ---------------------------------------------------------------------------
if (-not $Interface) {
    Write-CcdcLog -Level INFO -Message "Listing available capture interfaces (needs Npcap/WinPcap installed to see any)..."
    $listOutcome = Invoke-CcdcSafe -Target 'tshark' -Action 'list capture interfaces' -ScriptBlock {
        & $tsharkPath -D 2>&1
    }
    if ($listOutcome.Success) {
        foreach ($line in @($listOutcome.Value)) { Write-Host "  $line" }
    }
    $Interface = Read-Host 'Interface number or name to capture on (from the list above)'
    if (-not $Interface) {
        Write-CcdcLog -Level ERROR -Message "No interface chosen -- nothing captured. (No Npcap/WinPcap installed is the most common reason the list above was empty.)"
        return
    }
}

# ---------------------------------------------------------------------------
# Capture.
# ---------------------------------------------------------------------------
$captureDir = Join-Path $session.LogRoot 'captures'
if (-not (Test-Path -Path $captureDir)) { New-Item -ItemType Directory -Path $captureDir -Force | Out-Null }
$safeHost = ($Hostname -replace '[^a-zA-Z0-9_\-]', '_')
$fileStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$capturePath = Join-Path $captureDir "$safeHost`_$fileStamp.pcapng"

$tsharkArgs = Get-CcdcTsharkArgs -Duration $DurationSeconds -Iface $Interface -Filter $CaptureFilter -OutputPath $capturePath
Write-CcdcLog -Level INFO -Message "About to run: tshark $($tsharkArgs -join ' ')"
Write-CcdcLog -Level WARN -Message "Capturing for $DurationSeconds second(s) -- this blocks until it's done."

if ($PSCmdlet.ShouldProcess($Interface, "Capture $DurationSeconds second(s) of traffic")) {
    $captureOutcome = Invoke-CcdcSafe -Target $Interface -Action "capture $DurationSeconds second(s) of traffic" -ScriptBlock {
        & $tsharkPath @tsharkArgs 2>&1 | Out-Null
        return $LASTEXITCODE
    }
    if ($captureOutcome.Success -and $captureOutcome.Value -eq 0 -and (Test-Path -Path $capturePath)) {
        Write-CcdcLog -Level OK -Message "Capture saved: $capturePath"

        $summaryPath = "$capturePath.summary.txt"
        $summaryOutcome = Invoke-CcdcSafe -Target $capturePath -Action 'summarize protocol hierarchy' -ScriptBlock {
            & $tsharkPath -q -z io,phs -r $capturePath 2>&1
        }
        if ($summaryOutcome.Success) {
            $summaryOutcome.Value | Out-File -FilePath $summaryPath -Encoding utf8
            Write-CcdcLog -Level OK -Message "Protocol summary: $summaryPath (read this before opening the full capture in Wireshark)"
        }
    } else {
        Write-CcdcLog -Level ERROR -Message "Capture failed or produced no file -- check that Npcap/WinPcap is installed and you're running as Administrator (capturing needs elevated privileges)."
    }
}

} finally {
    Show-CcdcSummary
    Stop-CcdcSession
}
