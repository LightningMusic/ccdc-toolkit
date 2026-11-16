#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or reconfigures Sysmon on the local host, using the bundled
    community config by default — the module that turns "we might notice
    an attack" into "we have a log of it."

.DESCRIPTION
    This one doesn't touch the firewall, doesn't rotate anything, and adds
    no inbound listener — of everything in this toolkit, it's one of the
    lowest-risk modules to run, which is exactly why it's worth running
    early and everywhere.

    Binary handling checks for Sysmon64.exe/Sysmon.exe in a local tools
    folder FIRST, and only falls back to fetching it from Microsoft's own
    stable Sysinternals URL if nothing's staged there — downloading is ON
    by default (-AllowDownload defaults true) since competition boxes are
    confirmed to have real internet access (the official team pack's own
    rules say so), and found live at the 2026-11-14 Invitational that a
    teammate launching this from the admin console's menu has no way to
    add a flag to that launch — an opt-IN download flag they never see is
    just a dead end, not a safety feature. Pre-stage it in tools\Sysmon\
    anyway if you want to (e.g. this box genuinely has no internet, or you
    just don't want to touch the network at all) — pass -AllowDownload:$false
    to refuse the fallback and only use a pre-staged copy. Either way,
    before running whatever binary it finds, this verifies it's
    Authenticode-signed by Microsoft — it will refuse to run something that
    isn't, rather than silently executing an unverified .exe with admin
    rights, so the download defaulting on doesn't mean trusting it blindly.

    Config handling: defaults to configs\sysmon\sysmonconfig-export.xml,
    the SwiftOnSecurity community config vendored into this repo (see
    configs\sysmon\README.md for its license/attribution). Pass
    -ConfigPath to use a different one.

    Safe to run again later to push an updated config — it detects an
    existing install and reconfigures in place rather than reinstalling.

.PARAMETER ConfigPath
    Path to a Sysmon config XML. Defaults to the bundled community config.

.PARAMETER BinaryDir
    Folder to look for Sysmon64.exe/Sysmon.exe in (and to download into,
    with -AllowDownload). Defaults to tools\Sysmon under the repo root.

.PARAMETER AllowDownload
    If the binary isn't found locally, fetch it from Microsoft's official
    Sysinternals download URL. ON by default — see DESCRIPTION for why.
    Pass -AllowDownload:$false to refuse the network fallback entirely.

.EXAMPLE
    .\Install-Sysmon.ps1 -WhatIf
    Shows what would happen (including which binary/config it found) without installing anything.

.EXAMPLE
    .\Install-Sysmon.ps1
    Uses a pre-staged binary if one exists in tools\Sysmon\, otherwise fetches it from Microsoft automatically.

.EXAMPLE
    .\Install-Sysmon.ps1 -AllowDownload:$false
    Refuses to touch the network -- fails clearly if nothing is pre-staged.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath,
    [string]$BinaryDir,
    [bool]$AllowDownload = $true
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$root = Split-Path -Parent $PSScriptRoot
$session = Start-CcdcSession -RootPath $root

Write-CcdcLog -Level INFO -Message "Sysmon install/update starting. Read-mostly and low-risk compared to the firewall/credential modules."
Assert-CcdcElevated -Because "installing a driver and a Windows service"

# ---------------------------------------------------------------------------
# 1. Resolve and sanity-check the config file.
# ---------------------------------------------------------------------------
if (-not $ConfigPath) {
    $ConfigPath = Join-Path (Join-Path $root 'configs') (Join-Path 'sysmon' 'sysmonconfig-export.xml')
}

if (-not (Test-Path $ConfigPath)) {
    Write-CcdcLog -Level ERROR -Message "Config file not found: $ConfigPath. Nothing changed."
    Stop-CcdcSession
    return
}

try {
    [xml](Get-Content -Path $ConfigPath -Raw) | Out-Null
} catch {
    Write-CcdcLog -Level ERROR -Message "Config at $ConfigPath isn't well-formed XML: $($_.Exception.Message). Refusing to install with a broken config. Nothing changed."
    Stop-CcdcSession
    return
}
Write-CcdcLog -Level OK -Message "Config OK: $ConfigPath"

# ---------------------------------------------------------------------------
# 2. Resolve the binary — local-first, download only if explicitly allowed.
# ---------------------------------------------------------------------------
if (-not $BinaryDir) {
    $BinaryDir = Join-Path (Join-Path $root 'tools') 'Sysmon'
}

function Find-SysmonBinary {
    param([string]$Dir)
    foreach ($name in @('Sysmon64.exe', 'Sysmon.exe')) {
        $candidate = Join-Path $Dir $name
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

$binaryPath = Find-SysmonBinary -Dir $BinaryDir

if (-not $binaryPath -and $AllowDownload) {
    Write-CcdcLog -Level INFO -Message "No local Sysmon binary found in $BinaryDir — attempting download from Microsoft's official Sysinternals URL."
    $zipPath = Join-Path $session.LogRoot 'Sysmon.zip'
    $downloadOutcome = Invoke-CcdcSafe -Target 'download.sysinternals.com' -Action 'download Sysmon.zip' -ScriptBlock {
        New-Item -ItemType Directory -Path $BinaryDir -Force | Out-Null
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zipPath -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $BinaryDir -Force -ErrorAction Stop
    }
    if ($downloadOutcome.Success) {
        $binaryPath = Find-SysmonBinary -Dir $BinaryDir
    }
}

if (-not $binaryPath) {
    $why = if ($AllowDownload) { "the automatic download just failed (check the error above -- likely no internet from this box right now)" } else { "-AllowDownload:`$false was passed, so it never tried the network" }
    Write-CcdcLog -Level ERROR -Message "No Sysmon binary available ($why). Stage it by hand: download https://download.sysinternals.com/files/Sysmon.zip and unzip Sysmon64.exe into $BinaryDir, then re-run. Nothing changed."
    Stop-CcdcSession
    return
}

# ---------------------------------------------------------------------------
# 3. Never run an unsigned/tampered binary, regardless of where it came from.
# ---------------------------------------------------------------------------
if (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
    $sig = Get-AuthenticodeSignature -FilePath $binaryPath
    $signedByMicrosoft = $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft*'
    if (-not $signedByMicrosoft) {
        Write-CcdcLog -Level ERROR -Message "$binaryPath is NOT a validly-signed Microsoft binary (signature status: $($sig.Status)). Refusing to run it — this is either corrupted or not the real Sysmon. Nothing changed."
        Stop-CcdcSession
        return
    }
    Write-CcdcLog -Level OK -Message "Binary signature verified: Microsoft-signed, status Valid."
} else {
    Write-CcdcLog -Level WARN -Message "Get-AuthenticodeSignature isn't available here — proceeding without verifying the binary is genuinely from Microsoft. Verify it yourself if you're not confident in its source."
}

# ---------------------------------------------------------------------------
# 4. Install fresh, or reconfigure an existing install.
# ---------------------------------------------------------------------------
$existingService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1

if ($existingService) {
    Write-CcdcLog -Level INFO -Message "Existing Sysmon service found ($($existingService.Name)) — updating its configuration rather than reinstalling."

    if ($PSCmdlet.ShouldProcess($existingService.Name, 'Back up current Sysmon config')) {
        $currentConfigOutcome = Invoke-CcdcSafe -Target $existingService.Name -Action 'dump current Sysmon config' -ScriptBlock {
            & $binaryPath -c 2>&1 | Out-String
        }
        if ($currentConfigOutcome.Success) {
            Backup-CcdcState -Name 'sysmon-config-before' -Data $currentConfigOutcome.Value | Out-Null
        }
    }

    if ($PSCmdlet.ShouldProcess($existingService.Name, "Apply config from $ConfigPath")) {
        Invoke-CcdcSafe -Target $existingService.Name -Action 'update Sysmon config' -ScriptBlock {
            & $binaryPath -c $ConfigPath 2>&1 | Out-String
        } | Out-Null
    }
} else {
    Write-CcdcLog -Level INFO -Message "No existing Sysmon install found — installing fresh."
    if ($PSCmdlet.ShouldProcess((hostname), "Install Sysmon with $ConfigPath")) {
        Invoke-CcdcSafe -Target (hostname) -Action 'install Sysmon' -ScriptBlock {
            & $binaryPath -accepteula -i $ConfigPath 2>&1 | Out-String
        } | Out-Null
    }
}

# ---------------------------------------------------------------------------
# 5. Verify.
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 2
$finalService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($finalService -and $finalService.Status -eq 'Running') {
    Write-CcdcLog -Level OK -Message "Verified: $($finalService.Name) service is Running."
} else {
    Write-CcdcLog -Level ERROR -Message "Sysmon service isn't confirmed Running after this. Check the output above for what the install/config command actually reported."
}

Show-CcdcSummary
Stop-CcdcSession
