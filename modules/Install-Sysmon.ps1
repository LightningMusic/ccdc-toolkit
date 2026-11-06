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

    Binary handling is deliberately local-first: this checks for
    Sysmon64.exe/Sysmon.exe in a local tools folder before ever touching
    the network. Pre-stage it there during your setup window (download
    https://download.sysinternals.com/files/Sysmon.zip from Microsoft and
    unzip it into tools\Sysmon\) if you don't know whether you'll have
    internet access once the round starts. Pass -AllowDownload if you do
    and want this to fetch it for you. Either way, before running whatever
    binary it finds, this verifies it's Authenticode-signed by Microsoft —
    it will refuse to run something that isn't, rather than silently
    executing an unverified .exe with admin rights.

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
    Sysinternals download URL. Off by default — see DESCRIPTION for why.

.EXAMPLE
    .\Install-Sysmon.ps1 -WhatIf
    Shows what would happen (including which binary/config it found) without installing anything.

.EXAMPLE
    .\Install-Sysmon.ps1 -AllowDownload
    Fetches Sysmon from Microsoft if it's not already staged locally, then installs with the bundled config.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath,
    [string]$BinaryDir,
    [switch]$AllowDownload
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
    Write-CcdcLog -Level INFO -Message "No local Sysmon binary found in $BinaryDir — attempting download from Microsoft's official Sysinternals URL (-AllowDownload was set)."
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
    Write-CcdcLog -Level ERROR -Message "No Sysmon binary available. Pre-stage it: download https://download.sysinternals.com/files/Sysmon.zip and unzip Sysmon64.exe into $BinaryDir, or re-run with -AllowDownload if you have internet access right now. Nothing changed."
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
