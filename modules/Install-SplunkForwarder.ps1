#Requires -Version 5.1
<#
.SYNOPSIS
    Installs and configures the Splunk Universal Forwarder on the local
    host, pointed at your indexer — the other half of "get logs somewhere
    centralized before you need them," alongside Install-Sysmon.ps1.

.DESCRIPTION
    Checks tools\SplunkForwarder\ for an .msi FIRST, same local-first
    pattern as Install-Sysmon.ps1. If nothing's staged there, -AllowDownload
    (on by default, same reasoning as Sysmon's — competition boxes have
    real internet per the official team pack, and a teammate launching this
    from the admin console's menu has no way to pass a flag anyway) fetches
    one from a PINNED direct-download URL (-DownloadUrl), confirmed working
    with no account/EULA click-through as of 2026-11-13.

    Unlike Sysmon's URL (Microsoft's own, version-free, always current),
    Splunk's download path embeds an exact version AND a release-specific
    hash in the filename — there is no stable "latest" link to point at, so
    the pinned default WILL go stale once Splunk ships a newer release.
    When it does, this fails with a clear error rather than silently
    installing something wrong: check
    https://www.splunk.com/en_us/download/universal-forwarder.html -> "copy
    wget link" for whatever's current, and pass it as -DownloadUrl (or just
    download it by hand into tools\SplunkForwarder\ — the local-first check
    always wins over downloading). Either way, whatever .msi ends up being
    used gets its Authenticode signature checked before install.

    Every value that's specific to your environment — the indexer address,
    optionally a deployment server — comes from config\answers.local.psd1
    or a prompt, never from anything hardcoded here (this repo is public).

    The forwarder's own admin password is randomly generated (same
    generator as Invoke-CredentialHardening.ps1) and written to the same
    kind of gitignored credential CSV under logs\ — never printed anywhere
    else, never hardcoded.

    Safe to run again later to point at a different indexer or add
    deployment-server config — it detects an existing install and
    reconfigures via edit + restart rather than reinstalling from scratch.

.PARAMETER MsiPath
    Path to the Splunk Universal Forwarder .msi. Defaults to whatever
    single .msi it finds in tools\SplunkForwarder\ under the repo root.

.PARAMETER AllowDownload
    If no .msi is staged locally, fetch one from -DownloadUrl. ON by
    default — see DESCRIPTION. Pass -AllowDownload:$false to refuse the
    network fallback and only ever use a pre-staged copy.

.PARAMETER DownloadUrl
    Direct download URL to use when falling back to the network. Defaults
    to a specific pinned Splunk UF 10.6.1.1 release, confirmed working
    without login as of 2026-11-13 — see DESCRIPTION for why this WILL go
    stale and what to do when it does.

.PARAMETER IndexerAddress
    Your Splunk indexer's hostname or IP. Pulled from config\answers.local.psd1
    (key: SplunkIndexerAddress) or prompted for if not set.

.PARAMETER IndexerPort
    Default 9997 (the standard Splunk-to-indexer receiving port) — only
    override if your environment uses something else.

.PARAMETER DeploymentServer
    Optional. Your Splunk deployment server (host:mgmt-port, default mgmt
    port 8089) for centrally pushing forwarder config later. Leave blank
    to skip.

.EXAMPLE
    .\Install-SplunkForwarder.ps1 -WhatIf
    Shows what would happen without installing anything.

.EXAMPLE
    .\Install-SplunkForwarder.ps1 -IndexerAddress 'splunk-idx01' -IndexerPort 9997

.EXAMPLE
    .\Install-SplunkForwarder.ps1 -AllowDownload:$false
    Refuses to touch the network -- fails clearly if nothing is pre-staged.

.EXAMPLE
    .\Install-SplunkForwarder.ps1 -DownloadUrl 'https://download.splunk.com/products/universalforwarder/releases/<newer-version>/windows/splunkforwarder-<newer-version>-<hash>-windows-x64.msi'
    Use once the pinned default version has gone stale.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$MsiPath,
    [bool]$AllowDownload = $true,
    [string]$DownloadUrl = 'https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi',
    [string]$IndexerAddress,
    [int]$IndexerPort = 9997,
    [string]$DeploymentServer
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$root = Split-Path -Parent $PSScriptRoot
$session = Start-CcdcSession -RootPath $root

Write-CcdcLog -Level INFO -Message "Splunk Universal Forwarder install/update starting."
Assert-CcdcElevated -Because "installing/reconfiguring a Windows service"

# ---------------------------------------------------------------------------
# 1. Find the MSI — local-first, network fallback only if nothing's staged.
# ---------------------------------------------------------------------------
$toolsDir = Join-Path (Join-Path $root 'tools') 'SplunkForwarder'
if (-not $MsiPath) {
    if (Test-Path $toolsDir) {
        $found = @(Get-ChildItem -Path $toolsDir -Filter '*.msi' -ErrorAction SilentlyContinue)
        if ($found.Count -eq 1) {
            $MsiPath = $found[0].FullName
        } elseif ($found.Count -gt 1) {
            Write-CcdcLog -Level ERROR -Message "Multiple .msi files found in $toolsDir — pass -MsiPath explicitly so there's no ambiguity about which one gets installed. Nothing changed."
            Stop-CcdcSession
            return
        }
    }
}

if ((-not $MsiPath -or -not (Test-Path $MsiPath)) -and $AllowDownload -and -not $PSBoundParameters.ContainsKey('MsiPath')) {
    Write-CcdcLog -Level INFO -Message "No local .msi found in $toolsDir — attempting download from the pinned URL: $DownloadUrl"
    Write-CcdcLog -Level WARN -Message "This URL is version-pinned and WILL eventually go stale — if the download fails, check https://www.splunk.com/en_us/download/universal-forwarder.html -> 'copy wget link' and pass the current one as -DownloadUrl."
    $downloadDest = Join-Path $toolsDir (Split-Path -Leaf $DownloadUrl)
    $downloadOutcome = Invoke-CcdcSafe -Target 'download.splunk.com' -Action 'download Splunk Universal Forwarder .msi' -ScriptBlock {
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $downloadDest -UseBasicParsing -ErrorAction Stop
    }
    if ($downloadOutcome.Success) { $MsiPath = $downloadDest }
}

if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
    $why = if ($PSBoundParameters.ContainsKey('MsiPath')) { "the -MsiPath you gave doesn't exist" }
        elseif ($AllowDownload) { "the automatic download just failed (check the error above -- likely no internet from this box right now, or the pinned version has gone stale)" }
        else { "-AllowDownload:`$false was passed, so it never tried the network" }
    Write-CcdcLog -Level ERROR -Message "No Splunk Universal Forwarder .msi available ($why). Stage it by hand: download the Windows x64 UF installer from splunk.com and put it in tools\SplunkForwarder\ (or pass -MsiPath), then re-run. Nothing changed."
    Stop-CcdcSession
    return
}
Write-CcdcLog -Level OK -Message "Using installer: $MsiPath"

if (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
    $sig = Get-AuthenticodeSignature -FilePath $MsiPath
    if ($sig.Status -ne 'Valid') {
        Write-CcdcLog -Level WARN -Message "$MsiPath doesn't have a valid Authenticode signature (status: $($sig.Status)). Splunk does sign their installers — if this came from anywhere other than splunk.com directly, verify it before continuing."
    } else {
        Write-CcdcLog -Level OK -Message "Installer signature status: Valid (signer: $($sig.SignerCertificate.Subject))."
    }
}

# ---------------------------------------------------------------------------
# 2. Environment-specific values — never hardcoded, always from the answer
#    file or a prompt.
# ---------------------------------------------------------------------------
$IndexerAddress = Get-CcdcAnswer -Key 'SplunkIndexerAddress' -Prompt 'Splunk indexer hostname/IP to forward logs to' -Value $IndexerAddress
if (-not $IndexerAddress) {
    Write-CcdcLog -Level ERROR -Message "No indexer address given — can't configure a forwarder that doesn't know where to forward to. Nothing changed."
    Stop-CcdcSession
    return
}

if (-not $DeploymentServer) {
    $DeploymentServer = Get-CcdcAnswer -Key 'SplunkDeploymentServer' -Prompt 'Deployment server (host:8089), blank to skip' -Default ''
}

# ---------------------------------------------------------------------------
# 3. Detect existing install. Wrapped, not left bare: an unexpected
#    environment quirk here (e.g. %ProgramFiles% not set the way expected)
#    should degrade to "assume not installed" with a clear log line, not
#    an uncaught stack trace — same standard as everything else.
# ---------------------------------------------------------------------------
$alreadyInstalled = $false
$installDir = $null
$detectOutcome = Invoke-CcdcSafe -Target (hostname) -Action 'check for existing Splunk UF install' -ScriptBlock {
    $dir = Join-Path $env:ProgramFiles 'SplunkUniversalForwarder'
    $exe = Join-Path (Join-Path $dir 'bin') 'splunk.exe'
    [pscustomobject]@{ InstallDir = $dir; Exists = (Test-Path $exe) }
}
if ($detectOutcome.Success) {
    $installDir = $detectOutcome.Value.InstallDir
    $alreadyInstalled = $detectOutcome.Value.Exists
} else {
    Write-CcdcLog -Level WARN -Message "Couldn't determine whether Splunk UF is already installed — proceeding as if it's a fresh install. If one already exists, this may fail rather than reconfigure it; re-run and check the error above if so."
    $installDir = 'C:\Program Files\SplunkUniversalForwarder'
}

if ($alreadyInstalled) {
    # Deliberately NOT going through the authenticated splunk.exe CLI here
    # (e.g. `splunk set deploy-poll ... -auth admin:...`) — that would need
    # this EXISTING install's admin password, which this run has no way to
    # know (it's whatever password a PRIOR run generated and saved to its
    # own timestamped CSV). Editing outputs.conf directly and restarting
    # the service is credential-independent and is how most Splunk UF
    # automation actually does this.
    Write-CcdcLog -Level INFO -Message "Existing Splunk Universal Forwarder install found at $installDir — reconfiguring outputs.conf directly rather than reinstalling."

    $localConfDir = Join-Path $installDir 'etc\system\local'
    $outputsConfPath = Join-Path $localConfDir 'outputs.conf'

    if (Test-Path $outputsConfPath) {
        $existingOutputs = Get-Content -Path $outputsConfPath -Raw -ErrorAction SilentlyContinue
        if ($existingOutputs) {
            Backup-CcdcState -Name 'splunkforwarder-outputs-conf-before' -Data $existingOutputs | Out-Null
        }
    }

    # The output-group name is a named artifact on the live box, so it comes
    # from ArtifactPrefix like every other one (a literal "ccdc_" name in a
    # public repo is a free fingerprint -- see docs/SECURITY.md).
    $artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for named artifacts (anything -- just avoid an obvious "CCDC" string since this repo is public)' -Default 'Baseline'
    $outputGroup = (($artifactPrefix -replace '[^A-Za-z0-9_]', '_') + '_indexers')
    $outputsConfContent = @"
[tcpout]
defaultGroup = $outputGroup

[tcpout:$outputGroup]
server = $IndexerAddress`:$IndexerPort
"@

    if ($PSCmdlet.ShouldProcess((hostname), "Point existing forwarder at $IndexerAddress`:$IndexerPort")) {
        Invoke-CcdcSafe -Target (hostname) -Action 'reconfigure receiving indexer (outputs.conf)' -ScriptBlock {
            if (-not (Test-Path $localConfDir)) { New-Item -ItemType Directory -Path $localConfDir -Force | Out-Null }
            Set-Content -Path $outputsConfPath -Value $outputsConfContent -Encoding ASCII -ErrorAction Stop
            Restart-Service -Name 'SplunkForwarder' -ErrorAction Stop
        } | Out-Null
    }

    if ($DeploymentServer) {
        $deployConfPath = Join-Path $localConfDir 'deploymentclient.conf'
        $deployConfContent = @"
[deployment-client]

[target-broker:deploymentServer]
targetUri = $DeploymentServer
"@
        if ($PSCmdlet.ShouldProcess((hostname), "Point existing forwarder at deployment server $DeploymentServer")) {
            Invoke-CcdcSafe -Target (hostname) -Action 'reconfigure deployment server (deploymentclient.conf)' -ScriptBlock {
                Set-Content -Path $deployConfPath -Value $deployConfContent -Encoding ASCII -ErrorAction Stop
                Restart-Service -Name 'SplunkForwarder' -ErrorAction Stop
            } | Out-Null
        }
    }
} else {
    Write-CcdcLog -Level INFO -Message "No existing install found — installing fresh."

    $forwarderPassword = New-CcdcRandomPassword
    $msiArgs = @(
        "/i `"$MsiPath`""
        'AGREETOLICENSE=yes'
        "RECEIVING_INDEXER=`"$IndexerAddress`:$IndexerPort`""
        'WINEVENTLOG_SEC_ENABLE=1'
        'WINEVENTLOG_SYS_ENABLE=1'
        'WINEVENTLOG_APP_ENABLE=1'
        'SPLUNKUSERNAME=admin'
        "SPLUNKPASSWORD=$forwarderPassword"
        '/quiet'
    )
    if ($DeploymentServer) {
        $msiArgs += "DEPLOYMENT_SERVER=`"$DeploymentServer`""
    }

    # Known limitation, stated plainly rather than hidden: the forwarder's
    # admin password has to reach the MSI as a SPLUNKPASSWORD= property, so it
    # sits on msiexec's command line for the length of the install. That is
    # the same class of exposure Invoke-NetworkRecon.ps1 avoids for nmap, and
    # unlike nmap there is no file-based option here that has been verified
    # against a real Splunk install (user-seed.conf is the candidate to test
    # in the lab -- see docs/ARCHITECTURE.md). It is a random, single-use,
    # this-host-only credential, so the blast radius is small, but it
    # matters: a Splunk UF management login is an administrative foothold.
    Write-CcdcLog -Level WARN -Message "The forwarder's random admin password is passed to msiexec on its command line for the duration of the install -- visible in a process listing and, if Sysmon is already running on this host, in Sysmon's process-creation log. Treat that log entry as sensitive (or install the forwarder before Sysmon on this host if you can). See docs/SECURITY.md."

    $installOutcome = $null
    if ($PSCmdlet.ShouldProcess((hostname), "Install Splunk UF, forwarding to $IndexerAddress`:$IndexerPort")) {
        $installOutcome = Invoke-CcdcSafe -Target (hostname) -Action 'install Splunk Universal Forwarder' -ScriptBlock {
            $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -ErrorAction Stop
            if ($proc.ExitCode -ne 0) {
                throw "msiexec exited with code $($proc.ExitCode)"
            }
        }
    }

    # ------------------------------------------------------------------
    # 4. Save the forwarder's admin password — ONLY if the install this
    #    password actually belongs to succeeded. Writing it out
    #    unconditionally would be actively misleading: it'd look like a
    #    working credential for an install that doesn't exist.
    # ------------------------------------------------------------------
    if ($installOutcome -and $installOutcome.Success) {
        $sheetPath = Join-Path $session.LogRoot "splunk-forwarder-credentials_$($session.Stamp).csv"
        [pscustomobject]@{ Account = 'admin (SplunkForwarder local)'; Password = $forwarderPassword } |
            Export-Csv -Path $sheetPath -NoTypeInformation
        Write-CcdcLog -Level WARN -Message "Forwarder admin password written to: $sheetPath (gitignored, this box only)."
    } elseif ($installOutcome) {
        Write-CcdcLog -Level INFO -Message "Install didn't succeed — not writing a credential file for a forwarder that isn't actually running."
    }
}

# ---------------------------------------------------------------------------
# 5. Verify. Wrapped for the same reason as the detection step above.
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 3
$verifyOutcome = Invoke-CcdcSafe -Target (hostname) -Action 'verify SplunkForwarder service state' -ScriptBlock {
    Get-Service -Name 'SplunkForwarder' -ErrorAction Stop
}
if ($verifyOutcome.Success -and $verifyOutcome.Value.Status -eq 'Running') {
    Write-CcdcLog -Level OK -Message "Verified: SplunkForwarder service is Running."
} else {
    Write-CcdcLog -Level ERROR -Message "SplunkForwarder service isn't confirmed Running. Check the output above — a common cause is a bad indexer address/port or the MSI needing a reboot it didn't get."
}

Show-CcdcSummary
Stop-CcdcSession
