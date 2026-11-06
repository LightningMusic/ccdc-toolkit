#Requires -Version 5.1
<#
.SYNOPSIS
    Installs and configures the Splunk Universal Forwarder on the local
    host, pointed at your indexer — the other half of "get logs somewhere
    centralized before you need them," alongside Install-Sysmon.ps1.

.DESCRIPTION
    Unlike Sysmon, there is deliberately NO -AllowDownload option here.
    Splunk's download flow goes through their website (account/EULA
    click-through, versioned redirect URLs) rather than one stable,
    directly-scriptable link the way Sysinternals' does — trying to
    automate that reliably would be exactly the kind of "clever but
    breaks in a way you can't debug live" thing this toolkit is built to
    avoid. Download the Windows x64 MSI from splunk.com yourself during
    your setup window and drop it in tools\SplunkForwarder\ — this module
    picks up whatever .msi it finds there.

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
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$MsiPath,
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
# 1. Find the MSI — local only, no download path. See DESCRIPTION for why.
# ---------------------------------------------------------------------------
if (-not $MsiPath) {
    $toolsDir = Join-Path (Join-Path $root 'tools') 'SplunkForwarder'
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

if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
    Write-CcdcLog -Level ERROR -Message "No Splunk Universal Forwarder .msi found. Download the Windows x64 UF installer from splunk.com during your setup window and put it in tools\SplunkForwarder\ (or pass -MsiPath). Nothing changed."
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
