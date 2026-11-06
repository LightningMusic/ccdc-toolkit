#Requires -Version 5.1
<#
.SYNOPSIS
    Runs nmap against your own team's subnet so you find your open ports
    and easy vulns before red team does — per an ATCC coach's field manual:
    "Run a credentialed scan pre-comp, not during. Scans are loud and slow."

.DESCRIPTION
    This wraps nmap, not reimplements it — nmap isn't part of Windows, so
    it needs staging like Sysmon/the Splunk forwarder do: this looks for
    tools\nmap\nmap.exe first (stage it there ahead of time — see
    docs/PREP-SHEET.md), then falls back to nmap on PATH if it's already
    installed. Its signature gets a best-effort Authenticode check (WARN,
    not a hard block — unlike Install-Sysmon.ps1's Microsoft-only check,
    this doesn't assert a specific expected publisher, since that hasn't
    been independently verified for this repo; a WARN on an invalid/missing
    signature is still worth reading before you trust the binary).

    Three scan profiles, all read-only against the network (nmap doesn't
    change anything on the hosts it scans):
      - Quick:  fast top-1000-port scan (-T4 -F), good for "did we forget
                to close something" spot checks.
      - Full:   all 65535 TCP ports (-T4 -p-), slower, more thorough.
      - Vuln:   Full's port range plus NSE's default + vuln script
                categories (--script default,vuln), matching the manual's
                "credentialed Nessus or nmap NSE scan" recon-week advice.
                Slowest and loudest of the three by a wide margin.

    "Credentialed" for nmap specifically means SMB credentials passed to
    NSE scripts that support them (smb-enum-shares, smb-enum-users, and
    others) so they can enumerate past what an unauthenticated scan sees.
    Pass -SmbUsername to be prompted for a password (SecureString, never
    written to disk long-term, never sourced from the answer file — this
    is a live credential, not reusable environment config, so it follows
    the same Read-Host-not-Get-CcdcAnswer rule as everything else one-off.
    See docs/ARCHITECTURE.md's design-rules note on that distinction).

    The credential is passed to nmap via --script-args-file (a short-lived
    temp file, deleted immediately after the scan) rather than
    --script-args on the command line. nmap is a separate process, and a
    process's command-line arguments are visible to anything that can list
    processes on the box — Task Manager's command-line column, `Get-CimInstance
    Win32_Process`, and critically, Sysmon's own Event ID 1 (process
    creation, which logs the full command line by design) if
    Install-Sysmon.ps1 is deployed on this same host, which it usually is.
    Putting a real password there would mean this toolkit's own logging
    module captures and potentially forwards a plaintext credential to
    Splunk — the exact kind of self-inflicted exposure docs/SECURITY.md
    warns about elsewhere. The temp file avoids that; only the file PATH
    (not its contents) ever appears in a log line or transcript.

    Results are saved under logs\recon\ (gitignored, same as everything
    else under logs\) in nmap's own normal-output format plus a greppable
    XML alongside it. If logs\inventory-latest.json exists (run
    Get-EnvironmentInventory.ps1 first), this cross-references what nmap
    found open against your ScoredServices list and flags ports that are
    open but NOT expected — that's the fast way to spot "wait, why is
    that port open" without reading a full nmap report line by line.

    This tool does NOT tell you which findings are exploitable — the
    manual is explicit that chasing vulns nobody can actually exploit
    wastes time better spent elsewhere, and that's a judgment call for
    you, not something to automate or hand to an LLM to decide. Read the
    output yourself.

.PARAMETER Target
    What to scan — a single host, or CIDR range. Defaults to the
    SubnetCidr answer-file value (prompts if not set).

.PARAMETER ScanProfile
    Quick, Full, or Vuln — see .DESCRIPTION. Default Quick.

.PARAMETER SmbUsername
    Optional. If set, you're prompted for the matching password
    (SecureString) and both get passed to NSE scripts that accept SMB
    credentials, for a "credentialed" scan per the manual's phrasing.

.PARAMETER Hostname
    Label used in the output filename. Defaults to the current computer
    name.

.EXAMPLE
    .\Invoke-NetworkRecon.ps1
    Quick scan of your configured subnet.

.EXAMPLE
    .\Invoke-NetworkRecon.ps1 -Target 10.10.10.5 -ScanProfile Vuln -SmbUsername svc_admin
    Full NSE vuln-script scan of one host, credentialed with svc_admin
    (prompts for the password).

.EXAMPLE
    .\Invoke-NetworkRecon.ps1 -WhatIf
    Shows the exact nmap command that would run without executing it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Target,
    [ValidateSet('Quick', 'Full', 'Vuln')]
    [string]$ScanProfile = 'Quick',
    [string]$SmbUsername,
    [string]$Hostname = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { (hostname) })
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level WARN -Message "Network recon starting. Per an ATCC coach's field manual: run this pre-competition to find your own holes, NOT during the round -- scans are loud and slow, and a Vuln-profile scan in particular looks a lot like exactly the traffic your own team should be hunting for."
Assert-CcdcElevated -Because "nmap's SYN scans and OS/service detection"

# The whole body below is wrapped in try/finally (not just relying on
# Invoke-CcdcSafe, which only covers individual actions) specifically so
# Show-CcdcSummary/Stop-CcdcSession still run and close out the session
# transcript even if something here fails in a way that bypasses normal
# try/catch -- confirmed via direct testing that Read-Host -AsSecureString
# below can do exactly that in a non-interactive host context. A real
# competition console is interactive, so this is belt-and-suspenders, but
# cheap insurance for a step this module is the only one in the toolkit
# to need at all.
try {

# The pure logic this module uses (service-to-port lookup, scored-service
# host matching, nmap argument building, the unexpected-port check) lives in
# modules\CcdcLogic.ps1, shared with the firewall module and covered by
# tests\ -- previously copy-pasted into each module.

# ---------------------------------------------------------------------------
# Resolve the nmap binary — local tools folder first, then PATH.
# ---------------------------------------------------------------------------
$nmapPath = $null
$stagedNmap = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\nmap\nmap.exe'
if (Test-Path -Path $stagedNmap -ErrorAction SilentlyContinue) {
    $nmapPath = $stagedNmap
} elseif (Get-Command -Name nmap -ErrorAction SilentlyContinue) {
    $nmapPath = (Get-Command -Name nmap).Source
}

if (-not $nmapPath) {
    Write-CcdcLog -Level ERROR -Message "nmap not found -- stage the Windows build at tools\nmap\nmap.exe (see docs/PREP-SHEET.md) or install it and make sure it's on PATH. Nothing was run."
    return
}

if (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
    $sig = Get-AuthenticodeSignature -FilePath $nmapPath
    if ($sig.Status -ne 'Valid') {
        Write-CcdcLog -Level WARN -Message "$nmapPath doesn't have a valid Authenticode signature (status: $($sig.Status)). The official Nmap Project Windows build is signed -- if this came from anywhere other than nmap.org directly, verify it before trusting the results."
    } else {
        Write-CcdcLog -Level OK -Message "nmap binary signature status: Valid (signer: $($sig.SignerCertificate.Subject))."
    }
} else {
    Write-CcdcLog -Level WARN -Message "Get-AuthenticodeSignature isn't available here -- proceeding without verifying the nmap binary's signature."
}

# ---------------------------------------------------------------------------
# Resolve target + credentials.
# ---------------------------------------------------------------------------
if (-not $Target) {
    $Target = Get-CcdcAnswer -Key 'SubnetCidr' -Prompt 'Target to scan (single host or CIDR range, e.g. 10.10.10.0/24)' -Default ''
}
if (-not $Target) {
    Write-CcdcLog -Level ERROR -Message "No target given and no SubnetCidr configured -- nothing to scan."
    return
}

# Only the PATH of the credential temp file is decided here (it goes into
# the nmap argument list); the password is prompted for, and the file
# written, further down -- and only if the scan is really going to run, so
# -WhatIf never asks for a password or puts one on disk. See
# Get-CcdcNmapArgs for why it's a file and not a command-line argument.
$scriptArgsFilePath = $null
if ($SmbUsername) {
    # A bare GUID name: a literal like "nmap-args" or "ccdc-..." would be a
    # greppable pointer to the one file on this box that briefly holds a password.
    $scriptArgsFilePath = Join-Path ([System.IO.Path]::GetTempPath()) "$([guid]::NewGuid()).tmp"
}

# ---------------------------------------------------------------------------
# Run it.
# ---------------------------------------------------------------------------
$reconDir = Join-Path $session.LogRoot 'recon'
if (-not (Test-Path -Path $reconDir)) { New-Item -ItemType Directory -Path $reconDir -Force | Out-Null }
$safeTarget = ($Target -replace '[^a-zA-Z0-9_\-\.]', '_')
$outputBase = Join-Path $reconDir "$safeTarget`_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')"

$nmapArgs = Get-CcdcNmapArgs -ScanProfileName $ScanProfile -TargetHost $Target -OutputBase $outputBase -SmbUser $SmbUsername -ScriptArgsFilePath $scriptArgsFilePath
# Nothing to redact here anymore: the credential lives only in the temp
# file at $scriptArgsFilePath (cleaned up in the outer finally below),
# never on nmap's own command line -- so the full argument list is safe
# to log and show as-is, including when there's no credential at all.
Write-CcdcLog -Level INFO -Message "About to run: nmap $($nmapArgs -join ' ')"

if ($PSCmdlet.ShouldProcess($Target, "Run nmap ($ScanProfile profile)")) {
    if ($SmbUsername) {
        $secureSmbPass = Read-Host "SMB password for $SmbUsername (used only for this scan, never written to disk long-term)" -AsSecureString
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSmbPass)
        try {
            $smbPassPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $secureSmbPass.Dispose()
        }
        # Written to a short-lived temp file rather than passed on nmap's
        # command line -- deleted in the outer try/finally below regardless
        # of how the scan turns out. The user's temp folder is per-user by
        # default on Windows, not world-readable.
        Set-Content -Path $scriptArgsFilePath -Value "smbuser=$SmbUsername,smbpass=$smbPassPlain" -NoNewline -Encoding ASCII
        $smbPassPlain = '' # nothing else in this script needs the plaintext value again.
    }
    $scanOutcome = Invoke-CcdcSafe -Target $Target -Action "run nmap $ScanProfile scan" -ScriptBlock {
        & $nmapPath @nmapArgs 2>&1 | Out-Null
        return $LASTEXITCODE
    }
    if ($scanOutcome.Success -and $scanOutcome.Value -eq 0) {
        Write-CcdcLog -Level OK -Message "Scan complete. Full output: $outputBase.txt (and $outputBase.xml)"

        # Cross-reference against the ScoredServices list -- from the
        # inventory when discovery has run, otherwise straight from the
        # answer file, so the cross-check still works on a box where the
        # only thing filled in is the answer file.
        $inventoryPath = Join-Path $session.LogRoot 'inventory-latest.json'
        $inv = $null
        if (Test-Path -Path $inventoryPath -ErrorAction SilentlyContinue) {
            $invOutcome = Invoke-CcdcSafe -Target $inventoryPath -Action 'load inventory for port cross-reference' -ScriptBlock {
                Get-Content -Path $inventoryPath -Raw | ConvertFrom-Json
            }
            if ($invOutcome.Success) { $inv = $invOutcome.Value }
        }
        $scoredAll = @(Get-CcdcScoredServiceList -RootPath $session.RootPath -Inventory $inv)
        if ($scoredAll.Count -eq 0) {
            Write-CcdcLog -Level INFO -Message "No ScoredServices list in the inventory or the answer file, so open ports can't be cross-checked against what SHOULD be open here. Run discovery (menu 1) or add a ScoredServices line to config\answers.local.psd1 for that next time."
        } else {
            $scoredForHost = Get-CcdcScoredServicesForHost -ScoredServices $scoredAll -HostName $Hostname
            $expectedPorts = New-Object System.Collections.Generic.List[int]
            foreach ($svc in $scoredForHost) {
                foreach ($p in (Resolve-CcdcServicePorts -ServiceName $svc)) { $expectedPorts.Add($p) }
            }
            foreach ($p in @(3389, 5985, 5986, 22)) { $expectedPorts.Add($p) } # common mgmt/admin ports, always allowed to be "expected"

            if (Test-Path -Path "$outputBase.txt") {
                $openPortLines = Get-Content -Path "$outputBase.txt" | Where-Object { $_ -match '^(\d+)/tcp\s+open' }
                $unexpected = New-Object System.Collections.Generic.List[string]
                foreach ($line in $openPortLines) {
                    if ($line -match '^(?<port>\d+)/tcp\s+open') {
                        $port = [int]$Matches.port
                        if (Test-CcdcUnexpectedOpenPort -Port $port -ExpectedPorts $expectedPorts) {
                            $unexpected.Add($line.Trim())
                        }
                    }
                }
                if ($unexpected.Count -gt 0) {
                    Write-CcdcLog -Level WARN -Message "Open port(s) not in your ScoredServices list or common mgmt ports -- worth a look:"
                    foreach ($u in $unexpected) { Write-CcdcLog -Level WARN -Message "  $u" }
                } else {
                    Write-CcdcLog -Level OK -Message "Every open port found matches something in your ScoredServices list or common mgmt ports."
                }
            }
        }
    } else {
        Write-CcdcLog -Level ERROR -Message "nmap exited with a non-zero code or failed to run -- check $outputBase.txt if it exists."
    }
}

} finally {
    if ($scriptArgsFilePath -and (Test-Path -Path $scriptArgsFilePath -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $scriptArgsFilePath -Force -ErrorAction SilentlyContinue
    }
    Show-CcdcSummary
    Stop-CcdcSession
}
