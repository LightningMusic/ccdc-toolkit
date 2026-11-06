#Requires -Version 5.1
<#
.SYNOPSIS
    Entry point. Run this from an elevated PowerShell prompt after cloning
    the repo onto a competition box: .\Invoke-CCDCToolkit.ps1

.DESCRIPTION
    A numbered menu over the modules in .\modules — nothing in here does
    anything on its own beyond discovery (read-only) until you pick an
    action. Each module also runs standalone if you'd rather call it
    directly with its own parameters (see the comment-based help in each
    file, e.g. Get-Help .\modules\Invoke-FirewallBaseline.ps1 -Full).

    Everything this script (and the modules it calls) does is logged to
    .\logs\session_<timestamp>.log in plain text, and anything destructive
    is backed up to .\logs\backups\<timestamp>\ first. See README.md for
    the full design philosophy.
#>
[CmdletBinding()]
param()

$root = $PSScriptRoot
$modulesPath = Join-Path $root 'modules'

Import-Module (Join-Path $modulesPath 'Common.psm1') -Force

function Show-Banner {
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  CCDC TOOLKIT" -ForegroundColor Cyan
    Write-Host "  Public repo. No environment-specific values are ever" -ForegroundColor Cyan
    Write-Host "  hardcoded here — everything comes from discovery," -ForegroundColor Cyan
    Write-Host "  config\answers.local.psd1 (gitignored), or a prompt." -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    Write-Host "  [1] Run environment discovery       (read-only, safe to run anytime)"
    Write-Host "  [2] Preview credential hardening    (-WhatIf, changes nothing)"
    Write-Host "  [3] Run credential hardening        (resets passwords for real)"
    Write-Host "  [4] Preview firewall baseline       (-WhatIf, changes nothing)"
    Write-Host "  [5] Run firewall baseline           (locks down the firewall for real)"
    Write-Host "  [6] Install/update Sysmon           (low-risk, no firewall/account changes)"
    Write-Host "  [7] Install/update Splunk forwarder (needs a .msi staged in tools\SplunkForwarder\)"
    Write-Host "  [8] Open the logs folder location"
    Write-Host "  [9] Run one threat-hunt pass          (read-only, safe to run anytime)"
    Write-Host "  [10] Admin console                    (fast ad-hoc changes -- injects, mostly)"
    Write-Host "  [11] Write an incident report          (scaffolds one against the scoring rubric)"
    Write-Host "  [12] Network recon (nmap wrapper)      (loud/slow -- run pre-comp, not during the round)"
    Write-Host "  [13] Packet capture (tshark wrapper)   (grabs evidence, read-only otherwise)"
    Write-Host "  [14] AD hardening & audit              (DOMAIN-WIDE -- accounts, GPO, password policy)"
    Write-Host "  [15] IIS/FTP audit                     (read-only -- web shells, what to put in the answer file)"
    Write-Host "  [16] IIS/FTP hardening                 (audit, then turns off directory browsing etc.)"
    Write-Host "  [17] Capture a config baseline         (read-only -- record how this box looks when it is right)"
    Write-Host "  [18] Verify against the baseline       (read-only -- what has changed since, and renamed files)"
    Write-Host "  [19] Known-exploit audit               (read-only -- the things red team reaches for first)"
    Write-Host "  [20] Close the safe known-exploit gaps (changes settings; each one backed up and explained)"
    Write-Host "  [21] DNS audit                         (read-only -- zone transfers, dynamic updates, odd records)"
    Write-Host "  [22] DNS hardening                     (refuses zone transfers, secures updates, hardens the cache)"
    Write-Host "  [23] Collect evidence                  (read-only -- event logs, a TCP snapshot, Splunk forwarder's own logs)"
    Write-Host ""
    Write-Host "  [W] Open the toolkit WINDOW            (health dashboard, scored services, accounts, services)" -ForegroundColor Cyan
    Write-Host "  [Q] Quit"
    Write-Host ""
}

function Confirm-MenuAction {
    <#
    .SYNOPSIS
        The menu's "type YES" gate. With -ShowTarget it first prints the
        target-check block (host, domain, DC or not, who you're running as,
        elevation, inventory age, protected accounts) so a wrong-box mistake
        gets caught BEFORE the YES, and tells the module it launches not to
        print the same block again.
    #>
    param([string]$Message, [switch]$ShowTarget)
    if ($ShowTarget) {
        Show-CcdcTargetContext -RootPath $root | Out-Null
        $env:CCDC_TARGET_SHOWN = '1'
    }
    Write-Host "$Message Type YES to continue: " -NoNewline -ForegroundColor Yellow
    return ((Read-CcdcInput) -eq 'YES')
}
function Invoke-MenuAction {
    param([scriptblock]$Action)
    try {
        & $Action
    } catch {
        Write-CcdcLog -Level ERROR -Message "Menu action threw an unhandled error: $($_.Exception.Message)"
        Write-CcdcLog -Level INFO -Message "The menu is still alive — this failure didn't take down the whole toolkit. Check the log above, fix the underlying issue, and try again."
    }
    Write-Host ""
    Read-Host "Press Enter to return to the menu" | Out-Null
}

Show-Banner

$configDir = Join-Path $root 'config'
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}
if (-not (Test-Path (Join-Path $root 'logs'))) {
    New-Item -ItemType Directory -Path (Join-Path $root 'logs') -Force | Out-Null
}
# config\ holds answers.local.psd1 -- restricted for the same reason
# Start-CcdcSession restricts logs\ (see Protect-CcdcSensitiveFolder in
# Common.psm1): best-effort, harmless if it can't apply.
Protect-CcdcSensitiveFolder -Path $configDir

$answersTemplate = Join-Path $configDir 'answers.template.psd1'
$answersLocal = Join-Path $configDir 'answers.local.psd1'
if ((Test-Path $answersTemplate) -and -not (Test-Path $answersLocal)) {
    Write-Host "No config\answers.local.psd1 yet — copy config\answers.template.psd1 to config\answers.local.psd1 and fill it in from your prep sheet if you don't want to be prompted for the same values every run." -ForegroundColor Yellow
    Write-Host ""
}

:menuLoop while ($true) {
    $env:CCDC_TARGET_SHOWN = $null
    Show-Menu
    $choice = Read-Host 'Choice'

    if ($null -eq $choice) {
        # Read-Host returns $null (rather than throwing) when there's no
        # console to read from — e.g. run non-interactively by mistake, or
        # stdin closed. Without this check the switch below throws on
        # $null.Trim() every loop iteration forever. Exit cleanly instead.
        Write-CcdcLog -Level ERROR -Message "Couldn't read input (no interactive console available). Exiting instead of looping forever."
        break menuLoop
    }

    switch ($choice.Trim().ToUpperInvariant()) {
        '1' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Get-EnvironmentInventory.ps1') }
        }
        '2' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-CredentialHardening.ps1') -WhatIf }
        }
        '3' {
            if (Confirm-MenuAction "This will change real passwords." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-CredentialHardening.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '4' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-FirewallBaseline.ps1') -WhatIf }
        }
        '5' {
            if (Confirm-MenuAction "This will change real firewall rules and can affect connectivity (there's a self-reverting safety net, but read the module's help first if this is your first run)." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-FirewallBaseline.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '6' {
            if (Confirm-MenuAction "This installs/reconfigures Sysmon for real (low risk, but it does install a driver and touch system state)." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Install-Sysmon.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '7' {
            if (Confirm-MenuAction "This installs/reconfigures the Splunk forwarder for real and restarts its service." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Install-SplunkForwarder.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '8' {
            Write-Host "Logs: $(Join-Path $root 'logs')"
            Write-Host ""
        }
        '9' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-ThreatHunt.ps1') }
        }
        '10' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-AdminConsole.ps1') }
        }
        '11' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'New-IncidentReport.ps1') }
        }
        '12' {
            if (Confirm-MenuAction "Scans are loud and slow -- run this pre-competition to find your own holes, not during the round (a Vuln-profile scan in particular looks like exactly the traffic your own team should be hunting for)." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-NetworkRecon.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '13' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-PacketCapture.ps1') }
        }
        '14' {
            if (Confirm-MenuAction "This is DOMAIN-WIDE, not per-host -- it can disable accounts, create a Domain Admin account, and change GPO/password policy for the whole domain. Run -WhatIf first if this is your first time (call the module directly: .\modules\Invoke-ADHardening.ps1 -WhatIf)." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-ADHardening.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '15' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-IISHardening.ps1') -ReportOnly }
        }
        '16' {
            if (Confirm-MenuAction "This audits IIS and then changes settings on it (directory browsing, identifying headers). It takes an IIS configuration backup first and tells you the one command that undoes everything." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-IISHardening.ps1') }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '17' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-ConfigBaseline.ps1') -Action Capture }
        }
        '18' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-ConfigBaseline.ps1') -Action Verify }
        }
        '19' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-ExploitAudit.ps1') }
        }
        '20' {
            if (Confirm-MenuAction "This changes real security settings (WDigest, SMBv1, LLMNR, NetBIOS, NTLM level, Guest, RDP NLA and more). Each one is backed up first and only the changes marked safe are applied -- run option 19 first and read what each can break." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-ExploitAudit.ps1') -Fix }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '21' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-DnsHardening.ps1') }
        }
        '22' {
            if (Confirm-MenuAction "This refuses zone transfers, sets AD-integrated zones to secure dynamic updates, and hardens the DNS cache. DNS is a SCORED service -- run option 21 first and read it. Recursion is deliberately NOT touched here." -ShowTarget) {
                Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-DnsHardening.ps1') -SecureZoneTransfers -SecureDynamicUpdates -HardenCache }
            } else {
                Write-Host "Cancelled." -ForegroundColor Yellow
            }
        }
        '23' {
            Invoke-MenuAction { & (Join-Path $modulesPath 'Invoke-EvidenceCollection.ps1') }
        }
        'W' {
            # Its own process on purpose: the window runs its own message loop,
            # which would block this menu until it closed, and WPF needs STA.
            $uiScript = Join-Path (Join-Path $root 'ui') 'Start-CcdcConsole.ps1'
            if (-not (Test-Path -LiteralPath $uiScript)) {
                Write-Host "Can't find $uiScript -- this copy of the repo is incomplete." -ForegroundColor Red
            } else {
                $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                Start-Process -FilePath $psExe -ArgumentList '-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$uiScript`"", '-NoRelaunch'
                Write-Host "Opening the toolkit window. It runs on its own, so this menu stays usable." -ForegroundColor Cyan
                Write-Host "(No window? The box may be Server Core, which has no desktop -- use the numbered options here instead.)" -ForegroundColor Yellow
                Write-Host ""
            }
        }
        'Q' { break menuLoop }
        default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
    }
}

Write-Host "Done. Logs and any backups from this session are under .\logs\" -ForegroundColor Cyan
