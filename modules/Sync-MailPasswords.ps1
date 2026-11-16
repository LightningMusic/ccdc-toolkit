#Requires -Version 5.1
<#
.SYNOPSIS
    Pushes AD password rotations out to a Linux mail server's own,
    separate local accounts -- built after finding (2026-11-16 debrief)
    that a Fedora mail box authenticating webmail/IMAP/POP3 is NOT
    AD-joined: it has its OWN local Unix passwords per user, so rotating
    an AD account's password does nothing for the mail server, and the
    scored webmail/IMAP/POP3 check (which logs in "using usernames from
    Active Directory," per the official team pack) breaks the instant
    the two drift apart.

.DESCRIPTION
    Reads the SAME headerless username,password PCR file
    Invoke-CredentialHardening.ps1 already writes (logs\credentials_*_pcr.csv)
    -- no separate credential list to keep in sync by hand -- and pushes
    every row to the mail server in ONE SSH session using `chpasswd`,
    the standard Linux tool for exactly this: non-interactive, batch,
    reads "user:password" lines from stdin. This is deliberately NOT the
    per-account interactive `passwd` dance -- chpasswd has no sub-prompt
    to read from the wrong place, which is exactly the class of bug that
    made the PAN-OS password script hang (see Set-FirewallPassword.ps1's
    header). One connection handles however many accounts are in the
    file, which matters here: this environment had 700+ AD accounts.

    chpasswd only sets passwords for accounts that ALREADY exist locally
    on the mail server -- it never creates one. An account in the PCR
    file with no matching mail-server account is reported, not silently
    dropped, but otherwise harmless: chpasswd itself just skips it.

    Connects as -Username (default root, matching this script's own
    class of emergency device script elsewhere in this toolkit). If you
    connect as a non-root sudo-capable account instead, pass
    -SudoPassword and this uses `sudo -S chpasswd`, which reads the sudo
    password from the SAME stdin stream rather than from the controlling
    terminal -- the one thing that would otherwise risk the same
    tty-vs-pipe deadlock PAN-OS hit.

    Passwords are never printed to the console or written to this
    session's transcript -- only a per-account success/skipped summary.

.PARAMETER MailHost
    The mail server's management IP or hostname.

.PARAMETER Username
    The SSH login account. Defaults to 'root'. If this account is not
    root, pass -SudoPassword too.

.PARAMETER SudoPassword
    Only needed if -Username is not root and that account needs a sudo
    password (not passwordless sudo). SecureString.

.PARAMETER PcrCsvPath
    Path to a headerless "username,password" file -- defaults to the
    newest logs\credentials_*_pcr.csv Invoke-CredentialHardening.ps1
    already produced.

.EXAMPLE
    .\Sync-MailPasswords.ps1 -MailHost 172.20.240.15
    Pushes the newest credential-hardening PCR file to the mail server, connecting as root.

.EXAMPLE
    .\Sync-MailPasswords.ps1 -MailHost 172.20.240.15 -Username sysadmin -PcrCsvPath .\logs\credentials_2026-11-14_080000_pcr.csv
    Connects as a non-root account; prompts for its sudo password since none was given.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$MailHost,
    [string]$Username = 'root',
    [securestring]$SudoPassword,
    [string]$PcrCsvPath
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$root = Split-Path -Parent $PSScriptRoot
$session = Start-CcdcSession -RootPath $root

Write-CcdcLog -Level WARN -Message "Syncing local mail-server passwords on $MailHost to match AD, as '$Username'. This changes LOGIN passwords, not usernames."

if (-not (Get-Command -Name ssh.exe -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level ERROR -Message "ssh.exe (Windows' built-in OpenSSH client) isn't on PATH. It normally ships by default on Windows 10/11/Server 2019+; if this box genuinely doesn't have it: Get-WindowsCapability -Online -Name 'OpenSSH.Client*' | Add-WindowsCapability -Online"
    Stop-CcdcSession
    return
}

# ---------------------------------------------------------------------------
# 1. Find the PCR file -- same convention Invoke-CredentialHardening.ps1 uses.
# ---------------------------------------------------------------------------
if (-not $PcrCsvPath) {
    $found = @(Get-ChildItem -Path (Join-Path $root 'logs') -Filter 'credentials_*_pcr.csv' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($found.Count -eq 0) {
        Write-CcdcLog -Level ERROR -Message "No logs\credentials_*_pcr.csv found, and no -PcrCsvPath given. Run Invoke-CredentialHardening.ps1 first, or pass the path explicitly. Nothing changed."
        Stop-CcdcSession
        return
    }
    $PcrCsvPath = $found[0].FullName
    Write-CcdcLog -Level INFO -Message "Using the newest PCR file: $PcrCsvPath"
}

if (-not (Test-Path -LiteralPath $PcrCsvPath)) {
    Write-CcdcLog -Level ERROR -Message "$PcrCsvPath does not exist. Nothing changed."
    Stop-CcdcSession
    return
}

# ---------------------------------------------------------------------------
# 2. Parse it -- headerless "account,password" (Invoke-CredentialHardening.ps1
#    never quotes or escapes either field, so a plain split on the FIRST
#    comma is exactly how it was written).
# ---------------------------------------------------------------------------
$pairs = New-Object System.Collections.Generic.List[object]
$badLines = 0
foreach ($line in (Get-Content -LiteralPath $PcrCsvPath -ErrorAction Stop)) {
    if (-not $line.Trim()) { continue }
    $idx = $line.IndexOf(',')
    if ($idx -lt 1 -or $idx -eq ($line.Length - 1)) { $badLines++; continue }
    $account = $line.Substring(0, $idx)
    $password = $line.Substring($idx + 1)
    # chpasswd's own format is "user:password" -- a colon in either field
    # would corrupt the line, and our own password generator never
    # produces one, so a colon here means something is wrong upstream,
    # not a value to carry through blind.
    if ($account.Contains(':') -or $password.Contains(':') -or $password.Contains("`n")) { $badLines++; continue }
    $pairs.Add([pscustomobject]@{ Account = $account; Password = $password })
}

if ($badLines -gt 0) {
    Write-CcdcLog -Level WARN -Message "$badLines line(s) in $PcrCsvPath didn't parse as 'account,password' or contained a character chpasswd can't carry -- skipped, not guessed at."
}
if ($pairs.Count -eq 0) {
    Write-CcdcLog -Level ERROR -Message "No usable account,password rows found in $PcrCsvPath. Nothing changed."
    Stop-CcdcSession
    return
}

Write-CcdcLog -Level INFO -Message "$($pairs.Count) account(s) queued to sync on $MailHost."

# ---------------------------------------------------------------------------
# 3. Push them, one SSH session, one chpasswd call -- not one connection
#    per account. This is the whole reason chpasswd is the right tool
#    here instead of looping `passwd` once per user.
# ---------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess("$Username@$MailHost", "chpasswd $($pairs.Count) account(s)")) {
    $chpasswdLines = ($pairs | ForEach-Object { "$($_.Account):$($_.Password)" }) -join "`n"
    $remoteCommand = 'chpasswd'
    $stdinContent = $chpasswdLines
    if ($Username -ne 'root') {
        # sudo -S reads ITS OWN password from stdin instead of the
        # controlling terminal -- the exact fix for the tty-vs-pipe
        # deadlock Set-FirewallPassword.ps1's header describes hitting
        # live against PAN-OS. Passwordless sudo also works fine here:
        # sudo just finds nothing to read and proceeds.
        $remoteCommand = 'sudo -S chpasswd'
        $effectiveSudoPassword = $SudoPassword
        if (-not $effectiveSudoPassword) {
            $effectiveSudoPassword = Read-Host -Prompt "Sudo password for '$Username' on $MailHost (blank if it has passwordless sudo)" -AsSecureString
        }
        $sudoPlain = ''
        if ($effectiveSudoPassword) { $sudoPlain = ConvertFrom-CcdcSecureStringPlain -Secure $effectiveSudoPassword }
        $stdinContent = "$sudoPlain`n$chpasswdLines"
    }

    Write-CcdcLog -Level ACTION -Message "Connecting to $MailHost over SSH as '$Username'..."
    $outcome = Invoke-CcdcSafe -Target $MailHost -Action "chpasswd $($pairs.Count) account(s)" -ScriptBlock {
        $result = $stdinContent | & ssh.exe -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$Username@$MailHost" $remoteCommand 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "ssh.exe exited with code $LASTEXITCODE. Output:`n$result" }
        $result
    }

    if ($outcome.Success) {
        $output = "$($outcome.Value)"
        $missing = @([regex]::Matches($output, "(?i)user ['""]?([^'""\s]+)['""]? does not exist") | ForEach-Object { $_.Groups[1].Value })
        $missing = @($missing | Select-Object -Unique)
        $syncedCount = $pairs.Count - $missing.Count
        Write-CcdcLog -Level OK -Message "$syncedCount of $($pairs.Count) account(s) synced on $MailHost."
        if ($missing.Count -gt 0) {
            Write-CcdcLog -Level WARN -Message "$($missing.Count) account(s) have no matching local account on $MailHost, so nothing changed for them: $($missing -join ', ')"
        }
        Write-CcdcLog -Level INFO -Message "VERIFY by logging into webmail/IMAP with one of the new passwords before walking away."
    } else {
        Write-CcdcLog -Level ERROR -Message "The sync failed -- see the error above. No account on $MailHost is confirmed changed; check manually before assuming any of them took."
    }
}

Show-CcdcSummary
Stop-CcdcSession
