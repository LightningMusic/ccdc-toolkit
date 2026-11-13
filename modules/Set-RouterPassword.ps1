#Requires -Version 5.1
<#
.SYNOPSIS
    Changes the VyOS router's login password over SSH -- built the day
    before the Invitational, after red team was found running an SSH
    script against the router's default credentials.

.DESCRIPTION
    Uses Windows' own built-in OpenSSH client (ssh.exe) -- no new software,
    no new dependency; it ships with Windows 10/11/Server 2019+ by default.
    Feeds the VyOS configuration commands to the remote CLI over stdin,
    exactly as if someone had typed them: configure, set the new password,
    commit, save, exit. -tt forces ssh to allocate a real pseudo-terminal
    even though stdin here is redirected -- VyOS's CLI needs that to behave
    the way it does for a real interactive session.

    The username is NEVER changed -- competition rules forbid that; only
    the password does.

    Refuses a password containing ' " $ ` or ! -- VyOS's underlying shell
    is bash-derived and a bare ! in a piped command can trigger bash
    history expansion ("event not found") instead of landing in the
    password literally, and the other four would break either this
    script's own command construction or the single-quoting it wraps the
    password in on the remote side. Every other symbol is fine.

    Not live-tested against a real VyOS device as of writing this --
    ssh.exe piping commands to an interactive-mode CLI is a well-established
    pattern, but test this against your actual router BEFORE trusting it
    under pressure, and have a console/physical-access fallback ready in
    case it doesn't behave the way this expects on your specific build.

.PARAMETER RouterHost
    The VyOS router's management IP or hostname. Not defaulted --
    deliberately nothing environment-specific is hardcoded in this repo.

.PARAMETER Username
    The VyOS login account to change. Defaults to 'vyos', the documented
    default account -- change this if your team already renamed it.

.PARAMETER NewPassword
    The new password, as a SecureString. Omit it and this prompts twice
    (typed, masked) instead -- the safer default, since Start-Transcript
    records a bare Read-Host verbatim.

.PARAMETER Generate
    Skip the prompt and generate a strong random password instead. Prints
    it once, to the console and this session's transcript -- write it down
    immediately, it is not shown again and is not recoverable from here.

.EXAMPLE
    .\Set-RouterPassword.ps1 -RouterHost 172.16.0.2
    Prompts for the new password (twice, masked), then changes it over SSH.

.EXAMPLE
    .\Set-RouterPassword.ps1 -RouterHost 172.16.0.2 -Generate
    Generates a new password, prints it once, and applies it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$RouterHost,
    [string]$Username = 'vyos',
    [securestring]$NewPassword,
    [switch]$Generate
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$root = Split-Path -Parent $PSScriptRoot
$session = Start-CcdcSession -RootPath $root

Write-CcdcLog -Level WARN -Message "Changing the VyOS login password for '$Username' on $RouterHost. This does NOT touch the username -- only passwords may change mid-competition."

if (-not (Get-Command -Name ssh.exe -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level ERROR -Message "ssh.exe (Windows' built-in OpenSSH client) isn't on PATH. It normally ships by default on Windows 10/11/Server 2019+; if this box genuinely doesn't have it: Get-WindowsCapability -Online -Name 'OpenSSH.Client*' | Add-WindowsCapability -Online"
    Stop-CcdcSession
    return
}

$plainPassword = $null
if ($Generate) {
    # New-CcdcRandomPassword's symbol set can include '!', which is fine for
    # Windows/AD accounts but unsafe here -- see the validation below, which
    # this also has to pass.
    do { $plainPassword = New-CcdcRandomPassword } while ($plainPassword -like '*!*')
    Write-CcdcLog -Level WARN -Message "Generated password for '$Username': $plainPassword -- write this down now. It will not be shown again."
} elseif ($NewPassword) {
    $plainPassword = ConvertFrom-CcdcSecureStringPlain -Secure $NewPassword
} else {
    $first = Read-Host -Prompt "New password for '$Username' on $RouterHost" -AsSecureString
    $confirm = Read-Host -Prompt 'Type it again to confirm' -AsSecureString
    $firstPlain = ConvertFrom-CcdcSecureStringPlain -Secure $first
    $confirmPlain = ConvertFrom-CcdcSecureStringPlain -Secure $confirm
    if ($firstPlain -ne $confirmPlain) {
        Write-CcdcLog -Level ERROR -Message "Those two entries didn't match. Nothing was changed -- run this again."
        Stop-CcdcSession
        return
    }
    $plainPassword = $firstPlain
}

if (-not $plainPassword) {
    Write-CcdcLog -Level ERROR -Message 'No password to apply. Nothing changed.'
    Stop-CcdcSession
    return
}

$unsafeChars = @("'", '"', '$', '`', '!')
$found = @($unsafeChars | Where-Object { $plainPassword.Contains($_) })
if ($found.Count -gt 0) {
    Write-CcdcLog -Level ERROR -Message "That password contains a character this script can't safely carry through to VyOS's shell ($($found -join ' ')). Avoid: ' `" `$ ``` ! -- every other symbol is fine. Pick a different password, or use -Generate. Nothing was changed."
    Stop-CcdcSession
    return
}

# Sent to the remote CLI over stdin, one line at a time, exactly as if
# someone had typed it at the console.
$remoteCommands = @"
configure
set system login user $Username authentication plaintext-password '$plainPassword'
commit
save
exit
"@

if ($PSCmdlet.ShouldProcess("$Username@$RouterHost", 'Change VyOS login password over SSH')) {
    Write-CcdcLog -Level ACTION -Message "Connecting to $RouterHost over SSH as '$Username'..."
    # StrictHostKeyChecking=no: this is a first-contact management
    # connection with no prior known_hosts entry on most boxes that would
    # run this script, and the interactive "are you sure (yes/no)" prompt
    # ssh would otherwise print cannot be answered once stdin is already
    # feeding it the config commands above -- it would just hang. Accepted
    # deliberately for this internal management link, not a general
    # recommendation.
    $outcome = Invoke-CcdcSafe -Target $RouterHost -Action 'change VyOS password over SSH' -ScriptBlock {
        $remoteCommands | & ssh.exe -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$Username@$RouterHost"
        if ($LASTEXITCODE -ne 0) { throw "ssh.exe exited with code $LASTEXITCODE -- the commands above may not all have applied." }
    }
    if ($outcome.Success) {
        Write-CcdcLog -Level OK -Message "Password-change commands sent and ssh.exe exited cleanly. VERIFY by logging in with the new password before walking away -- a config that looked like it went through but didn't commit/save is the worst version of this to find out about later."
    } else {
        Write-CcdcLog -Level ERROR -Message "Log in manually (console if SSH itself is now in doubt) and check: show configuration commands | match login"
    }
}

Show-CcdcSummary
Stop-CcdcSession
