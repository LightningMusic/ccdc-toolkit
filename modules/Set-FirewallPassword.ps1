#Requires -Version 5.1
<#
.SYNOPSIS
    Changes a Palo Alto (PAN-OS) administrator's password over SSH -- built
    the day before the Invitational, after red team was found running an
    SSH script against default credentials (router and firewall both).

.DESCRIPTION
    Uses Windows' own built-in OpenSSH client (ssh.exe) -- no new software,
    no new dependency; it ships with Windows 10/11/Server 2019+ by default.
    Feeds PAN-OS's own CLI command for this over stdin, exactly as if
    someone had typed it: configure, set mgt-config users <name> password
    (which itself then prompts for the new password twice), commit, exit.
    PAN-OS stores one credential shared by the CLI and the web admin UI --
    changing it here changes both, confirmed directly against this team's
    own device, not assumed.

    The username is NEVER changed -- competition rules forbid that; only
    the password does.

    LOWER CONFIDENCE THAN Set-RouterPassword.ps1, SAY SO PLAINLY: PAN-OS's
    password prompt is a masked, character-level read, not a simple
    line-buffered one like VyOS's. Piping the new password to it over SSH
    SHOULD work the same way (this is a documented, commonly used PAN-OS
    automation pattern), but this has not been live-tested against a real
    PAN-OS device as of writing this -- test it once, deliberately, before
    relying on it under pressure. If it does anything other than cleanly
    confirm success, STOP and use the Web UI fallback instead (Device >
    Administrators > click the account > enter the new password > OK >
    Commit) rather than retrying blind against a firewall.

    Refuses a password containing ' " $ ` or ! for the same reason as the
    router script: PAN-OS's underlying shell is bash-derived (the same
    history-expansion risk for !), and the other three would break this
    script's own command construction. Every other symbol is fine.

.PARAMETER FirewallHost
    The firewall's management IP or hostname. Not defaulted --
    deliberately nothing environment-specific is hardcoded in this repo.

.PARAMETER Username
    The PAN-OS administrator account to change. Defaults to 'admin', the
    documented default account.

.PARAMETER NewPassword
    The new password, as a SecureString. Omit it and this prompts twice
    (typed, masked) instead -- the safer default, since Start-Transcript
    records a bare Read-Host verbatim.

.PARAMETER Generate
    Skip the prompt and generate a strong random password instead. Prints
    it once, to the console and this session's transcript -- write it down
    immediately, it is not shown again and is not recoverable from here.

.EXAMPLE
    .\Set-FirewallPassword.ps1 -FirewallHost 172.16.0.1
    Prompts for the new password (twice, masked), then changes it over SSH.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$FirewallHost,
    [string]$Username = 'admin',
    [securestring]$NewPassword,
    [switch]$Generate
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$root = Split-Path -Parent $PSScriptRoot
$session = Start-CcdcSession -RootPath $root

Write-CcdcLog -Level WARN -Message "Changing the PAN-OS password for '$Username' on $FirewallHost. This does NOT touch the username -- only passwords may change mid-competition. This script is lower-confidence than the VyOS one -- see its own header comment -- watch the output closely."

if (-not (Get-Command -Name ssh.exe -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level ERROR -Message "ssh.exe (Windows' built-in OpenSSH client) isn't on PATH. It normally ships by default on Windows 10/11/Server 2019+; if this box genuinely doesn't have it: Get-WindowsCapability -Online -Name 'OpenSSH.Client*' | Add-WindowsCapability -Online"
    Stop-CcdcSession
    return
}

$plainPassword = $null
if ($Generate) {
    do { $plainPassword = New-CcdcRandomPassword } while ($plainPassword -like '*!*')
    Write-CcdcLog -Level WARN -Message "Generated password for '$Username': $plainPassword -- write this down now. It will not be shown again."
} elseif ($NewPassword) {
    $plainPassword = ConvertFrom-CcdcSecureStringPlain -Secure $NewPassword
} else {
    $first = Read-Host -Prompt "New password for '$Username' on $FirewallHost" -AsSecureString
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
    Write-CcdcLog -Level ERROR -Message "That password contains a character this script can't safely carry through to PAN-OS's shell ($($found -join ' ')). Avoid: ' `" `$ ``` ! -- every other symbol is fine. Pick a different password, or use -Generate. Nothing was changed."
    Stop-CcdcSession
    return
}

# 'set mgt-config users <name> password' itself prompts twice more (new,
# then confirm) -- those are the next two lines fed over stdin, not part
# of the command text itself.
$remoteCommands = @"
configure
set mgt-config users $Username password
$plainPassword
$plainPassword
commit
exit
"@

if ($PSCmdlet.ShouldProcess("$Username@$FirewallHost", 'Change PAN-OS administrator password over SSH')) {
    Write-CcdcLog -Level ACTION -Message "Connecting to $FirewallHost over SSH as '$Username'..."
    # StrictHostKeyChecking=no: see Set-RouterPassword.ps1's identical note
    # -- a first-contact management connection with no known_hosts entry
    # would otherwise hang on an unanswerable interactive prompt.
    $outcome = Invoke-CcdcSafe -Target $FirewallHost -Action 'change PAN-OS password over SSH' -ScriptBlock {
        $remoteCommands | & ssh.exe -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$Username@$FirewallHost"
        if ($LASTEXITCODE -ne 0) { throw "ssh.exe exited with code $LASTEXITCODE -- the commands above may not all have applied." }
    }
    if ($outcome.Success) {
        Write-CcdcLog -Level OK -Message "Commands sent and ssh.exe exited cleanly. VERIFY by logging into the Web UI with the new password before walking away -- read back through the console output above first; if 'commit' doesn't show success there, the change did not take even though ssh.exe itself exited cleanly."
    } else {
        Write-CcdcLog -Level ERROR -Message "Use the Web UI fallback instead: Device > Administrators > click '$Username' > enter the new password > OK > Commit (top right). Don't retry this script blind against a firewall."
    }
}

Show-CcdcSummary
Stop-CcdcSession
