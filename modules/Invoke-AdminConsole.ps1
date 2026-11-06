#Requires -Version 5.1
<#
.SYNOPSIS
    The "one place to make any change fast" tool — a menu-driven console
    over the common ad-hoc AD/local-system admin actions an inject can ask
    for, so you're picking from a readable list instead of hunting for the
    right raw command under time pressure.

.DESCRIPTION
    This is the module built for injects specifically: they can ask for
    almost anything, so this isn't one narrow tool, it's a categorized menu
    of small, consistent actions (create/reset/disable an account, flip a
    service, add a DNS record, adjust a firewall rule, block a malicious
    IP or sinkhole a domain, change a folder's permissions, and so on),
    all built on the exact same safety pattern as
    everything else in this toolkit — confirm before it does anything,
    back up what it can before changing existing state, log every attempt
    in plain English, never crash the whole console because one action
    failed.

    It cannot cover literally everything — nothing could. When an inject
    asks for something with no matching action here, use option 9 (Run a
    custom command), which runs whatever one-liner you type through the
    same logging/error-handling wrapper as everything else, so you still
    get a clean plain-English result and a transcript entry instead of a
    raw PowerShell error dump. It does NOT get an automatic backup first
    (there's no way to know what state to save for an arbitrary command),
    so prefer a purpose-built action when one exists — the whole point of
    building this out over time is that fewer injects need the escape
    hatch.

    A deliberate exception to this toolkit's usual "never call Read-Host
    directly, always go through Get-CcdcAnswer" rule: Get-CcdcAnswer exists
    for environment CONFIGURATION — values that are genuinely reusable
    across a whole run (domain name, a default OU). Almost everything this
    console asks for is fresh, one-off operational input ("which account,
    this time") that has no business living in an answer file, so those
    prompts use Read-Host directly, the same way the main menu's own
    choice prompt does. The few genuinely reusable values here (DomainName,
    DefaultOU) still go through Get-CcdcAnswer.

    Every account/password this console creates or resets is logged to
    logs\admin-console-credentials_<session>.csv — gitignored, same as
    every other credential file this toolkit produces.

.EXAMPLE
    .\Invoke-AdminConsole.ps1
    Opens the console. Also reachable as option 10 from the main menu.
#>
[CmdletBinding()]
param()

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Admin console starting. One place for fast ad-hoc changes — mostly for injects. Read every confirmation line before typing YES; this can make real changes."
Assert-CcdcElevated -Because "most of this console's actions (accounts, services, scheduled tasks, firewall rules, GPOs) need admin rights"

$consoleCredLog = Join-Path $session.LogRoot "admin-console-credentials_$($session.Stamp).csv"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

function Save-ConsoleCredential {
    param([string]$Target, [string]$Value, [string]$Kind)
    try {
        [pscustomobject]@{
            Timestamp = (Get-Date -Format 'o')
            Target    = $Target
            Kind      = $Kind
            Value     = $Value
        } | Export-Csv -Path $consoleCredLog -NoTypeInformation -Append
    } catch {
        Write-CcdcLog -Level WARN -Message "Couldn't write to the console credential log ($($_.Exception.Message)) — copy this down by hand right now: $Target -> $Value"
    }
}

function Confirm-CcdcAction {
    <#
    .SYNOPSIS
        The one confirmation gate every state-changing console action uses.
        Shows exactly what's about to happen and requires typing YES.
    #>
    param([Parameter(Mandatory)][string]$Description)
    Write-Host "$Description Type YES to continue: " -NoNewline -ForegroundColor Yellow
    return (Read-CcdcInput) -eq 'YES'
}

# -- Input validation (Test-CcdcValidPort / Test-CcdcValidIPv4 /
#    Test-CcdcValidFileSystemRight) lives in modules\CcdcLogic.ps1 -----




# -- Cmdlet-availability guards, one per subsystem this console touches ----

function Test-CcdcAdAvailable {
    if (-not (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "AD cmdlets aren't available on this box (not domain-joined, or RSAT's ActiveDirectory module isn't installed)."
        return $false
    }
    return $true
}
function Test-CcdcLocalUserAvailable {
    if (-not (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "Get-LocalUser isn't available on this box (older Windows/WMF version)."
        return $false
    }
    return $true
}
function Test-CcdcServiceCmdletsAvailable {
    if (-not (Get-Command -Name Get-Service -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "Service cmdlets aren't available on this box."
        return $false
    }
    return $true
}
function Test-CcdcTaskCmdletsAvailable {
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "Get-ScheduledTask isn't available on this box."
        return $false
    }
    return $true
}
function Test-CcdcFirewallAvailable {
    if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "Get-NetFirewallRule isn't available on this box — this needs the NetSecurity module (Windows only)."
        return $false
    }
    return $true
}
function Test-CcdcDnsAvailable {
    if (-not (Get-Command -Name Get-DnsServerResourceRecord -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "DNS server cmdlets aren't available on this box (this needs the DnsServer module — usually only present on the DNS server itself)."
        return $false
    }
    return $true
}
function Test-CcdcGpoAvailable {
    if (-not (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "Get-GPO isn't available on this box (needs the GroupPolicy RSAT module)."
        return $false
    }
    return $true
}

# ---------------------------------------------------------------------------
# Active Directory — Users & Groups
# ---------------------------------------------------------------------------

function Invoke-AC-CreateADUser {
    if (-not (Test-CcdcAdAvailable)) { return }
    $given = Read-CcdcInput 'First name'
    $surname = Read-CcdcInput 'Last name'
    $sam = Read-CcdcInput 'SamAccountName (login name)'
    if (-not $sam) { Write-CcdcLog -Level WARN -Message 'No SamAccountName entered — cancelled.'; return }
    $domainName = Get-CcdcAnswer -Key 'DomainName' -Prompt "Domain name for this user's UPN (e.g. domain.local) — blank to skip UPN" -Default ''
    $ou = Get-CcdcAnswer -Key 'DefaultOU' -Prompt 'OU distinguished name for new users (blank = AD default location)' -Default ''
    $groupToJoin = Read-CcdcInput 'Group to add them to right away (blank = none)'

    if (-not (Confirm-CcdcAction "About to create AD user '$sam' ($given $surname).")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }

    $newPassword = New-CcdcRandomPassword
    $outcome = Invoke-CcdcSafe -Target $sam -Action 'create AD user' -ScriptBlock {
        $params = @{
            Name                  = "$given $surname".Trim()
            GivenName             = $given
            Surname               = $surname
            SamAccountName        = $sam
            AccountPassword       = (ConvertTo-SecureString $newPassword -AsPlainText -Force)
            Enabled               = $true
            ChangePasswordAtLogon = $false
            ErrorAction           = 'Stop'
        }
        if ($domainName) { $params['UserPrincipalName'] = "$sam@$domainName" }
        if ($ou) { $params['Path'] = $ou }
        New-ADUser @params
    }
    if ($outcome.Success) {
        Write-CcdcLog -Level OK -Message "Created AD user '$sam'. Password: $newPassword"
        Save-ConsoleCredential -Target $sam -Value $newPassword -Kind 'AD user create'
        if ($groupToJoin) {
            Invoke-CcdcSafe -Target $sam -Action "add to group '$groupToJoin'" -ScriptBlock {
                Add-ADGroupMember -Identity $groupToJoin -Members $sam -ErrorAction Stop
            } | Out-Null
        }
    }
}

function Invoke-AC-ResetADPassword {
    if (-not (Test-CcdcAdAvailable)) { return }
    $identity = Read-CcdcInput 'AD username (SamAccountName) to reset'
    if (-not $identity) { Write-CcdcLog -Level WARN -Message 'No username entered — cancelled.'; return }
    $lookup = Invoke-CcdcSafe -Target $identity -Action 'look up AD user before reset' -ScriptBlock {
        Get-ADUser -Identity $identity -ErrorAction Stop
    }
    if (-not $lookup.Success) { return }
    Backup-CcdcState -Name "adhoc-ADUser-$identity" -Data $lookup.Value | Out-Null

    if (-not (Confirm-CcdcAction "About to reset the password for AD user '$identity'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }

    $newPassword = New-CcdcRandomPassword
    $outcome = Invoke-CcdcSafe -Target $identity -Action 'reset AD user password' -ScriptBlock {
        Set-ADAccountPassword -Identity $identity -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset -ErrorAction Stop
    }
    if ($outcome.Success) {
        Write-CcdcLog -Level OK -Message "New password for '$identity': $newPassword"
        Save-ConsoleCredential -Target $identity -Value $newPassword -Kind 'AD user password reset'
    }
}

function Invoke-AC-ToggleADUser {
    if (-not (Test-CcdcAdAvailable)) { return }
    $identity = Read-CcdcInput 'AD username (SamAccountName)'
    if (-not $identity) { Write-CcdcLog -Level WARN -Message 'No username entered — cancelled.'; return }
    $action = Read-CcdcInput 'Enable or Disable this account? (E/D)'
    $lookup = Invoke-CcdcSafe -Target $identity -Action 'look up AD user before enable/disable' -ScriptBlock {
        Get-ADUser -Identity $identity -Properties Enabled -ErrorAction Stop
    }
    if (-not $lookup.Success) { return }
    Backup-CcdcState -Name "adhoc-ADUser-$identity" -Data $lookup.Value | Out-Null

    if ($action -match '^D') {
        if (-not (Confirm-CcdcAction "About to DISABLE AD user '$identity'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $identity -Action 'disable AD user' -ScriptBlock { Disable-ADAccount -Identity $identity -ErrorAction Stop } | Out-Null
    } elseif ($action -match '^E') {
        if (-not (Confirm-CcdcAction "About to ENABLE AD user '$identity'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $identity -Action 'enable AD user' -ScriptBlock { Enable-ADAccount -Identity $identity -ErrorAction Stop } | Out-Null
    } else {
        Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' as Enable or Disable — cancelled."
    }
}

function Invoke-AC-ADGroupMembership {
    if (-not (Test-CcdcAdAvailable)) { return }
    $identity = Read-CcdcInput 'AD username (SamAccountName)'
    $group = Read-CcdcInput 'Group name'
    $action = Read-CcdcInput 'Add or Remove from this group? (A/R)'
    if (-not $identity -or -not $group) { Write-CcdcLog -Level WARN -Message 'Username and group are both required — cancelled.'; return }

    $before = Invoke-CcdcSafe -Target $group -Action 'snapshot group membership before change' -ScriptBlock {
        Get-ADGroupMember -Identity $group -ErrorAction Stop | ForEach-Object { $_.SamAccountName }
    }
    if ($before.Success) { Backup-CcdcState -Name "adhoc-ADGroup-$group" -Data $before.Value | Out-Null }

    if ($action -match '^R') {
        if (-not (Confirm-CcdcAction "About to REMOVE '$identity' from group '$group'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $identity -Action "remove from group '$group'" -ScriptBlock {
            Remove-ADGroupMember -Identity $group -Members $identity -Confirm:$false -ErrorAction Stop
        } | Out-Null
    } elseif ($action -match '^A') {
        if (-not (Confirm-CcdcAction "About to ADD '$identity' to group '$group'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $identity -Action "add to group '$group'" -ScriptBlock {
            Add-ADGroupMember -Identity $group -Members $identity -ErrorAction Stop
        } | Out-Null
    } else {
        Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' as Add or Remove — cancelled."
    }
}

function Invoke-AC-ShowADUserInfo {
    if (-not (Test-CcdcAdAvailable)) { return }
    $identity = Read-CcdcInput 'AD username (SamAccountName) to look up'
    if (-not $identity) { return }
    $outcome = Invoke-CcdcSafe -Target $identity -Action 'look up AD user info' -ScriptBlock {
        $u = Get-ADUser -Identity $identity -Properties Enabled, LastLogonDate, MemberOf, PasswordLastSet, Created -ErrorAction Stop
        $groups = $u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
        [pscustomobject]@{
            Enabled         = $u.Enabled
            LastLogonDate   = $u.LastLogonDate
            PasswordLastSet = $u.PasswordLastSet
            Created         = $u.Created
            Groups          = ($groups -join ', ')
        }
    }
    if ($outcome.Success) {
        $i = $outcome.Value
        Write-Host ""
        Write-Host "  Enabled:          $($i.Enabled)"
        Write-Host "  Last logon:       $($i.LastLogonDate)"
        Write-Host "  Password set:     $($i.PasswordLastSet)"
        Write-Host "  Created:          $($i.Created)"
        Write-Host "  Groups:           $($i.Groups)"
        Write-Host ""
    }
}

function Show-ACMenu-AD {
    Write-Host ""
    Write-Host "-- Active Directory: Users & Groups --" -ForegroundColor Cyan
    Write-Host "  [1] Create AD user"
    Write-Host "  [2] Reset AD user password"
    Write-Host "  [3] Enable/Disable AD user"
    Write-Host "  [4] Add/Remove AD user to/from a group"
    Write-Host "  [5] Show AD user info (read-only)"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-AD {
    :adLoop while ($true) {
        Show-ACMenu-AD
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break adLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-CreateADUser }
            '2' { Invoke-AC-ResetADPassword }
            '3' { Invoke-AC-ToggleADUser }
            '4' { Invoke-AC-ADGroupMembership }
            '5' { Invoke-AC-ShowADUserInfo }
            'B' { break adLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Local users & groups
# ---------------------------------------------------------------------------

function Invoke-AC-CreateLocalUser {
    if (-not (Test-CcdcLocalUserAvailable)) { return }
    $name = Read-CcdcInput 'Local username to create'
    if (-not $name) { Write-CcdcLog -Level WARN -Message 'No username entered — cancelled.'; return }
    $groupToJoin = Read-CcdcInput 'Local group to add them to (blank = none)'
    if (-not (Confirm-CcdcAction "About to create local user '$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }

    $newPassword = New-CcdcRandomPassword
    $outcome = Invoke-CcdcSafe -Target $name -Action 'create local user' -ScriptBlock {
        New-LocalUser -Name $name -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force) -ErrorAction Stop
    }
    if ($outcome.Success) {
        Write-CcdcLog -Level OK -Message "Created local user '$name'. Password: $newPassword"
        Save-ConsoleCredential -Target $name -Value $newPassword -Kind 'local user create'
        if ($groupToJoin) {
            Invoke-CcdcSafe -Target $name -Action "add to local group '$groupToJoin'" -ScriptBlock {
                Add-LocalGroupMember -Group $groupToJoin -Member $name -ErrorAction Stop
            } | Out-Null
        }
    }
}

function Invoke-AC-ResetLocalPassword {
    if (-not (Test-CcdcLocalUserAvailable)) { return }
    $name = Read-CcdcInput 'Local username to reset'
    if (-not $name) { return }
    if (-not (Confirm-CcdcAction "About to reset the password for local user '$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    $newPassword = New-CcdcRandomPassword
    $outcome = Invoke-CcdcSafe -Target $name -Action 'reset local user password' -ScriptBlock {
        Set-LocalUser -Name $name -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force) -ErrorAction Stop
    }
    if ($outcome.Success) {
        Write-CcdcLog -Level OK -Message "New password for '$name': $newPassword"
        Save-ConsoleCredential -Target $name -Value $newPassword -Kind 'local user password reset'
    }
}

function Invoke-AC-ToggleLocalUser {
    if (-not (Test-CcdcLocalUserAvailable)) { return }
    $name = Read-CcdcInput 'Local username'
    $action = Read-CcdcInput 'Enable or Disable this account? (E/D)'
    if (-not $name) { return }
    $before = Invoke-CcdcSafe -Target $name -Action 'look up local user before enable/disable' -ScriptBlock { Get-LocalUser -Name $name -ErrorAction Stop }
    if ($before.Success) { Backup-CcdcState -Name "adhoc-LocalUser-$name" -Data $before.Value | Out-Null }

    if ($action -match '^D') {
        if (-not (Confirm-CcdcAction "About to DISABLE local user '$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $name -Action 'disable local user' -ScriptBlock { Disable-LocalUser -Name $name -ErrorAction Stop } | Out-Null
    } elseif ($action -match '^E') {
        if (-not (Confirm-CcdcAction "About to ENABLE local user '$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $name -Action 'enable local user' -ScriptBlock { Enable-LocalUser -Name $name -ErrorAction Stop } | Out-Null
    } else {
        Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' as Enable or Disable — cancelled."
    }
}

function Invoke-AC-LocalGroupMembership {
    if (-not (Test-CcdcLocalUserAvailable)) { return }
    $name = Read-CcdcInput 'Local username'
    $group = Read-CcdcInput 'Local group name (e.g. Administrators)'
    $action = Read-CcdcInput 'Add or Remove from this group? (A/R)'
    if (-not $name -or -not $group) { Write-CcdcLog -Level WARN -Message 'Username and group are both required — cancelled.'; return }

    $before = Invoke-CcdcSafe -Target $group -Action 'snapshot local group membership before change' -ScriptBlock {
        Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object { $_.Name }
    }
    if ($before.Success) { Backup-CcdcState -Name "adhoc-LocalGroup-$group" -Data $before.Value | Out-Null }

    if ($action -match '^R') {
        if (-not (Confirm-CcdcAction "About to REMOVE '$name' from local group '$group'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $name -Action "remove from local group '$group'" -ScriptBlock {
            Remove-LocalGroupMember -Group $group -Member $name -ErrorAction Stop
        } | Out-Null
    } elseif ($action -match '^A') {
        if (-not (Confirm-CcdcAction "About to ADD '$name' to local group '$group'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target $name -Action "add to local group '$group'" -ScriptBlock {
            Add-LocalGroupMember -Group $group -Member $name -ErrorAction Stop
        } | Out-Null
    } else {
        Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' as Add or Remove — cancelled."
    }
}

function Show-ACMenu-Local {
    Write-Host ""
    Write-Host "-- Local Users & Groups --" -ForegroundColor Cyan
    Write-Host "  [1] Create local user"
    Write-Host "  [2] Reset local user password"
    Write-Host "  [3] Enable/Disable local user"
    Write-Host "  [4] Add/Remove local user to/from a local group"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Local {
    :localLoop while ($true) {
        Show-ACMenu-Local
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break localLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-CreateLocalUser }
            '2' { Invoke-AC-ResetLocalPassword }
            '3' { Invoke-AC-ToggleLocalUser }
            '4' { Invoke-AC-LocalGroupMembership }
            'B' { break localLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

function Invoke-AC-ServiceControl {
    if (-not (Test-CcdcServiceCmdletsAvailable)) { return }
    $name = Read-CcdcInput 'Service name'
    $action = Read-CcdcInput 'Start, Stop, or Restart? (S/T/R)'
    if (-not $name) { return }
    $label = switch -Regex ($action) { '^S' { 'start' } '^T' { 'stop' } '^R' { 'restart' } default { $null } }
    if (-not $label) { Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' — cancelled."; return }
    if (-not (Confirm-CcdcAction "About to $label service '$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target $name -Action "$label service" -ScriptBlock {
        switch ($label) {
            'start'   { Start-Service -Name $name -ErrorAction Stop }
            'stop'    { Stop-Service -Name $name -ErrorAction Stop }
            'restart' { Restart-Service -Name $name -ErrorAction Stop }
        }
    } | Out-Null
}

function Invoke-AC-ServiceStartupType {
    if (-not (Test-CcdcServiceCmdletsAvailable)) { return }
    $name = Read-CcdcInput 'Service name'
    $type = Read-CcdcInput 'Startup type: Automatic, Manual, or Disabled'
    if (-not $name -or $type -notin @('Automatic', 'Manual', 'Disabled')) {
        Write-CcdcLog -Level WARN -Message "Need a service name and one of Automatic/Manual/Disabled — cancelled."
        return
    }
    $before = Invoke-CcdcSafe -Target $name -Action 'look up service before changing startup type' -ScriptBlock { Get-Service -Name $name -ErrorAction Stop }
    if ($before.Success) { Backup-CcdcState -Name "adhoc-Service-$name" -Data $before.Value | Out-Null }

    if (-not (Confirm-CcdcAction "About to set service '$name' startup type to $type.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target $name -Action "set startup type to $type" -ScriptBlock {
        Set-Service -Name $name -StartupType $type -ErrorAction Stop
    } | Out-Null
}

function Invoke-AC-ShowServiceStatus {
    if (-not (Test-CcdcServiceCmdletsAvailable)) { return }
    $name = Read-CcdcInput 'Service name'
    if (-not $name) { return }
    $outcome = Invoke-CcdcSafe -Target $name -Action 'look up service status' -ScriptBlock {
        Get-Service -Name $name -ErrorAction Stop | Select-Object Name, Status, StartType
    }
    if ($outcome.Success) {
        $s = $outcome.Value
        Write-Host ""
        Write-Host "  Name:       $($s.Name)"
        Write-Host "  Status:     $($s.Status)"
        Write-Host "  StartType:  $($s.StartType)"
        Write-Host ""
    }
}

function Show-ACMenu-Services {
    Write-Host ""
    Write-Host "-- Services --" -ForegroundColor Cyan
    Write-Host "  [1] Start/Stop/Restart a service"
    Write-Host "  [2] Set a service's startup type"
    Write-Host "  [3] Show service status (read-only)"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Services {
    :svcLoop while ($true) {
        Show-ACMenu-Services
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break svcLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-ServiceControl }
            '2' { Invoke-AC-ServiceStartupType }
            '3' { Invoke-AC-ShowServiceStatus }
            'B' { break svcLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

function Invoke-AC-ToggleTask {
    if (-not (Test-CcdcTaskCmdletsAvailable)) { return }
    $path = Read-CcdcInput 'Task path (e.g. \)'
    $name = Read-CcdcInput 'Task name'
    $action = Read-CcdcInput 'Enable or Disable this task? (E/D)'
    if (-not $name) { return }
    if (-not $path) { $path = '\' }
    $before = Invoke-CcdcSafe -Target "$path$name" -Action 'look up task before enable/disable' -ScriptBlock {
        Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop
    }
    if ($before.Success) { Backup-CcdcState -Name "adhoc-Task-$name" -Data $before.Value | Out-Null }

    if ($action -match '^D') {
        if (-not (Confirm-CcdcAction "About to DISABLE task '$path$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target "$path$name" -Action 'disable scheduled task' -ScriptBlock {
            Disable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop
        } | Out-Null
    } elseif ($action -match '^E') {
        if (-not (Confirm-CcdcAction "About to ENABLE task '$path$name'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
        Invoke-CcdcSafe -Target "$path$name" -Action 'enable scheduled task' -ScriptBlock {
            Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop
        } | Out-Null
    } else {
        Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' as Enable or Disable — cancelled."
    }
}

function Invoke-AC-ListTasks {
    if (-not (Test-CcdcTaskCmdletsAvailable)) { return }
    $filter = Read-CcdcInput 'Filter task names containing (blank = show all, capped at 40)'
    $outcome = Invoke-CcdcSafe -Target 'scheduled tasks' -Action 'list scheduled tasks' -ScriptBlock {
        $all = Get-ScheduledTask -ErrorAction Stop
        if ($filter) { $all = $all | Where-Object { $_.TaskName -like "*$filter*" } }
        $all | Select-Object -First 40 | ForEach-Object { "$($_.TaskPath)$($_.TaskName) [$($_.State)]" }
    }
    if ($outcome.Success) {
        foreach ($t in @($outcome.Value)) { Write-Host "  $t" }
    }
}

function Show-ACMenu-Tasks {
    Write-Host ""
    Write-Host "-- Scheduled Tasks --" -ForegroundColor Cyan
    Write-Host "  [1] Enable/Disable a task"
    Write-Host "  [2] List tasks (read-only)"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Tasks {
    :taskLoop while ($true) {
        Show-ACMenu-Tasks
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break taskLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-ToggleTask }
            '2' { Invoke-AC-ListTasks }
            'B' { break taskLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Firewall — quick one-off rule (separate from the full baseline module)
# ---------------------------------------------------------------------------

function Invoke-AC-AddFirewallRule {
    if (-not (Test-CcdcFirewallAvailable)) { return }
    $portText = Read-CcdcInput 'Port number'
    if (-not (Test-CcdcValidPort $portText)) { Write-CcdcLog -Level WARN -Message "'$portText' isn't a valid port (1-65535) — cancelled."; return }
    $action = Read-CcdcInput 'Allow or Block this port inbound? (A/B)'
    $fwAction = switch -Regex ($action) { '^A' { 'Allow' } '^B' { 'Block' } default { $null } }
    if (-not $fwAction) { Write-CcdcLog -Level WARN -Message "Didn't recognize '$action' as Allow or Block — cancelled."; return }
    $artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for this rule''s name (same one you use elsewhere — avoid an obvious "CCDC" string)' -Default 'Baseline'
    $ruleName = "$artifactPrefix-Adhoc-TCP-$portText-$fwAction"

    if (-not (Confirm-CcdcAction "About to create a $fwAction rule for TCP/$portText named '$ruleName'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target "TCP/$portText" -Action "create $fwAction firewall rule" -ScriptBlock {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort ([int]$portText) -Action $fwAction -ErrorAction Stop | Out-Null
    } | Out-Null
}

function Invoke-AC-RemoveFirewallRule {
    if (-not (Test-CcdcFirewallAvailable)) { return }
    $ruleName = Read-CcdcInput 'Exact rule DisplayName to remove'
    if (-not $ruleName) { return }
    $before = Invoke-CcdcSafe -Target $ruleName -Action 'look up rule before removing' -ScriptBlock {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
    }
    if (-not $before.Success) { return }
    Backup-CcdcState -Name "adhoc-FirewallRule-$ruleName" -Data $before.Value | Out-Null

    if (-not (Confirm-CcdcAction "About to REMOVE firewall rule '$ruleName'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target $ruleName -Action 'remove firewall rule' -ScriptBlock {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
    } | Out-Null
}

function Show-ACMenu-Firewall {
    Write-Host ""
    Write-Host "-- Firewall: quick one-off rule --" -ForegroundColor Cyan
    Write-Host "  [1] Add an inbound Allow/Block rule for a port"
    Write-Host "  [2] Remove a rule by exact name"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Firewall {
    :fwLoop while ($true) {
        Show-ACMenu-Firewall
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break fwLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-AddFirewallRule }
            '2' { Invoke-AC-RemoveFirewallRule }
            'B' { break fwLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

function Invoke-AC-AddDnsRecord {
    if (-not (Test-CcdcDnsAvailable)) { return }
    $zone = Get-CcdcAnswer -Key 'DomainName' -Prompt 'DNS zone name (e.g. domain.local)' -Default ''
    if (-not $zone) { Write-CcdcLog -Level WARN -Message 'No zone entered — cancelled.'; return }
    $recordName = Read-CcdcInput 'Record name (host part only, e.g. "web2")'
    $ip = Read-CcdcInput 'IP address'
    if (-not (Test-CcdcValidIPv4 $ip)) { Write-CcdcLog -Level WARN -Message "'$ip' isn't a valid IPv4 address — cancelled."; return }

    if (-not (Confirm-CcdcAction "About to add A record '$recordName.$zone' -> $ip.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target "$recordName.$zone" -Action 'add DNS A record' -ScriptBlock {
        Add-DnsServerResourceRecordA -ZoneName $zone -Name $recordName -IPv4Address $ip -ErrorAction Stop
    } | Out-Null
}

function Invoke-AC-RemoveDnsRecord {
    if (-not (Test-CcdcDnsAvailable)) { return }
    $zone = Get-CcdcAnswer -Key 'DomainName' -Prompt 'DNS zone name (e.g. domain.local)' -Default ''
    if (-not $zone) { Write-CcdcLog -Level WARN -Message 'No zone entered — cancelled.'; return }
    $recordName = Read-CcdcInput 'Record name (host part only) to remove'
    if (-not $recordName) { return }

    $before = Invoke-CcdcSafe -Target "$recordName.$zone" -Action 'look up DNS record before removing' -ScriptBlock {
        Get-DnsServerResourceRecord -ZoneName $zone -Name $recordName -RRType A -ErrorAction Stop
    }
    if ($before.Success) { Backup-CcdcState -Name "adhoc-DnsRecord-$recordName" -Data $before.Value | Out-Null }

    if (-not (Confirm-CcdcAction "About to REMOVE A record '$recordName.$zone'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target "$recordName.$zone" -Action 'remove DNS A record' -ScriptBlock {
        Remove-DnsServerResourceRecord -ZoneName $zone -Name $recordName -RRType A -Force -ErrorAction Stop
    } | Out-Null
}

function Invoke-AC-ListDnsRecords {
    if (-not (Test-CcdcDnsAvailable)) { return }
    $zone = Get-CcdcAnswer -Key 'DomainName' -Prompt 'DNS zone name (e.g. domain.local)' -Default ''
    if (-not $zone) { return }
    $outcome = Invoke-CcdcSafe -Target $zone -Action 'list DNS A records' -ScriptBlock {
        Get-DnsServerResourceRecord -ZoneName $zone -RRType A -ErrorAction Stop |
            ForEach-Object { "$($_.HostName) -> $($_.RecordData.IPv4Address)" }
    }
    if ($outcome.Success) {
        foreach ($r in @($outcome.Value)) { Write-Host "  $r" }
    }
}

function Show-ACMenu-Dns {
    Write-Host ""
    Write-Host "-- DNS --" -ForegroundColor Cyan
    Write-Host "  [1] Add an A record"
    Write-Host "  [2] Remove an A record"
    Write-Host "  [3] List A records for the zone (read-only)"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Dns {
    :dnsLoop while ($true) {
        Show-ACMenu-Dns
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break dnsLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-AddDnsRecord }
            '2' { Invoke-AC-RemoveDnsRecord }
            '3' { Invoke-AC-ListDnsRecords }
            'B' { break dnsLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Threat response — reactively block a malicious IP or domain once you've
# found one (Splunk flagged it, the threat hunt found it, whatever). The
# team packet explicitly allows this: "Teams MAY restrict specific IPs
# found to be sending malicious traffic" (reactive blocking is fine;
# blanket allow-listing to just the scoring engine is not — see
# docs/SECURITY.md and the 2026 Invitational team pack). This is
# deliberately the FAST path for exactly that one allowed action, separate
# from the general-purpose port rule above: it blocks the whole remote
# address (inbound AND outbound), not a single port, and removal reuses
# the existing "remove firewall rule by name"/"remove DNS A record"
# actions above rather than duplicating them.
# ---------------------------------------------------------------------------

function Invoke-AC-BlockMaliciousIp {
    if (-not (Test-CcdcFirewallAvailable)) { return }
    $ip = Read-CcdcInput 'Malicious IP address to block (inbound AND outbound)'
    if (-not (Test-CcdcValidIPv4 $ip)) { Write-CcdcLog -Level WARN -Message "'$ip' isn't a valid IPv4 address -- cancelled."; return }
    $reason = Read-CcdcInput 'Why? (one line -- goes in the rule description, and you will want this exact wording for an incident report later)'
    $artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for this rule''s name (same one you use elsewhere -- avoid an obvious "CCDC" string)' -Default 'Baseline'
    $safeIp = $ip -replace '[^0-9]', '-'
    $inName = "$artifactPrefix-Block-$safeIp-In"
    $outName = "$artifactPrefix-Block-$safeIp-Out"

    if (-not (Confirm-CcdcAction "About to block ALL inbound and outbound traffic to/from $ip on this host (rules '$inName' / '$outName'). This is reactive blocking of a specific malicious IP, which the packet allows -- do NOT use this to allow-list just the scoring engine's IP instead of leaving scored ports open to Any, that's explicitly against the rules.")) {
        Write-CcdcLog -Level WARN -Message 'Cancelled.'
        return
    }
    $inOk = Invoke-CcdcSafe -Target $ip -Action 'create inbound block rule for malicious IP' -ScriptBlock {
        New-NetFirewallRule -DisplayName $inName -Description $reason -Direction Inbound -RemoteAddress $ip -Action Block -ErrorAction Stop | Out-Null
    }
    $outOk = Invoke-CcdcSafe -Target $ip -Action 'create outbound block rule for malicious IP' -ScriptBlock {
        New-NetFirewallRule -DisplayName $outName -Description $reason -Direction Outbound -RemoteAddress $ip -Action Block -ErrorAction Stop | Out-Null
    }
    if ($inOk.Success -and $outOk.Success) {
        Write-CcdcLog -Level OK -Message "Blocked $ip inbound and outbound. To undo later: Firewall menu -> Remove a rule by exact name -> '$inName' and '$outName'."
    }
}

function Invoke-AC-BlackholeDnsDomain {
    if (-not (Test-CcdcDnsAvailable)) { return }
    $domain = Read-CcdcInput 'Malicious domain name to sinkhole (e.g. evil-c2.example.com)'
    if (-not $domain) { return }
    $domain = $domain.Trim().TrimEnd('.')
    $blackhole = Read-CcdcInput 'Address to point it at (blank = 0.0.0.0)'
    if (-not $blackhole) { $blackhole = '0.0.0.0' }
    if (-not (Test-CcdcValidIPv4 $blackhole)) { Write-CcdcLog -Level WARN -Message "'$blackhole' isn't a valid IPv4 address -- cancelled."; return }

    $existing = Invoke-CcdcSafe -Target $domain -Action 'check whether a zone for this domain already exists' -ScriptBlock {
        Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue
    }
    if ($existing.Success -and $existing.Value) {
        Write-CcdcLog -Level WARN -Message "A zone for '$domain' already exists on this DNS server -- that's unexpected for an external malicious domain, and this action only creates a NEW zone. Use the DNS menu above to edit it directly instead. Nothing changed."
        return
    }

    Write-Host ""
    Write-Host "This makes THIS DNS server authoritative for '$domain' and answers every" -ForegroundColor Yellow
    Write-Host "query for it (and *.$domain)" -ForegroundColor Yellow
    Write-Host "with $blackhole -- so any client using this server to resolve names can no" -ForegroundColor Yellow
    Write-Host "longer reach the real domain at all. Only works for clients that actually" -ForegroundColor Yellow
    Write-Host "use this server as their resolver." -ForegroundColor Yellow
    if (-not (Confirm-CcdcAction "About to create zone '$domain' as a DNS sinkhole pointed at $blackhole.")) {
        Write-CcdcLog -Level WARN -Message 'Cancelled.'
        return
    }
    $zoneOk = Invoke-CcdcSafe -Target $domain -Action 'create sinkhole DNS zone' -ScriptBlock {
        Add-DnsServerPrimaryZone -Name $domain -ReplicateToAllDnsServers -ErrorAction Stop
    }
    if (-not $zoneOk.Success) { return }
    Invoke-CcdcSafe -Target $domain -Action 'add sinkhole root A record' -ScriptBlock {
        Add-DnsServerResourceRecordA -ZoneName $domain -Name '@' -IPv4Address $blackhole -ErrorAction Stop
    } | Out-Null
    $wcOk = Invoke-CcdcSafe -Target $domain -Action 'add sinkhole wildcard A record (covers subdomains)' -ScriptBlock {
        Add-DnsServerResourceRecordA -ZoneName $domain -Name '*' -IPv4Address $blackhole -ErrorAction Stop
    }
    if ($wcOk.Success) {
        Write-CcdcLog -Level OK -Message "'$domain' (and every subdomain) now resolves to $blackhole for any client using this DNS server. To undo later: DNS menu, or 'Remove-DnsServerZone -Name $domain -Force' by hand."
    }
}

function Show-ACMenu-ThreatResponse {
    Write-Host ""
    Write-Host "-- Threat response: block a malicious IP/domain --" -ForegroundColor Cyan
    Write-Host "  [1] Block an IP address (inbound + outbound, firewall)"
    Write-Host "  [2] Sinkhole a domain name (new DNS zone -> blackhole address)"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-ThreatResponse {
    :threatLoop while ($true) {
        Show-ACMenu-ThreatResponse
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break threatLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-BlockMaliciousIp }
            '2' { Invoke-AC-BlackholeDnsDomain }
            'B' { break threatLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# File / folder permissions (NTFS ACLs)
# ---------------------------------------------------------------------------

function Invoke-AC-ShowAcl {
    $path = Read-CcdcInput 'Path to a file or folder'
    if (-not $path) { return }
    $outcome = Invoke-CcdcSafe -Target $path -Action 'read ACL' -ScriptBlock {
        $acl = Get-Acl -Path $path -ErrorAction Stop
        [pscustomobject]@{
            Owner = $acl.Owner
            Rules = $acl.Access | ForEach-Object { "$($_.IdentityReference)  $($_.FileSystemRights)  $($_.AccessControlType)$(if ($_.IsInherited) { ' (inherited)' })" }
        }
    }
    if ($outcome.Success) {
        $r = $outcome.Value
        Write-Host ""
        Write-Host "  Owner: $($r.Owner)"
        foreach ($line in @($r.Rules)) { Write-Host "  $line" }
        Write-Host ""
    }
}

function Invoke-AC-GrantAcl {
    $path = Read-CcdcInput 'Path to a file or folder'
    $identity = Read-CcdcInput 'User or group (e.g. DOMAIN\username or BUILTIN\Users)'
    $right = Read-CcdcInput 'Rights: ReadAndExecute, Read, Write, Modify, or FullControl'
    if (-not $path -or -not $identity) { Write-CcdcLog -Level WARN -Message 'Path and identity are both required — cancelled.'; return }
    if (-not (Test-CcdcValidFileSystemRight $right)) {
        Write-CcdcLog -Level WARN -Message "'$right' isn't one of ReadAndExecute/Read/Write/Modify/FullControl — cancelled."
        return
    }
    $before = Invoke-CcdcSafe -Target $path -Action 'back up ACL before granting permission' -ScriptBlock { Get-Acl -Path $path -ErrorAction Stop }
    if (-not $before.Success) { return }
    Backup-CcdcState -Name "adhoc-ACL-$(($path -replace '[^a-zA-Z0-9_\-]', '_'))" -Data $before.Value | Out-Null

    if (-not (Confirm-CcdcAction "About to grant '$identity' $right on '$path'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target $path -Action "grant $right to $identity" -ScriptBlock {
        $acl = Get-Acl -Path $path
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, $right, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
    } | Out-Null
}

function Invoke-AC-RemoveAcl {
    $path = Read-CcdcInput 'Path to a file or folder'
    $identity = Read-CcdcInput 'User or group to remove ALL explicit (non-inherited) permissions for'
    if (-not $path -or -not $identity) { Write-CcdcLog -Level WARN -Message 'Path and identity are both required — cancelled.'; return }
    $before = Invoke-CcdcSafe -Target $path -Action 'back up ACL before removing permission' -ScriptBlock { Get-Acl -Path $path -ErrorAction Stop }
    if (-not $before.Success) { return }
    Backup-CcdcState -Name "adhoc-ACL-$(($path -replace '[^a-zA-Z0-9_\-]', '_'))" -Data $before.Value | Out-Null

    if (-not (Confirm-CcdcAction "About to remove ALL explicit permissions for '$identity' on '$path'.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    Invoke-CcdcSafe -Target $path -Action "remove explicit permissions for $identity" -ScriptBlock {
        $acl = Get-Acl -Path $path
        $toRemove = $acl.Access | Where-Object { $_.IdentityReference -eq $identity -and -not $_.IsInherited }
        foreach ($rule in $toRemove) { $acl.RemoveAccessRule($rule) | Out-Null }
        Set-Acl -Path $path -AclObject $acl -ErrorAction Stop
    } | Out-Null
}

function Show-ACMenu-Files {
    Write-Host ""
    Write-Host "-- File/Folder Permissions --" -ForegroundColor Cyan
    Write-Host "  [1] Show ACL for a path (read-only)"
    Write-Host "  [2] Grant a permission"
    Write-Host "  [3] Remove a user/group's explicit permissions"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Files {
    :fileLoop while ($true) {
        Show-ACMenu-Files
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break fileLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-ShowAcl }
            '2' { Invoke-AC-GrantAcl }
            '3' { Invoke-AC-RemoveAcl }
            'B' { break fileLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Group Policy (read-mostly — GPO editing is complex, this covers the
# fast/common cases: see what changed, disable a link if something's wrong)
# ---------------------------------------------------------------------------

function Invoke-AC-ListGpos {
    if (-not (Test-CcdcGpoAvailable)) { return }
    $outcome = Invoke-CcdcSafe -Target 'GPOs' -Action 'list GPOs' -ScriptBlock {
        Get-GPO -All -ErrorAction Stop | Sort-Object ModificationTime -Descending |
            ForEach-Object { "$($_.DisplayName)  (modified $($_.ModificationTime))" }
    }
    if ($outcome.Success) {
        foreach ($g in @($outcome.Value)) { Write-Host "  $g" }
    }
}

function Invoke-AC-DisableGpoLink {
    if (-not (Test-CcdcGpoAvailable)) { return }
    $name = Read-CcdcInput 'GPO name'
    $target = Read-CcdcInput 'Link target distinguished name (e.g. dc=domain,dc=local)'
    if (-not $name -or -not $target) { Write-CcdcLog -Level WARN -Message 'GPO name and link target are both required — cancelled.'; return }

    if (-not (Confirm-CcdcAction "About to DISABLE the link for GPO '$name' at '$target'. This is a real behavior change for everything under that target — make sure that's intended.")) {
        Write-CcdcLog -Level WARN -Message 'Cancelled.'
        return
    }
    Invoke-CcdcSafe -Target $name -Action 'disable GPO link' -ScriptBlock {
        Set-GPLink -Name $name -Target $target -LinkEnabled No -ErrorAction Stop
    } | Out-Null
}

function Show-ACMenu-Gpo {
    Write-Host ""
    Write-Host "-- Group Policy --" -ForegroundColor Cyan
    Write-Host "  [1] List GPOs by modification time (read-only)"
    Write-Host "  [2] Disable a GPO's link (doesn't delete it)"
    Write-Host "  [B] Back"
    Write-Host ""
}

function Invoke-ACLoop-Gpo {
    :gpoLoop while ($true) {
        Show-ACMenu-Gpo
        $c = Read-CcdcInput 'Choice'
        if ($null -eq $c) { break gpoLoop }
        switch ($c.Trim().ToUpperInvariant()) {
            '1' { Invoke-AC-ListGpos }
            '2' { Invoke-AC-DisableGpoLink }
            'B' { break gpoLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    }
}

# ---------------------------------------------------------------------------
# Escape hatch — for the injects nothing above covers
# ---------------------------------------------------------------------------

function Invoke-AC-RunCustomCommand {
    Write-Host ""
    Write-Host "No auto-backup happens here — there's no way to know what state to save for an arbitrary command. Prefer a menu action above if one exists." -ForegroundColor Yellow
    Write-Host "The exact text you type is written to this session's plaintext transcript log (that's what makes this traceable for an incident report later) — never type a password or other secret directly into this command. If a command needs a credential, generate one with a menu action above and reference it by account name, or use -AsSecureString in a script you save and run separately." -ForegroundColor Yellow
    $cmd = Read-CcdcInput 'PowerShell command to run (one line)'
    if (-not $cmd) { return }
    Write-Host "About to run (this exact line is about to be logged and transcripted):" -ForegroundColor Yellow
    Write-Host "  $cmd"
    if (-not (Confirm-CcdcAction "Confirm.")) { Write-CcdcLog -Level WARN -Message 'Cancelled.'; return }
    $outcome = Invoke-CcdcSafe -Target 'custom command' -Action $cmd -ScriptBlock {
        Invoke-Expression $cmd
    }
    if ($outcome.Success -and $null -ne $outcome.Value) {
        # Out-String rather than Format-Table: Format-Table renders a scalar
        # result (a single DateTime, a string, a bool) as blank, since it's
        # built for collections. Out-String uses PowerShell's normal default
        # formatting either way, which is what you'd see typing the command
        # directly at a prompt. -Width is set explicitly and generously: a
        # console whose width PowerShell can't detect (confirmed in testing
        # — happens with no real interactive window, and can happen over
        # some remote/portal-based sessions) makes Out-String silently
        # render table output as blank instead of erroring, which would be a
        # much worse surprise mid-round than a slightly wide default.
        Write-Host ""
        Write-Host (($outcome.Value | Out-String -Width 200).TrimEnd())
    }
}

# ---------------------------------------------------------------------------
# Top-level console loop
# ---------------------------------------------------------------------------

function Show-ACMenu-Top {
    Write-Host ""
    Write-Host "===================== ADMIN CONSOLE =====================" -ForegroundColor Cyan
    Write-Host "  [1] Active Directory — Users & Groups"
    Write-Host "  [2] Local Users & Groups"
    Write-Host "  [3] Services"
    Write-Host "  [4] Scheduled Tasks"
    Write-Host "  [5] Firewall — quick one-off rule"
    Write-Host "  [6] DNS"
    Write-Host "  [7] File/Folder Permissions"
    Write-Host "  [8] Group Policy"
    Write-Host "  [9] Run a custom command (no auto-backup — read the warning first)"
    Write-Host "  [10] Threat response — block a malicious IP/domain"
    Write-Host "  [B] Back to main menu / quit"
    Write-Host "==========================================================="
    Write-Host ""
}

:topLoop while ($true) {
    Show-ACMenu-Top
    $choice = Read-CcdcInput 'Choice'
    if ($null -eq $choice) {
        Write-CcdcLog -Level ERROR -Message "Couldn't read input (no interactive console available). Exiting."
        break topLoop
    }
    try {
        switch ($choice.Trim().ToUpperInvariant()) {
            '1' { Invoke-ACLoop-AD }
            '2' { Invoke-ACLoop-Local }
            '3' { Invoke-ACLoop-Services }
            '4' { Invoke-ACLoop-Tasks }
            '5' { Invoke-ACLoop-Firewall }
            '6' { Invoke-ACLoop-Dns }
            '7' { Invoke-ACLoop-Files }
            '8' { Invoke-ACLoop-Gpo }
            '9' { Invoke-AC-RunCustomCommand }
            '10' { Invoke-ACLoop-ThreatResponse }
            'B' { break topLoop }
            default { Write-Host "Not a valid choice." -ForegroundColor Yellow }
        }
    } catch {
        Write-CcdcLog -Level ERROR -Message "Something in the console threw an unhandled error: $($_.Exception.Message)"
        Write-CcdcLog -Level INFO -Message "The console is still alive — this didn't crash the whole thing. Check the log above and try again."
    }
}

Show-CcdcSummary
Stop-CcdcSession
