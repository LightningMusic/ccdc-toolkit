#Requires -Version 5.1
<#
.SYNOPSIS
    A window for the toolkit: how healthy this box is right now, whether the
    services your packet scores are actually up, and the account and service
    changes an inject usually asks for -- without hunting for the right command.

.DESCRIPTION
    Run it from an elevated PowerShell on the box you are defending:

        .\ui\Start-CcdcConsole.ps1

    Ten tabs:
      Dashboard  Read-only. Firewall default action, Sysmon and the Splunk
                 forwarder, failed logons, listening ports, privileged group
                 sizes, inventory age -- each with what it means and what to do.
                 Plus every service ScoredServices says is scored on this host,
                 checked against what is actually listening.
      Accounts   List, reset, disable, enable, add to / remove from a group,
                 create. AD or local. New passwords are generated, never
                 typed, and written to a file under logs\.
      DNS        Zones, records, and the same zone-transfer / dynamic-update /
                 cache hardening Invoke-DnsHardening.ps1 does -- only useful
                 on the box running the DnsServer role.
      DHCP       Scopes and reservations -- only useful on the box running
                 the DhcpServer role (the same machine as DNS/AD at the real
                 site). A rogue reservation is exactly what the threat hunt
                 also watches for pass-to-pass.
      Group      List every GPO and what it's linked to, link/unlink one,
      Policy     and create the toolkit's hardening GPO (LLMNR off, anonymous
                 SMB/SAM enumeration off, NTLMv2 only, SMB signing required)
                 through the exact same shared function Invoke-ADHardening.ps1
                 uses -- the window and that module can't quietly disagree.
      Services   List, filter, start, stop, restart, change startup type.
      Tasks      List, filter, enable, disable, delete, create a scheduled
                 task. Flags one whose action runs from an unusual path, the
                 same way the Services tab flags an odd service.
      Firewall   One rule at a time, for the inject that says "allow this" or
                 "block that". The default-block sweep stays on the Modules
                 tab on purpose -- it needs its own safety net, not a button.
      Modules    The same modules as the numbered menu, each opening in its own
                 PowerShell window (they ask questions and print a lot, neither
                 of which belongs in a window that has to stay responsive).
      Activity   Everything this window did, mirrored into the session
                 transcript so the incident report generator can find it.

    The numbered menu (Invoke-CCDCToolkit.ps1) still works and is unchanged --
    this is another way in, not a replacement. Use whichever suits the moment.

    Reliability notes, because a window that freezes mid-round is worse than no
    window: every action runs on a background runspace, so the UI never blocks;
    the buttons disable while one is running; every handler is wrapped so a
    failure shows up in Activity instead of killing the window; and anything
    that changes state asks first and is written to the transcript.

    Needs a desktop (it will not run on Server Core) and Windows PowerShell
    with WPF, which every Desktop Experience install of Windows Server has.

.PARAMETER NoRelaunch
    Internal. WPF needs a single-threaded apartment, so this script relaunches
    itself with -STA if it was not started that way; this switch stops that
    happening twice.

.PARAMETER SelfTest
    Build everything -- load the layout, find every control, wire every button,
    run one health check -- then report and exit WITHOUT showing the window.
    Use it to find out whether this box can run the window at all, and to see
    the real error if it cannot:

        powershell.exe -STA -File .\ui\Start-CcdcConsole.ps1 -SelfTest

    tests\Ui.Tests.ps1 runs this too, so a startup failure shows up here rather
    than as a window that flashes and disappears.

.EXAMPLE
    .\ui\Start-CcdcConsole.ps1
#>
[CmdletBinding()]
param([switch]$NoRelaunch, [switch]$SelfTest)

# --- WPF needs STA; relaunch once if we were not started that way -------------
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    if ($NoRelaunch) {
        Write-Host "This window needs PowerShell running in a single-threaded apartment (STA) and could not switch to one. Start it with: powershell.exe -STA -File .\ui\Start-CcdcConsole.ps1" -ForegroundColor Red
        return
    }
    Write-Host 'Restarting in STA mode (WPF requires it)...' -ForegroundColor Cyan
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $relaunchArgs = @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-NoRelaunch')
    if ($SelfTest) { $relaunchArgs += '-SelfTest' }
    Start-Process -FilePath $exe -ArgumentList $relaunchArgs
    return
}

$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
} catch {
    Write-Host "Couldn't load WPF ($($_.Exception.Message)). This needs a Desktop Experience install of Windows -- Server Core has no GUI, so use the numbered menu (.\Invoke-CCDCToolkit.ps1) there instead." -ForegroundColor Red
    return
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $repoRoot
Write-CcdcLog -Level INFO -Message 'Toolkit window starting.'

# Everything from here is wrapped. A window that flashes up and disappears with
# no explanation is the worst possible failure during a round: the whole point
# of this toolkit is that you can tell what went wrong without a debugger. So
# any failure is written to the session transcript, shown in a message box if
# there is still a desktop to show it on, and the console is held open so the
# message does not scroll away with the process.
$script:StartupFailed = $null
try {

# ---------------------------------------------------------------------------
# Load the window. Every control the code below touches is named here, and
# tests\Ui.Tests.ps1 checks this list against the XAML, so a rename cannot
# quietly turn a button into a no-op.
# ---------------------------------------------------------------------------
$script:ControlNames = @(
    'HealthPill', 'HealthPillText', 'HostText', 'DomainText', 'UserText', 'ElevatedText',
    'RefreshButton', 'OpenLogsButton', 'ElevationBanner', 'ElevationBannerText',
    'HealthCards', 'ScoredGrid',
    'AccountScopeCombo', 'AccountFilterBox', 'AccountSearchButton', 'AccountGrid',
    'AccountResetButton', 'AccountDisableButton', 'AccountEnableButton',
    'AccountGroupBox', 'AccountAddGroupButton', 'AccountRemoveGroupButton', 'AccountNewName', 'AccountNewGroup', 'AccountCreateButton',
    'DnsZoneGrid', 'DnsListZonesButton', 'DnsRecordGrid', 'DnsListRecordsButton',
    'DnsRecordName', 'DnsRecordTypeCombo', 'DnsRecordValue', 'DnsRecordTtl',
    'DnsAddRecordButton', 'DnsRemoveRecordButton',
    'DnsSecureTransfersButton', 'DnsSecureUpdatesButton', 'DnsHardenCacheButton',
    'DhcpListScopesButton', 'DhcpScopeGrid', 'DhcpListReservationsButton', 'DhcpReservationGrid',
    'DhcpResIp', 'DhcpResClientId', 'DhcpResName', 'DhcpResDescription',
    'DhcpAddReservationButton', 'DhcpRemoveReservationButton',
    'GpoListButton', 'GpoGrid', 'GpoListLinksButton', 'GpoLinkGrid',
    'GpoLinkTarget', 'GpoLinkButton', 'GpoUnlinkButton',
    'GpoCreateName', 'GpoCreateTarget', 'GpoCreateButton',
    'ServiceFilterBox', 'ServiceSearchButton', 'ServiceGrid',
    'TaskFilterBox', 'TaskSearchButton', 'TaskGrid',
    'TaskDisableButton', 'TaskEnableButton', 'TaskDeleteButton',
    'TaskNewName', 'TaskNewCommand', 'TaskNewArgs', 'TaskNewTrigger', 'TaskCreateButton',
    'FirewallFilterBox', 'FirewallSearchButton', 'FirewallGrid',
    'FirewallDisableButton', 'FirewallEnableButton', 'FirewallRemoveButton',
    'FwNewName', 'FwDirectionCombo', 'FwActionCombo', 'FwProtocolCombo', 'FwPortBox', 'FwRemoteAddressBox', 'FirewallAddButton',
    'ServiceStartButton', 'ServiceStopButton', 'ServiceRestartButton',
    'ServiceStartupCombo', 'ServiceSetStartupButton',
    'ModuleList', 'LogBox', 'StatusText', 'BusyBar'
)

$xamlPath = Join-Path $PSScriptRoot 'CcdcConsole.xaml'
if (-not (Test-Path -LiteralPath $xamlPath)) {
    Write-CcdcLog -Level ERROR -Message "Can't find $xamlPath. This copy of the repo is incomplete -- re-clone it."
    Stop-CcdcSession
    return
}
try {
    $reader = New-Object System.Xml.XmlNodeReader ([xml](Get-Content -LiteralPath $xamlPath -Raw))
    $window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-CcdcLog -Level ERROR -Message "The window layout failed to load: $($_.Exception.Message)"
    Stop-CcdcSession
    return
}

$ui = @{}
foreach ($name in $script:ControlNames) {
    $ctrl = $window.FindName($name)
    if (-not $ctrl) {
        Write-CcdcLog -Level ERROR -Message "The layout is missing the control '$name' -- the window would only half work, so stopping here."
        Stop-CcdcSession
        return
    }
    $ui[$name] = $ctrl
}

$script:StatusBrushes = @{ Good = '#3FB950'; Warn = '#D29922'; Bad = '#F85149'; Unknown = '#9A9AA8'
                           Up = '#3FB950'; Down = '#F85149'; Running = '#3FB950'; Stopped = '#F85149' }
function Get-StatusBrush { param([string]$Status) if ($script:StatusBrushes.ContainsKey("$Status")) { return $script:StatusBrushes["$Status"] } return '#9A9AA8' }

# ---------------------------------------------------------------------------
# Logging, busy state, confirmation
# ---------------------------------------------------------------------------
function Write-UiLog {
    param([ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'ACTION')][string]$Level = 'INFO', [Parameter(Mandatory)][string]$Message)
    # Write-CcdcLog puts it on the console and therefore into the session
    # transcript; the box gives the operator the same thing without alt-tabbing.
    Write-CcdcLog -Level $Level -Message $Message
    # Built on its own line on purpose. Inside a method call's parentheses,
    # commas separate ARGUMENTS, so AppendText("{0}{1}{2}" -f $a, $b, $c) hands
    # -f only $a and then fails with "Error formatting a string" -- which is
    # what crashed this window on its first real outing.
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    $ui.LogBox.AppendText($line + [Environment]::NewLine)
    $ui.LogBox.ScrollToEnd()
}

$script:ActionButtons = @()
function Set-UiBusy {
    param([bool]$Busy, [string]$Status = 'Ready')
    $ui.StatusText.Text = $Status
    $ui.BusyBar.Visibility = if ($Busy) { 'Visible' } else { 'Hidden' }
    foreach ($b in $script:ActionButtons) { $b.IsEnabled = -not $Busy }
    $window.Cursor = if ($Busy) { [System.Windows.Input.Cursors]::Wait } else { $null }
}

function Confirm-UiAction {
    param([Parameter(Mandatory)][string]$Message, [string]$Title = 'Confirm')
    $answer = [System.Windows.MessageBox]::Show($window, $Message, $Title,
        [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    return ($answer -eq [System.Windows.MessageBoxResult]::Yes)
}

# ---------------------------------------------------------------------------
# Background work.
#
# Everything slow runs in its own runspace so the window stays responsive --
# a frozen window during a round is worse than no window. The work script is
# passed as text (a scriptblock belongs to the session that made it), gets the
# repo root and one hashtable of arguments, and returns an object with .Log
# (lines to show) and .Data (whatever the caller wants). The completion
# handler runs on a DispatcherTimer tick, which is already the UI thread, so
# touching controls from it is safe.
# ---------------------------------------------------------------------------
$script:Pending = $null
$script:Timer = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval = [TimeSpan]::FromMilliseconds(150)

function Start-UiWork {
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$ScriptText,
        [hashtable]$Arguments = @{},
        [scriptblock]$OnDone
    )
    if ($script:Pending) {
        Write-UiLog -Level WARN -Message 'Something is already running -- wait for it to finish.'
        return
    }
    Set-UiBusy -Busy $true -Status $Status

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    [void]$ps.AddScript($ScriptText).AddArgument($repoRoot).AddArgument($Arguments)
    $script:Pending = @{ Shell = $ps; Handle = $ps.BeginInvoke(); Runspace = $runspace; OnDone = $OnDone; Status = $Status }
    $script:Timer.Start()
}

function Complete-PendingWork {
    <#
        Collect a finished background job and hand its result to the caller's
        OnDone. Called from the timer tick while the window is up, and directly
        from the -SelfTest loop, which has no message loop to tick it.
    #>
    if (-not $script:Pending -or -not $script:Pending.Handle.IsCompleted) { return }
    $script:Timer.Stop()
    $job = $script:Pending
    $script:Pending = $null

    $result = $null
    $failure = $null
    try {
        $out = $job.Shell.EndInvoke($job.Handle)
        foreach ($e in $job.Shell.Streams.Error) { Write-UiLog -Level ERROR -Message "$($e.Exception.Message)" }
        $result = @($out) | Where-Object { $_ -is [hashtable] -or $_ -is [pscustomobject] } | Select-Object -Last 1
    } catch {
        $failure = $_.Exception.Message
    } finally {
        $job.Shell.Dispose()
        $job.Runspace.Close()
        $job.Runspace.Dispose()
    }

    if ($failure) {
        Write-UiLog -Level ERROR -Message "$($job.Status): $failure"
        Set-UiBusy -Busy $false -Status 'Ready'
        return
    }
    # No @() here: wrapping a List[object] that holds hashtables throws
    # "Argument types do not match". foreach copes with $null and with any
    # enumerable, so it is both safer and shorter.
    foreach ($line in $result.Log) {
        if ($line -is [string]) { Write-UiLog -Level INFO -Message $line }
        else { Write-UiLog -Level "$($line.Level)" -Message "$($line.Message)" }
    }
    Set-UiBusy -Busy $false -Status 'Ready'
    if ($job.OnDone) {
        try { & $job.OnDone $result } catch { Write-UiLog -Level ERROR -Message "Showing the result of '$($job.Status)' failed: $($_.Exception.Message)" }
    }
}

# The tick body is wrapped, and there is a dispatcher-level net below it.
# Both are here because of a real failure: on the lab servers the window
# logged "Ready" and the process was gone about two seconds later, with no
# error, no "window closed" line, and -- the giveaway -- no SUMMARY block,
# which meant the script's own finally never ran. A finally that does not
# run means the process was killed rather than unwound, and an exception
# escaping a DispatcherTimer tick does exactly that: it goes to the
# dispatcher, not to any try/catch in this script, and takes the process
# with it. Silently.
$script:Timer.Add_Tick({
    try {
        Complete-PendingWork
    } catch {
        # Stop the timer first: if the tick throws once it will usually
        # throw every 150ms, and a flood of identical errors buries the
        # first one.
        $script:Timer.Stop()
        Write-UiLog -Level ERROR -Message "Background work failed while being collected: $($_.Exception.Message)"
        Write-UiLog -Level ERROR -Message "At: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
        Set-UiBusy -Busy $false -Status 'Ready'
    }
})

# A handler that throws must never take the window down with it.
function Register-UiClick {
    param([Parameter(Mandatory)]$Button, [Parameter(Mandatory)][scriptblock]$Action, [switch]$NotAnActionButton)
    $Button.Add_Click({
        try { & $Action } catch { Write-UiLog -Level ERROR -Message "That didn't work: $($_.Exception.Message)" ; Set-UiBusy -Busy $false -Status 'Ready' }
    }.GetNewClosure())
    if (-not $NotAnActionButton) { $script:ActionButtons += $Button }
}

# ---------------------------------------------------------------------------
# Work scripts. Each one: param($RepoRoot, $Arg) -> @{ Log = @(); Data = ... }
# ---------------------------------------------------------------------------

$script:WorkRefresh = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$cards = New-Object System.Collections.Generic.List[object]

$hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'unknown' }
$domain = 'unknown'; $role = 'unknown'
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $domain = if ($cs.PartOfDomain) { $cs.Domain } else { "workgroup ($($cs.Domain))" }
    $role = switch ([int]$cs.DomainRole) { 0 {'standalone workstation'} 1 {'member workstation'} 2 {'standalone server'} 3 {'member server'} 4 {'domain controller (backup)'} 5 {'DOMAIN CONTROLLER'} default {'unknown'} }
} catch { }

# firewall
$actions = @()
try { $actions = @(Get-NetFirewallProfile -All -ErrorAction Stop | ForEach-Object { "$($_.DefaultInboundAction)" }) } catch { }
$cards.Add((Get-CcdcFirewallVerdict -DefaultInboundActions $actions))

# the two logging services
foreach ($svc in @(@{ N='Sysmon'; P='Sysmon*'; M='No Sysmon here. Without it you have far less to show in an incident report about what red team ran.' },
                   @{ N='Splunk forwarder'; P='SplunkForwarder'; M='No Splunk forwarder here. That is fine if your team is not using one.' })) {
    $state = $null
    try { $s = Get-Service -Name $svc.P -ErrorAction SilentlyContinue | Select-Object -First 1; if ($s) { $state = "$($s.Status)" } } catch { }
    $optional = ($svc.N -ne 'Sysmon')
    $cards.Add((Get-CcdcServiceVerdict -Title $svc.N -Status $state -WhenMissing $svc.M -Optional:$optional))
}

# failed logons
$failed = $null
try {
    $since = (Get-Date).AddMinutes(-30)
    $failed = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$since } -ErrorAction SilentlyContinue).Count
} catch { }
$cards.Add((Get-CcdcFailedLogonVerdict -Count $failed -Minutes 30))

# listening ports
$tcp = $null; $udp = $null
try { $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique) } catch { }
try { $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique) } catch { }
$cards.Add((Get-CcdcC2PortVerdict -ListeningPorts $tcp))

# privileged groups
try {
    # Get-CcdcAdministratorsMember, not Get-LocalGroupMember: the latter
    # fails on a domain controller, which used to show this card as
    # "unknown" on the one box where it matters most.
    $adminResult = Get-CcdcAdministratorsMember
    if ($adminResult.Success) {
        $localAdmins = @($adminResult.Members).Count
        $st = if ($localAdmins -le 3) { 'Good' } else { 'Warn' }
        $cards.Add((New-CcdcHealthCard -Title 'Administrators' -Status $st -Value "$localAdmins member(s)" -Detail "Read from the $($adminResult.Source). Every name in this group should be one you can account for."))
    } else {
        $cards.Add((New-CcdcHealthCard -Title 'Administrators' -Status Unknown -Value 'unknown' -Detail "Could not read the Administrators group: $($adminResult.Message)"))
    }
} catch {
    $cards.Add((New-CcdcHealthCard -Title 'Administrators' -Status Unknown -Value 'unknown' -Detail "Could not read the Administrators group: $($_.Exception.Message)"))
}
if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {
    try {
        $da = @(Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction Stop).Count
        $st = if ($da -le 4) { 'Good' } else { 'Warn' }
        $cards.Add((New-CcdcHealthCard -Title 'Domain Admins' -Status $st -Value "$da member(s)" -Detail 'The group red team wants to be in. Any name here you did not put there is an incident.'))
    } catch { }
}

# answer file + inventory
$answers = Import-CcdcAnswers -RootPath $RepoRoot
$protected = 0
if ($answers.ContainsKey('ProtectedAccounts') -and $answers['ProtectedAccounts']) {
    $protected = @($answers['ProtectedAccounts'] -split ',' | Where-Object { $_.Trim() }).Count
}
$cards.Add((Get-CcdcProtectedAccountsVerdict -Count $protected))

$age = $null
try {
    $invPath = Join-Path (Join-Path $RepoRoot 'logs') 'inventory-latest.json'
    if (Test-Path -LiteralPath $invPath) {
        $inv = Get-Content -LiteralPath $invPath -Raw | ConvertFrom-Json
        $age = [int][math]::Round(((Get-Date) - [datetime]$inv.Timestamp).TotalMinutes, 0)
    }
} catch { }
$cards.Add((Get-CcdcInventoryVerdict -AgeMinutes $age))

# scored services
$scored = @()
if ($answers.ContainsKey('ScoredServices') -and $answers['ScoredServices']) { $scored = @($answers['ScoredServices'] -split ',' | ForEach-Object { $_.Trim() }) }
$custom = @{}
foreach ($k in $answers.Keys) { if ($k -like 'Port_*') { $custom[$k.Substring(5)] = [string]$answers[$k] } }
$rows = @(Get-CcdcScoredServiceStatus -ScoredServices $scored -HostName $hostName -CustomPorts $custom -ListeningTcp $tcp -ListeningUdp $udp)
if ($scored.Count -eq 0) {
    $log.Add(@{ Level='WARN'; Message='No ScoredServices in config\answers.local.psd1, so there is nothing to check against. Fill it in from your packet -- it is what the firewall baseline opens ports for, too.' })
}

@{
    Log = $log.ToArray()
    Data = @{
        Host = $hostName; Domain = $domain; Role = $role
        User = "$env:USERDOMAIN\$env:USERNAME"; Elevated = (Test-CcdcElevated)
        Cards = $cards.ToArray(); Scored = $rows
    }
}
'@

$script:WorkAccounts = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]
$filter = "$($Arg.Filter)"

if ($Arg.Scope -eq 'Active Directory') {
    if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        $log.Add(@{ Level='ERROR'; Message='The Active Directory module is not available here. Run this on a domain controller, or on a box with RSAT installed.' })
    } else {
        $users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, MemberOf -ErrorAction Stop
        foreach ($u in $users) {
            if ($filter -and $u.SamAccountName -notlike "*$filter*") { continue }
            $groups = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' })
            $rows.Add([pscustomobject]@{
                Name = $u.SamAccountName; Enabled = $u.Enabled
                LastLogon = $(if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { 'never' })
                PasswordSet = $(if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'never' })
                Note = ($groups -join ', ')
            })
        }
    }
} else {
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        $log.Add(@{ Level='ERROR'; Message='Get-LocalUser is not available on this build of Windows.' })
    } else {
        $admins = @()
        try { $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch { }
        foreach ($u in (Get-LocalUser -ErrorAction Stop)) {
            if ($filter -and $u.Name -notlike "*$filter*") { continue }
            $rows.Add([pscustomobject]@{
                Name = $u.Name; Enabled = $u.Enabled
                LastLogon = $(if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'never' })
                PasswordSet = $(if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'never' })
                Note = $(if ($admins -contains $u.Name) { 'LOCAL ADMINISTRATOR' } else { '' })
            })
        }
    }
}
@{ Log = $log.ToArray(); Data = $rows.ToArray() }
'@

$script:WorkAccountAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$name = "$($Arg.Name)"
$isAd = ($Arg.Scope -eq 'Active Directory')
$newPassword = $null

function Save-UiCredential {
    param($Session, [string]$Account, [string]$Password, [string]$Kind)
    $path = Join-Path $Session.LogRoot "ui-credentials_$($Session.Stamp).csv"
    [pscustomobject]@{ Timestamp = (Get-Date -Format 'o'); Account = $Account; Kind = $Kind; Password = $Password } |
        Export-Csv -Path $path -NoTypeInformation -Append
    return $path
}

switch ($Arg.Action) {
    'Reset' {
        $newPassword = New-CcdcRandomPassword
        $secure = ConvertTo-SecureString $newPassword -AsPlainText -Force
        if ($isAd) {
            Backup-CcdcState -Name "ui-ADUser-$name" -Data (Get-ADUser -Identity $name -Properties * -ErrorAction Stop) | Out-Null
            Set-ADAccountPassword -Identity $name -Reset -NewPassword $secure -ErrorAction Stop
        } else {
            Backup-CcdcState -Name "ui-LocalUser-$name" -Data (Get-LocalUser -Name $name -ErrorAction Stop) | Out-Null
            Set-LocalUser -Name $name -Password $secure -ErrorAction Stop
        }
        $path = Save-UiCredential -Session $session -Account $name -Password $newPassword -Kind 'password reset'
        $log.Add(@{ Level='OK'; Message="Reset the password for '$name'. Written to $path." })
    }
    'Disable' {
        if ($isAd) {
            Backup-CcdcState -Name "ui-ADUser-$name" -Data (Get-ADUser -Identity $name -Properties * -ErrorAction Stop) | Out-Null
            Disable-ADAccount -Identity $name -ErrorAction Stop
        } else {
            Backup-CcdcState -Name "ui-LocalUser-$name" -Data (Get-LocalUser -Name $name -ErrorAction Stop) | Out-Null
            Disable-LocalUser -Name $name -ErrorAction Stop
        }
        $log.Add(@{ Level='OK'; Message="Disabled '$name'." })
    }
    'Enable' {
        if ($isAd) { Enable-ADAccount -Identity $name -ErrorAction Stop } else { Enable-LocalUser -Name $name -ErrorAction Stop }
        $log.Add(@{ Level='OK'; Message="Enabled '$name'." })
    }
    'AddToGroup' {
        $group = "$($Arg.Group)"
        if ($isAd) {
            Backup-CcdcState -Name "ui-ADGroup-$group" -Data (Get-ADGroupMember -Identity $group -ErrorAction Stop | ForEach-Object { $_.SamAccountName }) | Out-Null
            Add-ADGroupMember -Identity $group -Members $name -ErrorAction Stop
        } else {
            Backup-CcdcState -Name "ui-LocalGroup-$group" -Data (Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object { "$($_.Name)" }) | Out-Null
            Add-LocalGroupMember -Group $group -Member $name -ErrorAction Stop
        }
        $log.Add(@{ Level='OK'; Message="Added '$name' to '$group'." })
    }
    'RemoveFromGroup' {
        $group = "$($Arg.Group)"
        if ($isAd) {
            Backup-CcdcState -Name "ui-ADGroup-$group" -Data (Get-ADGroupMember -Identity $group -ErrorAction Stop | ForEach-Object { $_.SamAccountName }) | Out-Null
            # -Confirm:$false: Remove-ADGroupMember's own confirm impact is
            # High, so without this it would stop and wait for a Y/N on a
            # console nobody is watching -- this runs in a background
            # runspace with no way to answer it, the same trap already
            # avoided for Unregister-ScheduledTask below.
            Remove-ADGroupMember -Identity $group -Members $name -Confirm:$false -ErrorAction Stop
        } else {
            Backup-CcdcState -Name "ui-LocalGroup-$group" -Data (Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object { "$($_.Name)" }) | Out-Null
            Remove-LocalGroupMember -Group $group -Member $name -Confirm:$false -ErrorAction Stop
        }
        $log.Add(@{ Level='OK'; Message="Removed '$name' from '$group'." })
    }
    'Create' {
        $newPassword = New-CcdcRandomPassword
        $secure = ConvertTo-SecureString $newPassword -AsPlainText -Force
        if ($isAd) {
            $params = @{ Name = $name; SamAccountName = $name; AccountPassword = $secure; Enabled = $true; ChangePasswordAtLogon = $false; ErrorAction = 'Stop' }
            $answers = Import-CcdcAnswers -RootPath $RepoRoot
            if ($answers.ContainsKey('DomainName') -and $answers['DomainName']) { $params['UserPrincipalName'] = "$name@$($answers['DomainName'])" }
            if ($answers.ContainsKey('DefaultOU') -and $answers['DefaultOU']) { $params['Path'] = $answers['DefaultOU'] }
            New-ADUser @params
        } else {
            New-LocalUser -Name $name -Password $secure -ErrorAction Stop | Out-Null
        }
        if ($Arg.Group) {
            if ($isAd) { Add-ADGroupMember -Identity "$($Arg.Group)" -Members $name -ErrorAction Stop }
            else { Add-LocalGroupMember -Group "$($Arg.Group)" -Member $name -ErrorAction Stop }
            $log.Add(@{ Level='OK'; Message="Added '$name' to '$($Arg.Group)'." })
        }
        $path = Save-UiCredential -Session $session -Account $name -Password $newPassword -Kind 'account created'
        $log.Add(@{ Level='OK'; Message="Created '$name'. Password written to $path." })
    }
}
@{ Log = $log.ToArray(); Data = @{ Password = $newPassword; Account = $name } }
'@

$script:WorkDns = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]

if (-not (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue)) {
    # INFO, not ERROR: every box except the DNS server legitimately has no
    # DnsServer module, same as the IIS audit correctly declining on a DC.
    $log.Add(@{ Level='INFO'; Message="The DnsServer module isn't available here. Run this on the DNS server." })
    return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
}

if ($Arg.Query -eq 'Zones') {
    foreach ($z in (Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated })) {
        $isPrimary = ("$($z.ZoneType)" -eq 'Primary')
        $transferBad = $false; $transfersText = '-'
        $updateBad = $false
        if ($isPrimary) {
            $tv = Get-CcdcDnsZoneTransferVerdict -SecureSecondaries "$($z.SecureSecondaries)"
            $transferBad = [bool]$tv.Vulnerable
            $transfersText = if ($transferBad) { 'Any server' } else { 'Refused' }
            $uv = Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate "$($z.DynamicUpdate)" -IsDsIntegrated ([bool]$z.IsDsIntegrated)
            $updateBad = [bool]$uv.Vulnerable
        }
        $rows.Add([pscustomobject]@{
            ZoneName = "$($z.ZoneName)"; ZoneType = "$($z.ZoneType)"; DsIntegrated = [bool]$z.IsDsIntegrated
            Transfers = $transfersText; TransfersBrush = $(if ($transferBad) { '#F85149' } else { '#3FB950' })
            Updates = "$($z.DynamicUpdate)"; UpdatesBrush = $(if ($updateBad) { '#F85149' } elseif ($isPrimary) { '#3FB950' } else { '#9A9AA8' })
        })
    }
} else {
    $zoneName = "$($Arg.ZoneName)"
    if (-not $zoneName) {
        $log.Add(@{ Level='WARN'; Message='Pick a zone in the list first.' })
        return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
    }
    # Same subnet-prefix derivation Invoke-DnsHardening.ps1 uses, so an
    # off-subnet A record is flagged here exactly the way it would be there.
    $prefix = $null
    $answers = Import-CcdcAnswers -RootPath $RepoRoot
    if ($answers -and $answers.ContainsKey('SubnetCidr') -and $answers['SubnetCidr']) {
        if ("$($answers['SubnetCidr'])" -match '^(\d+\.\d+\.\d+)\.') { $prefix = $Matches[1] + '.' }
    }
    foreach ($r in (Get-DnsServerResourceRecord -ZoneName $zoneName -ErrorAction Stop)) {
        $ttl = 3600
        try { if ($r.TimeToLive) { $ttl = [int]$r.TimeToLive.TotalSeconds } } catch { }
        $data = Get-CcdcDnsRecordDataText -RecordData $r.RecordData
        if ($data -eq 'unknown') { $data = '' }
        $flags = @(Get-CcdcSuspiciousDnsRecordFlag -HostName "$($r.HostName)" -RecordType "$($r.RecordType)" -TtlSeconds $ttl -RecordData $data -ExpectedSubnetPrefix $prefix)
        $rows.Add([pscustomobject]@{ HostName = "$($r.HostName)"; RecordType = "$($r.RecordType)"; Data = $data; Ttl = $ttl; Flags = ($flags -join '; ') })
    }
}
@{ Log = $log.ToArray(); Data = $rows.ToArray() }
'@

$script:WorkDnsRecordAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$zoneName = "$($Arg.ZoneName)"
$name = "$($Arg.Name)"
$type = "$($Arg.Type)"
$value = "$($Arg.Value)"

switch ($Arg.Action) {
    'Add' {
        Backup-CcdcState -Name "ui-DnsZone-$zoneName" -Data (Get-DnsServerResourceRecord -ZoneName $zoneName -ErrorAction SilentlyContinue) | Out-Null
        $ttl = 3600
        $parsed = 0
        if ("$($Arg.Ttl)".Trim() -and [int]::TryParse("$($Arg.Ttl)", [ref]$parsed) -and $parsed -gt 0) { $ttl = $parsed }
        $ttlSpan = New-TimeSpan -Seconds $ttl
        switch ($type) {
            'A'     { Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $name -IPv4Address $value -TimeToLive $ttlSpan -ErrorAction Stop }
            'CNAME' { Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $name -HostNameAlias $value -TimeToLive $ttlSpan -ErrorAction Stop }
            'TXT'   { Add-DnsServerResourceRecord -ZoneName $zoneName -Name $name -Txt -DescriptiveText $value -TimeToLive $ttlSpan -ErrorAction Stop }
            default { throw "Unknown record type '$type'." }
        }
        $log.Add(@{ Level='OK'; Message="Added $type record '$name' -> '$value' in $zoneName (TTL ${ttl}s)." })
    }
    'Remove' {
        $target = @(Get-DnsServerResourceRecord -ZoneName $zoneName -Name $name -RRType $type -ErrorAction Stop |
                Where-Object { (Get-CcdcDnsRecordDataText -RecordData $_.RecordData) -eq $value })
        if ($target.Count -eq 0) {
            $log.Add(@{ Level='WARN'; Message='Could not find that exact record any more -- it may have already changed. Nothing removed.' })
        } else {
            Backup-CcdcState -Name "ui-DnsRecord-$name" -Data $target | Out-Null
            foreach ($t in $target) { Remove-DnsServerResourceRecord -ZoneName $zoneName -InputObject $t -Force -ErrorAction Stop }
            $log.Add(@{ Level='OK'; Message="Removed $type record '$name' from $zoneName." })
        }
    }
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkDnsHarden = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$zoneName = "$($Arg.ZoneName)"

switch ($Arg.Action) {
    'SecureZoneTransfers' {
        $z = Get-DnsServerZone -Name $zoneName -ErrorAction Stop
        Backup-CcdcState -Name "ui-DnsZone-$zoneName" -Data $z | Out-Null
        $v = Get-CcdcDnsZoneTransferVerdict -SecureSecondaries "$($z.SecureSecondaries)"
        if (-not $v.Vulnerable) {
            $log.Add(@{ Level='INFO'; Message="$zoneName already refuses zone transfers." })
        } else {
            Set-DnsServerPrimaryZone -Name $zoneName -SecureSecondaries 'NoTransfer' -ErrorAction Stop
            $log.Add(@{ Level='OK'; Message="$zoneName now refuses zone transfers." })
        }
    }
    'SecureDynamicUpdates' {
        $z = Get-DnsServerZone -Name $zoneName -ErrorAction Stop
        Backup-CcdcState -Name "ui-DnsZone-$zoneName" -Data $z | Out-Null
        $v = Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate "$($z.DynamicUpdate)" -IsDsIntegrated ([bool]$z.IsDsIntegrated)
        if (-not $v.Vulnerable) {
            $log.Add(@{ Level='INFO'; Message="$zoneName's dynamic updates are already secure." })
        } elseif (-not $v.SafeToChange) {
            $log.Add(@{ Level='WARN'; Message="$zoneName is file-backed, so the only secure value is '$($v.Target)', which stops clients registering themselves. Convert it to AD-integrated or decide deliberately -- not changed." })
        } else {
            Set-DnsServerPrimaryZone -Name $zoneName -DynamicUpdate $v.Target -ErrorAction Stop
            $log.Add(@{ Level='OK'; Message="$zoneName dynamic updates set to $($v.Target)." })
        }
    }
    'HardenCache' {
        $cache = Get-DnsServerCache -ErrorAction Stop
        Backup-CcdcState -Name 'ui-DnsCache' -Data $cache | Out-Null
        if ($cache.LockingPercent -ge 100 -and $cache.EnablePollutionProtection) {
            $log.Add(@{ Level='INFO'; Message='The cache is already hardened.' })
        } else {
            Set-DnsServerCache -LockingPercent 100 -PollutionProtection $true -ErrorAction Stop
            $log.Add(@{ Level='OK'; Message='Cache locking set to 100% and pollution protection turned on (server-wide, every zone).' })
        }
    }
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkDhcp = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]

if (-not (Get-Command -Name Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
    # INFO, not ERROR: every box except the DHCP server legitimately has no
    # DhcpServer module, same as the DNS tab correctly declining elsewhere.
    $log.Add(@{ Level='INFO'; Message="The DhcpServer module isn't available here. Run this on the DHCP server." })
    return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
}

if ($Arg.Query -eq 'Scopes') {
    foreach ($s in (Get-DhcpServerv4Scope -ErrorAction Stop)) {
        $rows.Add([pscustomobject]@{
            ScopeId = "$($s.ScopeId)"; Name = "$($s.Name)"; State = "$($s.State)"
            Range = "$($s.StartRange) - $($s.EndRange)"; SubnetMask = "$($s.SubnetMask)"
            LeaseDuration = "$($s.LeaseDuration)"
        })
    }
} else {
    $scopeId = "$($Arg.ScopeId)"
    if (-not $scopeId) {
        $log.Add(@{ Level='WARN'; Message='Pick a scope in the list first.' })
        return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
    }
    foreach ($r in (Get-DhcpServerv4Reservation -ScopeId $scopeId -ErrorAction Stop)) {
        $rows.Add([pscustomobject]@{
            IPAddress = "$($r.IPAddress)"; ClientId = "$($r.ClientId)"; Name = "$($r.Name)"
            Description = "$($r.Description)"; Type = "$($r.Type)"
        })
    }
}
@{ Log = $log.ToArray(); Data = $rows.ToArray() }
'@

$script:WorkDhcpReservationAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$scopeId = "$($Arg.ScopeId)"
$ip = "$($Arg.IPAddress)"

switch ($Arg.Action) {
    'Add' {
        Backup-CcdcState -Name "ui-DhcpScope-$scopeId" -Data (Get-DhcpServerv4Reservation -ScopeId $scopeId -ErrorAction SilentlyContinue) | Out-Null
        $params = @{ ScopeId = $scopeId; IPAddress = $ip; ClientId = "$($Arg.ClientId)"; ErrorAction = 'Stop' }
        if ("$($Arg.Name)") { $params.Name = "$($Arg.Name)" }
        if ("$($Arg.Description)") { $params.Description = "$($Arg.Description)" }
        Add-DhcpServerv4Reservation @params
        $log.Add(@{ Level='OK'; Message="Reserved $ip for client $($Arg.ClientId) in scope $scopeId." })
    }
    'Remove' {
        Backup-CcdcState -Name "ui-DhcpReservation-$ip" -Data (Get-DhcpServerv4Reservation -ScopeId $scopeId -ErrorAction SilentlyContinue | Where-Object { "$($_.IPAddress)" -eq $ip }) | Out-Null
        Remove-DhcpServerv4Reservation -IPAddress $ip -ErrorAction Stop
        $log.Add(@{ Level='OK'; Message="Removed the reservation for $ip." })
    }
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkGpo = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]

if (-not (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue)) {
    $log.Add(@{ Level='INFO'; Message="The GroupPolicy module isn't available here. Run this from a domain-joined host with RSAT (ideally a domain controller)." })
    return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
}

if ($Arg.Query -eq 'Gpos') {
    foreach ($g in (Get-GPO -All -ErrorAction Stop)) {
        $rows.Add([pscustomobject]@{
            DisplayName = "$($g.DisplayName)"; Id = "$($g.Id)"; GpoStatus = "$($g.GpoStatus)"
            Owner = "$($g.Owner)"; CreationTime = "$($g.CreationTime)"
        })
    }
} else {
    $gpoName = "$($Arg.GpoName)"
    if (-not $gpoName) {
        $log.Add(@{ Level='WARN'; Message='Pick a GPO in the list first.' })
        return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
    }
    # No single cmdlet returns "every place this GPO is linked" -- GpInheritance
    # is scoped to an OU/domain, not a GPO, so every OU plus the domain root
    # has to be checked. Fine at a small practice-lab domain's OU count; if
    # this ever needs to scale to a large real-world domain, narrow it with
    # -SearchBase first.
    $targets = New-Object System.Collections.Generic.List[string]
    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    if ($domain) { $targets.Add($domain.DistinguishedName) }
    foreach ($ou in (Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue)) { $targets.Add("$($ou.DistinguishedName)") }
    foreach ($t in $targets) {
        $links = @(Get-GPInheritance -Target $t -ErrorAction SilentlyContinue | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $gpoName })
        foreach ($l in $links) {
            $rows.Add([pscustomobject]@{ Target = $t; Enabled = "$($l.Enabled)"; Enforced = "$($l.Enforced)" })
        }
    }
}
@{ Log = $log.ToArray(); Data = $rows.ToArray() }
'@

$script:WorkGpoLinkAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$gpoName = "$($Arg.GpoName)"
$target = "$($Arg.Target)"

switch ($Arg.Action) {
    'Link' {
        Backup-CcdcState -Name "ui-GpoLinks-$target" -Data (Get-GPInheritance -Target $target -ErrorAction SilentlyContinue) | Out-Null
        New-GPLink -Name $gpoName -Target $target -ErrorAction Stop | Out-Null
        $log.Add(@{ Level='OK'; Message="Linked '$gpoName' to $target." })
    }
    'Unlink' {
        Backup-CcdcState -Name "ui-GpoLinks-$target" -Data (Get-GPInheritance -Target $target -ErrorAction SilentlyContinue) | Out-Null
        Remove-GPLink -Name $gpoName -Target $target -ErrorAction Stop
        $log.Add(@{ Level='OK'; Message="Unlinked '$gpoName' from $target." })
    }
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkGpoCreate = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]

# New-CcdcHardeningGpo is the ONE place the policy values and the real
# New-GPO/Set-GPRegistryValue/New-GPLink calls live -- Invoke-ADHardening.ps1
# calls the exact same function, so this button and that module cannot
# quietly disagree about what the hardening GPO contains.
$result = New-CcdcHardeningGpo -GpoName "$($Arg.GpoName)" -TargetOU "$($Arg.TargetOU)"
if ($result.Success) {
    $log.Add(@{ Level='OK'; Message=$result.Message })
} else {
    $log.Add(@{ Level='ERROR'; Message=$result.Message })
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkTasks = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]
$filter = "$($Arg.Filter)"
$patterns = @('\\Temp\\', '\\AppData\\', '\\Downloads\\', '\\Users\\Public\\', '\\ProgramData\\(?!Microsoft)')

if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    $log.Add(@{ Level='ERROR'; Message='Get-ScheduledTask is not available on this build of Windows.' })
    return @{ Log = $log.ToArray(); Data = $rows.ToArray() }
}
foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
    $full = "$($t.TaskPath)$($t.TaskName)"
    if ($filter -and $full -notlike "*$filter*") { continue }
    $exec = @($t.Actions | Where-Object { $_.Execute } | Select-Object -First 1)
    $cmd = if ($exec.Count -gt 0) { "$($exec[0].Execute) $($exec[0].Arguments)".Trim() } else { '(no executable action)' }
    $note = $cmd
    if (Test-CcdcSuspiciousPath -Path $cmd -Patterns $patterns) { $note = "SUSPICIOUS PATH -- $cmd" }
    $principal = "$($t.Principal.UserId)$(if ("$($t.Principal.RunLevel)" -eq 'Highest') { ' (highest)' })"
    $lastRun = 'never'
    try {
        $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
        if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1999) { $lastRun = $info.LastRunTime.ToString('yyyy-MM-dd HH:mm') }
    } catch { }
    $rows.Add([pscustomobject]@{
        Path = $full; TaskName = "$($t.TaskName)"; TaskPath = "$($t.TaskPath)"
        State = "$($t.State)"; RunAs = $principal; LastRun = $lastRun; Command = $note
    })
}
@{ Log = $log.ToArray(); Data = @($rows.ToArray() | Sort-Object Path) }
'@

$script:WorkTaskAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$taskName = "$($Arg.TaskName)"
$taskPath = "$($Arg.TaskPath)"

switch ($Arg.Action) {
    'Enable' {
        Backup-CcdcState -Name "ui-Task-$taskName" -Data (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop) | Out-Null
        Enable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
        $log.Add(@{ Level='OK'; Message="Enabled '$taskPath$taskName'." })
    }
    'Disable' {
        Backup-CcdcState -Name "ui-Task-$taskName" -Data (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop) | Out-Null
        Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop | Out-Null
        $log.Add(@{ Level='OK'; Message="Disabled '$taskPath$taskName'." })
    }
    'Delete' {
        $full = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        Backup-CcdcState -Name "ui-Task-$taskName" -Data $full | Out-Null
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
        $log.Add(@{ Level='OK'; Message="Deleted '$taskPath$taskName'. The full task definition is in the backup above if it needs to come back." })
    }
    'Create' {
        $trigger = switch ("$($Arg.Trigger)") {
            'At startup' { New-ScheduledTaskTrigger -AtStartup }
            'Daily 3am'  { New-ScheduledTaskTrigger -Daily -At '03:00' }
            default      { New-ScheduledTaskTrigger -AtLogOn }
        }
        $action = New-ScheduledTaskAction -Execute "$($Arg.Command)" -Argument "$($Arg.CommandArgs)"
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -ErrorAction Stop | Out-Null
        $log.Add(@{ Level='OK'; Message="Created task '$taskName'." })
    }
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkFirewall = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]
$filter = "$($Arg.Filter)"

# Bulk-fetch every port/address filter ONCE and join by InstanceID, rather
# than piping each rule through Get-NetFirewallPortFilter /
# -AddressFilter individually. Found for real, by this window's own
# self-test: the per-rule form does a separate CIM association query for
# EVERY rule, and a normal Windows box easily carries 500-700+ firewall
# rules -- that took over 90 seconds and made "List rules" look like the
# window had hung. Bulk-then-join is two queries total, not one per rule:
# well under a second for the same box. Verified the join is correct
# (matches the slow per-rule lookup on real sample rules) before trusting it.
$portByRule = @{}
foreach ($pf in (Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) { $portByRule[$pf.InstanceID] = $pf }
$addrByRule = @{}
foreach ($af in (Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)) { $addrByRule[$af.InstanceID] = $af }

foreach ($r in (Get-NetFirewallRule -ErrorAction Stop)) {
    if ($filter -and $r.DisplayName -notlike "*$filter*" -and $r.Name -notlike "*$filter*") { continue }
    $port = ''; $proto = ''
    if ($portByRule.ContainsKey($r.InstanceID)) {
        $pf = $portByRule[$r.InstanceID]
        $proto = "$($pf.Protocol)"; $port = "$($pf.LocalPort)"
    }
    $remote = ''
    if ($addrByRule.ContainsKey($r.InstanceID)) {
        $remote = "$($addrByRule[$r.InstanceID].RemoteAddress -join ', ')"
        if ($remote -eq 'Any') { $remote = '' }
    }
    $rows.Add([pscustomobject]@{
        Name = "$($r.DisplayName)"; InternalName = "$($r.Name)"
        Direction = "$($r.Direction)"; Action = "$($r.Action)"
        Enabled = $(if ("$($r.Enabled)" -eq 'True') { 'Yes' } else { 'No' })
        Protocol = $proto; Port = $port; RemoteAddress = $remote
    })
}
@{ Log = $log.ToArray(); Data = @($rows.ToArray() | Sort-Object Direction, Name) }
'@

$script:WorkFirewallAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$name = "$($Arg.Name)"

switch ($Arg.Action) {
    'Add' {
        Backup-CcdcState -Name 'ui-FirewallRules-before' -Data (Get-NetFirewallRule -ErrorAction SilentlyContinue) | Out-Null
        $params = @{ DisplayName = $name; Direction = "$($Arg.Direction)"; Action = "$($Arg.RuleAction)"; Protocol = "$($Arg.Protocol)"; ErrorAction = 'Stop' }
        if ("$($Arg.Port)".Trim()) { $params['LocalPort'] = "$($Arg.Port)".Trim() }
        if ("$($Arg.RemoteAddress)".Trim()) { $params['RemoteAddress'] = "$($Arg.RemoteAddress)".Trim() }
        New-NetFirewallRule @params | Out-Null
        $desc = "$($Arg.Direction) $($Arg.RuleAction) $($Arg.Protocol)$(if ($params.ContainsKey('LocalPort')) { "/$($params.LocalPort)" })$(if ($params.ContainsKey('RemoteAddress')) { " from $($params.RemoteAddress)" })"
        $log.Add(@{ Level='OK'; Message="Created rule '$name': $desc." })
    }
    'Enable' {
        Backup-CcdcState -Name "ui-FirewallRule-$name" -Data (Get-NetFirewallRule -Name $name -ErrorAction Stop) | Out-Null
        Enable-NetFirewallRule -Name $name -ErrorAction Stop
        $log.Add(@{ Level='OK'; Message="Enabled '$name'." })
    }
    'Disable' {
        Backup-CcdcState -Name "ui-FirewallRule-$name" -Data (Get-NetFirewallRule -Name $name -ErrorAction Stop) | Out-Null
        Disable-NetFirewallRule -Name $name -ErrorAction Stop
        $log.Add(@{ Level='OK'; Message="Disabled '$name'." })
    }
    'Remove' {
        Backup-CcdcState -Name "ui-FirewallRule-$name" -Data (Get-NetFirewallRule -Name $name -ErrorAction Stop) | Out-Null
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
        $log.Add(@{ Level='OK'; Message="Removed '$name'." })
    }
}
@{ Log = $log.ToArray(); Data = $null }
'@

$script:WorkServices = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$log = New-Object System.Collections.Generic.List[object]
$rows = New-Object System.Collections.Generic.List[object]
$filter = "$($Arg.Filter)"
$patterns = @('\\Temp\\', '\\AppData\\', '\\Downloads\\', '\\Users\\Public\\', '\\ProgramData\\(?!Microsoft)')
foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
    if ($filter -and $s.Name -notlike "*$filter*" -and $s.DisplayName -notlike "*$filter*") { continue }
    $path = "$($s.PathName)"
    $note = $path
    if (Test-CcdcSuspiciousPath -Path $path -Patterns $patterns) { $note = "SUSPICIOUS PATH -- $path" }
    $rows.Add([pscustomobject]@{
        Name = $s.Name; State = "$($s.State)"; StartMode = "$($s.StartMode)"; Account = "$($s.StartName)"; Path = $note
    })
}
@{ Log = $log.ToArray(); Data = @($rows.ToArray() | Sort-Object Name) }
'@

$script:WorkServiceAction = @'
param($RepoRoot, $Arg)
Import-Module (Join-Path $RepoRoot 'modules\Common.psm1') -Force
$session = Start-CcdcSession -RootPath $RepoRoot
$log = New-Object System.Collections.Generic.List[object]
$name = "$($Arg.Name)"
Backup-CcdcState -Name "ui-Service-$name" -Data (Get-Service -Name $name -ErrorAction Stop) | Out-Null
switch ($Arg.Action) {
    'Start'   { Start-Service   -Name $name -ErrorAction Stop; $log.Add(@{ Level='OK'; Message="Started '$name'." }) }
    'Stop'    { Stop-Service    -Name $name -Force -ErrorAction Stop; $log.Add(@{ Level='OK'; Message="Stopped '$name'." }) }
    'Restart' { Restart-Service -Name $name -Force -ErrorAction Stop; $log.Add(@{ Level='OK'; Message="Restarted '$name'." }) }
    'Startup' { Set-Service -Name $name -StartupType "$($Arg.StartupType)" -ErrorAction Stop; $log.Add(@{ Level='OK'; Message="Set '$name' startup type to $($Arg.StartupType)." }) }
}
@{ Log = $log.ToArray(); Data = $null }
'@

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
function Update-Dashboard {
    Start-UiWork -Status 'Checking this box...' -ScriptText $script:WorkRefresh -OnDone {
        param($result)
        $d = $result.Data
        if (-not $d) { Write-UiLog -Level ERROR -Message 'The health check came back empty.'; return }

        $ui.HostText.Text = "$($d.Host)"
        $ui.DomainText.Text = "$($d.Domain)  --  $($d.Role)"
        $ui.UserText.Text = "running as $($d.User)"
        $elevated = $d.Elevated
        $ui.ElevatedText.Text = if ($elevated -eq $true) { 'elevated (Administrator)' } elseif ($elevated -eq $false) { 'NOT elevated' } else { 'elevation unknown' }
        $ui.ElevationBanner.Visibility = if ($elevated -eq $false) { 'Visible' } else { 'Collapsed' }

        $cards = @($d.Cards | ForEach-Object {
            [pscustomobject]@{ Title = $_.Title; Status = $_.Status; Value = $_.Value; Detail = $_.Detail; StatusBrush = (Get-StatusBrush $_.Status) }
        })
        $ui.HealthCards.ItemsSource = $cards
        $overall = Get-CcdcOverallHealth -Cards $cards
        $ui.HealthPillText.Text = switch ($overall) { 'Good' { 'all clear' } 'Warn' { 'needs a look' } 'Bad' { 'act now' } default { 'incomplete' } }
        $ui.HealthPill.Background = (Get-StatusBrush $overall)

        $scored = @($d.Scored | ForEach-Object {
            [pscustomobject]@{ Service = $_.Service; Protocol = $_.Protocol; Port = $_.Port; Status = $_.Status; Detail = $_.Detail; StatusBrush = (Get-StatusBrush $_.Status) }
        })
        $ui.ScoredGrid.ItemsSource = $scored
        $down = @($scored | Where-Object { $_.Status -eq 'Down' })
        if ($down.Count -gt 0) {
            Write-UiLog -Level ERROR -Message "$($down.Count) scored service(s) are NOT listening right now: $(($down | ForEach-Object { "$($_.Service) $($_.Protocol)/$($_.Port)" }) -join ', '). If the packet scores those, you are losing points while this is true."
        }
        Write-UiLog -Level INFO -Message "Health refreshed: $overall."
    }
}

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
foreach ($scope in 'Local', 'Active Directory') { [void]$ui.AccountScopeCombo.Items.Add($scope) }
$ui.AccountScopeCombo.SelectedIndex = 0

function Update-Accounts {
    $scope = "$($ui.AccountScopeCombo.SelectedItem)"
    Start-UiWork -Status "Listing $scope accounts..." -ScriptText $script:WorkAccounts `
        -Arguments @{ Scope = $scope; Filter = $ui.AccountFilterBox.Text } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.AccountGrid.ItemsSource = $rows
        Write-UiLog -Level INFO -Message "$($rows.Count) account(s) listed."
    }
}

function Get-SelectedAccount {
    $row = $ui.AccountGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick an account in the list first.'; return $null }
    return "$($row.Name)"
}

function Invoke-AccountAction {
    param([string]$Action, [string]$Name, [string]$Group, [string]$Confirm)
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    $scope = "$($ui.AccountScopeCombo.SelectedItem)"
    Write-UiLog -Level ACTION -Message "$Action on '$Name' ($scope)."
    Start-UiWork -Status "$Action on $Name..." -ScriptText $script:WorkAccountAction `
        -Arguments @{ Action = $Action; Name = $Name; Group = $Group; Scope = $scope } -OnDone {
        param($result)
        $pw = $result.Data.Password
        if ($pw) {
            [System.Windows.MessageBox]::Show($window,
                "New password for $($result.Data.Account):`n`n$pw`n`nIt is also in the credential file under logs\ (see Activity). Copy it somewhere your team can use it, and remember it is in this session's transcript too.",
                'Password', [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        }
        Update-Accounts
    }
}

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
foreach ($t in 'A', 'CNAME', 'TXT') { [void]$ui.DnsRecordTypeCombo.Items.Add($t) }
$ui.DnsRecordTypeCombo.SelectedIndex = 0

function Update-DnsZones {
    Start-UiWork -Status 'Listing DNS zones...' -ScriptText $script:WorkDns -Arguments @{ Query = 'Zones' } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.DnsZoneGrid.ItemsSource = $rows
        $bad = @($rows | Where-Object { $_.TransfersBrush -eq '#F85149' -or $_.UpdatesBrush -eq '#F85149' })
        if ($bad.Count -gt 0) { Write-UiLog -Level WARN -Message "$($bad.Count) zone(s) have an open transfer or update setting: $(($bad | ForEach-Object { $_.ZoneName }) -join ', ')." }
        Write-UiLog -Level INFO -Message "$($rows.Count) zone(s) listed."
    }
}

function Get-SelectedZone {
    $row = $ui.DnsZoneGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a zone in the list first.'; return $null }
    return "$($row.ZoneName)"
}

function Update-DnsRecords {
    $zone = Get-SelectedZone; if (-not $zone) { return }
    Start-UiWork -Status "Listing records in $zone..." -ScriptText $script:WorkDns -Arguments @{ Query = 'Records'; ZoneName = $zone } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.DnsRecordGrid.ItemsSource = $rows
        $flagged = @($rows | Where-Object { $_.Flags })
        if ($flagged.Count -gt 0) { Write-UiLog -Level WARN -Message "$($flagged.Count) record(s) worth a look -- see the Flags column. Flagged is not malicious: read them and decide." }
        Write-UiLog -Level INFO -Message "$($rows.Count) record(s) listed for $zone."
    }
}

function Get-SelectedRecord {
    $row = $ui.DnsRecordGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a record in the list first.'; return $null }
    return $row
}

function Invoke-DnsRecordAction {
    param([string]$Action, [string]$Name, [string]$Type, [string]$Value, [string]$Ttl, [string]$Confirm)
    $zone = Get-SelectedZone; if (-not $zone) { return }
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action $Type record '$Name' in $zone."
    Start-UiWork -Status "$Action record..." -ScriptText $script:WorkDnsRecordAction `
        -Arguments @{ Action = $Action; ZoneName = $zone; Name = $Name; Type = $Type; Value = $Value; Ttl = $Ttl } -OnDone {
        param($result)
        Update-DnsRecords
    }
}

function Invoke-DnsHardenAction {
    param([string]$Action, [string]$Confirm)
    $zone = $null
    if ($Action -ne 'HardenCache') { $zone = Get-SelectedZone; if (-not $zone) { return } }
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action$(if ($zone) { " on $zone" })."
    Start-UiWork -Status "$Action..." -ScriptText $script:WorkDnsHarden -Arguments @{ Action = $Action; ZoneName = $zone } -OnDone {
        param($result)
        if ($zone) { Update-DnsZones }
    }
}

# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------
function Update-DhcpScopes {
    Start-UiWork -Status 'Listing DHCP scopes...' -ScriptText $script:WorkDhcp -Arguments @{ Query = 'Scopes' } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.DhcpScopeGrid.ItemsSource = $rows
        Write-UiLog -Level INFO -Message "$($rows.Count) scope(s) listed."
    }
}

function Get-SelectedScope {
    $row = $ui.DhcpScopeGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a scope in the list first.'; return $null }
    return "$($row.ScopeId)"
}

function Update-DhcpReservations {
    $scope = Get-SelectedScope; if (-not $scope) { return }
    Start-UiWork -Status "Listing reservations in $scope..." -ScriptText $script:WorkDhcp -Arguments @{ Query = 'Reservations'; ScopeId = $scope } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.DhcpReservationGrid.ItemsSource = $rows
        Write-UiLog -Level INFO -Message "$($rows.Count) reservation(s) listed for $scope."
    }
}

function Get-SelectedReservation {
    $row = $ui.DhcpReservationGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a reservation in the list first.'; return $null }
    return $row
}

function Invoke-DhcpReservationAction {
    param([string]$Action, [string]$IPAddress, [string]$ClientId, [string]$Name, [string]$Description, [string]$Confirm)
    $scope = Get-SelectedScope; if (-not $scope) { return }
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action reservation $IPAddress in scope $scope."
    Start-UiWork -Status "$Action reservation..." -ScriptText $script:WorkDhcpReservationAction `
        -Arguments @{ Action = $Action; ScopeId = $scope; IPAddress = $IPAddress; ClientId = $ClientId; Name = $Name; Description = $Description } -OnDone {
        param($result)
        Update-DhcpReservations
    }
}

# ---------------------------------------------------------------------------
# Group Policy
# ---------------------------------------------------------------------------
function Update-GpoList {
    Start-UiWork -Status 'Listing GPOs...' -ScriptText $script:WorkGpo -Arguments @{ Query = 'Gpos' } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.GpoGrid.ItemsSource = $rows
        Write-UiLog -Level INFO -Message "$($rows.Count) GPO(s) listed."
    }
}

function Get-SelectedGpo {
    $row = $ui.GpoGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a GPO in the list first.'; return $null }
    return "$($row.DisplayName)"
}

function Update-GpoLinks {
    $gpo = Get-SelectedGpo; if (-not $gpo) { return }
    Start-UiWork -Status "Listing links for $gpo..." -ScriptText $script:WorkGpo -Arguments @{ Query = 'Links'; GpoName = $gpo } -OnDone {
        param($result)
        $rows = @($result.Data)
        $ui.GpoLinkGrid.ItemsSource = $rows
        Write-UiLog -Level INFO -Message "$($rows.Count) link(s) listed for $gpo."
    }
}

function Get-SelectedGpoLink {
    $row = $ui.GpoLinkGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a link in the list first.'; return $null }
    return $row
}

function Invoke-GpoLinkAction {
    param([string]$Action, [string]$Target, [string]$Confirm)
    $gpo = Get-SelectedGpo; if (-not $gpo) { return }
    if (-not $Target) { Write-UiLog -Level WARN -Message 'Type a target distinguished name first.'; return }
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action '$gpo' to $Target."
    Start-UiWork -Status "$Action..." -ScriptText $script:WorkGpoLinkAction -Arguments @{ Action = $Action; GpoName = $gpo; Target = $Target } -OnDone {
        param($result)
        Update-GpoLinks
    }
}

function Invoke-GpoCreate {
    param([string]$GpoName, [string]$TargetOU, [string]$Confirm)
    if (-not $GpoName) { Write-UiLog -Level WARN -Message 'Type a GPO name first.'; return }
    if (-not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "Create/update hardening GPO '$GpoName'."
    Start-UiWork -Status 'Creating hardening GPO...' -ScriptText $script:WorkGpoCreate -Arguments @{ GpoName = $GpoName; TargetOU = $TargetOU } -OnDone {
        param($result)
        Update-GpoList
    }
}

# ---------------------------------------------------------------------------
# Scheduled Tasks
# ---------------------------------------------------------------------------
foreach ($t in 'At logon', 'At startup', 'Daily 3am') { [void]$ui.TaskNewTrigger.Items.Add($t) }
$ui.TaskNewTrigger.SelectedIndex = 0

function Update-Tasks {
    Start-UiWork -Status 'Listing scheduled tasks...' -ScriptText $script:WorkTasks `
        -Arguments @{ Filter = $ui.TaskFilterBox.Text } -OnDone {
        param($result)
        $rows = @($result.Data | ForEach-Object {
                [pscustomobject]@{
                    Path = $_.Path; TaskName = $_.TaskName; TaskPath = $_.TaskPath
                    State = $_.State; RunAs = $_.RunAs; LastRun = $_.LastRun; Command = $_.Command
                    StatusBrush = $(if ($_.State -eq 'Disabled') { '#9A9AA8' } else { Get-StatusBrush 'Running' })
                }
            })
        $ui.TaskGrid.ItemsSource = $rows
        $odd = @($rows | Where-Object { $_.Command -like 'SUSPICIOUS PATH*' })
        if ($odd.Count -gt 0) { Write-UiLog -Level WARN -Message "$($odd.Count) task(s) run from an unusual location: $(($odd | ForEach-Object { $_.Path }) -join ', '). This is exactly the shape a dropped persistence task takes." }
        Write-UiLog -Level INFO -Message "$($rows.Count) task(s) listed."
    }
}

function Get-SelectedTask {
    $row = $ui.TaskGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a task in the list first.'; return $null }
    return $row
}

function Invoke-TaskAction {
    param([string]$Action, [string]$TaskName, [string]$TaskPath, [string]$Command, [string]$CommandArgs, [string]$Trigger, [string]$Confirm)
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action task '$TaskPath$TaskName'."
    Start-UiWork -Status "$Action task..." -ScriptText $script:WorkTaskAction `
        -Arguments @{ Action = $Action; TaskName = $TaskName; TaskPath = $TaskPath; Command = $Command; CommandArgs = $CommandArgs; Trigger = $Trigger } `
        -OnDone { param($result) Update-Tasks }
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
foreach ($t in 'Inbound', 'Outbound') { [void]$ui.FwDirectionCombo.Items.Add($t) }
$ui.FwDirectionCombo.SelectedIndex = 0
foreach ($t in 'Allow', 'Block') { [void]$ui.FwActionCombo.Items.Add($t) }
$ui.FwActionCombo.SelectedIndex = 0
foreach ($t in 'TCP', 'UDP', 'ICMPv4') { [void]$ui.FwProtocolCombo.Items.Add($t) }
$ui.FwProtocolCombo.SelectedIndex = 0

function Update-Firewall {
    Start-UiWork -Status 'Listing firewall rules...' -ScriptText $script:WorkFirewall `
        -Arguments @{ Filter = $ui.FirewallFilterBox.Text } -OnDone {
        param($result)
        $rows = @($result.Data | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name; InternalName = $_.InternalName; Direction = $_.Direction
                    Action = $_.Action; ActionBrush = $(if ($_.Action -eq 'Block') { '#F85149' } else { '#3FB950' })
                    Enabled = $_.Enabled; Protocol = $_.Protocol; Port = $_.Port; RemoteAddress = $_.RemoteAddress
                }
            })
        $ui.FirewallGrid.ItemsSource = $rows
        Write-UiLog -Level INFO -Message "$($rows.Count) rule(s) listed.$(if (-not $ui.FirewallFilterBox.Text.Trim()) { ' That is every rule on the box, Windows'' own included -- type a filter to narrow it down.' })"
    }
}

function Get-SelectedFirewallRule {
    $row = $ui.FirewallGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a rule in the list first.'; return $null }
    return $row
}

function Invoke-FirewallRuleAction {
    param([string]$Action, [string]$Name, [hashtable]$Extra = @{}, [string]$Confirm)
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action firewall rule '$Name'."
    $ruleArgs = @{ Action = $Action; Name = $Name }
    foreach ($k in $Extra.Keys) { $ruleArgs[$k] = $Extra[$k] }
    Start-UiWork -Status "$Action rule..." -ScriptText $script:WorkFirewallAction -Arguments $ruleArgs -OnDone { param($result) Update-Firewall }
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------
foreach ($t in 'Automatic', 'Manual', 'Disabled') { [void]$ui.ServiceStartupCombo.Items.Add($t) }
$ui.ServiceStartupCombo.SelectedIndex = 0

function Update-Services {
    Start-UiWork -Status 'Listing services...' -ScriptText $script:WorkServices `
        -Arguments @{ Filter = $ui.ServiceFilterBox.Text } -OnDone {
        param($result)
        $rows = @($result.Data | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; State = $_.State; StartMode = $_.StartMode; Account = $_.Account; Path = $_.Path
                               StatusBrush = (Get-StatusBrush $_.State) }
        })
        $ui.ServiceGrid.ItemsSource = $rows
        $odd = @($rows | Where-Object { $_.Path -like 'SUSPICIOUS PATH*' })
        if ($odd.Count -gt 0) { Write-UiLog -Level WARN -Message "$($odd.Count) service(s) run from an unusual location: $(($odd | ForEach-Object { $_.Name }) -join ', '). Worth checking who put them there." }
        Write-UiLog -Level INFO -Message "$($rows.Count) service(s) listed."
    }
}

function Get-SelectedService {
    $row = $ui.ServiceGrid.SelectedItem
    if (-not $row) { Write-UiLog -Level WARN -Message 'Pick a service in the list first.'; return $null }
    return "$($row.Name)"
}

function Invoke-ServiceAction {
    param([string]$Action, [string]$Name, [string]$StartupType, [string]$Confirm)
    if ($Confirm -and -not (Confirm-UiAction -Message $Confirm)) { Write-UiLog -Level INFO -Message 'Cancelled.'; return }
    Write-UiLog -Level ACTION -Message "$Action on service '$Name'."
    Start-UiWork -Status "$Action on $Name..." -ScriptText $script:WorkServiceAction `
        -Arguments @{ Action = $Action; Name = $Name; StartupType = $StartupType } -OnDone { param($r) Update-Services }
}

# ---------------------------------------------------------------------------
# Modules: open each in its own console window, which is where they belong.
# ---------------------------------------------------------------------------
$script:Modules = @(
    @{ Name = 'Environment discovery'; Script = 'Get-EnvironmentInventory.ps1'; ReadOnly = $true
       Desc = 'Finds the domain, the hosts and the accounts, and saves them for the other modules. Read-only. Run this first.' }
    @{ Name = 'Threat hunt (one pass)'; Script = 'Invoke-ThreatHunt.ps1'; ReadOnly = $true
       Desc = 'What changed since the last pass, plus what looks wrong regardless. Read-only, safe to run constantly.' }
    @{ Name = 'Threat hunt (continuous)'; Script = 'Invoke-ThreatHunt.ps1'; Args = @('-Continuous'); ReadOnly = $true
       Desc = 'The same thing on a timer, in its own window. Leave it open all round.' }
    @{ Name = 'Capture configuration baseline'; Script = 'Invoke-ConfigBaseline.ps1'; Args = @('-Action', 'Capture'); ReadOnly = $true
       Desc = 'Records DNS, services, tasks, admins, ports, firewall, autoruns and patch level as they are right now. Run this once, early, on a box you trust. Read-only -- writes a record under logs\, changes nothing on the box.' }
    @{ Name = 'Verify against baseline'; Script = 'Invoke-ConfigBaseline.ps1'; Args = @('-Action', 'Verify'); ReadOnly = $true
       Desc = 'Compares right now against that record and says exactly what changed. Run this the moment something feels wrong. Read-only -- writes a drift report under logs\, changes nothing on the box.' }
    @{ Name = 'IIS / FTP audit'; Script = 'Invoke-IISHardening.ps1'; Args = @('-ReportOnly'); ReadOnly = $true
       Desc = 'Web shells worth reading, the answer-file lines for this box including the FTP passive range, and an FTP audit. Read-only.' }
    @{ Name = 'Credential hardening (preview)'; Script = 'Invoke-CredentialHardening.ps1'; Args = @('-WhatIf'); ReadOnly = $true
       Desc = 'Shows exactly which accounts would be rotated. Changes nothing.' }
    @{ Name = 'Firewall baseline (preview)'; Script = 'Invoke-FirewallBaseline.ps1'; Args = @('-WhatIf'); ReadOnly = $true
       Desc = 'Shows the allow list it would build. Changes nothing.' }
    @{ Name = 'Credential hardening'; Script = 'Invoke-CredentialHardening.ps1'
       Desc = 'Rotates local and AD passwords to fresh random values. Fill in ProtectedAccounts first.' }
    @{ Name = 'Firewall baseline'; Script = 'Invoke-FirewallBaseline.ps1'
       Desc = 'Allow-list the scored ports, then default-block, behind a safety net that reverts itself if it goes wrong.' }
    @{ Name = 'IIS / FTP hardening'; Script = 'Invoke-IISHardening.ps1'
       Desc = 'The audit, then directory browsing off and identifying headers removed. Backs up the IIS config first.' }
    @{ Name = 'Install Sysmon'; Script = 'Install-Sysmon.ps1'
       Desc = 'Detailed process logging. Low risk and worth doing early.' }
    @{ Name = 'Install Splunk forwarder'; Script = 'Install-SplunkForwarder.ps1'
       Desc = 'Ships the logs off the box. Needs the .msi staged in tools\SplunkForwarder\.' }
    @{ Name = 'AD hardening'; Script = 'Invoke-ADHardening.ps1'
       Desc = 'DOMAIN-WIDE: stale accounts, a documented blue-team admin, a hardening GPO, password policy. Run once, from a DC.' }
    @{ Name = 'DNS audit'; Script = 'Invoke-DnsHardening.ps1'; ReadOnly = $true
       Desc = 'Zone transfers, dynamic updates, cache protection, and records worth reading. Changes nothing.' }
    @{ Name = 'DNS hardening'; Script = 'Invoke-DnsHardening.ps1'; Args = @('-SecureZoneTransfers', '-SecureDynamicUpdates', '-HardenCache')
       Desc = 'Refuses zone transfers, secures dynamic updates, hardens the cache. Leaves recursion alone -- DNS is scored.' }
    @{ Name = 'Known-exploit audit'; Script = 'Invoke-ExploitAudit.ps1'; ReadOnly = $true
       Desc = 'The things red team reaches for first: WDigest, SMBv1, LLMNR, spooler, machine-account quota and more. Changes nothing.' }
    @{ Name = 'Close known-exploit gaps'; Script = 'Invoke-ExploitAudit.ps1'; Args = @('-Fix')
       Desc = 'Applies only the mitigations marked safe, each backed up first. Run the audit and read the risks before this.' }
    @{ Name = 'Admin console'; Script = 'Invoke-AdminConsole.ps1'
       Desc = 'The full text menu for anything this window does not cover yet -- file/folder permissions is the main gap left.' }
    @{ Name = 'Write an incident report'; Script = 'New-IncidentReport.ps1'
       Desc = 'Every field the packet requires, plus the evidence this toolkit already logged. Writes a memo ready to print to PDF.' }
    @{ Name = 'Packet capture'; Script = 'Invoke-PacketCapture.ps1'
       Desc = 'A short timestamped capture as evidence. Grab this BEFORE you clean anything up.' }
    @{ Name = 'Network recon (nmap)'; Script = 'Invoke-NetworkRecon.ps1'
       Desc = 'Loud and slow. For practice runs, not during a round.' }
)

function Start-ModuleWindow {
    param([hashtable]$Module)
    $path = Join-Path (Join-Path $repoRoot 'modules') $Module.Script
    if (-not (Test-Path -LiteralPath $path)) { Write-UiLog -Level ERROR -Message "Can't find $path."; return }
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    # Built by Get-CcdcModuleLaunchArgs, which drops nulls. Most module
    # entries have no Args key, and @($null) is an array holding one $null
    # rather than an empty one -- which Start-Process rejects outright.
    # See that function for the full story; it cost eleven dead buttons.
    $argList = Get-CcdcModuleLaunchArgs -ScriptPath $path -ExtraArgs $Module.Args
    Start-Process -FilePath $exe -ArgumentList $argList | Out-Null
    Write-UiLog -Level ACTION -Message "Opened '$($Module.Name)' in its own window. It stays open when it finishes so you can read the output."
}

foreach ($m in $script:Modules) {
    $card = New-Object System.Windows.Controls.Border
    $card.Width = 300; $card.Margin = '0,0,13,13'; $card.Padding = '14,12'; $card.CornerRadius = 5
    $card.Background = '#26262E'; $card.BorderBrush = if ($m.ReadOnly) { '#3A5A3E' } else { '#3A3A46' }
    $card.BorderThickness = 1
    $stack = New-Object System.Windows.Controls.StackPanel

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = $m.Name; $title.FontFamily = 'Segoe UI Semibold'; $title.FontSize = 13.5
    $title.Foreground = '#E6E6EB'; $title.TextWrapping = 'Wrap'; $title.Margin = '0,0,0,4'
    [void]$stack.Children.Add($title)

    $tag = New-Object System.Windows.Controls.TextBlock
    $tag.Text = if ($m.ReadOnly) { 'read-only' } else { 'changes this machine' }
    $tag.FontSize = 11; $tag.Margin = '0,0,0,6'
    $tag.Foreground = if ($m.ReadOnly) { '#3FB950' } else { '#D29922' }
    [void]$stack.Children.Add($tag)

    $desc = New-Object System.Windows.Controls.TextBlock
    $desc.Text = $m.Desc; $desc.FontSize = 11.5; $desc.Foreground = '#9A9AA8'
    $desc.TextWrapping = 'Wrap'; $desc.Margin = '0,0,0,10'; $desc.MinHeight = 56
    [void]$stack.Children.Add($desc)

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content = 'Open'; $btn.HorizontalAlignment = 'Left'
    $captured = $m
    $btn.Add_Click({ try { Start-ModuleWindow -Module $captured } catch { Write-UiLog -Level ERROR -Message "Couldn't start that: $($_.Exception.Message)" } }.GetNewClosure())
    [void]$stack.Children.Add($btn)

    $card.Child = $stack
    [void]$ui.ModuleList.Items.Add($card)
}

# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------
Register-UiClick -Button $ui.RefreshButton -Action { Update-Dashboard }
Register-UiClick -Button $ui.OpenLogsButton -NotAnActionButton -Action {
    Start-Process explorer.exe $session.LogRoot | Out-Null
    Write-UiLog -Level INFO -Message "Opened $($session.LogRoot)."
}
Register-UiClick -Button $ui.AccountSearchButton -Action { Update-Accounts }
Register-UiClick -Button $ui.ServiceSearchButton -Action { Update-Services }

Register-UiClick -Button $ui.AccountResetButton -Action {
    $n = Get-SelectedAccount; if (-not $n) { return }
    Invoke-AccountAction -Action 'Reset' -Name $n -Confirm "Give '$n' a brand-new random password?`n`nAnything using the old one stops working immediately -- if a scoring check logs in as this account, that check fails until you report the new password."
}
Register-UiClick -Button $ui.AccountDisableButton -Action {
    $n = Get-SelectedAccount; if (-not $n) { return }
    Invoke-AccountAction -Action 'Disable' -Name $n -Confirm "Disable '$n'?`n`nThey cannot log in at all until it is enabled again."
}
Register-UiClick -Button $ui.AccountEnableButton -Action {
    $n = Get-SelectedAccount; if (-not $n) { return }
    Invoke-AccountAction -Action 'Enable' -Name $n
}
Register-UiClick -Button $ui.AccountAddGroupButton -Action {
    $n = Get-SelectedAccount; if (-not $n) { return }
    $g = $ui.AccountGroupBox.Text.Trim()
    if (-not $g) { Write-UiLog -Level WARN -Message 'Type a group name first.'; return }
    Invoke-AccountAction -Action 'AddToGroup' -Name $n -Group $g -Confirm "Add '$n' to '$g'?`n`nIf that group is privileged, this hands them those rights straight away."
}
Register-UiClick -Button $ui.AccountRemoveGroupButton -Action {
    $n = Get-SelectedAccount; if (-not $n) { return }
    $g = $ui.AccountGroupBox.Text.Trim()
    if (-not $g) { Write-UiLog -Level WARN -Message 'Type a group name first.'; return }
    Invoke-AccountAction -Action 'RemoveFromGroup' -Name $n -Group $g -Confirm "Remove '$n' from '$g'?`n`nIf that group is what grants them some access, they lose it the moment this runs."
}
Register-UiClick -Button $ui.AccountCreateButton -Action {
    $n = $ui.AccountNewName.Text.Trim()
    if (-not $n) { Write-UiLog -Level WARN -Message 'Type a login name first.'; return }
    Invoke-AccountAction -Action 'Create' -Name $n -Group $ui.AccountNewGroup.Text.Trim() -Confirm "Create the account '$n'?"
}

Register-UiClick -Button $ui.DnsListZonesButton -Action { Update-DnsZones }
Register-UiClick -Button $ui.DnsListRecordsButton -Action { Update-DnsRecords }
Register-UiClick -Button $ui.DnsAddRecordButton -Action {
    $n = $ui.DnsRecordName.Text.Trim()
    if (-not $n) { Write-UiLog -Level WARN -Message 'Type a host name first.'; return }
    $v = $ui.DnsRecordValue.Text.Trim()
    if (-not $v) { Write-UiLog -Level WARN -Message 'Type a value first (an IP for A, a target host for CNAME, text for TXT).'; return }
    $t = "$($ui.DnsRecordTypeCombo.SelectedItem)"
    Invoke-DnsRecordAction -Action 'Add' -Name $n -Type $t -Value $v -Ttl $ui.DnsRecordTtl.Text.Trim() `
        -Confirm "Add a $t record '$n' -> '$v' to the selected zone?"
}
Register-UiClick -Button $ui.DnsRemoveRecordButton -Action {
    $row = Get-SelectedRecord; if (-not $row) { return }
    Invoke-DnsRecordAction -Action 'Remove' -Name "$($row.HostName)" -Type "$($row.RecordType)" -Value "$($row.Data)" `
        -Confirm "Remove the $($row.RecordType) record '$($row.HostName)' -> '$($row.Data)'?`n`nAnything that resolves this name stops finding it immediately."
}
Register-UiClick -Button $ui.DnsSecureTransfersButton -Action {
    Invoke-DnsHardenAction -Action 'SecureZoneTransfers' -Confirm "Refuse zone transfers for the selected zone?`n`nAny legitimate secondary DNS server that relies on a transfer from this zone stops getting updates."
}
Register-UiClick -Button $ui.DnsSecureUpdatesButton -Action {
    Invoke-DnsHardenAction -Action 'SecureDynamicUpdates' -Confirm "Set the selected zone's dynamic updates to Secure?`n`nA non-domain-joined device that relies on unauthenticated registration will stop being able to register or update its own record."
}
Register-UiClick -Button $ui.DnsHardenCacheButton -Action {
    Invoke-DnsHardenAction -Action 'HardenCache' -Confirm "Harden the DNS cache server-wide (locking 100%, pollution protection on)?`n`nThis affects every zone this server answers for, not just one."
}

Register-UiClick -Button $ui.DhcpListScopesButton -Action { Update-DhcpScopes }
Register-UiClick -Button $ui.DhcpListReservationsButton -Action { Update-DhcpReservations }
Register-UiClick -Button $ui.DhcpAddReservationButton -Action {
    $ip = $ui.DhcpResIp.Text.Trim()
    if (-not $ip) { Write-UiLog -Level WARN -Message 'Type an IP address first.'; return }
    $mac = $ui.DhcpResClientId.Text.Trim()
    if (-not $mac) { Write-UiLog -Level WARN -Message 'Type a client MAC address first.'; return }
    Invoke-DhcpReservationAction -Action 'Add' -IPAddress $ip -ClientId $mac -Name $ui.DhcpResName.Text.Trim() -Description $ui.DhcpResDescription.Text.Trim() `
        -Confirm "Reserve $ip for client $mac in the selected scope?"
}
Register-UiClick -Button $ui.DhcpRemoveReservationButton -Action {
    $row = Get-SelectedReservation; if (-not $row) { return }
    Invoke-DhcpReservationAction -Action 'Remove' -IPAddress "$($row.IPAddress)" `
        -Confirm "Remove the reservation for $($row.IPAddress) (client $($row.ClientId))?`n`nThat IP becomes available for any client to lease again."
}

Register-UiClick -Button $ui.GpoListButton -Action { Update-GpoList }
Register-UiClick -Button $ui.GpoListLinksButton -Action { Update-GpoLinks }
Register-UiClick -Button $ui.GpoLinkButton -Action {
    Invoke-GpoLinkAction -Action 'Link' -Target $ui.GpoLinkTarget.Text.Trim() -Confirm "Link the selected GPO to '$($ui.GpoLinkTarget.Text.Trim())'?`n`nIts settings apply there on the next Group Policy refresh."
}
Register-UiClick -Button $ui.GpoUnlinkButton -Action {
    $row = Get-SelectedGpoLink; if (-not $row) { return }
    Invoke-GpoLinkAction -Action 'Unlink' -Target "$($row.Target)" -Confirm "Unlink the selected GPO from $($row.Target)?`n`nIts settings stop applying there on the next refresh."
}
Register-UiClick -Button $ui.GpoCreateButton -Action {
    Invoke-GpoCreate -GpoName $ui.GpoCreateName.Text.Trim() -TargetOU $ui.GpoCreateTarget.Text.Trim() `
        -Confirm "Create/update the hardening GPO '$($ui.GpoCreateName.Text.Trim())' and link it to '$($ui.GpoCreateTarget.Text.Trim())'?`n`nThis sets registry policy (LLMNR off, anonymous SMB/SAM enumeration off, NTLMv2 only, SMB signing required) that applies to everything under that target on the next refresh."
}

Register-UiClick -Button $ui.TaskSearchButton -Action { Update-Tasks }
Register-UiClick -Button $ui.TaskDisableButton -Action {
    $r = Get-SelectedTask; if (-not $r) { return }
    Invoke-TaskAction -Action 'Disable' -TaskName $r.TaskName -TaskPath $r.TaskPath -Confirm "Disable '$($r.Path)'?`n`nIt stops running on its trigger until re-enabled."
}
Register-UiClick -Button $ui.TaskEnableButton -Action {
    $r = Get-SelectedTask; if (-not $r) { return }
    Invoke-TaskAction -Action 'Enable' -TaskName $r.TaskName -TaskPath $r.TaskPath
}
Register-UiClick -Button $ui.TaskDeleteButton -Action {
    $r = Get-SelectedTask; if (-not $r) { return }
    Invoke-TaskAction -Action 'Delete' -TaskName $r.TaskName -TaskPath $r.TaskPath `
        -Confirm "DELETE '$($r.Path)'?`n`nThis is permanent -- the full definition is backed up first, but recreating it means rebuilding it by hand. If this is a built-in Windows task, deleting it is rarely the right move; disabling is usually enough."
}
Register-UiClick -Button $ui.TaskCreateButton -Action {
    $n = $ui.TaskNewName.Text.Trim()
    if (-not $n) { Write-UiLog -Level WARN -Message 'Type a task name first.'; return }
    $c = $ui.TaskNewCommand.Text.Trim()
    if (-not $c) { Write-UiLog -Level WARN -Message 'Type a program to run first.'; return }
    Invoke-TaskAction -Action 'Create' -TaskName $n -TaskPath '\' -Command $c -CommandArgs $ui.TaskNewArgs.Text.Trim() `
        -Trigger "$($ui.TaskNewTrigger.SelectedItem)" -Confirm "Create the task '$n', running '$c'?"
}

Register-UiClick -Button $ui.FirewallSearchButton -Action { Update-Firewall }
Register-UiClick -Button $ui.FirewallDisableButton -Action {
    $r = Get-SelectedFirewallRule; if (-not $r) { return }
    Invoke-FirewallRuleAction -Action 'Disable' -Name $r.InternalName -Confirm "Disable the rule '$($r.Name)'?"
}
Register-UiClick -Button $ui.FirewallEnableButton -Action {
    $r = Get-SelectedFirewallRule; if (-not $r) { return }
    Invoke-FirewallRuleAction -Action 'Enable' -Name $r.InternalName
}
Register-UiClick -Button $ui.FirewallRemoveButton -Action {
    $r = Get-SelectedFirewallRule; if (-not $r) { return }
    Invoke-FirewallRuleAction -Action 'Remove' -Name $r.InternalName `
        -Confirm "Remove the rule '$($r.Name)' ($($r.Direction) $($r.Action))?`n`nIf this was the only rule allowing a scored port through, that service goes unreachable the moment this runs."
}
Register-UiClick -Button $ui.FirewallAddButton -Action {
    $n = $ui.FwNewName.Text.Trim()
    if (-not $n) { Write-UiLog -Level WARN -Message 'Type a rule name first.'; return }
    $proto = "$($ui.FwProtocolCombo.SelectedItem)"
    $portText = $ui.FwPortBox.Text.Trim()
    # Validated here, on the UI thread, with the SAME pure checks the rest
    # of the toolkit trusts for this -- not reinvented, and caught before a
    # background round-trip rather than after New-NetFirewallRule rejects it.
    if ($portText -and $proto -ne 'ICMPv4' -and -not (Test-CcdcValidPort -PortText $portText)) {
        Write-UiLog -Level WARN -Message "'$portText' is not a valid port (1-65535, a single number -- this box does not take a range or a list)."
        return
    }
    $remoteText = $ui.FwRemoteAddressBox.Text.Trim()
    if ($remoteText -and $remoteText -ne 'Any' -and -not (Test-CcdcValidIPv4 $remoteText) -and $remoteText -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
        Write-UiLog -Level WARN -Message "'$remoteText' does not look like an IP address or a CIDR block (e.g. 10.10.10.0/24). Leave it blank for Any."
        return
    }
    $direction = "$($ui.FwDirectionCombo.SelectedItem)"
    $ruleAction = "$($ui.FwActionCombo.SelectedItem)"
    Invoke-FirewallRuleAction -Action 'Add' -Name $n `
        -Extra @{ Direction = $direction; RuleAction = $ruleAction; Protocol = $proto; Port = $portText; RemoteAddress = $remoteText } `
        -Confirm "Create a $direction $ruleAction rule for $proto$(if ($portText) { "/$portText" })$(if ($remoteText) { " from $remoteText" }), named '$n'?"
}

Register-UiClick -Button $ui.ServiceStartButton -Action {
    $n = Get-SelectedService; if (-not $n) { return }
    Invoke-ServiceAction -Action 'Start' -Name $n
}
Register-UiClick -Button $ui.ServiceStopButton -Action {
    $n = Get-SelectedService; if (-not $n) { return }
    Invoke-ServiceAction -Action 'Stop' -Name $n -Confirm "Stop '$n'?`n`nIf a scored service depends on it, that service goes down with it."
}
Register-UiClick -Button $ui.ServiceRestartButton -Action {
    $n = Get-SelectedService; if (-not $n) { return }
    Invoke-ServiceAction -Action 'Restart' -Name $n -Confirm "Restart '$n'?`n`nIt will be unavailable for a moment."
}
Register-UiClick -Button $ui.ServiceSetStartupButton -Action {
    $n = Get-SelectedService; if (-not $n) { return }
    $t = "$($ui.ServiceStartupCombo.SelectedItem)"
    Invoke-ServiceAction -Action 'Startup' -Name $n -StartupType $t -Confirm "Set '$n' startup type to $t?`n`nDisabled means it will not come back after a reboot."
}

$ui.AccountFilterBox.Add_KeyDown({ if ($_.Key -eq 'Return') { try { Update-Accounts } catch { } } })
$ui.ServiceFilterBox.Add_KeyDown({ if ($_.Key -eq 'Return') { try { Update-Services } catch { } } })

$window.Add_Closing({
    if ($script:Pending) {
        # Let it finish rather than tearing down a runspace mid-change.
        $_.Cancel = $true
        [System.Windows.MessageBox]::Show($window, 'Something is still running. Wait for it to finish before closing.', 'Busy',
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
    }
})

# The last net. Anything that throws on the UI thread and is not caught by
# the handler that raised it arrives here instead of terminating the
# process. Marking it Handled keeps the window alive: a window that stays
# up with an error in its log is far more useful mid-round than one that
# vanishes, and it means the failure ends up in the session transcript
# where it can actually be read afterwards.
$dispatcher = [System.Windows.Threading.Dispatcher]::CurrentDispatcher
$dispatcher.Add_UnhandledException({
    # Not named $sender: that is an automatic variable in PowerShell and
    # assigning to it has side effects.
    param($raiser, $e)
    try {
        $null = $raiser
        $ex = $e.Exception
        Write-CcdcLog -Level ERROR -Message "Unhandled UI error: $($ex.GetType().Name): $($ex.Message)"
        Write-UiLog -Level ERROR -Message "Something failed on the UI thread: $($ex.Message)"
        Write-UiLog -Level ERROR -Message "The window is still up. This is in the session log; send it on if it keeps happening."
        if ($script:Timer) { $script:Timer.Stop() }
        $script:Pending = $null
        Set-UiBusy -Busy $false -Status 'Ready'
    } catch { }
    $e.Handled = $true
})

Write-UiLog -Level INFO -Message "Ready. Session log: $($session.TranscriptPath)"

function Wait-UiWork {
    # No window means no message loop in -SelfTest, so the timer never
    # ticks: drive the completion directly instead of trying to pump a
    # dispatcher that is not running.
    param([int]$TimeoutSeconds = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($script:Pending -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
        Complete-PendingWork
    }
    if ($script:Pending) { throw "Background work did not finish within $TimeoutSeconds second(s)." }
}

if ($SelfTest) {
    # Prove the health check itself runs, not just that the window was built:
    # that path touches the firewall, the event log, services and AD, and it is
    # where a box-specific failure is most likely to appear.
    Update-Dashboard
    Wait-UiWork
    Write-Host ''
    Write-Host 'SELFTEST OK -- the layout loaded, every control was found, every button was wired, and a health check completed.' -ForegroundColor Green
    Write-Host "Cards shown: $(@($ui.HealthCards.ItemsSource).Count); scored-service rows: $(@($ui.ScoredGrid.ItemsSource).Count)"

    # The DNS tab too -- added after the dashboard's own self-test coverage
    # was the thing that caught a crashing string-format call before any
    # amount of static checking would have. A box with no DnsServer module
    # (every box except the DNS server, including whatever machine runs this
    # self-test) legitimately lists zero zones; WorkDns reports that as INFO,
    # not an error, so it does not fail this check.
    Update-DnsZones
    Wait-UiWork
    Write-Host "DNS zones shown: $(@($ui.DnsZoneGrid.ItemsSource).Count) (0 is normal off the DNS server)"

    # DHCP and Group Policy too -- same reasoning: a box with no DhcpServer
    # or GroupPolicy module (every box except the DC, including this one)
    # legitimately lists zero rows, and WorkDhcp/WorkGpo report that as INFO.
    Update-DhcpScopes
    Wait-UiWork
    Write-Host "DHCP scopes shown: $(@($ui.DhcpScopeGrid.ItemsSource).Count) (0 is normal off the DHCP server)"

    Update-GpoList
    Wait-UiWork
    Write-Host "GPOs shown: $(@($ui.GpoGrid.ItemsSource).Count) (0 is normal off a domain-joined host with RSAT)"

    # Tasks and Firewall too -- these were shipped with their controls
    # proven present and wired, but Get-ScheduledTask and Get-NetFirewallRule
    # themselves had never actually run inside this self-test, which is
    # exactly the gap that let the DNS tab ship before being proven for
    # real. Neither needs a selection first; both list on a blank filter,
    # same as their own "List" button does.
    Update-Tasks
    Wait-UiWork
    Write-Host "Scheduled tasks shown: $(@($ui.TaskGrid.ItemsSource).Count)"

    Update-Firewall
    Wait-UiWork
    Write-Host "Firewall rules shown: $(@($ui.FirewallGrid.ItemsSource).Count)"

    # Accounts and Services were wired and declared present like every other
    # tab, but neither had ever actually been RUN inside this self-test --
    # the identical gap that let the DNS tab ship with a crashing
    # string-format call before anything exercised it for real. Local scope
    # is the default the window opens on and Get-LocalUser/Win32_Service both
    # work on every edition of Windows (including a DC, where Get-LocalUser
    # still works even though Get-LocalGroupMember does not), so there is no
    # reason either one should be let through untested.
    Update-Accounts
    Wait-UiWork
    Write-Host "Accounts shown: $(@($ui.AccountGrid.ItemsSource).Count)"

    Update-Services
    Wait-UiWork
    Write-Host "Services shown: $(@($ui.ServiceGrid.ItemsSource).Count)"
} else {
    Update-Dashboard
    [void]$window.ShowDialog()
    Write-CcdcLog -Level INFO -Message 'Toolkit window closed.'
}

} catch {
    $script:StartupFailed = $_
    $where = "$($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
    Write-CcdcLog -Level ERROR -Message "The window failed to start: $($_.Exception.Message)"
    Write-CcdcLog -Level ERROR -Message "Where: $where"
    Write-CcdcLog -Level ERROR -Message "Line:  $("$($_.InvocationInfo.Line)".Trim())"
    Write-Host ''
    Write-Host 'SELFTEST FAILED' -ForegroundColor Red
    Write-Host "  $($_.Exception.GetType().Name): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  at $where" -ForegroundColor Red
    Write-Host "  $("$($_.InvocationInfo.Line)".Trim())" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'The full details are in this session log:' -ForegroundColor Yellow
    Write-Host "  $($session.TranscriptPath)" -ForegroundColor Yellow
    Write-Host 'The numbered menu (.\Invoke-CCDCToolkit.ps1) does not need a desktop and still works.' -ForegroundColor Yellow
    # Not in -SelfTest: a modal box waits for a click, and nobody is there to
    # give it one, so it would hang instead of reporting.
    if (-not $SelfTest) {
        try {
            $detail = "The toolkit window could not start." + [Environment]::NewLine * 2 +
                      $_.Exception.Message + [Environment]::NewLine * 2 +
                      "at $where" + [Environment]::NewLine * 2 +
                      "The full details are in:" + [Environment]::NewLine + $session.TranscriptPath
            [System.Windows.MessageBox]::Show($detail, 'CCDC Toolkit',
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
        } catch { }
    }
} finally {
    Show-CcdcSummary
    Stop-CcdcSession
    # Without this the console closes the instant the script ends and takes the
    # error with it -- which is exactly how "it opened and closed right away"
    # happens, with nothing left to read.
    if ($script:StartupFailed -and -not $SelfTest) {
        Write-Host ''
        Read-Host 'Press Enter to close this window' | Out-Null
    }
}
