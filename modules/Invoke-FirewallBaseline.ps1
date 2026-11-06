#Requires -Version 5.1
<#
.SYNOPSIS
    Locks the host firewall down to "only what's scored, plus a way for
    you to still get in" -- with a self-healing safety net so a mistake
    here can't lock your own team out mid-competition.

.DESCRIPTION
    This is the riskiest module in the toolkit (get it wrong and you score
    yourself a self-inflicted outage, which the blog this was built from
    specifically calls out as blue teams' most common own-goal), so it has
    the most guardrails of anything here:

      1. Backs up every existing firewall rule AND the current default
         inbound/outbound actions before touching anything.
      2. Figures out which scored services live on THIS host (matches
         hostname against the inventory's ScoredServices list) and adds
         explicit allow rules for them -- TCP and UDP as each service
         needs (DNS, Kerberos and NTP are UDP or TCP+UDP, not TCP-only) --
         plus a management-access allow rule for RDP/WinRM scoped to an
         admin subnet you specify.

         IMPORTANT -- check your rules packet before relying on that scoping:
         a lot of CCDC rulesets explicitly forbid restricting traffic by
         source IP, at least for scored public-facing services (the scoring
         engine / red team / orange team can come from anywhere, and you're
         supposed to defend the service, not dodge specific IPs). This
         module never source-restricts a SCORED port regardless of what you
         enter -- that's not optional. Whether it's even OK to scope
         RDP/WinRM (not scored, just your own team's admin access) to your
         subnet depends on how your specific ruleset is worded. If in doubt,
         or until you've confirmed it's allowed, leave AdminSubnet as 'Any'
         -- that's the safe default and is what this module ships with.
      3. Before switching the default inbound action to Block, it
         registers a one-time scheduled task that reverts the default
         action back to Allow after a few minutes -- a dead-man's switch.
         The task runs as SYSTEM with the highest run level (a task
         registered with no principal runs as the current user, only while
         they're logged on, with a non-elevated token, which is not enough
         to change firewall profiles). After registering it, this module
         reads the task back and checks that it really is SYSTEM/Highest.
         If the safety net can't be armed and verified, the default action
         is NOT switched to Block (see -AllowNoSafetyNet).
      4. Only removes that safety-net task at the very end, after verifying
         every allow rule (scored AND management) actually landed enabled
         with the right protocol and port, and the default action is
         confirmed as Block -- not a localhost ping, since Windows doesn't
         filter loopback traffic and that would give a false "it's fine"
         even when the real rule is broken.

    Custom (non-standard) scored services: list them in ScoredServices as
    usual (e.g. WEB01:CustomApp) and give their ports in the answer file as
    Port_<Name>. The value can be a single port ('8443'), a list
    ('8443,9443'), a range ('50000-50100'), or include a protocol prefix
    ('udp:5060,tcp:5061'). TCP is assumed when there's no prefix.

    FTP note: FTP's control channel is TCP 21, but passive-mode DATA
    connections use a separate port range (in IIS: FTP Firewall Support ->
    Data Channel Port Range). With the default inbound action on Block, a
    scored FTP login can succeed while listings and transfers hang. List a
    pseudo-service in ScoredServices (e.g. FTP01:FTPPassive) and set
    Port_FTPPassive to the same range configured in IIS, e.g. '50000-50100'.
    This module warns if FTP is scored on this host and no FTPPassive entry
    exists.

    Run Get-EnvironmentInventory.ps1 first so this has a ScoredServices
    list to work from. Without one, it still runs -- it'll just only set up
    management access and ask you to add scored-service rules by hand.

.PARAMETER RevertMinutes
    How long the dead-man's-switch waits before reverting the default
    inbound action back to Allow if nothing cancels it. Default 10.

.PARAMETER SkipDefaultBlock
    Add the allow rules but leave the existing default inbound action
    alone. Use this if you want to layer the allow-list in first and flip
    to default-block yourself once you're confident, e.g. on competition
    morning after testing the allow rules the night before.

.PARAMETER FullBlackout
    The alternate sequencing the team settled on 2026-10-19 after a coach
    conversation and the firewall admin's sign-off: deny EVERYTHING inbound
    first, with no allow rules at all -- not scored services, not even your
    own RDP/WinRM management access -- then run credential hardening while
    nothing can reach the box on any account that existed when the round
    started, THEN add the allow rules and reopen. The normal (default) mode
    builds the allow-list first and never has an outage; this one trades a
    short, counted outage for closing the stale-credential window
    completely, because the alternative -- RDP staying open on
    possibly-already-leaked credentials for however long it takes to reach
    credential hardening several steps later -- is what reportedly cost the
    team a round before.

    Order with this switch: back up -> arm the safety net -> block
    everything (zero allow rules exist yet, so this really is everything,
    including your own access if you are on RDP rather than local console)
    -> launch Invoke-CredentialHardening.ps1 in its own window and WAIT for
    it to close -> add the scored-service, management, and ICMP allow rules
    -> self-check -> disarm. If the safety net can't be armed, this refuses
    to enter the blackout at all (same fail-safe rule as every other path
    through this module) -- a lockout with no rules and no way back is the
    one outcome worse than not doing this at all.

    IF YOU ARE RUNNING THIS OVER RDP RATHER THAN LOCAL/HYPERVISOR CONSOLE,
    YOU WILL LOSE YOUR OWN CONNECTION FOR THE DURATION OF THE BLACKOUT.
    Credential hardening has to run some other way during that window --
    local console, or a second administrator already on console -- not
    through the session this module just cut off.

.PARAMETER AllowNoSafetyNet
    Off by default. Normally, if the self-reverting safety net can't be
    armed and verified, this module refuses to switch the default inbound
    action to Block (it leaves the allow rules in place and tells you why).
    Pass this only if you've decided that switching to Block WITHOUT a
    safety net is worth it -- e.g. you have console access and don't need
    one -- because a lockout in that state will not heal itself.

.PARAMETER DisableLegacySmbRpcPorts
    Off by default -- opt in explicitly. Per an ATCC coach's field manual,
    the specific ZeroLogon mitigation is blocking TCP 135 and 139 from
    outside, separate from port 445 (which the scored-SMB allow rule
    above already governs and this never touches). The reason this needs
    its own opt-in instead of being automatic: setting the profile's
    DefaultInboundAction to Block only blocks traffic that ISN'T already
    matched by some other enabled Allow rule, and a fresh Windows Server
    box commonly ships with built-in rule groups (File and Printer
    Sharing, Network Discovery) that explicitly allow 135/139/445 inbound
    -- those would keep working right through the default-block step
    unless disabled directly. This switch finds currently-ENABLED
    inbound rules matching port 135 or 139 (skipping anything this
    toolkit itself created) and disables -- never deletes -- them; the
    full pre-change rule set is already captured by this module's own
    firewall-rules-before backup either way. Confirm with your rules
    packet/coach that closing 135/139 doesn't conflict with something
    scored before turning this on for real.

.PARAMETER NoIcmpEcho
    Skips the inbound ICMPv4 echo (ping) allow rule that this module
    otherwise always creates.

    Why ping is allowed by default, when a hardening script's instinct is
    to drop it: the 2026 Midwest team packet states the scoring engine
    relies on ICMP and tells teams to keep it up on every device except
    the Palo Alto core port. A silent side effect of default-inbound-Block
    is that the box stops answering ping -- Windows Server ships the
    built-in "File and Printer Sharing (Echo Request - ICMPv4-In)" rule
    DISABLED, so there is nothing to keep it alive once the default flips.
    That turns a hardening step into an availability loss, which is the
    one thing this toolkit is meant never to do. Only pass this if your
    own rules packet says otherwise.

.EXAMPLE
    .\Invoke-FirewallBaseline.ps1 -WhatIf
    Shows exactly what rules would be created/changed without touching anything.

.EXAMPLE
    .\Invoke-FirewallBaseline.ps1 -SkipDefaultBlock
    Adds the allow rules only; you flip to default-block later once verified.

.EXAMPLE
    .\Invoke-FirewallBaseline.ps1 -FullBlackout
    Denies everything, runs credential hardening while nothing is reachable,
    then opens the allow list. Run this from local/hypervisor console, not RDP.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 120)]
    [int]$RevertMinutes = 10,
    [switch]$SkipDefaultBlock,
    [switch]$FullBlackout,
    [switch]$AllowNoSafetyNet,
    [switch]$DisableLegacySmbRpcPorts,
    [switch]$NoIcmpEcho
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Firewall baseline starting. This is the module most likely to hurt you if something's wrong, so read every WARN line before continuing."
Assert-CcdcElevated -Because "creating firewall rules and a scheduled task"
Show-CcdcTargetContext -RootPath $session.RootPath -SkipIfShownByMenu | Out-Null

if ($FullBlackout -and $SkipDefaultBlock) {
    Write-CcdcLog -Level ERROR -Message "-FullBlackout and -SkipDefaultBlock contradict each other (one denies everything, the other leaves the default action alone) -- pick one. Nothing was changed."
    Stop-CcdcSession
    return
}
if ($FullBlackout) {
    Write-CcdcLog -Level WARN -Message "FULL BLACKOUT MODE. If you are on RDP or WinRM rather than local/hypervisor console, this is about to cut YOUR OWN connection too -- there will be zero allow rules, including management access, until credential hardening finishes and this module re-opens the allow list. Make sure whoever is running credential hardening during the blackout window can actually reach this box."
}

$thisHost = $env:COMPUTERNAME
if (-not $thisHost) { $thisHost = (hostname) }

$inventory = Get-CcdcInventory -RootPath $session.RootPath
$scoredAll = @(Get-CcdcScoredServiceList -RootPath $session.RootPath -Inventory $inventory)
$scoredForThisHost = @()
if ($scoredAll.Count -gt 0) {
    $scoredForThisHost = @(Get-CcdcScoredServicesForHost -ScoredServices $scoredAll -HostName $thisHost)
}

if ($scoredForThisHost.Count -eq 0) {
    if ($scoredAll.Count -gt 0) {
        Write-CcdcLog -Level WARN -Message "A ScoredServices list exists ($($scoredAll.Count) entries) but none of them name this host, '$thisHost'. Entries look like HOSTNAME:Service -- check the hostname spelling. You'll only get the management-access rule until that matches."
    } else {
        Write-CcdcLog -Level WARN -Message "No ScoredServices list found in either the inventory or config\answers.local.psd1, so this run has nothing to protect and will only create the management-access rule. Fix that first: run discovery (menu 1), or put a ScoredServices line in your answer file."
    }
} else {
    Write-CcdcLog -Level INFO -Message "Scored services for '$thisHost': $($scoredForThisHost -join ', ')"
}

# ---------------------------------------------------------------------------
# Build the full allow list as (Protocol, Port, Kind) specs. Kind is 'Scored'
# or 'Management'; only Management specs are ever eligible for source-IP
# scoping, and a spec that is both (a scored service that happens to use a
# management port) counts as Scored, so it is never restricted.
# ---------------------------------------------------------------------------
$specTable = [ordered]@{}

function Add-AllowSpec {
    param([string]$Protocol, [string]$Port, [string]$Kind)
    $key = "$Protocol/$Port"
    if ($specTable.Contains($key)) {
        if ($Kind -eq 'Scored') { $specTable[$key].Kind = 'Scored' }
        return
    }
    $specTable[$key] = [pscustomobject]@{ Protocol = $Protocol; Port = $Port; Kind = $Kind; RuleName = $null }
}

$unmappedServices = New-Object System.Collections.Generic.List[string]
foreach ($svc in $scoredForThisHost) {
    $known = @(Get-CcdcServiceRuleSpecs -ServiceName $svc)
    if ($known.Count -gt 0) {
        foreach ($s in $known) { Add-AllowSpec -Protocol $s.Protocol -Port $s.Port -Kind 'Scored' }
    } else {
        $unmappedServices.Add($svc)
    }
}

foreach ($svc in $unmappedServices) {
    $manualPorts = Get-CcdcAnswer -Key "Port_$svc" -Prompt "Don't know the port for scored service '$svc' -- enter it (e.g. 8443, 8443,9443, 50000-50100, or udp:5060; blank to skip)" -Default ''
    $parsed = ConvertFrom-CcdcPortSpec -Spec $manualPorts
    foreach ($s in $parsed.Specs) { Add-AllowSpec -Protocol $s.Protocol -Port $s.Port -Kind 'Scored' }
    if ($parsed.Invalid.Count -gt 0) {
        Write-CcdcLog -Level WARN -Message "Ignored what doesn't look like a valid port for '$svc': $($parsed.Invalid -join ', ') (use a number, a lo-hi range, or a udp:/tcp: prefix)."
    }
    if ($parsed.Specs.Count -eq 0) {
        Write-CcdcLog -Level WARN -Message "No usable port for scored service '$svc' -- nothing will be allowed for it. If it's genuinely scored, add Port_$svc to config\answers.local.psd1 and re-run."
    }
}

# FTP passive-mode data ports are a separate range from the control port.
$ftpScored = @($scoredForThisHost | Where-Object { $_ -ieq 'FTP' }).Count -gt 0
$ftpPassiveListed = @($scoredForThisHost | Where-Object { $_ -ieq 'FTPPassive' }).Count -gt 0
if ($ftpScored -and -not $ftpPassiveListed) {
    Write-CcdcLog -Level WARN -Message "FTP is scored on this host, but only its control port (TCP 21) is being allowed. Passive-mode FTP data connections use a separate port range (in IIS: FTP Firewall Support -> Data Channel Port Range; a setting of 0-0 there means the Windows ephemeral range, 49152-65535), and with the default inbound action on Block a login can succeed while directory listings and transfers hang -- exactly what a functional scoring check catches. Add '$thisHost`:FTPPassive' to ScoredServices and set Port_FTPPassive (e.g. '50000-50100', matching the IIS setting) in config\answers.local.psd1, then re-run. Some boxes already have built-in 'FTP Server Passive' rules enabled; check with: Get-NetFirewallRule -DisplayName 'FTP*'"
}

# ---------------------------------------------------------------------------
# Management access -- never lock yourself out. Required, not optional.
# ---------------------------------------------------------------------------
$adminSubnet = Get-CcdcAnswer -Key 'AdminSubnet' -Prompt 'Admin/management subnet allowed to RDP/WinRM in, CIDR form (e.g. 10.10.10.0/24 -- use your team VLAN, not "any"). CHECK YOUR RULES PACKET FIRST: many CCDC rulesets forbid restricting traffic by source IP; if unsure, just press Enter for Any' -Default 'Any'

$restrictManagement = $false
if ($adminSubnet -eq 'Any') {
    Write-CcdcLog -Level WARN -Message "Management access is set to 'Any' -- that's wide open, not scoped to your team. That's the safe default if you haven't confirmed source-IP restriction is allowed under your rules; tighten it once you have."
} elseif ($adminSubnet -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') {
    Write-CcdcLog -Level WARN -Message "AdminSubnet value '$adminSubnet' doesn't look like a valid IP/CIDR (e.g. 10.10.10.0/24) -- falling back to 'Any' rather than silently creating a rule that doesn't do what you typed."
    $adminSubnet = 'Any'
} else {
    $restrictManagement = $true
    Write-CcdcLog -Level INFO -Message "Management access (RDP/WinRM) will be restricted to $adminSubnet. Scored ports are never restricted by source IP, no matter what -- see this module's help for why."
}

foreach ($mgmtPort in @('3389', '5985', '5986')) { # RDP, WinRM HTTP, WinRM HTTPS
    Add-AllowSpec -Protocol 'TCP' -Port $mgmtPort -Kind 'Management'
}

# Since this repo is public, a hardcoded "CCDC-" prefix on every rule and
# scheduled task name is a free fingerprint -- anyone who's read this repo
# (including red team) knows exactly what to grep for. Pulling it from the
# answer file costs nothing and means the literal names in play on the day
# aren't sitting in the public source. Falls back to a generic default so
# this still works if you haven't set one.
$artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for firewall rule / scheduled task names (anything -- just avoid an obvious "CCDC" string since this repo is public)' -Default 'Baseline'

foreach ($s in $specTable.Values) { $s.RuleName = "$artifactPrefix-Allow-$($s.Protocol)-$($s.Port)" }
$allSpecs = @($specTable.Values)

Write-CcdcLog -Level INFO -Message "Final allow list for '$thisHost': $(($allSpecs | ForEach-Object { "$($_.Protocol)/$($_.Port)" }) -join ', ') (management access from $adminSubnet)"

if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level ERROR -Message "Get-NetFirewallRule isn't available on this box -- this module only works on Windows with the NetSecurity module. Stopping here; nothing was changed."
    Stop-CcdcSession
    return
}

# ---------------------------------------------------------------------------
# 1. Backup current state -- mandatory, Backup-CcdcState throws if this fails
#    and the whole script stops rather than proceeding unbacked-up.
# ---------------------------------------------------------------------------
$currentRules = Get-NetFirewallRule
Backup-CcdcState -Name 'firewall-rules-before' -Data $currentRules | Out-Null

$currentProfiles = Get-NetFirewallProfile
Backup-CcdcState -Name 'firewall-profiles-before' -Data $currentProfiles | Out-Null

# ---------------------------------------------------------------------------
# 1b. Opt-in ZeroLogon mitigation: disable (never delete) currently-enabled
#     inbound rules matching port 135 or 139 -- the specific mitigation an
#     ATCC coach's field manual calls out. Off unless -DisableLegacySmbRpcPorts
#     is passed; see the PARAMETER help for why this can't just be automatic.
#     $currentRules above already has the full pre-change state backed up.
# ---------------------------------------------------------------------------
if ($DisableLegacySmbRpcPorts) {
    $legacyRuleTargets = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $currentRules) {
        if ($rule.Direction -ne 'Inbound' -or $rule.Enabled -ne 'True' -or $rule.Action -ne 'Allow') { continue }
        if ($rule.DisplayName -like "$artifactPrefix-*") { continue } # never touch our own rules
        $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
        if (-not $portFilter) { continue }
        # Deliberately narrow: only rules whose port list explicitly names
        # 135 or 139. A rule scoped to LocalPort 'Any' (common for
        # program-scoped rules unrelated to SMB/RPC) is left alone --
        # disabling those would be a much bigger, unrelated change than
        # the specific ZeroLogon mitigation this switch is for.
        $ports = @($portFilter.LocalPort) -join ','
        if ($ports -match '(^|,)(135|139)($|,)') {
            $legacyRuleTargets.Add($rule)
        }
    }
    if ($legacyRuleTargets.Count -eq 0) {
        Write-CcdcLog -Level INFO -Message "No enabled inbound rules matched TCP 135/139 to disable -- either already closed, or the built-in rule groups aren't present/enabled on this box."
    } else {
        foreach ($rule in $legacyRuleTargets) {
            if (-not $PSCmdlet.ShouldProcess($rule.DisplayName, 'Disable inbound rule (ZeroLogon mitigation: TCP 135/139)')) { continue }
            Invoke-CcdcSafe -Target $rule.DisplayName -Action 'disable inbound rule matching TCP 135/139' -ScriptBlock {
                Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            } | Out-Null
        }
        Write-CcdcLog -Level OK -Message "Disabled $($legacyRuleTargets.Count) pre-existing inbound rule(s) matching TCP 135/139. They're disabled, not deleted -- re-enable by name via Get-NetFirewallRule if something needs them, and the full pre-change rule set is in this session's firewall-rules-before backup either way."
    }
}

# ---------------------------------------------------------------------------
# 2. Add allow rules for scored services + management access, plus the
#    ICMP echo rule. Factored into a function: the default path calls this
#    BEFORE touching the default action (so scored services are never
#    unprotected); -FullBlackout calls it AFTER the blackout + credential
#    hardening window instead (see "Put it together" below).
# ---------------------------------------------------------------------------
function Add-CcdcFirewallRules {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    foreach ($spec in $allSpecs) {
        $ruleName = $spec.RuleName
        if (-not $PSCmdlet.ShouldProcess("$($spec.Protocol)/$($spec.Port)", 'Create inbound allow rule')) { continue }
        $scopeThisRule = $restrictManagement -and ($spec.Kind -eq 'Management')
        Invoke-CcdcSafe -Target "$($spec.Protocol)/$($spec.Port)" -Action 'create inbound allow rule' -ScriptBlock {
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                $ruleParams = @{
                    DisplayName = $ruleName
                    Direction   = 'Inbound'
                    Protocol    = $spec.Protocol
                    LocalPort   = $spec.Port
                    Action      = 'Allow'
                    ErrorAction = 'Stop'
                }
                if ($scopeThisRule) { $ruleParams['RemoteAddress'] = $adminSubnet }
                New-NetFirewallRule @ruleParams | Out-Null
            }
        } | Out-Null
    }

    # Allow inbound ICMPv4 echo (ping). The scoring engine pings; a box
    # that stops answering ping after this module runs is an availability
    # loss we caused ourselves. See the -NoIcmpEcho help above for the
    # full reasoning.
    $script:icmpRuleName = "$artifactPrefix-Allow-ICMPv4-Echo"
    if ($NoIcmpEcho) {
        Write-CcdcLog -Level WARN -Message "-NoIcmpEcho was passed, so no ping allow rule was created. Once the default inbound action flips to Block this box will stop answering ping. Confirm your rules packet actually wants that -- scoring engines commonly use ICMP for reachability."
    } elseif ($PSCmdlet.ShouldProcess('ICMPv4 echo request', 'Create inbound allow rule (keep ping answering)')) {
        Invoke-CcdcSafe -Target 'ICMPv4 echo request' -Action 'create inbound allow rule' -ScriptBlock {
            if (-not (Get-NetFirewallRule -DisplayName $icmpRuleName -ErrorAction SilentlyContinue)) {
                # Protocol ICMPv4 with IcmpType 8 is echo request
                # specifically, rather than opening every ICMP type. Never
                # scoped by RemoteAddress: we don't know the scoring
                # engine's source address, and guessing it wrong costs the
                # uptime points this rule exists to protect.
                New-NetFirewallRule -DisplayName $icmpRuleName -Direction Inbound `
                    -Protocol ICMPv4 -IcmpType 8 -Action Allow -ErrorAction Stop | Out-Null
            }
        } | Out-Null
    }
}

# ---------------------------------------------------------------------------
# 3. Dead-man's switch, then flip default inbound to Block. Also factored
#    into a function: -FullBlackout calls this FIRST, before any allow
#    rules exist at all, so the block really does deny everything; the
#    default path calls it after Add-CcdcFirewallRules, exactly as before.
# ---------------------------------------------------------------------------
function Enable-CcdcFirewallBlock {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:taskName = "$artifactPrefix-FirewallRevertSafety"
    $script:safetyArmed = $false

    if ((Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue) -and
        (Get-Command -Name New-ScheduledTaskPrincipal -ErrorAction SilentlyContinue)) {
        if ($PSCmdlet.ShouldProcess('firewall default action', "Register $RevertMinutes-minute safety-net revert task (SYSTEM)")) {
            $armOutcome = Invoke-CcdcSafe -Target 'safety-net task' -Action 'register dead-man switch (SYSTEM, highest run level)' -ScriptBlock {
                $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                $action = New-ScheduledTaskAction -Execute $psExe `
                    -Argument '-NoProfile -NonInteractive -Command "Set-NetFirewallProfile -All -DefaultInboundAction Allow"'
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RevertMinutes)
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                $taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                    -Principal $principal -Settings $taskSettings -Force -ErrorAction Stop | Out-Null

                # Read it back: a safety net that merely registered is not
                # the same as one that will actually be able to fire. If it
                # registered wrong, remove it rather than leave a task behind
                # that looks like a safety net but can't work.
                try {
                    $registered = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $runAs = "$($registered.Principal.UserId)"
                    if ($runAs -notmatch '^(SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$') {
                        throw "task registered but runs as '$runAs', not SYSTEM"
                    }
                    if ("$($registered.Principal.RunLevel)" -ne 'Highest') {
                        throw "task registered but run level is '$($registered.Principal.RunLevel)', not Highest"
                    }
                    if ("$($registered.State)" -eq 'Disabled') {
                        throw 'task registered but is Disabled'
                    }
                } catch {
                    $verifyError = $_
                    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
                    throw $verifyError
                }
                return $registered
            }
            # $script: prefix is load-bearing now that this lives inside a
            # function: a bare assignment here would only shadow a local
            # copy, leaving the top-level script's own $safetyArmed stuck
            # at the $false this function set it to on entry -- which is
            # exactly what happened on the first pass of this refactor
            # (caught by the test suite, not by manual -WhatIf testing,
            # since -WhatIf never reaches this line at all).
            $script:safetyArmed = [bool]$armOutcome.Success
        }
    } else {
        Write-CcdcLog -Level WARN -Message "Register-ScheduledTask / New-ScheduledTaskPrincipal aren't available here, so the safety net can't be armed."
    }

    if ($safetyArmed) {
        Write-CcdcLog -Level WARN -Message "Safety net armed and verified (SYSTEM, highest run level): if nothing cancels it, the default inbound action reverts to Allow in $RevertMinutes minutes. If you get locked out, just wait."
    } elseif ($AllowNoSafetyNet) {
        Write-CcdcLog -Level WARN -Message "The safety net is NOT armed, and -AllowNoSafetyNet was passed -- continuing to Block anyway. A lockout from here will not heal itself; make sure you have console access."
    } else {
        Write-CcdcLog -Level ERROR -Message "Couldn't arm and verify the self-reverting safety net, so the default inbound action was NOT switched to Block. The allow rules above are in place. Fix the error above and re-run; or use -SkipDefaultBlock to keep just the allow rules; or -AllowNoSafetyNet if you accept that a lockout won't self-heal."
    }

    if ($safetyArmed -or $AllowNoSafetyNet) {
        if ($PSCmdlet.ShouldProcess('all firewall profiles', 'Set default inbound action to Block')) {
            Invoke-CcdcSafe -Target 'firewall profiles' -Action 'set default inbound action to Block' -ScriptBlock {
                Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
            } | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Self-check, then disarm the safety net only if it looks safe. Runs
#    after both Add-CcdcFirewallRules and Enable-CcdcFirewallBlock, in
#    whichever order this run used -- by this point rules exist and the
#    default action is set, regardless of path.
#
# Deliberately NOT a Test-NetConnection to localhost: Windows Firewall
# does not filter loopback traffic by design, so a localhost check would
# report "open" even if the real inbound rule is broken -- a false
# reassurance on exactly the module where zero downtime matters most.
# Instead this verifies the actual rule/profile STATE landed the way we
# intended. That's real and deterministic, but it's still a local check --
# it can't see actual cross-host reachability the way a second machine on
# the network can. Treat "self-check passed" as "the configuration is
# correct," not as "someone has confirmed they can actually get in from
# off-box."
# ---------------------------------------------------------------------------
function Test-CcdcFirewallSelfCheck {
    [CmdletBinding()]
    param()
    Start-Sleep -Seconds 2
        $failedSpecs = New-Object System.Collections.Generic.List[object]
        foreach ($spec in $allSpecs) {
            $rule = Get-NetFirewallRule -DisplayName $spec.RuleName -ErrorAction SilentlyContinue
            if (-not $rule -or $rule.Enabled -ne 'True' -or $rule.Action -ne 'Allow') {
                $failedSpecs.Add($spec)
                continue
            }
            # The rule can exist under the right NAME yet carry the wrong
            # protocol/port (e.g. left over from an older run). Only fail on
            # a mismatch we can positively see.
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($portFilter) {
                $protoOk = ("$($portFilter.Protocol)" -ieq $spec.Protocol)
                $portOk = (@($portFilter.LocalPort) | ForEach-Object { "$_" }) -contains $spec.Port
                if (-not ($protoOk -and $portOk)) { $failedSpecs.Add($spec) }
            }
        }
        $profileOk = $true
        foreach ($p in (Get-NetFirewallProfile -All -ErrorAction SilentlyContinue)) {
            if ($p.DefaultInboundAction -ne 'Block') { $profileOk = $false }
        }

        # Ping is checked with the same weight as a scored port. A box that
        # quietly stopped answering ICMP after this module ran looks fine
        # locally and fails the scoring engine's reachability check.
        $icmpOk = $true
        if (-not $NoIcmpEcho) {
            $icmpRule = Get-NetFirewallRule -DisplayName $icmpRuleName -ErrorAction SilentlyContinue
            if (-not $icmpRule -or $icmpRule.Enabled -ne 'True' -or $icmpRule.Action -ne 'Allow') { $icmpOk = $false }
        }

        # If management access was scoped to AdminSubnet, verify the address
        # filter actually landed the way it was requested -- a rule that exists
        # and is Enabled/Allow but never picked up the RemoteAddress restriction
        # would otherwise report as "fine" while being wide open (fails safe,
        # not a lockout, but the self-check should still say so honestly rather
        # than claiming a restriction is in place when it isn't).
        $scopeFailed = New-Object System.Collections.Generic.List[string]
        if ($restrictManagement) {
            foreach ($spec in @($allSpecs | Where-Object { $_.Kind -eq 'Management' })) {
                $rule = Get-NetFirewallRule -DisplayName $spec.RuleName -ErrorAction SilentlyContinue
                if ($rule) {
                    $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                    if (-not $addrFilter -or ($addrFilter.RemoteAddress -notcontains $adminSubnet -and "$($addrFilter.RemoteAddress)" -ne $adminSubnet)) {
                        $scopeFailed.Add("$($spec.Protocol)/$($spec.Port)")
                    }
                }
            }
            if ($scopeFailed.Count -gt 0) {
                Write-CcdcLog -Level WARN -Message "RemoteAddress scoping to $adminSubnet didn't verifiably land on $($scopeFailed -join ', ') -- those rules may be wider open than intended (not a lockout risk, but check them by hand: Get-NetFirewallRule -DisplayName '<name>' | Get-NetFirewallAddressFilter)."
            }
        }

        $scoredFailed = @($failedSpecs | Where-Object { $_.Kind -eq 'Scored' })
        $mgmtFailed = @($failedSpecs | Where-Object { $_.Kind -eq 'Management' })

        if ($failedSpecs.Count -eq 0 -and $profileOk -and $icmpOk -and $scopeFailed.Count -eq 0) {
            Write-CcdcLog -Level OK -Message "Self-check passed: all $($allSpecs.Count) allow rules are present/enabled with the right protocol and port, ping still answers, and the default inbound action is confirmed Block."
            Write-CcdcLog -Level INFO -Message "This confirms local configuration state, not off-box reachability -- have someone on your team actually try RDP/WinRM from the admin subnet when you get a chance."
            if ($safetyArmed) {
                Write-CcdcLog -Level INFO -Message "Disarming the safety net."
                Invoke-CcdcSafe -Target 'safety-net task' -Action 'remove dead-man switch (self-check passed)' -ScriptBlock {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                } | Out-Null
            }
        } else {
            if ($scoredFailed.Count -gt 0) {
                Write-CcdcLog -Level ERROR -Message "SCORED rule(s) failed self-check: $(($scoredFailed | ForEach-Object { "$($_.Protocol)/$($_.Port)" }) -join ', '). This can cost you uptime points right now."
            }
            if ($mgmtFailed.Count -gt 0) {
                Write-CcdcLog -Level WARN -Message "Management rule(s) failed self-check: $(($mgmtFailed | ForEach-Object { "$($_.Protocol)/$($_.Port)" }) -join ', ')."
            }
            if (-not $profileOk) {
                Write-CcdcLog -Level WARN -Message "Default inbound action didn't come back as confirmed Block on every profile."
            }
            if (-not $icmpOk) {
                Write-CcdcLog -Level ERROR -Message "The inbound ping (ICMPv4 echo) allow rule '$icmpRuleName' isn't present and enabled, and the default inbound action is now Block -- this box has most likely stopped answering ping. Scoring engines commonly check reachability that way, so treat this as an uptime problem, not a cosmetic one. Fix: New-NetFirewallRule -DisplayName '$icmpRuleName' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow"
            }
            if ($safetyArmed) {
                Write-CcdcLog -Level WARN -Message "NOT removing the safety net -- it will auto-revert the default action to Allow in $RevertMinutes minutes. Go fix the failed rule(s) now; re-run this module afterward to re-verify."
            }
        }
}

# ---------------------------------------------------------------------------
# Put it together. -FullBlackout reverses the order: block (with nothing
# allowed yet) -> rotate credentials while nothing can get in -> THEN add
# the allow rules and self-check. Every other path keeps the original
# order: add allow rules -> arm + block -> self-check, so scored services
# are never left unprotected and the box is never actually unreachable.
# ---------------------------------------------------------------------------
if ($FullBlackout -and -not $SkipDefaultBlock -and -not $WhatIfPreference) {
    Enable-CcdcFirewallBlock
    if ($safetyArmed -or $AllowNoSafetyNet) {
        Write-CcdcLog -Level WARN -Message "BLACKOUT ACTIVE: every inbound connection is being denied right now, including RDP/WinRM to THIS box -- there are no allow rules yet. Launching credential hardening in its own window; once that window closes, the allow list goes up and access reopens."
        $credScript = Join-Path $PSScriptRoot 'Invoke-CredentialHardening.ps1'
        if (Test-Path -LiteralPath $credScript) {
            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            # -AcknowledgeNoProtectedAccounts is forced here, not optional:
            # this child process gets its own fresh console with nobody at
            # it (that is the entire point of a blackout), so if it hit the
            # normal interactive ProtectedAccounts prompt it would sit at
            # Read-Host forever -- and the box would stay in full deny-all,
            # unreachable, with no snapshot/revert on competition day. The
            # WARN log line in Invoke-CredentialHardening.ps1 still fires
            # either way, so an empty ProtectedAccounts list is still
            # visible in the transcript afterward; it just cannot block.
            $credArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $credScript + '"'), '-AcknowledgeNoProtectedAccounts')
            Invoke-CcdcSafe -Target 'credential hardening' -Action 'run during the blackout window' -ScriptBlock {
                Start-Process -FilePath $psExe -ArgumentList $credArgs -Wait
            } | Out-Null
            Write-CcdcLog -Level OK -Message "Credential hardening window closed. Opening the allow list now."
        } else {
            Write-CcdcLog -Level ERROR -Message "Can't find $credScript to run credential hardening during the blackout -- opening the allow list now anyway rather than leaving the box fully denied with no plan to reopen it. Rotate credentials by hand."
        }
    } else {
        Write-CcdcLog -Level ERROR -Message "Could not enter the blackout safely -- the safety net failed to arm, so this refuses to deny everything with no way back. Nothing was changed; the default inbound action is whatever it was before this ran."
        Show-CcdcSummary
        Stop-CcdcSession
        return
    }
}

Add-CcdcFirewallRules

if ($SkipDefaultBlock) {
    Write-CcdcLog -Level INFO -Message "-SkipDefaultBlock set: allow rules were added but the default inbound action was left as-is. Re-run without that switch once you've verified the allow list."
} elseif ($WhatIfPreference) {
    if ($FullBlackout) {
        Write-CcdcLog -Level INFO -Message "-WhatIf -FullBlackout: would deny everything inbound first (zero allow rules), run credential hardening while nothing can get in, then add the allow rules, self-check, and disarm. Nothing was changed."
    } else {
        Write-CcdcLog -Level INFO -Message "-WhatIf: would arm a SYSTEM-run safety-net task ($RevertMinutes-minute revert), switch the default inbound action to Block, self-check the result, and disarm the safety net only if the check passes. Nothing was changed."
    }
} else {
    if (-not $FullBlackout) {
        Enable-CcdcFirewallBlock
    }
    if ($safetyArmed -or $AllowNoSafetyNet) {
        Test-CcdcFirewallSelfCheck
    }
}

Show-CcdcSummary
Stop-CcdcSession
