#Requires -Version 5.1
<#
.SYNOPSIS
    Records what this box's configuration looks like when it is known good,
    then tells you what has changed since. Built around DNS and the on-disk
    files a DNS server depends on, but it covers services, scheduled tasks,
    administrators, firewall state, listening ports and patch level too.

.DESCRIPTION
    A returning competitor's advice was blunt: know what the configuration
    is supposed to look like, and what it looks like now, so you can find
    what is wrong quickly. That is this module. Two verbs:

      -Action Capture   Write down how things are right now.
      -Action Verify    Compare how things are now against that record.

    Capture on a clean box, early, before anyone has had a chance to change
    anything. Verify whenever something feels wrong, and on a timer. The
    record is a single JSON file you can read, diff and copy.

    WHAT IS CAPTURED
      DnsZones            every zone, its type, and whether it is AD-integrated
      DnsZoneFiles        SHA-256 of each file-backed zone on disk
      DnsServerSettings   recursion, forwarders, socket pool, cache locking
      DnsRecordCounts     how many records each zone holds
      DhcpScopes          each scope's range, mask, state and lease duration
      DhcpScopeOptions    each scope's DNS server, domain and router options
      DhcpAuthorizedServers  DHCP servers authorized for this domain in AD
      WatchedFiles        SHA-256 of everything under -WatchPath (web roots etc.)
      Services            start type and binary path per service
      ScheduledTasks      non-Microsoft tasks and what they execute
      LocalAdministrators local Administrators group membership
      LocalUsers          local accounts and whether they are enabled
      ListeningPorts      listening TCP/UDP ports and the owning process
      FirewallProfiles    per-profile default actions
      FirewallRules       enabled inbound rules, direction and action
      AutoRuns            Run/RunOnce keys and the Startup folders
      Hotfixes            installed updates, newest first

    THE NAME CHECK, WHICH NEEDS NO BASELINE
    Every filename this module touches also goes through a tampering check
    that runs whether or not a baseline exists. It exists because of a
    specific attack: a team lost Active Directory when a file the DNS
    server loads was renamed with a space added to the end. Nothing was
    deleted, nothing looked missing, and the domain stopped authenticating
    because a zone that will not load takes its SRV records with it.

    A trailing space is invisible in Explorer and in a directory listing.
    It is not invisible to a string comparison, so this reports it, along
    with leading whitespace, trailing dots, doubled spaces, homoglyphs,
    text-direction overrides and double extensions.

    AD-INTEGRATED ZONES ARE IMMUNE TO THAT PARTICULAR TRICK, because they
    live in the directory rather than in a file. This module says which
    kind you have, and that is worth knowing before you need it.

    NOTHING HERE CHANGES ANYTHING. Capture writes one file under logs\;
    Verify writes a report. Neither touches configuration, which is why
    this is safe to run at any point in a round, including while you are
    still working out whether you have a problem at all.

.PARAMETER Action
    Capture, Verify, or Show (print the stored baseline's summary). Default
    is Verify when a baseline exists and Capture when one does not, so the
    first run on a clean box does the right thing without being told.

.PARAMETER BaselineFile
    Where the record lives. Defaults to logs\baselines\<HOSTNAME>-baseline.json.
    Keeping several and pointing at them by name is fine and sometimes
    useful -- one from before hardening, one from after.

.PARAMETER WatchPath
    Extra folders to hash, beyond the DNS zone folder. Web roots, config
    directories, anything whose contents should not change on their own.
    Also read from the answer file key BaselineWatchPaths.

.PARAMETER MaxFilesPerPath
    Safety limit per watched folder. Default 3000. Hashing a folder with
    hundreds of thousands of files under time pressure helps nobody.

.PARAMETER SkipFileHashes
    Capture and compare everything except file contents. Much faster, and
    still catches a file appearing, disappearing or being renamed.

.PARAMETER NoAutoWatch
    Don't add this box's content roots automatically. By default the IIS
    site paths, the IIS FTP site paths and the DNS zone folder are watched
    without being asked for, because those are the folders whose contents
    should not change on their own and the ones worth noticing first.

.EXAMPLE
    .\Invoke-ConfigBaseline.ps1 -Action Capture
    Records the current configuration. Do this first, on a clean box.

.EXAMPLE
    .\Invoke-ConfigBaseline.ps1 -Action Verify
    Shows what has changed since. This is the one you run when DNS breaks.

.EXAMPLE
    .\Invoke-ConfigBaseline.ps1 -Action Capture -WatchPath 'C:\inetpub\wwwroot'
    Also fingerprints the web root, so defacement shows up as changed hashes.
#>
[CmdletBinding()]
param(
    [ValidateSet('Capture', 'Verify', 'Show')]
    [string]$Action,
    [string]$BaselineFile,
    [string[]]$WatchPath,
    [ValidateRange(1, 200000)]
    [int]$MaxFilesPerPath = 3000,
    [switch]$SkipFileHashes,
    [switch]$NoAutoWatch
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

$thisHost = $env:COMPUTERNAME
if (-not $thisHost) { $thisHost = 'unknown-host' }

$baselineDir = Join-Path $session.LogRoot 'baselines'
if (-not (Test-Path -LiteralPath $baselineDir)) { New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null }
if (-not $BaselineFile) {
    $safeHost = ($thisHost -replace '[^a-zA-Z0-9_\-]', '_')
    $BaselineFile = Join-Path $baselineDir "$safeHost-baseline.json"
}

# Choosing the default action from whether a baseline exists means the
# first run on a clean box captures instead of complaining, and every run
# after that verifies.
if (-not $Action) {
    $Action = if (Test-Path -LiteralPath $BaselineFile) { 'Verify' } else { 'Capture' }
    Write-CcdcLog -Level INFO -Message "No -Action given; using -Action $Action (a baseline file $(if ($Action -eq 'Verify') { 'already exists' } else { 'does not exist yet' }) at $BaselineFile)."
}

Show-CcdcTargetContext -RootPath $session.RootPath -SkipIfShownByMenu | Out-Null

# Read straight from the answer file rather than through Get-CcdcAnswer:
# this key is optional, and Get-CcdcAnswer's job is to prompt when a value
# is missing. Stopping a read-only verify to ask "which extra folders?"
# would be exactly the wrong behaviour when you are running it because
# something is already broken.
$answers = Import-CcdcAnswers
$answerWatch = ''
if ($answers -and $answers.ContainsKey('BaselineWatchPaths')) { $answerWatch = [string]$answers['BaselineWatchPaths'] }

$allWatchPaths = New-Object System.Collections.Generic.List[string]
foreach ($w in @($WatchPath)) { if ($w) { $allWatchPaths.Add($w) } }
if ($answerWatch) {
    foreach ($w in ($answerWatch -split ';')) { if ($w.Trim()) { $allWatchPaths.Add($w.Trim()) } }
}

# ---------------------------------------------------------------------------
# Work out the content roots on this box automatically, unless told not to.
#
# The first real run of this on the lab FTP server captured "WatchedFiles: 0"
# -- a perfectly successful baseline of a content server that fingerprinted
# none of its content, because nobody had set BaselineWatchPaths. The whole
# point on a web or FTP box is to notice defacement or a dropped shell, so
# the paths that matter most should not depend on remembering to configure
# them under time pressure.
# ---------------------------------------------------------------------------
# Capture only. On a Verify run the paths come from the baseline itself
# (see the Verify branch, which re-adds $stored.WatchPaths), because the
# baseline defines what is being compared. Discovering paths afresh at
# verify time would report every file under a newly-found root as "added"
# -- drift that is really just the two runs having looked at different
# folders, which is worse than useless when you are reading the output
# because something is already wrong.
if (-not $NoAutoWatch -and $Action -eq 'Capture') {
    $auto = New-Object System.Collections.Generic.List[string]

    if (Get-Command -Name Get-Website -ErrorAction SilentlyContinue) {
        $siteOutcome = Invoke-CcdcSafe -Target 'IIS sites' -Action 'find web content roots' -ScriptBlock {
            Get-Website -ErrorAction Stop | ForEach-Object { $_.PhysicalPath }
        }
        if ($siteOutcome.Success) {
            foreach ($p in @($siteOutcome.Value)) {
                if ($p) { $auto.Add([Environment]::ExpandEnvironmentVariables([string]$p)) }
            }
        }
    }
    if (Get-Command -Name Get-WebFtpSite -ErrorAction SilentlyContinue) {
        $ftpOutcome = Invoke-CcdcSafe -Target 'IIS FTP sites' -Action 'find FTP content roots' -ScriptBlock {
            Get-WebFtpSite -ErrorAction Stop | ForEach-Object { $_.PhysicalPath }
        }
        if ($ftpOutcome.Success) {
            foreach ($p in @($ftpOutcome.Value)) {
                if ($p) { $auto.Add([Environment]::ExpandEnvironmentVariables([string]$p)) }
            }
        }
    }
    # The DNS folder holds file-backed zones. Hashing it is how a changed
    # zone file shows up, and listing it is how a RENAMED one does.
    $dnsDir = Join-Path $env:SystemRoot 'System32\dns'
    if (Test-Path -LiteralPath $dnsDir) { $auto.Add($dnsDir) }

    foreach ($p in $auto) {
        if ($p -and (Test-Path -LiteralPath $p) -and -not $allWatchPaths.Contains($p)) {
            $allWatchPaths.Add($p)
            Write-CcdcLog -Level INFO -Message "Watching '$p' automatically (content root found on this box). Use -NoAutoWatch to stop that."
        }
    }
}

# ---------------------------------------------------------------------------
# Collectors. Each returns an array of @{ Key; Value } so one comparison
# function serves every area. Each is wrapped so that a role which is not
# installed (no DNS server here) is an INFO line, not a failure.
# ---------------------------------------------------------------------------

$script:NameFindings = New-Object System.Collections.Generic.List[object]

function Add-NameCheck {
    param([string]$Name, [string]$Where, [string]$Context)
    $flags = @(Get-CcdcNameTamperFlag -Name $Name)
    if ($flags.Count -gt 0) {
        $script:NameFindings.Add([pscustomobject]@{
                Name    = $Name
                Where   = $Where
                Context = $Context
                Flags   = ($flags -join '; ')
            })
    }
}

function New-Pair {
    param([string]$Key, [string]$Value)
    [pscustomobject]@{ Key = $Key; Value = $Value }
}

function Get-DnsZoneArea {
    $zones = New-Object System.Collections.Generic.List[object]
    $files = New-Object System.Collections.Generic.List[object]
    $settings = New-Object System.Collections.Generic.List[object]
    $counts = New-Object System.Collections.Generic.List[object]
    $fileBacked = 0
    $adIntegrated = 0

    if (-not (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level INFO -Message "No DnsServer module on this box -- skipping the DNS areas. That is expected on anything that is not the DNS server."
        return [pscustomobject]@{ Zones = @(); Files = @(); Settings = @(); Counts = @(); FileBacked = 0; AdIntegrated = 0 }
    }

    $zoneOutcome = Invoke-CcdcSafe -Target 'DNS zones' -Action 'read zone list' -ScriptBlock {
        Get-DnsServerZone -ErrorAction Stop
    }
    if (-not $zoneOutcome.Success) {
        return [pscustomobject]@{ Zones = @(); Files = @(); Settings = @(); Counts = @(); FileBacked = 0; AdIntegrated = 0 }
    }

    $dnsDir = Join-Path $env:SystemRoot 'System32\dns'
    foreach ($z in @($zoneOutcome.Value)) {
        $zones.Add((New-Pair -Key $z.ZoneName -Value ("type=$($z.ZoneType); adintegrated=$($z.IsDsIntegrated); dynamicupdate=$($z.DynamicUpdate); zonefile=$($z.ZoneFile)")))
        Add-NameCheck -Name $z.ZoneName -Where 'DNS zone name' -Context $z.ZoneName

        if ($z.IsDsIntegrated) {
            $adIntegrated++
        } elseif ($z.ZoneFile) {
            $fileBacked++
            $zonePath = Join-Path $dnsDir $z.ZoneFile
            Add-NameCheck -Name $z.ZoneFile -Where 'DNS zone file (as the zone references it)' -Context $zonePath
            if (Test-Path -LiteralPath $zonePath) {
                $value = 'present'
                if (-not $SkipFileHashes) {
                    $h = Invoke-CcdcSafe -Target $zonePath -Action 'hash zone file' -ScriptBlock {
                        (Get-FileHash -LiteralPath $zonePath -Algorithm SHA256 -ErrorAction Stop).Hash
                    }
                    if ($h.Success) { $value = $h.Value }
                }
                $files.Add((New-Pair -Key $zonePath -Value $value))
            } else {
                # The exact failure the returning competitor described:
                # the zone still references a file that is not there under
                # that name any more.
                Write-CcdcLog -Level ERROR -Message "Zone '$($z.ZoneName)' references the file '$($z.ZoneFile)', but no file by that name exists in $dnsDir. A renamed file looks exactly like this -- list the folder and compare character by character before assuming it was deleted."
                $files.Add((New-Pair -Key $zonePath -Value 'MISSING'))
            }
        }

        $rrOutcome = Invoke-CcdcSafe -Target $z.ZoneName -Action 'count resource records' -ScriptBlock {
            @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction Stop).Count
        }
        if ($rrOutcome.Success) { $counts.Add((New-Pair -Key $z.ZoneName -Value ([string]$rrOutcome.Value))) }
    }

    # Every file actually sitting in the DNS folder also gets name-checked,
    # not just the ones a zone points at -- the renamed copy is the thing
    # we are looking for and by definition no zone references it.
    if (Test-Path -LiteralPath $dnsDir) {
        $onDisk = Invoke-CcdcSafe -Target $dnsDir -Action 'list the DNS folder' -ScriptBlock {
            Get-ChildItem -LiteralPath $dnsDir -File -ErrorAction Stop
        }
        if ($onDisk.Success) {
            foreach ($f in @($onDisk.Value)) {
                Add-NameCheck -Name $f.Name -Where 'file in the DNS folder' -Context $f.FullName
            }
        }
    }

    foreach ($pair in @(
            @{ N = 'Recursion'; S = { (Get-DnsServerRecursion -ErrorAction Stop).Enable } },
            @{ N = 'Forwarders'; S = { ((Get-DnsServerForwarder -ErrorAction Stop).IPAddress -join ',') } },
            @{ N = 'CacheLockingPercent'; S = { (Get-DnsServerCache -ErrorAction Stop).LockingPercent } }
        )) {
        $o = Invoke-CcdcSafe -Target "DNS $($pair.N)" -Action 'read setting' -ScriptBlock $pair.S
        if ($o.Success) { $settings.Add((New-Pair -Key $pair.N -Value ([string]$o.Value))) }
    }

    return [pscustomobject]@{
        Zones        = $zones.ToArray()
        Files        = $files.ToArray()
        Settings     = $settings.ToArray()
        Counts       = $counts.ToArray()
        FileBacked   = $fileBacked
        AdIntegrated = $adIntegrated
    }
}

function Get-DhcpScopeArea {
    <#
    .SYNOPSIS
        DHCP's equivalent of Get-DnsZoneArea. Where DHCP actually runs is
        the AD/DNS box itself, not a separate server -- a scope silently
        losing its range, or its DNS/router options getting pointed at a
        hostile box, is the same shape of attack as a DNS zone file going
        missing: everything downstream just stops working, quietly.

    .DESCRIPTION
        Three areas, same granularity as the DNS ones:
          Scopes             range, mask, state, lease duration per scope
          ScopeOptions       the DNS server / domain / router options per
                              scope -- specifically what a redirect attack
                              would change
          AuthorizedServers  DHCP servers authorized for this domain in AD
                              (Get-DhcpServerInDC) -- catches a rogue second
                              server getting authorized, or the real one
                              losing authorization

        Individual RESERVATIONS are deliberately not captured here -- a
        reservation appearing or changing between two points in time is a
        threat-hunt question ("what is new since I last looked"), the same
        way individual DNS records are Invoke-ThreatHunt's job and not
        this module's. This function only covers scope-level structure,
        same boundary as Get-DnsZoneArea covers zone-level structure and
        leaves individual records to the hunt.
    #>
    $scopes = New-Object System.Collections.Generic.List[object]
    $options = New-Object System.Collections.Generic.List[object]
    $authServers = New-Object System.Collections.Generic.List[object]

    if (-not (Get-Command -Name Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level INFO -Message "No DhcpServer module on this box -- skipping the DHCP areas. That is expected on anything that is not the DHCP server."
        return [pscustomobject]@{ Scopes = @(); Options = @(); AuthorizedServers = @() }
    }

    $scopeOutcome = Invoke-CcdcSafe -Target 'DHCP scopes' -Action 'read scope list' -ScriptBlock {
        Get-DhcpServerv4Scope -ErrorAction Stop
    }
    if (-not $scopeOutcome.Success) {
        return [pscustomobject]@{ Scopes = @(); Options = @(); AuthorizedServers = @() }
    }

    foreach ($s in @($scopeOutcome.Value)) {
        $scopeKey = $s.ScopeId.IPAddressToString
        $scopes.Add((New-Pair -Key $scopeKey -Value ("range=$($s.StartRange)-$($s.EndRange); mask=$($s.SubnetMask); state=$($s.State); leaseduration=$($s.LeaseDuration)")))

        $optOutcome = Invoke-CcdcSafe -Target "DHCP options for $scopeKey" -Action 'read scope options' -ScriptBlock {
            Get-DhcpServerv4OptionValue -ScopeId $s.ScopeId -ErrorAction Stop
        }
        if ($optOutcome.Success) {
            $byId = @{}
            foreach ($o in @($optOutcome.Value)) { $byId[[int]$o.OptionId] = ($o.Value -join ',') }
            # 3 = Router, 6 = DNS Servers, 15 = DNS Domain Name -- the three
            # options a redirect attack would actually change.
            $dns = if ($byId.ContainsKey(6)) { $byId[6] } else { '' }
            $domain = if ($byId.ContainsKey(15)) { $byId[15] } else { '' }
            $router = if ($byId.ContainsKey(3)) { $byId[3] } else { '' }
            $options.Add((New-Pair -Key $scopeKey -Value "dns=$dns; domain=$domain; router=$router"))
        }
    }

    $authOutcome = Invoke-CcdcSafe -Target 'DHCP authorized servers' -Action 'read authorized servers' -ScriptBlock {
        Get-DhcpServerInDC -ErrorAction Stop
    }
    if ($authOutcome.Success) {
        foreach ($a in @($authOutcome.Value)) { $authServers.Add((New-Pair -Key $a.DnsName -Value ([string]$a.IPAddress))) }
    }

    return [pscustomobject]@{
        Scopes            = $scopes.ToArray()
        Options           = $options.ToArray()
        AuthorizedServers = $authServers.ToArray()
    }
}

function Get-WatchedFileArea {
    param([string[]]$Paths)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Paths)) {
        if (-not (Test-Path -LiteralPath $p)) {
            Write-CcdcLog -Level WARN -Message "Watched path '$p' does not exist on this box -- skipping it."
            continue
        }
        $listing = Invoke-CcdcSafe -Target $p -Action 'enumerate files to fingerprint' -ScriptBlock {
            Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue
        }
        if (-not $listing.Success) { continue }
        $items = @($listing.Value)
        if ($items.Count -gt $MaxFilesPerPath) {
            Write-CcdcLog -Level WARN -Message "'$p' holds $($items.Count) files, over the -MaxFilesPerPath limit of $MaxFilesPerPath. Fingerprinting the first $MaxFilesPerPath only; raise the limit or point at a narrower folder if that matters."
            $items = $items[0..($MaxFilesPerPath - 1)]
        }
        foreach ($f in $items) {
            Add-NameCheck -Name $f.Name -Where 'watched file' -Context $f.FullName
            $value = "size=$($f.Length)"
            if (-not $SkipFileHashes) {
                $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h) {
                    $value = $h.Hash
                } else {
                    # Worth saying rather than silently degrading to size:
                    # a name with a trailing space cannot be opened through
                    # an ordinary path at all, because Win32 normalization
                    # strips the space before the file system sees it. So
                    # "hash unavailable" is itself a signal, not just a
                    # missing value.
                    $value = "size=$($f.Length) (hash unavailable - the file could not be opened by this path)"
                }
            }
            $out.Add((New-Pair -Key $f.FullName -Value $value))
        }
        Write-CcdcLog -Level OK -Message "Fingerprinted $($items.Count) file(s) under '$p'."
    }
    return $out.ToArray()
}

function Get-ServiceArea {
    $out = New-Object System.Collections.Generic.List[object]
    $o = Invoke-CcdcSafe -Target 'services' -Action 'read service configuration' -ScriptBlock {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    }
    if (-not $o.Success) { return $out.ToArray() }
    foreach ($s in @($o.Value)) {
        # StartMode and path, deliberately NOT current state: a service
        # stopping and starting is normal traffic and would bury the
        # config changes that actually matter.
        $out.Add((New-Pair -Key $s.Name -Value ("startmode=$($s.StartMode); path=$($s.PathName)")))
        $exe = Get-CcdcServiceExePath -PathName $s.PathName
        if ($exe) { Add-NameCheck -Name (Split-Path -Leaf $exe) -Where "service '$($s.Name)' binary" -Context $exe }
    }
    return $out.ToArray()
}

function Get-ScheduledTaskArea {
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) { return $out.ToArray() }
    $o = Invoke-CcdcSafe -Target 'scheduled tasks' -Action 'read task definitions' -ScriptBlock {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
    }
    if (-not $o.Success) { return $out.ToArray() }
    foreach ($t in @($o.Value)) {
        $actions = @($t.Actions | ForEach-Object { (("$($_.Execute) $($_.Arguments)").Trim()) }) -join ' && '
        $out.Add((New-Pair -Key "$($t.TaskPath)$($t.TaskName)" -Value ("state=$($t.State); action=$actions")))
        foreach ($a in @($t.Actions)) {
            if ($a.Execute) { Add-NameCheck -Name (Split-Path -Leaf $a.Execute) -Where "scheduled task '$($t.TaskName)' action" -Context $a.Execute }
        }
    }
    return $out.ToArray()
}

function Get-AccountArea {
    $admins = New-Object System.Collections.Generic.List[object]
    $users = New-Object System.Collections.Generic.List[object]
    # Not Get-LocalGroupMember directly -- it fails on a domain controller.
    # See Get-CcdcAdministratorsMember in Common.psm1.
    $o = Invoke-CcdcSafe -Target 'Administrators group' -Action 'read membership' -ScriptBlock {
        $r = Get-CcdcAdministratorsMember
        if (-not $r.Success) { throw $r.Message }
        $r.Members
    }
    if ($o.Success) { foreach ($m in @($o.Value)) { $admins.Add((New-Pair -Key ([string]$m) -Value 'member')) } }
    if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
        $o = Invoke-CcdcSafe -Target 'local accounts' -Action 'read local users' -ScriptBlock {
            Get-LocalUser -ErrorAction Stop
        }
        if ($o.Success) { foreach ($u in @($o.Value)) { $users.Add((New-Pair -Key $u.Name -Value "enabled=$($u.Enabled)")) } }
    }
    return [pscustomobject]@{ Admins = $admins.ToArray(); Users = $users.ToArray() }
}

function Get-PortArea {
    # Ports at or above 49152 are Windows' dynamic/ephemeral range. Those
    # are transient client sockets that come and go every few seconds, so
    # recording them guarantees drift on every single verify run --
    # findings nobody can act on, in the middle of the findings that
    # matter. A service worth knowing about listens below this.
    $ephemeralFrom = 49152
    $out = New-Object System.Collections.Generic.List[object]
    if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $o = Invoke-CcdcSafe -Target 'listening TCP ports' -Action 'read listeners' -ScriptBlock {
            Get-NetTCPConnection -State Listen -ErrorAction Stop
        }
        if ($o.Success) {
            foreach ($c in @($o.Value)) {
                if ($c.LocalPort -ge $ephemeralFrom) { continue }
                $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                $name = if ($proc) { $proc.ProcessName } else { "pid $($c.OwningProcess)" }
                $out.Add((New-Pair -Key "TCP/$($c.LocalPort)" -Value $name))
            }
        }
    }
    if (Get-Command -Name Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $o = Invoke-CcdcSafe -Target 'listening UDP ports' -Action 'read listeners' -ScriptBlock {
            Get-NetUDPEndpoint -ErrorAction Stop
        }
        if ($o.Success) {
            foreach ($c in @($o.Value)) {
                if ($c.LocalPort -ge $ephemeralFrom) { continue }
                $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                $name = if ($proc) { $proc.ProcessName } else { "pid $($c.OwningProcess)" }
                $out.Add((New-Pair -Key "UDP/$($c.LocalPort)" -Value $name))
            }
        }
    }
    # Several listeners can share a port across addresses; one entry each
    # is what we want, and the first writer wins.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $unique = New-Object System.Collections.Generic.List[object]
    foreach ($p in $out) { if ($seen.Add($p.Key)) { $unique.Add($p) } }
    return $unique.ToArray()
}

function Get-FirewallArea {
    $profiles = New-Object System.Collections.Generic.List[object]
    $rules = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Profiles = @(); Rules = @() }
    }
    $o = Invoke-CcdcSafe -Target 'firewall profiles' -Action 'read profile settings' -ScriptBlock {
        Get-NetFirewallProfile -All -ErrorAction Stop
    }
    if ($o.Success) {
        foreach ($p in @($o.Value)) {
            $profiles.Add((New-Pair -Key ([string]$p.Name) -Value "enabled=$($p.Enabled); inbound=$($p.DefaultInboundAction); outbound=$($p.DefaultOutboundAction)"))
        }
    }
    $o = Invoke-CcdcSafe -Target 'firewall rules' -Action 'read enabled inbound rules' -ScriptBlock {
        Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }
    }
    if ($o.Success) {
        foreach ($r in @($o.Value)) {
            # Keyed on DisplayName AND Name. Windows ships many rules that
            # share a display name across profiles and packages -- keying
            # on the display name alone collapsed 272 rules into 170 and
            # would have hidden a change inside any collapsed group.
            $rules.Add((New-Pair -Key ("$($r.DisplayName) [$($r.Name)]") -Value "action=$($r.Action)"))
        }
    }
    return [pscustomobject]@{ Profiles = $profiles.ToArray(); Rules = $rules.ToArray() }
}

function Get-AutoRunArea {
    $out = New-Object System.Collections.Generic.List[object]
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $out.Add((New-Pair -Key "$k::$($p.Name)" -Value ([string]$p.Value)))
        }
    }
    foreach ($sf in @(
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
        )) {
        if (-not (Test-Path -LiteralPath $sf)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $sf -File -Force -ErrorAction SilentlyContinue)) {
            $out.Add((New-Pair -Key $f.FullName -Value "startup-folder-item; size=$($f.Length)"))
            Add-NameCheck -Name $f.Name -Where 'Startup folder item' -Context $f.FullName
        }
    }
    return $out.ToArray()
}

function Get-HotfixArea {
    $out = New-Object System.Collections.Generic.List[object]
    $o = Invoke-CcdcSafe -Target 'installed updates' -Action 'read update history' -ScriptBlock {
        Get-HotFix -ErrorAction Stop
    }
    if (-not $o.Success) { return $out.ToArray() }
    foreach ($h in @($o.Value)) {
        $when = if ($h.InstalledOn) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { 'unknown' }
        $out.Add((New-Pair -Key ([string]$h.HotFixID) -Value $when))
    }
    return $out.ToArray()
}

function Test-RebootPending {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($p in $paths) { if (Test-Path -LiteralPath $p) { return $true } }
    $sm = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($sm -and $sm.PendingFileRenameOperations) { return $true }
    return $false
}

function Get-CurrentSnapshot {
    Write-CcdcLog -Level INFO -Message "Collecting current configuration. Nothing is changed by this."
    $dns = Get-DnsZoneArea
    $dhcp = Get-DhcpScopeArea
    $accounts = Get-AccountArea
    $fw = Get-FirewallArea
    $hotfix = Get-HotfixArea

    $newest = [datetime]::MinValue
    foreach ($h in $hotfix) {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse($h.Value, [ref]$parsed) -and $parsed -gt $newest) { $newest = $parsed }
    }

    return [ordered]@{
        Host                = $thisHost
        CapturedUtc         = (Get-Date).ToUniversalTime().ToString('o')
        DnsZones            = $dns.Zones
        DnsZoneFiles        = $dns.Files
        DnsServerSettings   = $dns.Settings
        DnsRecordCounts     = $dns.Counts
        DnsFileBackedZones  = $dns.FileBacked
        DnsAdIntegratedZones = $dns.AdIntegrated
        DhcpScopes          = $dhcp.Scopes
        DhcpScopeOptions    = $dhcp.Options
        DhcpAuthorizedServers = $dhcp.AuthorizedServers
        WatchedFiles        = (Get-WatchedFileArea -Paths $allWatchPaths)
        Services            = (Get-ServiceArea)
        ScheduledTasks      = (Get-ScheduledTaskArea)
        LocalAdministrators = $accounts.Admins
        LocalUsers          = $accounts.Users
        ListeningPorts      = (Get-PortArea)
        FirewallProfiles    = $fw.Profiles
        FirewallRules       = $fw.Rules
        AutoRuns            = (Get-AutoRunArea)
        Hotfixes            = $hotfix
        NewestHotfixDate    = $(if ($newest -eq [datetime]::MinValue) { '' } else { $newest.ToString('yyyy-MM-dd') })
        RebootPending       = (Test-RebootPending)
        WatchPaths          = $allWatchPaths.ToArray()
    }
}

# The order areas are compared and reported in. Most consequential first,
# so that a long report still leads with what matters.
$script:AreaOrder = @(
    'DnsZones', 'DnsZoneFiles', 'DnsServerSettings', 'DnsRecordCounts',
    'DhcpScopes', 'DhcpScopeOptions', 'DhcpAuthorizedServers',
    'LocalAdministrators', 'Services', 'ScheduledTasks', 'AutoRuns',
    'WatchedFiles', 'LocalUsers', 'ListeningPorts',
    'FirewallProfiles', 'FirewallRules', 'Hotfixes'
)

function Show-NameFindings {
    if ($script:NameFindings.Count -eq 0) {
        Write-CcdcLog -Level OK -Message "Name check: nothing odd in any filename this pass looked at (no trailing spaces, homoglyphs, double extensions or direction overrides)."
        return
    }
    Write-CcdcLog -Level ERROR -Message "Name check: $($script:NameFindings.Count) name(s) look deliberately altered. This is the shape of the attack that renames a file so a reference to it stops resolving."
    foreach ($f in $script:NameFindings) {
        # Wrapped in brackets so trailing whitespace is visible on screen,
        # which is the entire problem with this attack.
        Write-CcdcLog -Level ERROR -Message "  [$($f.Name)] ($($f.Where)) -- $($f.Flags). Full path: $($f.Context)"
    }
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

switch ($Action) {

    'Capture' {
        $snapshot = Get-CurrentSnapshot
        Show-NameFindings

        if ($script:NameFindings.Count -gt 0) {
            Write-CcdcLog -Level WARN -Message "Capturing anyway, but be aware: a baseline taken while something is already wrong records the wrong thing as normal. If this box might already be tampered with, deal with the names above first and capture again."
        }

        $json = $snapshot | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath $BaselineFile -Value $json -Encoding UTF8
        Write-CcdcLog -Level OK -Message "Baseline written to $BaselineFile"

        foreach ($area in $script:AreaOrder) {
            $count = @($snapshot[$area]).Count
            Write-CcdcLog -Level INFO -Message ("  {0,-20} {1} item(s)" -f $area, $count)
        }
        if ($snapshot.DnsFileBackedZones -gt 0) {
            Write-CcdcLog -Level WARN -Message "$($snapshot.DnsFileBackedZones) DNS zone(s) here are file-backed, so they can be broken by renaming a file on disk. Converting them to AD-integrated removes that whole class of attack and gives you replication as well -- worth doing if nothing depends on the file form."
        }
        if ($snapshot.DnsAdIntegratedZones -gt 0) {
            Write-CcdcLog -Level OK -Message "$($snapshot.DnsAdIntegratedZones) DNS zone(s) are AD-integrated, so they live in the directory rather than in a file and cannot be broken by renaming one."
        }
    }

    'Show' {
        if (-not (Test-Path -LiteralPath $BaselineFile)) {
            Write-CcdcLog -Level ERROR -Message "No baseline at $BaselineFile. Run with -Action Capture first."
        } else {
            $stored = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
            Write-CcdcLog -Level INFO -Message "Baseline for $($stored.Host), captured $($stored.CapturedUtc) UTC."
            foreach ($area in $script:AreaOrder) {
                Write-CcdcLog -Level INFO -Message ("  {0,-20} {1} item(s)" -f $area, @($stored.$area).Count)
            }
        }
    }

    'Verify' {
        if (-not (Test-Path -LiteralPath $BaselineFile)) {
            Write-CcdcLog -Level ERROR -Message "No baseline at $BaselineFile, so there is nothing to compare against. Run with -Action Capture on a box you believe is clean, then come back to this."
        } else {
            $stored = Get-Content -LiteralPath $BaselineFile -Raw | ConvertFrom-Json
            if ($stored.Host -ne $thisHost) {
                Write-CcdcLog -Level WARN -Message "That baseline was captured on '$($stored.Host)' but this box is '$thisHost'. Everything will look different. Point -BaselineFile at the right one."
            }
            Write-CcdcLog -Level INFO -Message "Comparing against the baseline captured $($stored.CapturedUtc) UTC."

            # Re-hash exactly the folders the baseline covered, or a
            # verify run that forgot -WatchPath reports the whole set as
            # missing and buries the real drift.
            foreach ($w in @($stored.WatchPaths)) {
                if ($w -and -not $allWatchPaths.Contains($w)) { $allWatchPaths.Add($w) }
            }

            $current = Get-CurrentSnapshot
            $verdicts = New-Object System.Collections.Generic.List[object]
            $details = New-Object System.Collections.Generic.List[string]

            foreach ($area in $script:AreaOrder) {
                $diff = Compare-CcdcBaselineSet -Baseline @($stored.$area) -Current @($current[$area])
                $verdict = Get-CcdcBaselineAreaVerdict -Area $area -Diff $diff
                $verdicts.Add($verdict)
                Write-CcdcLog -Level $verdict.Level -Message $verdict.Message

                if ($diff.DriftCount -gt 0) {
                    $details.Add("### $area")
                    foreach ($a in $diff.Added) {
                        Write-CcdcLog -Level $verdict.Level -Message "    + new: $($a.Key) => $($a.Value)"
                        $details.Add("- NEW      $($a.Key) => $($a.Value)")
                    }
                    foreach ($r in $diff.Removed) {
                        Write-CcdcLog -Level $verdict.Level -Message "    - gone: $($r.Key) (was $($r.Value))"
                        $details.Add("- MISSING  $($r.Key) (was $($r.Value))")
                    }
                    foreach ($c in $diff.Changed) {
                        Write-CcdcLog -Level $verdict.Level -Message "    ~ changed: $($c.Key)"
                        Write-CcdcLog -Level $verdict.Level -Message "        was: $($c.Was)"
                        Write-CcdcLog -Level $verdict.Level -Message "        now: $($c.Now)"
                        $details.Add("- CHANGED  $($c.Key)")
                        $details.Add("             was: $($c.Was)")
                        $details.Add("             now: $($c.Now)")
                    }
                }
            }

            Show-NameFindings

            $patchCard = Get-CcdcPatchStatusVerdict `
                -NewestHotfixDate $(if ($current.NewestHotfixDate) { [datetime]$current.NewestHotfixDate } else { [datetime]::MinValue }) `
                -RebootPending ([bool]$current.RebootPending)
            Write-CcdcLog -Level INFO -Message "Patching: $($patchCard.Value) -- $($patchCard.Detail)"

            $drifted = @($verdicts | Where-Object { $_.Level -eq 'ERROR' -or $_.Level -eq 'WARN' })
            if ($drifted.Count -eq 0 -and $script:NameFindings.Count -eq 0) {
                Write-CcdcLog -Level OK -Message "Everything matches the baseline. That is a real answer: whatever is wrong, it is not a configuration change this baseline covers."
            }

            $reportDir = Join-Path $session.LogRoot 'baselines'
            $reportPath = Join-Path $reportDir ("verify-" + (Get-Date -Format 'yyyy-MM-dd_HHmmss') + '.md')
            $report = New-Object System.Collections.Generic.List[string]
            $report.Add("# Configuration drift report")
            $report.Add('')
            $report.Add("Host: $thisHost")
            $report.Add("Baseline captured: $($stored.CapturedUtc) UTC")
            $report.Add("Verified: $((Get-Date).ToUniversalTime().ToString('o')) UTC")
            $report.Add('')
            $report.Add('## Summary')
            $report.Add('')
            foreach ($v in $verdicts) { $report.Add("- [$($v.Level)] $($v.Message)") }
            $report.Add("- Patching: $($patchCard.Value)")
            $report.Add('')
            if ($script:NameFindings.Count -gt 0) {
                $report.Add('## Names that look deliberately altered')
                $report.Add('')
                foreach ($f in $script:NameFindings) {
                    $report.Add("- ``[$($f.Name)]`` ($($f.Where)) -- $($f.Flags)")
                    $report.Add("  - $($f.Context)")
                }
                $report.Add('')
            }
            if ($details.Count -gt 0) {
                $report.Add('## Detail')
                $report.Add('')
                foreach ($d in $details) { $report.Add($d) }
            }
            Set-Content -LiteralPath $reportPath -Value ($report.ToArray()) -Encoding UTF8
            Write-CcdcLog -Level OK -Message "Drift report written to $reportPath"
        }
    }
}

Show-CcdcSummary
Stop-CcdcSession
