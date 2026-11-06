#Requires -Version 5.1
<#
.SYNOPSIS
    Audits the DNS server and, on request, closes the settings that let
    someone copy your zone or rewrite records in it. For the AD/DNS box.

.DESCRIPTION
    DNS is a scored service AND the thing every other service depends on
    to be found, which makes it the worst place to be careless in either
    direction: leaving it open hands over the map of the network, and
    tightening the wrong setting takes the whole environment down.

    So this runs read-only first, always, and changes nothing unless asked.

    READ-ONLY AUDIT (always runs)
      1. Every zone: type, whether it is AD-integrated, its dynamic update
         mode and its zone file.
      2. Zone transfers per zone. "Any server" means one request copies
         every hostname and address you have.
      3. Dynamic updates per zone. Nonsecure means an unauthenticated host
         can overwrite records, including the ones clients use to find the
         domain controller.
      4. Server settings: recursion, forwarders, cache locking, cache
         pollution protection.
      5. Records worth a human look -- wildcards, TXT/NULL/HINFO, TTLs
         under a minute, and A records pointing outside your subnet. This
         narrows hundreds of records down to a handful; it does not decide
         anything for you.

    CHANGES (opt-in, each backed up first)
      -SecureZoneTransfers   sets every primary zone to NoTransfer
      -SecureDynamicUpdates  sets AD-integrated zones to Secure
      -HardenCache           cache locking to 100% and pollution protection on
      -DisableRecursion      READ THE WARNING. Off by default.

    THE ONE THAT CAN COST YOU THE ROUND: disabling recursion. If anything
    in the topology resolves external names through this server, turning
    recursion off breaks that, and DNS is scored. It is a switch here, on
    its own, requiring an explicit decision -- not part of any bundle.

    A note on dynamic updates: 'Secure' requires AD integration. On a
    file-backed zone the cmdlet rejects it, and the only secure value is
    'None', which stops clients registering at all. This reports those
    zones and does not change them, because that is a decision rather
    than a fix.

    Related: Invoke-ConfigBaseline.ps1 fingerprints the zone FILES and
    catches a renamed one; this module looks at the server's settings.

.PARAMETER SecureZoneTransfers
    Set every primary zone to NoTransfer.

.PARAMETER SecureDynamicUpdates
    Set AD-integrated zones with nonsecure updates to Secure. File-backed
    zones are reported and left alone.

.PARAMETER HardenCache
    Cache locking to 100% and cache pollution protection on.

.PARAMETER DisableRecursion
    Turn recursion off. Only if nothing resolves external names through
    this server. Read the warning in the description first.

.PARAMETER ExpectedSubnetPrefix
    Used to flag A records pointing outside your network, e.g. '10.10.10.'.
    Read from the answer file key SubnetCidr when not given.

.PARAMETER ShortTtlSeconds
    A record with a TTL below this is flagged. Default 60.

.EXAMPLE
    .\Invoke-DnsHardening.ps1
    Audits and changes nothing.

.EXAMPLE
    .\Invoke-DnsHardening.ps1 -SecureZoneTransfers -SecureDynamicUpdates -HardenCache
    The three changes that are safe on a normal domain controller.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SecureZoneTransfers,
    [switch]$SecureDynamicUpdates,
    [switch]$HardenCache,
    [switch]$DisableRecursion,
    [string]$ExpectedSubnetPrefix,
    [ValidateRange(1, 86400)]
    [int]$ShortTtlSeconds = 60
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

$changing = $SecureZoneTransfers -or $SecureDynamicUpdates -or $HardenCache -or $DisableRecursion

Write-CcdcLog -Level INFO -Message "DNS audit starting. The audit is read-only; nothing changes unless you asked for a specific change."
if ($changing) { Assert-CcdcElevated -Because 'changing DNS server and zone settings' }
Show-CcdcTargetContext -RootPath $session.RootPath -SkipIfShownByMenu | Out-Null

if (-not (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level INFO -Message "The DnsServer module isn't installed on this box, so there's nothing for this module to do here. Run it on the DNS server."
    Show-CcdcSummary; Stop-CcdcSession; return
}

# Subnet prefix for the off-network record check. Derived from SubnetCidr
# rather than asked for, because it is already in the answer file.
if (-not $ExpectedSubnetPrefix) {
    $answers = Import-CcdcAnswers -RootPath $session.RootPath
    if ($answers -and $answers.ContainsKey('SubnetCidr') -and $answers['SubnetCidr']) {
        $cidr = [string]$answers['SubnetCidr']
        if ($cidr -match '^(\d+\.\d+\.\d+)\.') { $ExpectedSubnetPrefix = $Matches[1] + '.' }
    }
}
if ($ExpectedSubnetPrefix) {
    Write-CcdcLog -Level INFO -Message "Flagging A records that point outside '$ExpectedSubnetPrefix'."
} else {
    Write-CcdcLog -Level INFO -Message "No subnet prefix known, so A records won't be checked for pointing off-network. Pass -ExpectedSubnetPrefix or set SubnetCidr in the answer file."
}

# ---------------------------------------------------------------------------
# 1. What zones are here
# ---------------------------------------------------------------------------
$zoneOutcome = Invoke-CcdcSafe -Target 'DNS zones' -Action 'list the zones' -ScriptBlock {
    Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated }
}
if (-not $zoneOutcome.Success) { Show-CcdcSummary; Stop-CcdcSession; return }
$zones = @($zoneOutcome.Value)

Write-Host ''
Write-Host '-- 1. Zones on this server --' -ForegroundColor Cyan
$zones | Select-Object ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, SecureSecondaries |
    Format-Table -AutoSize | Out-String -Width 160 | Write-Host

# ---------------------------------------------------------------------------
# 2 + 3. Zone transfers and dynamic updates
# ---------------------------------------------------------------------------
$transferTargets = New-Object System.Collections.Generic.List[object]
$updateTargets = New-Object System.Collections.Generic.List[object]
$updateManual = New-Object System.Collections.Generic.List[object]

Write-Host '-- 2. Zone transfers --' -ForegroundColor Cyan
foreach ($z in @($zones | Where-Object { $_.ZoneType -eq 'Primary' })) {
    $v = Get-CcdcDnsZoneTransferVerdict -SecureSecondaries "$($z.SecureSecondaries)"
    if ($v.Vulnerable) {
        Write-CcdcLog -Level ERROR -Message "$($z.ZoneName): $($v.Detail)"
        $transferTargets.Add($z)
    } else {
        Write-CcdcLog -Level OK -Message "$($z.ZoneName): $($v.Detail)"
    }
}

Write-Host ''
Write-Host '-- 3. Dynamic updates --' -ForegroundColor Cyan
foreach ($z in @($zones | Where-Object { $_.ZoneType -eq 'Primary' })) {
    $v = Get-CcdcDnsDynamicUpdateVerdict -DynamicUpdate "$($z.DynamicUpdate)" -IsDsIntegrated ([bool]$z.IsDsIntegrated)
    if (-not $v.Vulnerable) {
        Write-CcdcLog -Level OK -Message "$($z.ZoneName): $($v.Detail)"
        continue
    }
    Write-CcdcLog -Level ERROR -Message "$($z.ZoneName): $($v.Detail)"
    if ($v.SafeToChange) {
        $updateTargets.Add([pscustomobject]@{ Zone = $z; Target = $v.Target })
    } else {
        $updateManual.Add([pscustomobject]@{ Zone = $z; Target = $v.Target })
    }
}

# ---------------------------------------------------------------------------
# 4. Server-wide settings
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '-- 4. Server settings --' -ForegroundColor Cyan

$recursionOn = $null
$rec = Invoke-CcdcSafe -Target 'recursion' -Action 'read the recursion setting' -ScriptBlock { Get-DnsServerRecursion -ErrorAction Stop }
if ($rec.Success) {
    $recursionOn = [bool]$rec.Value.Enable
    if ($recursionOn) {
        Write-CcdcLog -Level INFO -Message "Recursion is ON. That is normal if anything here resolves external names, and turning it off would break those lookups. Not a finding by itself."
    } else {
        Write-CcdcLog -Level OK -Message "Recursion is off."
    }
}

$fwd = Invoke-CcdcSafe -Target 'forwarders' -Action 'read the forwarder list' -ScriptBlock { (Get-DnsServerForwarder -ErrorAction Stop).IPAddress }
if ($fwd.Success) {
    $list = @($fwd.Value | ForEach-Object { "$_" })
    Write-CcdcLog -Level INFO -Message "Forwarders: $(if ($list.Count) { $list -join ', ' } else { '(none)' }). Check these against what you expect -- a forwarder you did not set is every lookup on this box going somewhere of someone else's choosing."
}

$cacheBad = $false
$cache = Invoke-CcdcSafe -Target 'DNS cache' -Action 'read cache protection settings' -ScriptBlock { Get-DnsServerCache -ErrorAction Stop }
if ($cache.Success) {
    $lock = $cache.Value.LockingPercent
    $poll = $cache.Value.EnablePollutionProtection
    if ($lock -lt 100) {
        Write-CcdcLog -Level WARN -Message "Cache locking is $lock%, so a cached entry can be overwritten before it expires. 100% is the hardened value."
        $cacheBad = $true
    } else {
        Write-CcdcLog -Level OK -Message "Cache locking is at 100%."
    }
    if (-not $poll) {
        Write-CcdcLog -Level WARN -Message "Cache pollution protection is off, which lets unrelated records ride along in a response and get cached."
        $cacheBad = $true
    } else {
        Write-CcdcLog -Level OK -Message "Cache pollution protection is on."
    }
}

$rootHints = Invoke-CcdcSafe -Target 'root hints' -Action 'count the root hints' -ScriptBlock { @(Get-DnsServerRootHint -ErrorAction Stop).Count }
if ($rootHints.Success) {
    $n = [int]$rootHints.Value
    # There are 13 root server letters. A count that is not 13 is not
    # proof of anything, but it is cheap to notice and expensive to miss.
    if ($n -ne 13) {
        Write-CcdcLog -Level WARN -Message "$n root hint(s) configured. The internet has 13 root server letters, so a different number is worth a look -- root hints are a quiet place to redirect everything this server cannot answer itself."
    } else {
        Write-CcdcLog -Level OK -Message "13 root hints, which is the expected number."
    }
}

# ---------------------------------------------------------------------------
# 5. Records worth reading
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '-- 5. Records worth a human look --' -ForegroundColor Cyan
$flagged = 0
foreach ($z in @($zones | Where-Object { $_.ZoneType -eq 'Primary' })) {
    $recOutcome = Invoke-CcdcSafe -Target $z.ZoneName -Action 'read the zone records' -ScriptBlock {
        Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction Stop
    }
    if (-not $recOutcome.Success) { continue }
    foreach ($r in @($recOutcome.Value)) {
        $ttl = 3600
        try { if ($r.TimeToLive) { $ttl = [int]$r.TimeToLive.TotalSeconds } } catch { }
        # Get-CcdcDnsRecordDataText reads whatever property a record's type
        # actually stores its payload in (not just IPv4Address), so a CNAME
        # or MX now prints its target too, instead of showing nothing.
        $data = Get-CcdcDnsRecordDataText -RecordData $r.RecordData
        if ($data -eq 'unknown') { $data = '' }
        $flags = @(Get-CcdcSuspiciousDnsRecordFlag -HostName "$($r.HostName)" -RecordType "$($r.RecordType)" `
                -TtlSeconds $ttl -RecordData $data -ExpectedSubnetPrefix $ExpectedSubnetPrefix)
        if ($flags.Count -gt 0) {
            $flagged++
            Write-CcdcLog -Level WARN -Message "$($z.ZoneName): $($r.HostName) $($r.RecordType)$(if ($data) { " -> $data" }) -- $($flags -join '; ')"
        }
    }
}
if ($flagged -eq 0) {
    Write-CcdcLog -Level OK -Message "No records matched the wildcard / TXT / short-TTL / off-subnet checks. That is not proof the zone is clean -- a record that looks ordinary will not be flagged."
} else {
    Write-CcdcLog -Level INFO -Message "$flagged record(s) flagged. Flagged is not malicious: read them and decide."
}

# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------
if (-not $changing) {
    Write-Host ''
    Write-CcdcLog -Level INFO -Message "Nothing was changed. The safe three on a domain controller are -SecureZoneTransfers -SecureDynamicUpdates -HardenCache. Leave -DisableRecursion alone unless you know nothing here resolves external names."
    Show-CcdcSummary; Stop-CcdcSession; return
}

Write-Host ''
Write-Host '-- Changes --' -ForegroundColor Yellow
Backup-CcdcState -Name 'dns-zones-before' -Data ($zones | Select-Object ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, SecureSecondaries) | Out-Null
if ($cache.Success) { Backup-CcdcState -Name 'dns-cache-before' -Data $cache.Value | Out-Null }

if ($SecureZoneTransfers) {
    foreach ($z in $transferTargets) {
        if (-not $PSCmdlet.ShouldProcess($z.ZoneName, 'Set zone transfers to NoTransfer')) { continue }
        Invoke-CcdcSafe -Target $z.ZoneName -Action 'refuse zone transfers' -ScriptBlock {
            Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries 'NoTransfer' -ErrorAction Stop
        } | Out-Null
    }
    if ($transferTargets.Count -eq 0) { Write-CcdcLog -Level INFO -Message 'No zone needed its transfer setting changed.' }
}

if ($SecureDynamicUpdates) {
    foreach ($t in $updateTargets) {
        $zoneName = $t.Zone.ZoneName
        $target = $t.Target
        if (-not $PSCmdlet.ShouldProcess($zoneName, "Set dynamic updates to $target")) { continue }
        Invoke-CcdcSafe -Target $zoneName -Action "set dynamic updates to $target" -ScriptBlock {
            Set-DnsServerPrimaryZone -Name $zoneName -DynamicUpdate $target -ErrorAction Stop
        } | Out-Null
    }
    foreach ($t in $updateManual) {
        Write-CcdcLog -Level WARN -Message "$($t.Zone.ZoneName) was NOT changed: it is file-backed, so the only secure value is '$($t.Target)', and that stops clients registering themselves. Convert it to AD-integrated or decide deliberately."
    }
    if ($updateTargets.Count -eq 0 -and $updateManual.Count -eq 0) { Write-CcdcLog -Level INFO -Message 'No zone needed its dynamic update mode changed.' }
}

if ($HardenCache) {
    if ($cacheBad) {
        if ($PSCmdlet.ShouldProcess('DNS cache', 'Set locking to 100% and turn on pollution protection')) {
            Invoke-CcdcSafe -Target 'DNS cache' -Action 'harden the cache' -ScriptBlock {
                Set-DnsServerCache -LockingPercent 100 -PollutionProtection $true -ErrorAction Stop
            } | Out-Null
        }
    } else {
        Write-CcdcLog -Level INFO -Message 'The cache was already hardened; nothing to do.'
    }
}

if ($DisableRecursion) {
    if ($recursionOn -eq $false) {
        Write-CcdcLog -Level INFO -Message 'Recursion is already off.'
    } else {
        Write-CcdcLog -Level WARN -Message 'Turning recursion OFF. If anything in this environment resolves external names through this server, those lookups stop working now -- and DNS is scored. Re-enable with: Set-DnsServerRecursion -Enable $true'
        if ($PSCmdlet.ShouldProcess('DNS recursion', 'Disable')) {
            Invoke-CcdcSafe -Target 'DNS recursion' -Action 'disable recursion' -ScriptBlock {
                Set-DnsServerRecursion -Enable $false -ErrorAction Stop
            } | Out-Null
        }
    }
}

Write-Host ''
Write-CcdcLog -Level INFO -Message "Re-run this module with no switches to confirm what landed, and check a lookup still works from another box: Resolve-DnsName -Name <a host in your zone> -Server <this server>"

Show-CcdcSummary
Stop-CcdcSession
