#Requires -Version 5.1
<#
.SYNOPSIS
    Figures out what you're actually standing in front of, so you don't
    have to hand-type 40 hostnames into every other module.

.DESCRIPTION
    Tries Active Directory first (domain controllers, computers, users).
    If that's not available — not domain-joined, AD module missing, or it
    just fails — falls back to local/network discovery (local accounts on
    this box, an ARP-table/ping sweep of the subnet you point it at).

    Anything it can't figure out for itself (which services are actually
    scored, what subnet to sweep if it can't guess one) it asks you for —
    once — and everything after that reads from the saved inventory file
    instead of asking again.

    Run this FIRST, before Invoke-CredentialHardening.ps1 or
    Invoke-FirewallBaseline.ps1 — they both look for the inventory file
    this produces and fall back to asking you host-by-host if it's missing.

.PARAMETER SubnetCidr
    Only used in the non-domain fallback path, e.g. "10.10.10.0/24". If you
    don't pass it and it's needed, you'll be prompted (or it'll be read
    from config/answers.local.psd1's SubnetCidr key).

.EXAMPLE
    .\Get-EnvironmentInventory.ps1
#>
[CmdletBinding()]
param(
    [string]$SubnetCidr
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Starting environment discovery. This only reads things — it doesn't change anything, so it's safe to run as many times as you want."

$inventory = [ordered]@{
    Timestamp         = (Get-Date).ToString('o')
    DomainJoined      = $false
    DomainName        = $null
    DomainControllers = @()
    Computers         = @()
    AdUsers           = @()
    LocalAccounts     = @()
    NetworkHosts      = @()
    ScoredServices    = @()
    Notes             = @()
}

# ---------------------------------------------------------------------------
# 1. Domain membership FIRST, from the operating system.
#
# This used to be inferred from whether Get-ADDomain worked, which meant a
# perfectly normal domain member without RSAT -- a web or FTP server, which
# is most of them -- was recorded as DomainJoined = $false. That is simply
# wrong, and other modules read this field. Win32_ComputerSystem knows the
# answer without RSAT, without the ActiveDirectory module and without
# talking to a DC at all.
# ---------------------------------------------------------------------------
Invoke-CcdcSafe -Target 'this computer' -Action 'read domain membership' -ScriptBlock {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $inventory.DomainJoined = [bool]$cs.PartOfDomain
    if ($cs.PartOfDomain) { $inventory.DomainName = $cs.Domain }
} | Out-Null

# ---------------------------------------------------------------------------
# 2. Then enrich from Active Directory, where it is available.
# ---------------------------------------------------------------------------
$adAvailable = [bool](Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue)
$gotAdData = $false

if ($adAvailable) {
    $domainOutcome = Invoke-CcdcSafe -Target 'AD' -Action 'query domain' -ScriptBlock {
        $domain = Get-ADDomain -ErrorAction Stop
        $inventory.DomainJoined = $true
        $inventory.DomainName = $domain.DNSRoot
        $true
    }
    $gotAdData = [bool]$domainOutcome.Success

    if ($gotAdData) {
        $dcOutcome = Invoke-CcdcSafe -Target $inventory.DomainName -Action 'enumerate domain controllers' -ScriptBlock {
            Get-ADDomainController -Filter * -ErrorAction Stop |
                Select-Object HostName, IPv4Address, OperatingSystem
        }
        if ($dcOutcome.Success) { $inventory.DomainControllers = @($dcOutcome.Value) }

        $compOutcome = Invoke-CcdcSafe -Target $inventory.DomainName -Action 'enumerate computer objects' -ScriptBlock {
            Get-ADComputer -Filter * -Properties OperatingSystem, IPv4Address, Enabled -ErrorAction Stop |
                Select-Object Name, DNSHostName, OperatingSystem, IPv4Address, Enabled
        }
        if ($compOutcome.Success) { $inventory.Computers = @($compOutcome.Value) }

        $userOutcome = Invoke-CcdcSafe -Target $inventory.DomainName -Action 'enumerate user accounts' -ScriptBlock {
            Get-ADUser -Filter * -Properties Enabled, AdminCount, PasswordLastSet -ErrorAction Stop |
                Select-Object SamAccountName, Enabled, AdminCount, PasswordLastSet
        }
        if ($userOutcome.Success) { $inventory.AdUsers = @($userOutcome.Value) }

        if ($inventory.AdUsers.Count -gt 0) {
            $privCount = @($inventory.AdUsers | Where-Object { $_.AdminCount -eq 1 }).Count
            Write-CcdcLog -Level WARN -Message "$privCount account(s) have AdminCount=1 (privileged / protected-group members, current or former). Check that list by hand — this is exactly where red team wants a foothold."
        }
    }
} else {
    Write-CcdcLog -Level WARN -Message "No ActiveDirectory module / Get-ADDomain command found on this box. Skipping AD discovery — if this box SHOULD be able to see AD, you're probably missing RSAT (Install-WindowsFeature RSAT-AD-PowerShell on a server, or the RSAT optional feature on client Windows)."
    $inventory.Notes += "AD discovery skipped: ActiveDirectory module unavailable on $(hostname 2>$null)."
}

# ---------------------------------------------------------------------------
# 3. Local accounts — always collected, even on a domain box, because it's
#    cheap and local admin accounts matter regardless of AD.
# ---------------------------------------------------------------------------
if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
    $localOutcome = Invoke-CcdcSafe -Target (hostname) -Action 'enumerate local accounts' -ScriptBlock {
        Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet
    }
    if ($localOutcome.Success) { $inventory.LocalAccounts = @($localOutcome.Value) }
} else {
    Write-CcdcLog -Level WARN -Message "Get-LocalUser not available (older Windows / WMF version) — falling back to 'net user'."
    $netOutcome = Invoke-CcdcSafe -Target (hostname) -Action 'enumerate local accounts via net.exe' -ScriptBlock {
        net user
    }
    if ($netOutcome.Success) { $inventory.Notes += "Raw 'net user' output captured in transcript; Get-LocalUser was unavailable." }
}

# ---------------------------------------------------------------------------
# 4. Network sweep fallback — only when AD gave us no host list, since it's
#    the slowest and least precise source of truth. Keyed on whether we
#    actually got AD DATA, not on whether this box is domain-joined: a
#    domain member without RSAT is joined and still has nothing to show,
#    which is exactly when the sweep earns its keep.
# ---------------------------------------------------------------------------
if (-not $gotAdData) {
    $why = if ($inventory.DomainJoined) {
        "This box is domain-joined ($($inventory.DomainName)) but couldn't query AD from here"
    } else {
        'No domain membership found'
    }
    Write-CcdcLog -Level INFO -Message "$why — doing a light network sweep so you at least know what's alive on your subnet."

    $cidr = Get-CcdcAnswer -Key 'SubnetCidr' -Prompt 'Subnet to sweep, CIDR form (e.g. 10.10.10.0/24)' -Value $SubnetCidr

    $cidrResult = Get-CcdcCidrAddresses -Cidr "$cidr"
    if ($cidrResult.Valid) {
        # Real CIDR math (not a hardcoded ".1-254" assumption) so this works
        # correctly whether the packet hands you a /24, a /27, or anything
        # else. Capped so a mistyped block can't sweep for an hour; the
        # sweep itself is Windows PowerShell 5.1-safe (the previous
        # ForEach-Object -Parallel / Test-Connection -TimeoutSeconds only
        # exist in PowerShell 7+, so it silently did nothing on 5.1).
        if ($cidrResult.Message) { Write-CcdcLog -Level WARN -Message $cidrResult.Message }
        Write-CcdcLog -Level INFO -Message "Sweeping $($cidrResult.Addresses.Count) address(es) in $cidr (this can take a minute or two)..."
        $alive = Invoke-CcdcPingSweep -Addresses $cidrResult.Addresses -TimeoutMs 1000
        $inventory.NetworkHosts = @($alive | ForEach-Object { [pscustomobject]@{ IPAddress = $_ } })
        Write-CcdcLog -Level OK -Message "Found $($inventory.NetworkHosts.Count) live host(s)."
    } else {
        Write-CcdcLog -Level WARN -Message "$($cidrResult.Message) Skipping the sweep."
    }

    if (Get-Command -Name Get-NetNeighbor -ErrorAction SilentlyContinue) {
        Invoke-CcdcSafe -Target 'local ARP table' -Action 'read ARP/neighbor cache' -ScriptBlock {
            Get-NetNeighbor -AddressFamily IPv4 | Where-Object State -ne 'Unreachable' |
                Select-Object IPAddress, LinkLayerAddress, State
        } | ForEach-Object { $inventory.Notes += "ARP cache captured in transcript ($(@($_.Value).Count) entries)." }
    }
}

# ---------------------------------------------------------------------------
# 4. The one thing NOTHING can auto-detect: which services are actually
#    being scored. Only a human reading the scoring sheet knows this.
# ---------------------------------------------------------------------------
$scoredRaw = Get-CcdcAnswer -Key 'ScoredServices' `
    -Prompt 'Comma-separated scored services from your packet, e.g. "DC01:DNS,DC01:LDAP,WEB01:HTTP,WEB01:HTTPS" (blank to skip and fill in later)' `
    -Default ''
if ($scoredRaw) {
    $inventory.ScoredServices = @($scoredRaw -split ',' | ForEach-Object { $_.Trim() })
}

# ---------------------------------------------------------------------------
# 5. Save it
# ---------------------------------------------------------------------------
$inventoryObj = [pscustomobject]$inventory
$jsonPath = Join-Path $session.LogRoot "inventory_$($session.Stamp).json"
$latestPath = Join-Path $session.LogRoot 'inventory-latest.json'

$inventoryObj | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding utf8
$inventoryObj | ConvertTo-Json -Depth 6 | Out-File -FilePath $latestPath -Encoding utf8

Write-CcdcLog -Level OK -Message "Inventory saved: $jsonPath (and copied to inventory-latest.json for other modules to pick up automatically)."

Write-Host ""
Write-Host "==================== INVENTORY SUMMARY ====================" -ForegroundColor White
Write-Host " Domain joined:        $($inventory.DomainJoined)  $(if ($inventory.DomainName) { "($($inventory.DomainName))" })"
Write-Host " Domain controllers:   $($inventory.DomainControllers.Count)"
Write-Host " AD computers:         $($inventory.Computers.Count)"
Write-Host " AD users:             $($inventory.AdUsers.Count)"
Write-Host " Local accounts:       $($inventory.LocalAccounts.Count)"
Write-Host " Network hosts found:  $($inventory.NetworkHosts.Count)"
Write-Host " Scored services:      $($inventory.ScoredServices.Count)"
if ($inventory.Notes.Count -gt 0) {
    Write-Host " Notes:" -ForegroundColor Yellow
    $inventory.Notes | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
}
Write-Host "=============================================================" -ForegroundColor White
Write-Host ""

Show-CcdcSummary
Stop-CcdcSession
