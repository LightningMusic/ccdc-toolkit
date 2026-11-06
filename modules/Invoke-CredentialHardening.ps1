#Requires -Version 5.1
<#
.SYNOPSIS
    Bulk-rotates default/known passwords on local and (optionally) domain
    accounts. This is the single highest-value five minutes of the whole
    competition — default creds are consistently red team's easiest way in.

.DESCRIPTION
    Reads the target account list from the inventory Get-EnvironmentInventory
    produced (run that first). Falls back to live Get-LocalUser / a manual
    list from config/answers.local.psd1 or a prompt if there's no inventory.

    Every account it touches gets a fresh random password (never a value
    typed into this script — this repo is public, nothing environment- or
    competition-specific is ever hardcoded here). New passwords are written
    to a gitignored CSV under logs/ so you have exactly one place to look
    them up — they are NEVER printed anywhere else or logged in plaintext
    to the transcript.

    Always excluded by default: the account you're currently running as
    (so you can't lock yourself out), krbtgt, and a short list of built-in
    Windows accounts that shouldn't get a random password. Pass
    -ExcludeAccounts to add more, or put a ProtectedAccounts entry in
    config/answers.local.psd1 (comma-separated) for the same effect
    without having to remember the flag every run.

    IMPORTANT — read this before your first real run: some regional
    packets score service "functionality" (not just uptime) by actually
    logging in with a specific account, or require you to report any
    password you change on a scored account back to the scoring engine
    via an inject. Blindly rotating an account like that breaks the
    functional check the moment you do it — that's a self-inflicted
    outage, which the CCDC research this toolkit was built from calls out
    as blue teams' single most common own-goal. Put every account your
    packet ties to a scored functional/SLA check into ProtectedAccounts
    (or -ExcludeAccounts) BEFORE you run this for real. If you're not
    sure whether an account is one of those, treat it as protected until
    you've checked the packet.

    Run with -WhatIf first if you want to see exactly who would be touched
    without changing anything.

.PARAMETER IncludeLocalAccounts
    Rotate local (non-domain) account passwords. Default: on.

.PARAMETER IncludeDomainAccounts
    Rotate AD account passwords. Default: on, but only if the inventory
    says this environment is domain-joined — otherwise skipped with a note.

.PARAMETER ExcludeAccounts
    Extra account names to leave alone, on top of the built-in exclude list.

.PARAMETER AcknowledgeNoProtectedAccounts
    A real (non -WhatIf) run with an EMPTY ProtectedAccounts list stops and
    asks you to confirm -- typing NONE -- that no account here feeds a scored
    login/functional check, because rotating one of those fails the check
    the instant it happens. Pass this switch to give that confirmation up
    front (e.g. when running non-interactively). It changes nothing else.

.EXAMPLE
    .\Invoke-CredentialHardening.ps1 -WhatIf
    Shows exactly which accounts would be touched, changes nothing.

.EXAMPLE
    .\Invoke-CredentialHardening.ps1 -ExcludeAccounts 'svc_backup','svc_monitor'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [bool]$IncludeLocalAccounts = $true,
    [bool]$IncludeDomainAccounts = $true,
    [string[]]$ExcludeAccounts = @(),
    [switch]$AcknowledgeNoProtectedAccounts
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "Credential hardening starting. Every account touched gets a brand-new random password — nothing here is ever hardcoded, since this repo is public."
Assert-CcdcElevated -Because "resetting local/AD account passwords"
Show-CcdcTargetContext -RootPath $session.RootPath -SkipIfShownByMenu | Out-Null

# ---------------------------------------------------------------------------
# Never touch these, no matter what the inventory/answer file says.
# ---------------------------------------------------------------------------
$currentUser = $env:USERNAME
if (-not $currentUser) { $currentUser = [System.Environment]::UserName }

$builtInExclude = @(
    $currentUser, 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount', 'SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE'
)

# Accounts your scoring packet ties to a functional/SLA check (login-based
# uptime, not just "service responds") — rotating these without reporting
# the new password through whatever channel your packet requires (usually
# an inject) breaks that check immediately. This is read from the answer
# file, not a parameter, specifically so it's easy to keep up to date as
# you learn more about a given packet without having to remember a flag.
$protectedRaw = Get-CcdcAnswer -Key 'ProtectedAccounts' -Prompt 'Any accounts tied to a scored functional/login check that must NOT be rotated? Comma-separated, blank if none/unsure yet' -Default ''
$protectedAccounts = @()
if ($protectedRaw) { $protectedAccounts = $protectedRaw -split ',' | ForEach-Object { $_.Trim() } }

$excludeSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]($builtInExclude + $ExcludeAccounts + $protectedAccounts), [System.StringComparer]::OrdinalIgnoreCase
)

Write-CcdcLog -Level INFO -Message "Excluding: $($excludeSet -join ', ')"
if ($protectedAccounts.Count -eq 0) {
    Write-CcdcLog -Level WARN -Message "No ProtectedAccounts set. If your scoring packet ties ANY account to a functional/login check, add it to config/answers.local.psd1 before running this for real -- otherwise this module will happily break it."
    if (-not $WhatIfPreference -and -not $AcknowledgeNoProtectedAccounts) {
        # A warning that scrolls past is not a safeguard for the single most
        # common way to score yourself an own-goal, so a real run stops here
        # until someone says out loud that it's intentional.
        $ack = Read-CcdcInput -Prompt 'Every enabled account below (except you, krbtgt and built-ins) is about to get a new random password. Type NONE to confirm that no account here feeds a scored login/functional check -- anything else cancels'
        if ($ack -ne 'NONE') {
            Write-CcdcLog -Level ERROR -Message "Cancelled -- nothing was changed. Add the scored/functional accounts to ProtectedAccounts in config\answers.local.psd1 (see docs/PREP-SHEET.md) and re-run, or pass -AcknowledgeNoProtectedAccounts if you're sure there are none."
            Stop-CcdcSession
            return
        }
    }
}

$inventory = Get-CcdcInventory -RootPath $session.RootPath

# ---------------------------------------------------------------------------
# Build the target list
# ---------------------------------------------------------------------------
$targets = New-Object System.Collections.Generic.List[object]

if ($IncludeLocalAccounts) {
    $localNames = @()
    if ($inventory -and $inventory.LocalAccounts) {
        $localNames = $inventory.LocalAccounts | Where-Object { $_.Enabled } | ForEach-Object { $_.Name }
    } elseif (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
        $localNames = (Get-LocalUser | Where-Object Enabled).Name
    } else {
        $manual = Get-CcdcAnswer -Key 'LocalAccountsManual' -Prompt 'No inventory and no Get-LocalUser here — comma-separated local account names to rotate (blank to skip)' -Default ''
        if ($manual) { $localNames = $manual -split ',' | ForEach-Object { $_.Trim() } }
    }
    foreach ($name in $localNames) {
        # Test-CcdcRotatableAccountName drops computer and trust accounts.
        # On a domain controller Get-LocalUser returns DIRECTORY objects,
        # computer accounts included, and rotating one of those breaks that
        # machine's secure channel with the domain. See that function.
        if (-not (Test-CcdcRotatableAccountName -Name $name)) {
            Write-CcdcLog -Level INFO -Message "Skipping '$name': that is a computer or trust account, and resetting its password would break that machine's domain trust."
            continue
        }
        if (-not $excludeSet.Contains($name)) {
            $targets.Add([pscustomobject]@{ Name = $name; Scope = 'Local' })
        }
    }
}

if ($IncludeDomainAccounts) {
    if ($inventory -and $inventory.DomainJoined) {
        $adNames = @()
        if ($inventory.AdUsers) {
            $adNames = $inventory.AdUsers | Where-Object { $_.Enabled } | ForEach-Object { $_.SamAccountName }
        }
        foreach ($name in $adNames) {
            if (-not (Test-CcdcRotatableAccountName -Name $name)) {
                Write-CcdcLog -Level INFO -Message "Skipping '$name': that is a computer or trust account, and resetting its password would break that machine's domain trust."
                continue
            }
            if (-not $excludeSet.Contains($name)) {
                $targets.Add([pscustomobject]@{ Name = $name; Scope = 'Domain' })
            }
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Skipping domain accounts (inventory says not domain-joined, or no inventory has been run yet)."
    }
}

# A domain controller enumerates the SAME directory objects as both "local"
# and "domain", so without this every account is queued twice and, for real,
# reset twice to two different passwords -- leaving a credential sheet where
# every entry is wrong. On a member server the two scopes are genuinely
# different principals and both are kept. See Select-CcdcCredentialTarget.
$isDomainController = $false
try {
    $domainRole = [int](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
    $isDomainController = ($domainRole -eq 4 -or $domainRole -eq 5)
} catch {
    Write-CcdcLog -Level WARN -Message "Couldn't tell whether this is a domain controller ($($_.Exception.Message)); treating it as not one, which keeps both scopes."
}
$before = $targets.Count
$targets = @(Select-CcdcCredentialTarget -Candidate $targets.ToArray() -IsDomainController $isDomainController)
if ($targets.Count -lt $before) {
    Write-CcdcLog -Level INFO -Message "Collapsed $($before - $targets.Count) duplicate account entr(y/ies): this is a domain controller, so its 'local' accounts ARE the directory accounts. Each account is rotated once."
}

if ($targets.Count -eq 0) {
    Write-CcdcLog -Level WARN -Message "No target accounts found: nothing on this box is both enabled and outside your protected list. That is a normal result on a member server, where the accounts worth rotating live in the directory and get rotated from the domain controller."
    Write-CcdcLog -Level INFO -Message "If you expected accounts here, run Get-EnvironmentInventory.ps1 first or pass a manual list."
    # Summary before the session closes, even on this early exit: a module
    # that ends without one looks indistinguishable from a module that died
    # partway, both to a person and to lab\ -Action TestToolkit.
    Show-CcdcSummary
    Stop-CcdcSession
    return
}

Write-CcdcLog -Level INFO -Message "$($targets.Count) account(s) queued for a password reset: $(($targets.Name) -join ', ')"

# Backing up "who we're about to touch" — not the old passwords (can't back
# those up, they're not retrievable), but a clear record of scope and timing
# in case anything needs to be explained later (audit, incident report).
Backup-CcdcState -Name 'credential-hardening-target-list' -Data $targets | Out-Null

# ---------------------------------------------------------------------------
# Do it
# ---------------------------------------------------------------------------
$credentialSheet = New-Object System.Collections.Generic.List[object]

foreach ($target in $targets) {
    if (-not $PSCmdlet.ShouldProcess($target.Name, "Reset $($target.Scope) account password")) {
        continue
    }

    $newPassword = New-CcdcRandomPassword
    $secure = ConvertTo-SecureString -String $newPassword -AsPlainText -Force

    if ($target.Scope -eq 'Local') {
        $outcome = Invoke-CcdcSafe -Target $target.Name -Action 'reset local account password' -ScriptBlock {
            Set-LocalUser -Name $target.Name -Password $secure -ErrorAction Stop
        }
    } else {
        $outcome = Invoke-CcdcSafe -Target $target.Name -Action 'reset AD account password' -ScriptBlock {
            Set-ADAccountPassword -Identity $target.Name -Reset -NewPassword $secure -ErrorAction Stop
        }
    }

    if ($outcome.Success) {
        $credentialSheet.Add([pscustomobject]@{
            Account  = $target.Name
            Scope    = $target.Scope
            Password = $newPassword
        })
    }
}

# ---------------------------------------------------------------------------
# Write the ONE place these new passwords live.
# ---------------------------------------------------------------------------
if ($credentialSheet.Count -gt 0) {
    $sheetPath = Join-Path $session.LogRoot "credentials_$($session.Stamp).csv"
    $credentialSheet | Export-Csv -Path $sheetPath -NoTypeInformation
    Write-CcdcLog -Level WARN -Message "NEW PASSWORDS (only successful resets) written to: $sheetPath"
    Write-CcdcLog -Level WARN -Message "This file is gitignored and lives only on this box. Copy the values you need somewhere your team can actually use them, then treat it as sensitive for the rest of the competition."
    Write-CcdcLog -Level WARN -Message "If ANY of the $($credentialSheet.Count) account(s) just changed feed a scored functional/login check, report the new password through whatever channel your packet requires (usually an inject) right now — before it gets checked and shows as down."

    # Some scoring engines (e.g. MWCCDC's Quotient) take password changes as
    # a plain username,password CSV pasted/uploaded into their own PCR form,
    # applied immediately with no manual review on their end. This toolkit
    # has no way to know which of these accounts a given scoring engine
    # actually logs into, so it writes ALL of them in that exact format —
    # review it and submit whichever rows are scoring-relevant, right now,
    # before the next check cycle hits a password it doesn't expect.
    $pcrPath = Join-Path $session.LogRoot "credentials_$($session.Stamp)_pcr.csv"
    $pcrLines = @($credentialSheet | ForEach-Object { "$($_.Account),$($_.Password)" })
    Set-Content -Path $pcrPath -Value $pcrLines -Encoding UTF8
    Write-CcdcLog -Level WARN -Message "Also wrote a ready-to-submit PCR file (username,password, no header) for a Quotient-style scoring engine: $pcrPath -- review it and submit whichever rows matter to your scoring portal now."
}

Show-CcdcSummary
Stop-CcdcSession
