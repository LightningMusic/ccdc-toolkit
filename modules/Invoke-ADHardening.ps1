#Requires -Version 5.1
<#
.SYNOPSIS
    Domain-wide AD hardening and audit — the "user layer and host layer,
    across the whole domain" piece, not just one box. Run once, from a
    domain-joined host with RSAT (ideally a domain controller).

.DESCRIPTION
    Everything else in this toolkit is scoped to one host at a time (see
    docs/ARCHITECTURE.md's "why per-host, not fleet-wide" note) — this
    module is the deliberate exception, because AD settings like the
    domain password policy or LLMNR/NTLMv2/SMB-signing policy AREN'T
    per-host things; they're domain-wide by nature, so there's no
    per-host version of this to run instead. Run it once, from wherever
    you have the ActiveDirectory/GroupPolicy RSAT modules.

    Six pieces, each independently gated by -WhatIf/ShouldProcess so you
    can preview exactly what would change before committing to any of it,
    and each backed up first the same way every other destructive action
    in this toolkit is:

      1. USER LAYER — stale/never-logged-in account audit. Lists enabled
         accounts with no logon in -StaleDays (default 90) or no logon
         ever, excluding built-ins and anything in ProtectedAccounts, then
         asks which (if any) to disable. Never auto-disables anything —
         you choose, by name, after seeing the list.
      2. USER LAYER — a documented "blue team admin" account, added to
         Domain Admins and logged to this module's own credential CSV
         the same way every generated password in this toolkit is. This
         is NEVER meant to be secret from your own teammates — see
         docs/SECURITY.md's zero-downtime section for why a secret admin
         account is a liability, not an asset, on a team.
      3. HOST LAYER (domain-wide policy) — disables SMB anonymous access
         (RestrictAnonymous / RestrictAnonymousSAM).
      4. HOST LAYER (domain-wide policy) — disables LLMNR
         (multicast name resolution), a common credential-relay vector.
      5. HOST LAYER (domain-wide policy) — enforces NTLMv2-only
         (LmCompatibilityLevel 5) and enables SMB signing on both the
         client and server side.
      6. USER LAYER — sets the domain's default password policy
         (length/history/lockout). Defaults below are a reasonable
         starting point, NOT a rules-packet requirement — override them
         if your packet specifies exact numbers.

    Items 3-5 are applied via ONE new GPO this module creates
    (-GpoName, default "<ArtifactPrefix>-Hardening-Policy") rather than
    editing every host's registry directly — that's the durable, correct
    way to push a domain-wide setting, and it self-documents as a single
    named GPO you can review, unlink, or delete if something needs to be
    walked back. Linked to the domain root by default; pass -TargetOU to
    scope it narrower.

    What this does NOT do, on purpose: BloodHound-style attack-path collection.
    That's genuinely useful for the same "see attack paths to Domain
    Admin before red team does" goal, but analyzing its output needs a
    separate BloodHound install, and whether that's even usable inside a
    NetLab+-style environment with no file transfer out is still an open
    question for this specific setup — see docs/ARCHITECTURE.md's
    roadmap rather than assuming this module secretly covers it.

.PARAMETER StaleDays
    How many days without a logon counts as "stale" for the account
    audit. Default 90.

.PARAMETER GpoName
    Name for the new hardening GPO. Defaults to "<ArtifactPrefix>-Hardening-Policy"
    — pulled from the answer file/prompt like every other named artifact
    this toolkit creates, for the same public-repo fingerprinting reason
    (see docs/SECURITY.md).

.PARAMETER TargetOU
    Distinguished name of the OU to link the hardening GPO to. Blank
    (default) links it at the domain root, meaning it applies everywhere.

.PARAMETER MinPasswordLength
    Domain password policy: minimum length. Default 12.

.PARAMETER PasswordHistoryCount
    Domain password policy: how many previous passwords are remembered.
    Default 5.

.PARAMETER LockoutThreshold
    Domain password policy: failed attempts before lockout. Default 5.

.PARAMETER LockoutDurationMinutes
    Domain password policy: how long an account stays locked out.
    Default 15.

.EXAMPLE
    .\Invoke-ADHardening.ps1 -WhatIf
    Shows every account that would be flagged as stale and every policy
    change that would be made, without changing anything.

.EXAMPLE
    .\Invoke-ADHardening.ps1
    Runs all six pieces, each with its own confirmation.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$StaleDays = 90,
    [string]$GpoName,
    [string]$TargetOU = '',
    [int]$MinPasswordLength = 12,
    [int]$PasswordHistoryCount = 5,
    [int]$LockoutThreshold = 5,
    [int]$LockoutDurationMinutes = 15
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level WARN -Message "AD hardening starting. Unlike every other module here, this one is DOMAIN-WIDE, not per-host -- review every WARN/action line, and run -WhatIf first if this is your first time."
Assert-CcdcElevated -Because "AD account/GPO/domain-policy changes (this also needs Domain Admin rights specifically, which local elevation alone doesn't guarantee)"
Show-CcdcTargetContext -RootPath $session.RootPath -SkipIfShownByMenu | Out-Null

try {

function Test-CcdcAdModuleAvailable {
    if (-not (Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "ActiveDirectory module not available -- this needs to run from a domain-joined host with RSAT (ideally a domain controller)."
        return $false
    }
    return $true
}

function Test-CcdcGpoModuleAvailable {
    if (-not (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue)) {
        Write-CcdcLog -Level ERROR -Message "GroupPolicy module not available -- install RSAT's Group Policy Management tools to use the policy-based sections of this module."
        return $false
    }
    return $true
}


# ---------------------------------------------------------------------------
# 1. USER LAYER — stale/never-logged-in account audit.
# ---------------------------------------------------------------------------
if (Test-CcdcAdModuleAvailable) {
    Write-CcdcLog -Level INFO -Message "-- 1. Stale/never-logged-in account audit --"

    $protectedRaw = Get-CcdcAnswer -Key 'ProtectedAccounts' -Prompt 'Any accounts tied to a scored functional/login check that must NOT be flagged? Comma-separated, blank if none/unsure yet' -Default ''
    $protectedAccounts = @()
    if ($protectedRaw) { $protectedAccounts = $protectedRaw -split ',' | ForEach-Object { $_.Trim() } }
    $builtInExclude = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount', 'WDAGUtilityAccount')
    $excludedNames = [string[]]($builtInExclude + $protectedAccounts)

    $staleOutcome = Invoke-CcdcSafe -Target 'AD users' -Action 'audit stale/never-logged-in accounts' -ScriptBlock {
        $now = Get-Date
        Get-ADUser -Filter * -Properties LastLogonDate, Enabled -ErrorAction Stop | Where-Object {
            Test-CcdcStaleAccount -Enabled $_.Enabled -SamAccountName $_.SamAccountName -LastLogonDate $_.LastLogonDate `
                -Now $now -StaleDaysThreshold $StaleDays -ExcludedNames $excludedNames
        } | ForEach-Object {
            [pscustomobject]@{
                SamAccountName = $_.SamAccountName
                LastLogonDate  = $_.LastLogonDate
            }
        }
    }
    if ($staleOutcome.Success) {
        $staleAccounts = @($staleOutcome.Value)
        if ($staleAccounts.Count -eq 0) {
            Write-CcdcLog -Level OK -Message "No stale or never-logged-in accounts found (beyond built-ins/protected)."
        } else {
            Write-CcdcLog -Level WARN -Message "$($staleAccounts.Count) account(s) enabled with no logon in $StaleDays+ day(s) or ever:"
            foreach ($a in $staleAccounts) {
                $lastLogonText = if ($a.LastLogonDate) { $a.LastLogonDate.ToString('yyyy-MM-dd') } else { 'never' }
                Write-Host "  $($a.SamAccountName) (last logon: $lastLogonText)"
            }
            $toDisable = Read-Host 'Disable any of these? Comma-separated SamAccountNames, or blank to skip'
            if ($toDisable) {
                $names = $toDisable -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                foreach ($name in $names) {
                    if (-not ($staleAccounts.SamAccountName -contains $name)) {
                        Write-CcdcLog -Level WARN -Message "'$name' wasn't in the flagged list above -- skipping it rather than disabling something not shown to you."
                        continue
                    }
                    if (-not $PSCmdlet.ShouldProcess($name, 'Disable AD account')) { continue }
                    Backup-CcdcState -Name "adhoc-ADUser-$name" -Data (Get-ADUser -Identity $name -Properties * -ErrorAction SilentlyContinue) | Out-Null
                    Invoke-CcdcSafe -Target $name -Action 'disable stale AD account' -ScriptBlock {
                        Disable-ADAccount -Identity $name -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 2. USER LAYER — documented blue-team admin account.
# ---------------------------------------------------------------------------
if (Test-CcdcAdModuleAvailable) {
    Write-CcdcLog -Level INFO -Message "-- 2. Blue-team admin account --"
    Write-Host "This account is added to Domain Admins and logged below -- it is NEVER meant to be secret from your own teammates. See docs/SECURITY.md for why." -ForegroundColor Yellow
    $blueTeamName = Read-Host 'SamAccountName for the blue-team admin account (blank to skip this step)'
    if ($blueTeamName) {
        $artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for named artifacts (anything -- just avoid an obvious "CCDC" string since this repo is public)' -Default 'Baseline'
        $domainName = Get-CcdcAnswer -Key 'DomainName' -Prompt 'Domain name (e.g. domain.local), for the account UPN' -Default ''
        $newPassword = New-CcdcRandomPassword

        if ($PSCmdlet.ShouldProcess($blueTeamName, 'Create AD user and add to Domain Admins')) {
            $createOutcome = Invoke-CcdcSafe -Target $blueTeamName -Action 'create blue-team admin account' -ScriptBlock {
                $params = @{
                    Name                  = $blueTeamName
                    SamAccountName        = $blueTeamName
                    AccountPassword       = (ConvertTo-SecureString $newPassword -AsPlainText -Force)
                    Enabled               = $true
                    PasswordNeverExpires  = $false
                    ErrorAction           = 'Stop'
                }
                if ($domainName) { $params['UserPrincipalName'] = "$blueTeamName@$domainName" }
                New-ADUser @params
                Add-ADGroupMember -Identity 'Domain Admins' -Members $blueTeamName -ErrorAction Stop
            }
            if ($createOutcome.Success) {
                Write-CcdcLog -Level OK -Message "Created '$blueTeamName' and added to Domain Admins."
                $credLog = Join-Path $session.LogRoot "ad-hardening-credentials_$($session.Stamp).csv"
                [pscustomobject]@{
                    Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Account   = $blueTeamName
                    Password  = $newPassword
                    Purpose   = 'Blue-team admin account (Domain Admins)'
                } | Export-Csv -Path $credLog -NoTypeInformation -Append
                Write-CcdcLog -Level OK -Message "Credential logged to $credLog -- share it with your team through whatever channel you'd use for any other credential."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 3-5. HOST LAYER (domain-wide policy) — one new GPO for SMB anonymous
#      access, LLMNR, NTLMv2, and SMB signing.
# ---------------------------------------------------------------------------
if ((Test-CcdcAdModuleAvailable) -and (Test-CcdcGpoModuleAvailable)) {
    Write-CcdcLog -Level INFO -Message "-- 3-5. Domain-wide policy: SMB anonymous access, LLMNR, NTLMv2, SMB signing --"

    if (-not $GpoName) {
        $artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for named artifacts (anything -- just avoid an obvious "CCDC" string since this repo is public)' -Default 'Baseline'
        $GpoName = "$artifactPrefix-Hardening-Policy"
    }

    # Table-driven: each entry is one registry-backed policy value. Kept
    # as data rather than one-off Set-GPRegistryValue calls so it's easy
    # to see the whole policy at a glance and extend later.
    $policyValues = @(
        [pscustomobject]@{ Key = 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Type = 'DWord'; Value = 0; Description = 'Disable LLMNR' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Type = 'DWord'; Value = 1; Description = 'Disable anonymous SMB enumeration' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Type = 'DWord'; Value = 1; Description = 'Disable anonymous SAM enumeration' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Type = 'DWord'; Value = 5; Description = 'NTLMv2 only (refuse LM/NTLM)' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1; Description = 'Require SMB signing (client)' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1; Description = 'Require SMB signing (server)' }
    )

    if ($PSCmdlet.ShouldProcess($GpoName, 'Create/update hardening GPO and link it')) {
        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if (-not $existingGpo) {
            $gpoOutcome = Invoke-CcdcSafe -Target $GpoName -Action 'create hardening GPO' -ScriptBlock {
                New-GPO -Name $GpoName -ErrorAction Stop
            }
        } else {
            Write-CcdcLog -Level INFO -Message "'$GpoName' already exists -- updating its registry values rather than creating a duplicate."
            $gpoOutcome = [pscustomobject]@{ Success = $true }
        }

        if ($gpoOutcome.Success) {
            $anyFailed = $false
            foreach ($pv in $policyValues) {
                $setOutcome = Invoke-CcdcSafe -Target "$($pv.Key)\$($pv.Name)" -Action "set GPO value: $($pv.Description)" -ScriptBlock {
                    Set-GPRegistryValue -Name $GpoName -Key $pv.Key -ValueName $pv.Name -Type $pv.Type -Value $pv.Value -ErrorAction Stop
                }
                if (-not $setOutcome.Success) { $anyFailed = $true }
            }
            if (-not $anyFailed) {
                Write-CcdcLog -Level OK -Message "All $($policyValues.Count) policy value(s) set on '$GpoName'."
            }

            $linkTarget = if ($TargetOU) { $TargetOU } else { (Get-ADDomain -ErrorAction SilentlyContinue).DistinguishedName }
            if ($linkTarget) {
                $linkOutcome = Invoke-CcdcSafe -Target $linkTarget -Action "link '$GpoName'" -ScriptBlock {
                    if (-not (Get-GPInheritance -Target $linkTarget -ErrorAction SilentlyContinue | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })) {
                        New-GPLink -Name $GpoName -Target $linkTarget -ErrorAction Stop | Out-Null
                    }
                }
                if ($linkOutcome.Success) {
                    Write-CcdcLog -Level OK -Message "'$GpoName' linked to $linkTarget. Changes apply on the next Group Policy refresh (gpupdate /force on a host, or wait for the normal refresh interval)."
                }
            } else {
                Write-CcdcLog -Level WARN -Message "Couldn't resolve a link target -- the GPO was created/updated but is NOT linked anywhere yet. Link it by hand (or pass -TargetOU) once you've confirmed where."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. USER LAYER — domain password policy.
# ---------------------------------------------------------------------------
if (Test-CcdcAdModuleAvailable) {
    Write-CcdcLog -Level INFO -Message "-- 6. Domain password policy --"
    if (Get-Command -Name Set-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue) {
        $currentPolicyOutcome = Invoke-CcdcSafe -Target 'domain password policy' -Action 'read current policy before changing it' -ScriptBlock {
            Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        }
        if ($currentPolicyOutcome.Success) {
            Backup-CcdcState -Name 'domain-password-policy-before' -Data $currentPolicyOutcome.Value | Out-Null
        }

        Write-Host "About to set: min length $MinPasswordLength, history $PasswordHistoryCount, lockout threshold $LockoutThreshold, lockout duration $LockoutDurationMinutes min. These are reasonable defaults, NOT a rules-packet requirement -- override the parameters if your packet specifies exact numbers." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess('domain default password policy', 'Set length/history/lockout policy')) {
            Invoke-CcdcSafe -Target 'domain password policy' -Action 'set domain password policy' -ScriptBlock {
                Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain -ErrorAction Stop).DistinguishedName `
                    -MinPasswordLength $MinPasswordLength `
                    -PasswordHistoryCount $PasswordHistoryCount `
                    -LockoutThreshold $LockoutThreshold `
                    -LockoutDuration ([timespan]::FromMinutes($LockoutDurationMinutes)) `
                    -LockoutObservationWindow ([timespan]::FromMinutes($LockoutDurationMinutes)) `
                    -ComplexityEnabled $true `
                    -ErrorAction Stop
            } | Out-Null
        }
    } else {
        Write-CcdcLog -Level INFO -Message "Set-ADDefaultDomainPasswordPolicy not available -- skipping domain password policy step."
    }
}

} finally {
    Show-CcdcSummary
    Stop-CcdcSession
}
