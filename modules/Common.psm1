#Requires -Version 5.1
<#
.SYNOPSIS
    Shared safety scaffolding for every module in the toolkit.

.DESCRIPTION
    Every module in this toolkit imports this file first. It exists so that
    "back up before you touch anything," "never crash the whole run because
    one host failed," and "tell me in plain English what just happened" are
    handled in ONE place instead of copy-pasted (and drifting) into every
    script. If you only ever read one file in this repo to understand how
    the whole thing thinks, read this one.

    Design rules baked in here:
      1. Nothing destructive runs without a backup of the prior state landing
         in logs/backups/<session>/ first.
      2. Every action is wrapped so one failure (unreachable host, missing
         AD module, whatever) logs plainly and lets the rest of the run
         continue — it does not abort the whole script.
      3. Every session gets a full plain-text transcript, so if something
         goes wrong you have a paper trail, and so you have raw material for
         an incident report or an inject response later without trying to
         reconstruct what you did from memory.
      4. Nothing in this file (or anything that uses it) hardcodes an
         environment-specific value. Answers come from -Parameters, from the
         gitignored local answer file, or from an interactive prompt — in
         that order.
#>

$script:CcdcResults = New-Object System.Collections.Generic.List[object]
$script:CcdcAnswers = $null
$script:CcdcSession = $null

# The pure helper functions (service-to-port tables, scored-service host
# matching, new-item diffing, CIDR math, argument builders, ...) live in
# their own file so tests can exercise them directly -- functions defined
# inside a module's script body can't be loaded without running the whole
# script. Dot-sourced here so every module still only has to import this
# one file.
$ccdcLogicPath = Join-Path $PSScriptRoot 'CcdcLogic.ps1'
if (-not (Test-Path -LiteralPath $ccdcLogicPath)) {
    throw "CcdcLogic.ps1 is missing from $PSScriptRoot -- the copy of the repo on this box is incomplete. Re-clone it (or re-extract the ZIP) before running anything."
}
. $ccdcLogicPath

function Start-CcdcSession {
    <#
    .SYNOPSIS
        Call this once at the top of any module you run standalone (the
        menu in Invoke-CCDCToolkit.ps1 calls it for you automatically).
        Sets up the timestamped log/backup folders and starts a transcript.
    #>
    [CmdletBinding()]
    param(
        [string]$RootPath = (Split-Path -Parent $PSScriptRoot)
    )

    if ($script:CcdcSession) { return $script:CcdcSession }

    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $logRoot = Join-Path $RootPath 'logs'
    $backupRoot = Join-Path (Join-Path $logRoot 'backups') $stamp
    $transcriptPath = Join-Path $logRoot "session_$stamp.log"

    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    # Restrict logs\ (transcripts, backups, credential CSVs, captures,
    # recon output -- everything sensitive this toolkit produces lives
    # under here) to Administrators/SYSTEM/the current user. Best-effort,
    # every session start, harmless if run twice or if it can't apply.
    Protect-CcdcSensitiveFolder -Path $logRoot

    try {
        Start-Transcript -Path $transcriptPath -Append | Out-Null
    } catch {
        Write-Warning "Could not start transcript at $transcriptPath (already running from a parent script is normal and fine)."
    }

    $script:CcdcSession = [pscustomobject]@{
        Stamp          = $stamp
        RootPath       = $RootPath
        LogRoot        = $logRoot
        BackupRoot     = $backupRoot
        TranscriptPath = $transcriptPath
    }

    Write-CcdcLog -Level INFO -Message "Session started. Backups for this run go to: $backupRoot"
    return $script:CcdcSession
}

function Stop-CcdcSession {
    [CmdletBinding()]
    param()
    try { Stop-Transcript | Out-Null } catch { }
}

function Write-CcdcLog {
    <#
    .SYNOPSIS
        The ONE function every module should use to print status. Plain
        English, timestamped, color-coded, and it's already going into the
        transcript because Start-CcdcSession is running.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'ACTION')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $ts = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'OK'     { 'Green' }
        'WARN'   { 'Yellow' }
        'ERROR'  { 'Red' }
        'ACTION' { 'Cyan' }
        default  { 'Gray' }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

function Backup-CcdcState {
    <#
    .SYNOPSIS
        Snapshot "the way things were" before you change them. Call this
        BEFORE any destructive action. Never skip this to save time — the
        whole point of this toolkit is that you never have to wonder
        "what did this overwrite?"

    .PARAMETER Name
        Short label for what you're backing up, e.g. "local-firewall-rules"
        or "AD-user-list". Used in the output filename.

    .PARAMETER Data
        The object(s) to save. Anything Export-Clixml can serialize — the
        actual live object (Get-NetFirewallRule output, Get-ADUser output,
        etc.), not a string you formatted yourself. Clixml round-trips
        cleanly if you ever need to restore or diff against it later.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Data
    )

    $session = Start-CcdcSession
    $safeName = ($Name -replace '[^a-zA-Z0-9_\-]', '_')
    $path = Join-Path $session.BackupRoot "$safeName.xml"

    try {
        $Data | Export-Clixml -Path $path -Depth 5
        Write-CcdcLog -Level OK -Message "Backed up '$Name' -> $path"
        return $path
    } catch {
        Write-CcdcLog -Level ERROR -Message "FAILED to back up '$Name': $($_.Exception.Message). Stopping rather than making an unbacked-up change — fix this before re-running."
        throw
    }
}

function Invoke-CcdcSafe {
    <#
    .SYNOPSIS
        Wrap one unit of work (usually "do this to one host/account/rule")
        so a single failure gets logged in plain English and recorded, but
        does NOT stop the rest of the run. Call Show-CcdcSummary at the end
        to see the scoreboard.

    .PARAMETER Target
        What this action is operating on (hostname, account name, rule
        name...) — shows up in the summary so you know exactly what failed.

    .PARAMETER Action
        A short human description of what's being attempted, e.g.
        "reset local admin password".

    .PARAMETER ScriptBlock
        The actual work. Anything it throws is caught here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [string]$Action,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock
    )

    Write-CcdcLog -Level ACTION -Message "$Action -> $Target"
    try {
        $result = & $ScriptBlock
        $outcome = [pscustomobject]@{
            Target = $Target; Action = $Action; Success = $true; Detail = 'OK'; Value = $result
        }
        $script:CcdcResults.Add($outcome)
        Write-CcdcLog -Level OK -Message "$Action -> $Target : succeeded"
        # Wrapped in a single object on purpose: if $result is itself a
        # collection (e.g. an array of AD computer objects), returning it
        # bare here would let PowerShell unroll it onto the pipeline one
        # element at a time, which silently breaks any caller doing
        # `Invoke-CcdcSafe ... | ForEach-Object { $x = @($_) }` — that
        # pattern would end up keeping only the LAST element. Callers use
        # $outcome.Success and $outcome.Value instead.
        return $outcome
    } catch {
        $detail = $_.Exception.Message
        $outcome = [pscustomobject]@{
            Target = $Target; Action = $Action; Success = $false; Detail = $detail; Value = $null
        }
        $script:CcdcResults.Add($outcome)
        Write-CcdcLog -Level ERROR -Message "$Action -> $Target : FAILED - $detail"
        return $outcome
    }
}

function ConvertFrom-CcdcSecureStringPlain {
    <#
    .SYNOPSIS
        Plaintext from a SecureString, for the one legitimate case of
        needing the real value -- handing a password to something that
        has no SecureString-aware API of its own (an external process's
        stdin, here). Zeroes the unmanaged buffer it briefly allocates.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][securestring]$Secure)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
}

function New-CcdcHardeningGpo {
    <#
    .SYNOPSIS
        Create (or update) the toolkit's hardening GPO and link it -- the
        exact same policy values Invoke-ADHardening.ps1 sets, as the one
        shared function both that module and the admin console's UI call.
        Kept here, not in CcdcLogic.ps1, because this is a real mutation
        (New-GPO/Set-GPRegistryValue/New-GPLink), not a pure verdict -- the
        same reason Invoke-CcdcSafe/Backup-CcdcState live in this module
        rather than CcdcLogic.ps1.

    .PARAMETER GpoName
        Name for the hardening GPO. Created if it doesn't exist; if it
        does, its registry values are updated rather than duplicating it.

    .PARAMETER TargetOU
        Distinguished name of the OU (or the domain root) to link the GPO
        to. Optional -- if blank, the GPO is still created/updated but
        left unlinked, with a WARN saying so (the caller resolves its own
        default, e.g. the domain root; this function doesn't guess).

    .DESCRIPTION
        Disables LLMNR, anonymous SMB/SAM enumeration, and requires
        NTLMv2 + SMB signing -- the same six registry values
        Invoke-ADHardening.ps1 has always set. Edit the $policyValues
        table here, not in that module, if the policy itself ever changes:
        this is the one place it's defined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [string]$TargetOU
    )

    $policyValues = @(
        [pscustomobject]@{ Key = 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Type = 'DWord'; Value = 0; Description = 'Disable LLMNR' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Type = 'DWord'; Value = 1; Description = 'Disable anonymous SMB enumeration' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Type = 'DWord'; Value = 1; Description = 'Disable anonymous SAM enumeration' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; Type = 'DWord'; Value = 5; Description = 'NTLMv2 only (refuse LM/NTLM)' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1; Description = 'Require SMB signing (client)' }
        [pscustomobject]@{ Key = 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1; Description = 'Require SMB signing (server)' }
    )

    $result = [pscustomobject]@{ Success = $false; GpoName = $GpoName; LinkedTo = $null; PolicyValuesSet = 0; Message = $null }
    if (-not $PSCmdlet.ShouldProcess($GpoName, 'Create/update hardening GPO and link it')) { return $result }

    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $existingGpo) {
        $gpoOutcome = Invoke-CcdcSafe -Target $GpoName -Action 'create hardening GPO' -ScriptBlock {
            New-GPO -Name $GpoName -ErrorAction Stop
        }
    } else {
        Write-CcdcLog -Level INFO -Message "'$GpoName' already exists -- updating its registry values rather than creating a duplicate."
        $gpoOutcome = [pscustomobject]@{ Success = $true }
    }
    if (-not $gpoOutcome.Success) { $result.Message = 'Could not create the GPO.'; return $result }

    $anyFailed = $false
    foreach ($pv in $policyValues) {
        $setOutcome = Invoke-CcdcSafe -Target "$($pv.Key)\$($pv.Name)" -Action "set GPO value: $($pv.Description)" -ScriptBlock {
            Set-GPRegistryValue -Name $GpoName -Key $pv.Key -ValueName $pv.Name -Type $pv.Type -Value $pv.Value -ErrorAction Stop
        }
        if ($setOutcome.Success) { $result.PolicyValuesSet++ } else { $anyFailed = $true }
    }
    if (-not $anyFailed) { Write-CcdcLog -Level OK -Message "All $($policyValues.Count) policy value(s) set on '$GpoName'." }

    if ($TargetOU) {
        $linkOutcome = Invoke-CcdcSafe -Target $TargetOU -Action "link '$GpoName'" -ScriptBlock {
            if (-not (Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })) {
                New-GPLink -Name $GpoName -Target $TargetOU -ErrorAction Stop | Out-Null
            }
        }
        if ($linkOutcome.Success) {
            $result.LinkedTo = $TargetOU
            Write-CcdcLog -Level OK -Message "'$GpoName' linked to $TargetOU. Changes apply on the next Group Policy refresh (gpupdate /force on a host, or wait for the normal refresh interval)."
        }
    } else {
        Write-CcdcLog -Level WARN -Message "No link target given -- '$GpoName' was created/updated but is NOT linked anywhere yet. Link it by hand (or pass -TargetOU) once you've confirmed where."
        $linkOutcome = [pscustomobject]@{ Success = $true }
    }

    $result.Success = (-not $anyFailed) -and $linkOutcome.Success
    $result.Message = if (-not $result.Success) { "'$GpoName' created/updated, but something failed -- see the log above." }
        elseif ($result.LinkedTo) { "'$GpoName' created/updated and linked to $TargetOU." }
        else { "'$GpoName' created/updated. Not linked anywhere yet." }
    return $result
}

function Show-CcdcSummary {
    <#
    .SYNOPSIS
        Plain-English pass/fail scoreboard for everything run through
        Invoke-CcdcSafe since the module started (or since the last call to
        this function, since it clears the list after printing).
    #>
    [CmdletBinding()]
    param()

    if ($script:CcdcResults.Count -eq 0) {
        Write-CcdcLog -Level INFO -Message "Nothing to summarize yet."
        return
    }

    $ok = @($script:CcdcResults | Where-Object Success)
    $bad = @($script:CcdcResults | Where-Object { -not $_.Success })

    Write-Host ""
    Write-Host "==================== SUMMARY ====================" -ForegroundColor White
    Write-Host " Succeeded: $($ok.Count)   Failed: $($bad.Count)   Total: $($script:CcdcResults.Count)" -ForegroundColor White
    if ($bad.Count -gt 0) {
        Write-Host " --- Failures (fix these first) ---" -ForegroundColor Yellow
        foreach ($f in $bad) {
            Write-Host "   [$($f.Target)] $($f.Action): $($f.Detail)" -ForegroundColor Red
        }
    }
    Write-Host "===================================================" -ForegroundColor White
    Write-Host ""

    $script:CcdcResults.Clear()
}

function Import-CcdcAnswers {
    <#
    .SYNOPSIS
        Loads config/answers.local.psd1 if it exists (it's gitignored —
        this is the file you fill in from your printed prep sheet right
        before you run anything, so you're not hand-typing the same 20
        values into every module). Safe to call repeatedly; only reads
        the file once per session.
    #>
    [CmdletBinding()]
    param(
        [string]$RootPath = (Split-Path -Parent $PSScriptRoot)
    )

    if ($null -ne $script:CcdcAnswers) { return $script:CcdcAnswers }

    $path = Join-Path (Join-Path $RootPath 'config') 'answers.local.psd1'
    if (Test-Path $path) {
        try {
            $script:CcdcAnswers = Import-PowerShellDataFile -Path $path
            Write-CcdcLog -Level OK -Message "Loaded local answer file: $path"
        } catch {
            Write-CcdcLog -Level WARN -Message "Found $path but couldn't parse it ($($_.Exception.Message)) — falling back to prompts."
            $script:CcdcAnswers = @{}
        }
    } else {
        $script:CcdcAnswers = @{}
    }
    return $script:CcdcAnswers
}

function Get-CcdcAnswer {
    <#
    .SYNOPSIS
        The single source of truth for "where does this value come from."
        Order: explicit -Value param > local answer file > interactive
        prompt. Never a hardcoded default baked into a script.

    .PARAMETER Key
        Name to look up in config/answers.local.psd1 (e.g. 'DomainName').

    .PARAMETER Prompt
        What to show the human if it has to ask.

    .PARAMETER Value
        Pass a value straight through (e.g. from a -Parameter on the
        calling script) to skip the file/prompt entirely.

    .PARAMETER AsSecureString
        Mask input at the prompt (for anything password-shaped).

    .PARAMETER Default
        Optional fallback shown in the prompt; press Enter to accept it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string]$Prompt,
        [string]$Value,
        [switch]$AsSecureString,
        [string]$Default
    )

    if ($Value) { return $Value }

    $answers = Import-CcdcAnswers
    if ($answers.ContainsKey($Key) -and $answers[$Key]) {
        Write-CcdcLog -Level INFO -Message "Using '$Key' from local answer file."
        return $answers[$Key]
    }

    $promptText = if ($Default) { "$Prompt [$Default]" } else { $Prompt }

    if ($AsSecureString) {
        $secure = Read-Host -Prompt $promptText -AsSecureString
        return $secure
    }

    $entered = Read-Host -Prompt $promptText
    if (-not $entered -and $Default) { return $Default }
    return $entered
}

function Read-CcdcInput {
    <#
    .SYNOPSIS
        Read-Host, trimmed and null-safe -- for fresh, one-off operational
        input (which account, which service, a yes/no). Read-Host normally
        returns an empty string on a blank Enter, but returns $null if
        stdin runs out (piped or non-interactive input); calling .Trim() on
        that directly would crash the caller. A stray leading/trailing
        space from typing under pressure would also otherwise turn "web01 "
        into a failed lookup.

        Never use this for an EXISTING secret: Start-Transcript captures
        plain Read-Host input verbatim (see docs/SECURITY.md). Use
        Read-Host -AsSecureString for those.
    #>
    [CmdletBinding()]
    param([string]$Prompt = '')
    # A caller that has already printed its own prompt text (a
    # "... Type YES to continue: " line written with -NoNewline) passes no
    # -Prompt, so Read-Host doesn't print a second one after it.
    $value = if ($Prompt) { Read-Host -Prompt $Prompt } else { Read-Host }
    if ($null -eq $value) { return '' }
    return $value.Trim()
}

function Show-CcdcTargetContext {
    <#
    .SYNOPSIS
        One compact "you are about to change THIS" block: host, domain,
        whether it's a domain controller, who you're running as, whether
        the session is elevated, how old the inventory is, and whether an
        answer file / protected-accounts list is loaded. Shown before the
        modules that change real state, so "I thought I was on the other
        box" gets caught before the YES, not after.

        Purely informational; every lookup is best-effort and falls back
        to "unknown" rather than failing.

    .OUTPUTS
        The same facts as an object (handy for tests and for the future UI).
    #>
    [CmdletBinding()]
    param(
        [string]$RootPath = (Split-Path -Parent $PSScriptRoot),
        # Set by the main menu, which shows this block BEFORE its "type YES"
        # prompt (where it can actually stop a wrong-box mistake); the module
        # it then launches shouldn't print the same thing a second time.
        [switch]$SkipIfShownByMenu
    )

    if ($SkipIfShownByMenu -and $env:CCDC_TARGET_SHOWN -eq '1') { return $null }

    $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'unknown' }
    $domain = 'unknown'
    $role = 'unknown'
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domain = if ($cs.PartOfDomain) { $cs.Domain } else { "workgroup ($($cs.Domain))" }
        $role = switch ([int]$cs.DomainRole) {
            0 { 'standalone workstation' } 1 { 'member workstation' } 2 { 'standalone server' }
            3 { 'member server' } 4 { 'domain controller (backup)' } 5 { 'DOMAIN CONTROLLER' }
            default { 'unknown' }
        }
    } catch {
        if ($env:USERDNSDOMAIN) { $domain = $env:USERDNSDOMAIN } elseif ($env:USERDOMAIN) { $domain = $env:USERDOMAIN }
    }
    $userName = if ($env:USERDOMAIN -and $env:USERNAME) { "$($env:USERDOMAIN)\$($env:USERNAME)" } elseif ($env:USERNAME) { $env:USERNAME } else { 'unknown' }
    $elevated = Test-CcdcElevated

    $inventoryText = 'none yet (run discovery first)'
    $inventoryAge = $null
    try {
        $invPath = Join-Path (Join-Path $RootPath 'logs') 'inventory-latest.json'
        if (Test-Path -LiteralPath $invPath) {
            $inv = Get-Content -LiteralPath $invPath -Raw | ConvertFrom-Json
            $inventoryAge = [math]::Round(((Get-Date) - [datetime]$inv.Timestamp).TotalMinutes, 0)
            $inventoryText = "$inventoryAge min old"
        }
    } catch { $inventoryText = 'unreadable' }

    $answers = Import-CcdcAnswers -RootPath $RootPath
    $answerText = if ($answers.Count -gt 0) { 'loaded' } else { 'none (you will be prompted)' }
    $protectedCount = 0
    if ($answers.ContainsKey('ProtectedAccounts') -and $answers['ProtectedAccounts']) {
        $protectedCount = @($answers['ProtectedAccounts'] -split ',' | Where-Object { $_.Trim() }).Count
    }

    Write-Host ""
    Write-Host "---- TARGET CHECK: make sure this is the box you mean to change ----" -ForegroundColor Cyan
    Write-Host "  Host:        $hostName   ($role)"
    Write-Host "  Domain:      $domain"
    Write-Host "  Running as:  $userName   (elevated: $(if ($null -eq $elevated) { 'unknown' } else { $elevated }))"
    Write-Host "  Inventory:   $inventoryText"
    Write-Host "  Answer file: $answerText   (ProtectedAccounts: $protectedCount)"
    Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    return [pscustomobject]@{
        Host                    = $hostName
        Domain                  = $domain
        Role                    = $role
        RunningAs               = $userName
        Elevated                = $elevated
        InventoryAgeMinutes     = $inventoryAge
        AnswerFileLoaded        = ($answers.Count -gt 0)
        ProtectedAccountCount   = $protectedCount
    }
}

function New-CcdcRandomPassword {
    <#
    .SYNOPSIS
        Generates a password that satisfies typical AD complexity rules
        (upper/lower/digit/symbol, no ambiguous look-alike characters so
        you can actually read it off a screen or handwritten sheet under
        time pressure).
    #>
    [CmdletBinding()]
    param(
        [int]$Length = 20
    )

    $upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ'   # no I, O
    $lower  = 'abcdefghijkmnpqrstuvwxyz'   # no l, o
    $digits = '23456789'                  # no 0, 1
    # No '=' or '"': both generators feeding this get used in contexts
    # that are themselves KEY=VALUE command-line syntax (MSI properties
    # in Install-SplunkForwarder.ps1 being the concrete example) — a
    # generated value containing one of those characters could silently
    # mis-parse there. One fewer symbol costs negligible entropy against
    # a large upper/lower/digit pool; it's not worth the risk.
    $symbol = '!@#%^&*-_+'

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    function Get-RandChar([string]$set) {
        $bytes = New-Object byte[] 1
        $rng.GetBytes($bytes)
        return $set[$bytes[0] % $set.Length]
    }

    $chars = [System.Collections.Generic.List[char]]::new()
    $chars.Add((Get-RandChar $upper))
    $chars.Add((Get-RandChar $lower))
    $chars.Add((Get-RandChar $digits))
    $chars.Add((Get-RandChar $symbol))
    $all = $upper + $lower + $digits + $symbol
    while ($chars.Count -lt $Length) {
        $chars.Add((Get-RandChar $all))
    }

    # Shuffle so the guaranteed character classes aren't always in the same position
    $shuffled = $chars | Sort-Object { Get-Random }
    return -join $shuffled
}

function Test-CcdcElevated {
    <#
    .SYNOPSIS
        Is this PowerShell session running elevated (Run as Administrator)?
        Returns $true/$false on Windows, $null if that can't be determined
        here (non-Windows — this toolkit's pure functions get tested on
        Linux — or the needed .NET types aren't available for some other
        reason). Callers should treat $null as "unknown, don't warn."

        Almost everything destructive in this toolkit (firewall rules, AD
        accounts, services, scheduled tasks, GPOs, Npcap-based packet
        capture) needs elevation to actually work. Finding that out from a
        cryptic access-denied error 10 minutes into a run is a worse
        experience than finding out before anything starts.
    #>
    [CmdletBinding()]
    param()
    if (-not ('System.Security.Principal.WindowsIdentity' -as [type])) { return $null }
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $null
    }
}

function Assert-CcdcElevated {
    <#
    .SYNOPSIS
        Call this near the top of any module that needs elevation to do
        real work. Logs one clear WARN up front if the session isn't
        elevated (or can't tell) -- it does NOT stop the module, because
        some actions inside a module might still work without it (a
        -WhatIf preview, a read-only sub-check), and this toolkit prefers
        "warn and let the operator decide" over a hard block wherever the
        outcome genuinely depends on what's attempted. Silent if elevated,
        or if elevation can't be determined on this platform.

    .PARAMETER Because
        Short phrase completing "...because <Because>", e.g. "it creates
        firewall rules and a scheduled task".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Because)

    $elevated = Test-CcdcElevated
    if ($elevated -eq $false) {
        Write-CcdcLog -Level WARN -Message "This PowerShell session doesn't look elevated (not Run as Administrator) -- $Because will likely fail partway through. Close this and re-launch PowerShell elevated before continuing."
    }
}

function Protect-CcdcSensitiveFolder {
    <#
    .SYNOPSIS
        Best-effort: restrict a folder's NTFS permissions to
        Administrators, SYSTEM, and the current user, so credential CSVs,
        state backups, session transcripts, and the local answer file
        aren't readable by every account on a shared/multi-user box. Uses
        well-known SIDs (not localized group names like "Administrators",
        which differ on non-English Windows builds) so this works the
        same everywhere.

        Non-fatal if it can't (logs a WARN and moves on) -- and worth
        being honest about what this is and isn't: on a box where red
        team already has Administrator or SYSTEM, this is not a real
        security boundary, since that's exactly the access level being
        granted here too. It's still worth doing for free: it keeps this
        toolkit's own sensitive output away from a LOWER-privileged
        account or process on a shared box, which is a real, if narrower,
        threat this can actually stop.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Get-Command -Name Set-Acl -ErrorAction SilentlyContinue)) { return }
    if (-not (Test-Path -Path $Path)) { return }

    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        # BUILTIN\Administrators, SYSTEM -- well-known SIDs, not names.
        foreach ($sid in @('S-1-5-32-544', 'S-1-5-18')) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($currentUser -and $currentUser.Value -notin @('S-1-5-32-544', 'S-1-5-18')) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $currentUser, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
    } catch {
        Write-CcdcLog -Level WARN -Message "Couldn't restrict permissions on $Path ($($_.Exception.Message)) -- its contents (credentials, backups, transcripts) are still sensitive regardless; treat the box's normal file-access controls as the only thing protecting it for now."
    }
}

function Get-CcdcAdministratorsMember {
    <#
    .SYNOPSIS
        Members of the built-in Administrators group, on any Windows box
        including a domain controller.

    .DESCRIPTION
        Get-LocalGroupMember -Group 'Administrators' is the obvious call
        and it FAILS ON A DOMAIN CONTROLLER. Observed on Server 2019 in
        the practice lab:

            Group Administrators was not found.

        which reads like the group is missing when it plainly is not. A
        DC has no local SAM database -- the built-in groups live in the
        directory instead -- and the LocalAccounts module does not see
        them. That one call took down the threat hunt's local-admin check
        on the DC, and the same call sits in the config baseline and the
        dashboard.

        So: on a DC, ask Active Directory for the BUILTIN Administrators
        group. Everywhere else, use the local cmdlet. If both are
        unavailable or fail, fall back to parsing `net localgroup`, which
        has worked on every Windows since NT and needs no module at all.

    .OUTPUTS
        An object with .Success, .Members (string[]), .Source (which route
        produced the answer) and .Message.
    #>
    [CmdletBinding()]
    param()

    $isDc = $false
    try {
        # DomainRole 4 = backup DC, 5 = primary DC.
        $role = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
        $isDc = ($role -eq 4 -or $role -eq 5)
    } catch {
        $isDc = [bool](Get-Service -Name NTDS -ErrorAction SilentlyContinue)
    }

    if ($isDc -and (Get-Command -Name Get-ADGroupMember -ErrorAction SilentlyContinue)) {
        try {
            $members = @(Get-ADGroupMember -Identity 'Administrators' -ErrorAction Stop | ForEach-Object { "$($_.SamAccountName)" })
            return [pscustomobject]@{ Success = $true; Members = $members; Source = 'Active Directory (BUILTIN\Administrators)'; Message = '' }
        } catch {
            # Fall through to net localgroup rather than giving up: a
            # nested or foreign-security-principal member can make
            # Get-ADGroupMember throw even when the group is readable.
            Write-CcdcLog -Level INFO -Message "Get-ADGroupMember on BUILTIN\Administrators failed ($($_.Exception.Message)); falling back to 'net localgroup'."
        }
    } elseif (-not $isDc -and (Get-Command -Name Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
        try {
            $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { "$($_.Name)" })
            return [pscustomobject]@{ Success = $true; Members = $members; Source = 'local Administrators group'; Message = '' }
        } catch {
            Write-CcdcLog -Level INFO -Message "Get-LocalGroupMember failed ($($_.Exception.Message)); falling back to 'net localgroup'."
        }
    }

    try {
        $raw = @(& net.exe localgroup Administrators 2>&1 | ForEach-Object { "$_" })
        $members = @(ConvertFrom-CcdcNetLocalGroupOutput -Lines $raw)
        if ($members.Count -gt 0) {
            return [pscustomobject]@{ Success = $true; Members = $members; Source = 'net localgroup Administrators'; Message = '' }
        }
        return [pscustomobject]@{ Success = $false; Members = @(); Source = 'net localgroup Administrators'; Message = 'net localgroup returned no members.' }
    } catch {
        return [pscustomobject]@{ Success = $false; Members = @(); Source = 'none'; Message = $_.Exception.Message }
    }
}

function Get-CcdcScoredServiceList {
    <#
    .SYNOPSIS
        The ScoredServices entries for this environment, preferring the
        inventory produced by Get-EnvironmentInventory.ps1 and falling
        back to the answer file.

    .DESCRIPTION
        Exists because the two places that value can live had no bridge
        between them, and the gap failed silently in the worst possible
        way. config\answers.local.psd1 has a ScoredServices key, and the
        practice lab writes one automatically -- but only
        Get-EnvironmentInventory.ps1 ever read it, copying it into
        logs\inventory-latest.json. Every consumer (the firewall
        baseline, network recon, the dashboard's scored-service rows)
        read only the JSON.

        So running the firewall baseline without running discovery first
        produced a box with management rules and no scored-service rules
        at all, reporting "no scored services matched" as if the answer
        file were empty when the values were sitting right there. Nothing
        errored; the protection simply was not applied. That is exactly
        the kind of quiet no-op that makes a tool look like it did
        nothing.

        The inventory still wins when it exists: it is the fresher of the
        two and may have been edited after discovery ran.

    .OUTPUTS
        An array of "HOST:Service" strings; empty if neither source has
        any.
    #>
    [CmdletBinding()]
    param(
        [string]$RootPath = (Split-Path -Parent $PSScriptRoot),
        $Inventory
    )

    if ($Inventory -and $Inventory.ScoredServices -and @($Inventory.ScoredServices).Count -gt 0) {
        return @($Inventory.ScoredServices)
    }

    $answers = Import-CcdcAnswers -RootPath $RootPath
    if ($answers -and $answers.ContainsKey('ScoredServices') -and $answers['ScoredServices']) {
        $fromAnswers = @([string]$answers['ScoredServices'] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($fromAnswers.Count -gt 0) {
            Write-CcdcLog -Level INFO -Message "No scored services in the inventory, so using the ScoredServices list from your answer file instead ($($fromAnswers.Count) entr(y/ies)). Running discovery first is still worth doing -- it records much more than this."
            return $fromAnswers
        }
    }
    return @()
}

function Get-CcdcInventory {
    <#
    .SYNOPSIS
        Loads the inventory-latest.json produced by
        Get-EnvironmentInventory.ps1, if it exists. Every other module
        should call this instead of re-discovering hosts/accounts itself.

    .OUTPUTS
        The inventory as a PSCustomObject, or $null if no inventory has
        been generated yet (caller should fall back to prompting).
    #>
    [CmdletBinding()]
    param(
        [string]$RootPath = (Split-Path -Parent $PSScriptRoot)
    )

    $path = Join-Path (Join-Path $RootPath 'logs') 'inventory-latest.json'
    if (-not (Test-Path $path)) {
        Write-CcdcLog -Level WARN -Message "No inventory-latest.json found. Run Get-EnvironmentInventory.ps1 first for best results — continuing with manual entry only."
        return $null
    }

    try {
        $inv = Get-Content -Path $path -Raw | ConvertFrom-Json
        $ageMinutes = [math]::Round(((Get-Date) - [datetime]$inv.Timestamp).TotalMinutes, 1)
        if ($ageMinutes -gt 120) {
            Write-CcdcLog -Level WARN -Message "Inventory is $ageMinutes minutes old ($($inv.Timestamp)). If hosts/accounts have changed since (reverts, new boxes), re-run Get-EnvironmentInventory.ps1 first."
        } else {
            Write-CcdcLog -Level OK -Message "Loaded inventory from $($inv.Timestamp) ($ageMinutes min old)."
        }
        return $inv
    } catch {
        Write-CcdcLog -Level ERROR -Message "Found $path but couldn't parse it: $($_.Exception.Message). Ignoring it — you'll need to enter things manually this run."
        return $null
    }
}

Export-ModuleMember -Function `
    Start-CcdcSession, Stop-CcdcSession, Write-CcdcLog, Backup-CcdcState, `
    Invoke-CcdcSafe, Show-CcdcSummary, New-CcdcHardeningGpo, ConvertFrom-CcdcSecureStringPlain, Import-CcdcAnswers, Get-CcdcAnswer, `
    New-CcdcRandomPassword, Get-CcdcInventory, Get-CcdcScoredServiceList, `
    Get-CcdcAdministratorsMember, Test-CcdcElevated, `
    Assert-CcdcElevated, Protect-CcdcSensitiveFolder, `
    Read-CcdcInput, Show-CcdcTargetContext, `
    Resolve-CcdcServicePorts, Get-CcdcServiceRuleSpecs, Get-CcdcScoredServicesForHost, `
    Test-CcdcValidPort, ConvertFrom-CcdcPortSpec, Test-CcdcValidIPv4, `
    Test-CcdcValidFileSystemRight, Get-CcdcCidrAddresses, Invoke-CcdcPingSweep, `
    Get-CcdcNewItems, Get-CcdcServiceExePath, Test-CcdcSuspiciousPath, `
    Test-CcdcStaleAccount, Get-CcdcLogLinesNearTime, Get-CcdcBackupFoldersNearTime, `
    Get-CcdcCaptureFilesNearTime, Test-CcdcAnyNonBlank, Get-CcdcNmapArgs, `
    Test-CcdcUnexpectedOpenPort, Get-CcdcTsharkArgs, `
    Test-CcdcExecutableWebExtension, Get-CcdcWebShellFlags, `
    Test-CcdcRiskyFtpAuthorization, Get-CcdcIisAnswerSuggestion, `
    New-CcdcHealthCard, Get-CcdcFirewallVerdict, Get-CcdcServiceVerdict, `
    Get-CcdcFailedLogonVerdict, Get-CcdcC2PortVerdict, Get-CcdcProtectedAccountsVerdict, `
    Get-CcdcInventoryVerdict, Get-CcdcScoredServiceStatus, Get-CcdcOverallHealth, `
    Get-CcdcNameTamperFlag, Compare-CcdcBaselineSet, Get-CcdcBaselineAreaVerdict, `
    Get-CcdcPatchStatusVerdict, ConvertTo-CcdcHtmlText, Get-CcdcIncidentReportGap, `
    ConvertFrom-CcdcNetLocalGroupOutput, Get-CcdcModuleLaunchArgs, `
    Test-CcdcExposureApplies, Test-CcdcUnquotedServicePath, Test-CcdcRotatableAccountName, `
    Select-CcdcCredentialTarget, `
    Get-CcdcLmCompatibilityVerdict, Get-CcdcMachineAccountQuotaVerdict, `
    Get-CcdcExposureSummary, Get-CcdcDnsZoneTransferVerdict, `
    Get-CcdcDnsDynamicUpdateVerdict, Get-CcdcSuspiciousDnsRecordFlag, Get-CcdcDnsRecordDataText
