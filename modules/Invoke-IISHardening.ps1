#Requires -Version 5.1
<#
.SYNOPSIS
    Audits and hardens IIS -- the web server and the FTP server. Finds the
    files under a web root that a human should look at (web shells), tells you
    exactly which ports to put in your answer file (including FTP's passive
    range, the one everyone misses), and turns off the handful of IIS settings
    that give away information or hand out directory listings.

.DESCRIPTION
    Written for the Windows Admin who has a web server and an FTP server in
    scope. It runs in two halves, and the read-only half always runs first:

    READ-ONLY (always, even with -WhatIf, even with -ReportOnly):
      1. What is actually here -- sites, bindings, physical paths, application
         pools and the identities they run as, FTP sites, and the FTP passive
         data-port range.
      2. The exact lines to paste into config\answers.local.psd1 so
         Invoke-FirewallBaseline.ps1 opens the right ports for this box. FTP's
         passive range is included, because a firewall that allows only port 21
         lets a scored FTP login succeed while every listing and transfer hangs.
      3. A web-shell hunt: every file under each web root that the server would
         EXECUTE (.aspx/.asp/.php/.jsp/... and web.config), flagged when it was
         modified recently, when it sits in a folder that exists to receive
         uploads, when it is much newer than the rest of the site, or when it
         contains one of the indicator strings in
         configs\iis\webshell-indicators.txt. Sorted newest first.
      4. An FTP audit: anonymous authentication, any authorization rule that
         lets everyone write, and recently-changed or executable-looking files
         sitting in the FTP root.

    A flagged file is NOT necessarily malicious -- real applications do most of
    these things. This narrows a folder of thousands of files down to the few
    worth reading. It does not decide anything for you; read them yourself.

    CHANGES (each backed up first, each skippable, all -WhatIf-able):
      5. Directory browsing off, per site (-KeepDirectoryBrowsing to skip).
      6. Identifying response headers removed: the X-Powered-By header, and
         the Server header where IIS supports suppressing it (IIS 10, which is
         what Windows Server 2016 and later run).
      7. Opt-in (-BlockRiskyExtensions): request filtering that refuses
         requests for the file extensions listed in -RiskyExtensions. Off by
         default because it is the one change here that can break a real
         application -- if the scored site legitimately serves .php, this
         takes it down.
      8. Opt-in (-DisableAnonymousFtp): turn off anonymous FTP authentication.
         Off by default because anonymous FTP is sometimes the scored service.

    Before changing anything, this takes an IIS-native configuration backup
    (Backup-WebConfiguration) as well as this toolkit's own snapshot, and tells
    you the one command that undoes everything it did.

.PARAMETER RecentHours
    How far back counts as "recently modified" in the hunt. Default 24.

.PARAMETER SinceTime
    Use an explicit cutoff instead of -RecentHours, e.g. when the competition
    started. Anything modified after this is flagged as recent.

.PARAMETER ReportOnly
    Do the read-only audit and change nothing at all.

.PARAMETER SkipWebShellHunt
    Skip the file hunt (the slowest part on a site with many files).

.PARAMETER KeepDirectoryBrowsing
    Leave directory browsing alone. Use this if a scored site genuinely serves
    a directory listing.

.PARAMETER BlockRiskyExtensions
    Opt in to request filtering for -RiskyExtensions. Read the warning above.

.PARAMETER RiskyExtensions
    What -BlockRiskyExtensions denies. Default: the scripting extensions a
    Windows/IIS site does not normally serve.

.PARAMETER DisableAnonymousFtp
    Opt in to turning off anonymous FTP authentication.

.PARAMETER IndicatorPath
    A different web-shell indicator file than configs\iis\webshell-indicators.txt.

.PARAMETER MaxFilesPerSite
    Stop enumerating a site's files after this many, so one enormous site
    cannot stall the run. Default 20000.

.EXAMPLE
    .\Invoke-IISHardening.ps1 -ReportOnly
    Audit only: what is here, what to put in the answer file, what to read.

.EXAMPLE
    .\Invoke-IISHardening.ps1 -WhatIf
    Same audit, plus exactly which changes it would make.

.EXAMPLE
    .\Invoke-IISHardening.ps1 -SinceTime '2026-01-01 08:00'
    Flag anything under a web root modified since the round started.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$RecentHours = 24,
    [datetime]$SinceTime,
    [switch]$ReportOnly,
    [switch]$SkipWebShellHunt,
    [switch]$KeepDirectoryBrowsing,
    [switch]$BlockRiskyExtensions,
    [string[]]$RiskyExtensions = @('.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.jspx', '.cgi', '.pl', '.py', '.rb', '.sh', '.bat', '.cmd', '.vbs', '.ps1'),
    [switch]$DisableAnonymousFtp,
    [string]$IndicatorPath,
    [int]$MaxFilesPerSite = 20000
)

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
$session = Start-CcdcSession -RootPath (Split-Path -Parent $PSScriptRoot)

Write-CcdcLog -Level INFO -Message "IIS hardening and audit starting. The audit part is read-only and always runs; changes are backed up first and listed before they happen."
Assert-CcdcElevated -Because 'reading and changing the IIS configuration'
Show-CcdcTargetContext -RootPath $session.RootPath -SkipIfShownByMenu | Out-Null

try {

$thisHost = $env:COMPUTERNAME
if (-not $thisHost) { $thisHost = (hostname) }
$cutoff = if ($PSBoundParameters.ContainsKey('SinceTime')) { $SinceTime } else { (Get-Date).AddHours(-$RecentHours) }
$changesAllowed = (-not $ReportOnly)

# ---------------------------------------------------------------------------
# Is IIS even here? This module is meant to be run on whatever box you are on,
# so "no IIS" is a normal answer, not an error.
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level INFO -Message "IIS isn't installed on '$thisHost' (no WebAdministration module), so there's nothing for this module to do here. Run it on the web or FTP server."
    return
}
Import-Module WebAdministration -ErrorAction Stop
if (-not (Get-Command -Name Get-Website -ErrorAction SilentlyContinue)) {
    Write-CcdcLog -Level ERROR -Message "The WebAdministration module loaded but Get-Website isn't available -- this IIS install looks incomplete. Nothing was changed."
    return
}

$sitesOutcome = Invoke-CcdcSafe -Target $thisHost -Action 'list IIS sites' -ScriptBlock { @(Get-Website) }
if (-not $sitesOutcome.Success) { return }
$sites = @($sitesOutcome.Value)
if ($sites.Count -eq 0) {
    Write-CcdcLog -Level WARN -Message "IIS is installed but has no sites configured. Nothing to audit."
    return
}

# ---------------------------------------------------------------------------
# 1. What is actually here.
# ---------------------------------------------------------------------------
Write-CcdcLog -Level INFO -Message "-- 1. What's on this box --"

function Get-BindingPort {
    # bindingInformation is "IP:port:hostheader"; the port is the middle field.
    param([string]$BindingInformation)
    $parts = "$BindingInformation" -split ':'
    if ($parts.Count -ge 2 -and $parts[1] -match '^\d+$') { return $parts[1] }
    return ''
}

$allBindings = New-Object System.Collections.Generic.List[object]
$siteRows = New-Object System.Collections.Generic.List[object]
foreach ($site in $sites) {
    $bindingText = New-Object System.Collections.Generic.List[string]
    foreach ($b in @($site.bindings.Collection)) {
        $port = Get-BindingPort -BindingInformation $b.bindingInformation
        $proto = "$($b.protocol)"
        if ($port) {
            $bindingText.Add("$proto/$port")
            $allBindings.Add([pscustomobject]@{ Protocol = $proto; Port = $port })
        }
    }
    $siteRows.Add([pscustomobject]@{
        Site     = $site.Name
        State    = "$($site.State)"
        Bindings = ($bindingText -join ', ')
        Path     = "$($site.PhysicalPath)"
        AppPool  = "$($site.ApplicationPool)"
    })
}
$siteRows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

# Application pool identities: a pool running as a highly-privileged account
# turns "someone dropped a file in the web root" into "someone is SYSTEM".
$poolOutcome = Invoke-CcdcSafe -Target $thisHost -Action 'check application pool identities' -ScriptBlock {
    @(Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Pool = $_.Name; Identity = "$($_.processModel.identityType)"; User = "$($_.processModel.userName)" }
    })
}
if ($poolOutcome.Success) {
    foreach ($p in @($poolOutcome.Value)) {
        if ($p.Identity -eq 'LocalSystem') {
            Write-CcdcLog -Level ERROR -Message "Application pool '$($p.Pool)' runs as LocalSystem. Any code that runs in that pool -- including anything dropped into the web root -- runs with full rights on this machine. Change it to ApplicationPoolIdentity unless something genuinely needs otherwise."
        } elseif ($p.Identity -eq 'SpecificUser' -and $p.User) {
            Write-CcdcLog -Level WARN -Message "Application pool '$($p.Pool)' runs as the specific account '$($p.User)' -- check what that account can do, and remember it's an account someone could try to use elsewhere."
        }
    }
}

# FTP passive range (a server-level setting, not per-site).
$ftpPassiveRange = $null
$rangeOutcome = Invoke-CcdcSafe -Target $thisHost -Action 'read the FTP passive data-port range' -ScriptBlock {
    $low = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.ftpServer/firewallSupport' -Name 'lowDataChannelPort' -ErrorAction Stop).Value
    $high = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.ftpServer/firewallSupport' -Name 'highDataChannelPort' -ErrorAction Stop).Value
    "$low-$high"
}
$ftpSites = @($sites | Where-Object { @($_.bindings.Collection | Where-Object { "$($_.protocol)" -eq 'ftp' }).Count -gt 0 })
if ($rangeOutcome.Success -and $ftpSites.Count -gt 0) {
    $ftpPassiveRange = "$($rangeOutcome.Value)"
    if ($ftpPassiveRange -eq '0-0') {
        Write-CcdcLog -Level WARN -Message "FTP's passive data-port range is 0-0, which means 'use the Windows ephemeral range' -- in practice 49152 to 65535. That's 16,000 ports to allow through a firewall. Consider setting a small explicit range in IIS (FTP Firewall Support -> Data Channel Port Range, e.g. 50000-50100) and allowing only that."
    } else {
        Write-CcdcLog -Level INFO -Message "FTP passive data-port range: $ftpPassiveRange."
    }
}

# ---------------------------------------------------------------------------
# 2. The answer-file lines for this box.
# ---------------------------------------------------------------------------
Write-CcdcLog -Level INFO -Message "-- 2. What to put in config\answers.local.psd1 --"
$suggestion = Get-CcdcIisAnswerSuggestion -HostName $thisHost -Bindings $allBindings.ToArray() -FtpPassiveRange $ftpPassiveRange
if ($suggestion.ScoredServices) {
    Write-Host ""
    Write-Host "  Add to ScoredServices (only the ones your scoring packet actually lists):" -ForegroundColor Cyan
    Write-Host "    $($suggestion.ScoredServices)"
    foreach ($line in @($suggestion.ExtraLines)) { Write-Host "    $line" }
    Write-Host ""
    Write-CcdcLog -Level INFO -Message "Those are what's listening here, not what's scored -- your packet decides that. But if FTP is scored, the FTPPassive entry matters: without it a login succeeds and every directory listing hangs once the firewall defaults to Block."
}

# ---------------------------------------------------------------------------
# 3. Web-shell hunt (read-only).
# ---------------------------------------------------------------------------
if (-not $SkipWebShellHunt) {
    Write-CcdcLog -Level INFO -Message "-- 3. Files under a web root worth reading (modified since $($cutoff.ToString('yyyy-MM-dd HH:mm')) counts as recent) --"

    if (-not $IndicatorPath) {
        $IndicatorPath = Join-Path (Join-Path (Join-Path $session.RootPath 'configs') 'iis') 'webshell-indicators.txt'
    }
    $indicators = @()
    if (Test-Path -LiteralPath $IndicatorPath) {
        $indicators = @(Get-Content -LiteralPath $IndicatorPath |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') })
        Write-CcdcLog -Level INFO -Message "Loaded $($indicators.Count) content indicator(s) from $IndicatorPath."
    } else {
        Write-CcdcLog -Level WARN -Message "No indicator file at $IndicatorPath -- checking file names, dates and locations only, not content."
    }

    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($site in $sites) {
        $root = "$($site.PhysicalPath)"
        # IIS stores paths with environment variables in them (%SystemDrive%).
        if ($root) { $root = [System.Environment]::ExpandEnvironmentVariables($root) }
        if (-not $root -or -not (Test-Path -LiteralPath $root)) {
            Write-CcdcLog -Level WARN -Message "Site '$($site.Name)': can't read its folder ($root) -- skipping it. A UNC path or a permissions problem will do this."
            continue
        }

        $scanOutcome = Invoke-CcdcSafe -Target $site.Name -Action "hunt through $root" -ScriptBlock {
            $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
                Select-Object -First $MaxFilesPerSite)
            # The site's own age: everything was published at some point, and a
            # lone executable file much newer than that stands out.
            $baseline = $null
            if ($files.Count -gt 0) {
                $baseline = ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
            }
            $hits = New-Object System.Collections.Generic.List[object]
            foreach ($f in $files) {
                if (-not (Test-CcdcExecutableWebExtension -FileName $f.Name)) { continue }
                $contentHits = @()
                # Only read files small enough to be worth reading; a shell is
                # a few KB, and this avoids pulling a 500 MB log into memory.
                if ($indicators.Count -gt 0 -and $f.Length -le 2MB) {
                    try {
                        $text = [System.IO.File]::ReadAllText($f.FullName)
                        $contentHits = @($indicators | Where-Object { $text.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
                    } catch { }
                }
                $relative = $f.FullName
                if ($relative.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $relative = $relative.Substring($root.Length).TrimStart('\', '/')
                }
                $flags = @(Get-CcdcWebShellFlags -FileName $f.Name -RelativePath $relative -LastWriteTime $f.LastWriteTime `
                    -ReferenceTime $cutoff -ContentIndicators $contentHits -SiteBaselineTime $baseline)
                if ($flags.Count -gt 0) {
                    $hits.Add([pscustomobject]@{
                        Site = $site.Name; File = $relative; Modified = $f.LastWriteTime
                        SizeKB = [math]::Round($f.Length / 1KB, 1); Flags = ($flags -join '; ')
                    })
                }
            }
            if ($files.Count -ge $MaxFilesPerSite) {
                Write-CcdcLog -Level WARN -Message "Site '$($site.Name)' has at least $MaxFilesPerSite files -- only the first $MaxFilesPerSite were looked at. Raise -MaxFilesPerSite if you need all of them."
            }
            return $hits
        }
        if ($scanOutcome.Success) { foreach ($h in @($scanOutcome.Value)) { $findings.Add($h) } }
    }

    if ($findings.Count -eq 0) {
        Write-CcdcLog -Level OK -Message "Nothing under a web root stood out. That is not proof the box is clean -- a shell that was planted before the cutoff, in a normal-looking folder, with no indicator string in it, would not be flagged."
    } else {
        Write-CcdcLog -Level ERROR -Message "$($findings.Count) file(s) under a web root are worth reading, newest first. A flag is not a verdict -- open them and decide."
        $findings | Sort-Object Modified -Descending | Select-Object -First 50 |
            Format-Table Site, File, Modified, SizeKB, Flags -AutoSize -Wrap | Out-String -Width 220 | Write-Host
        if ($findings.Count -gt 50) { Write-CcdcLog -Level WARN -Message "...and $($findings.Count - 50) more (only the 50 most recent are shown; the full list is in this session's transcript)." }
        Write-CcdcLog -Level INFO -Message "If one of these turns out to be real: grab a packet capture and this file BEFORE you delete it (menu 13), then write it up (menu 11) -- prevention is worth half the rubric, so say what you changed so it can't happen again."
    }
}

# ---------------------------------------------------------------------------
# 4. FTP audit (read-only).
# ---------------------------------------------------------------------------
if ($ftpSites.Count -gt 0) {
    Write-CcdcLog -Level INFO -Message "-- 4. FTP audit --"
    foreach ($site in $ftpSites) {
        $anonOutcome = Invoke-CcdcSafe -Target $site.Name -Action 'check FTP anonymous authentication' -ScriptBlock {
            (Get-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -ErrorAction Stop).Value
        }
        if ($anonOutcome.Success -and $anonOutcome.Value -eq $true) {
            Write-CcdcLog -Level WARN -Message "FTP site '$($site.Name)' allows ANONYMOUS logins. If your packet scores anonymous FTP, leave it -- otherwise turn it off (-DisableAnonymousFtp), and either way check what an anonymous user can reach."
        }

        $authzOutcome = Invoke-CcdcSafe -Target $site.Name -Action 'check FTP authorization rules' -ScriptBlock {
            @(Get-WebConfiguration -Filter '/system.ftpServer/security/authorization/add' -PSPath 'IIS:\' -Location $site.Name -ErrorAction Stop)
        }
        if ($authzOutcome.Success) {
            foreach ($rule in @($authzOutcome.Value)) {
                if (Test-CcdcRiskyFtpAuthorization -Users "$($rule.users)" -Roles "$($rule.roles)" -Permissions "$($rule.permissions)") {
                    Write-CcdcLog -Level ERROR -Message "FTP site '$($site.Name)' has an authorization rule letting users='$($rule.users)' roles='$($rule.roles)' WRITE. Anyone who can log in (or nobody at all, if that's the anonymous rule) can plant a file here. Narrow it to the accounts that need it."
                }
            }
        }

        $ftpRoot = [System.Environment]::ExpandEnvironmentVariables("$($site.PhysicalPath)")
        if ($ftpRoot -and (Test-Path -LiteralPath $ftpRoot)) {
            $dropOutcome = Invoke-CcdcSafe -Target $site.Name -Action "look through the FTP root ($ftpRoot)" -ScriptBlock {
                @(Get-ChildItem -LiteralPath $ftpRoot -File -Recurse -Force -ErrorAction SilentlyContinue |
                    Select-Object -First $MaxFilesPerSite |
                    Where-Object { $_.LastWriteTime -gt $cutoff -or (Test-CcdcExecutableWebExtension -FileName $_.Name) } |
                    ForEach-Object { [pscustomobject]@{ File = $_.FullName; Modified = $_.LastWriteTime; SizeKB = [math]::Round($_.Length / 1KB, 1) } })
            }
            if ($dropOutcome.Success) {
                $drops = @($dropOutcome.Value)
                if ($drops.Count -gt 0) {
                    Write-CcdcLog -Level WARN -Message "$($drops.Count) file(s) in the FTP root are new since the cutoff or are the kind of file that can be executed. On a scored FTP server the expected contents are usually boring and unchanging -- anything else is worth a look."
                    $drops | Sort-Object Modified -Descending | Select-Object -First 25 | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
                } else {
                    Write-CcdcLog -Level OK -Message "Nothing new or executable-looking in the FTP root for '$($site.Name)'."
                }
            }
        }
    }
}

if ($ReportOnly) {
    Write-CcdcLog -Level INFO -Message "-ReportOnly: nothing was changed. Re-run without it (or with -WhatIf first) to apply the hardening steps."
    return
}

# ---------------------------------------------------------------------------
# Back up the IIS configuration before changing any of it. Two ways: IIS's own
# named backup (one command to undo everything) and this toolkit's snapshot.
# ---------------------------------------------------------------------------
$backupName = $null
if (-not $WhatIfPreference) {
    $artifactPrefix = Get-CcdcAnswer -Key 'ArtifactPrefix' -Prompt 'Prefix for named artifacts (anything -- just avoid an obvious "CCDC" string since this repo is public)' -Default 'Baseline'
    $backupName = "$artifactPrefix-iis-$($session.Stamp)"
    $backupOutcome = Invoke-CcdcSafe -Target $thisHost -Action "take an IIS configuration backup ('$backupName')" -ScriptBlock {
        Backup-WebConfiguration -Name $backupName -ErrorAction Stop | Out-Null
    }
    if (-not $backupOutcome.Success) {
        Write-CcdcLog -Level ERROR -Message "Couldn't take the IIS configuration backup, so nothing was changed. Fix that first -- this module doesn't change IIS settings it can't undo."
        return
    }
    Write-CcdcLog -Level OK -Message "IIS configuration backed up. To undo everything below in one step: Restore-WebConfiguration -Name '$backupName'"

    $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $appHost) {
        Invoke-CcdcSafe -Target $appHost -Action 'snapshot applicationHost.config' -ScriptBlock {
            Backup-CcdcState -Name 'iis-applicationHost-config-before' -Data (Get-Content -LiteralPath $appHost -Raw)
        } | Out-Null
    }
}

# ---------------------------------------------------------------------------
# 5. Directory browsing off.
# ---------------------------------------------------------------------------
if ($KeepDirectoryBrowsing) {
    Write-CcdcLog -Level INFO -Message "-- 5. Directory browsing: left alone (-KeepDirectoryBrowsing) --"
} else {
    Write-CcdcLog -Level INFO -Message "-- 5. Directory browsing --"
    foreach ($site in $sites) {
        $psPath = "IIS:\Sites\$($site.Name)"
        $stateOutcome = Invoke-CcdcSafe -Target $site.Name -Action 'check directory browsing' -ScriptBlock {
            (Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -PSPath $psPath -ErrorAction Stop).Value
        }
        if (-not $stateOutcome.Success) { continue }
        if ($stateOutcome.Value -ne $true) {
            Write-CcdcLog -Level OK -Message "Site '$($site.Name)': directory browsing is already off."
            continue
        }
        Write-CcdcLog -Level WARN -Message "Site '$($site.Name)': directory browsing is ON -- anyone can list the files in a folder that has no default document."
        if (-not $PSCmdlet.ShouldProcess($site.Name, 'Turn directory browsing off')) { continue }
        Invoke-CcdcSafe -Target $site.Name -Action 'turn directory browsing off' -ScriptBlock {
            Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value $false -PSPath $psPath -ErrorAction Stop
        } | Out-Null
    }
}

# ---------------------------------------------------------------------------
# 6. Identifying response headers.
# ---------------------------------------------------------------------------
Write-CcdcLog -Level INFO -Message "-- 6. Response headers that name the software --"
foreach ($site in $sites) {
    $psPath = "IIS:\Sites\$($site.Name)"
    $hdrOutcome = Invoke-CcdcSafe -Target $site.Name -Action 'check for an X-Powered-By header' -ScriptBlock {
        @(Get-WebConfiguration -Filter '/system.webServer/httpProtocol/customHeaders/add' -PSPath $psPath -ErrorAction Stop |
            Where-Object { "$($_.name)" -eq 'X-Powered-By' })
    }
    if ($hdrOutcome.Success -and @($hdrOutcome.Value).Count -gt 0) {
        if (-not $PSCmdlet.ShouldProcess($site.Name, 'Remove the X-Powered-By response header')) { continue }
        Invoke-CcdcSafe -Target $site.Name -Action 'remove the X-Powered-By response header' -ScriptBlock {
            Remove-WebConfigurationProperty -Filter '/system.webServer/httpProtocol/customHeaders' -Name '.' -AtElement @{ name = 'X-Powered-By' } -PSPath $psPath -ErrorAction Stop
        } | Out-Null
    }
}

# removeServerHeader exists from IIS 10.0 (Windows Server 2016 and later, on
# 1709+). On anything older the attribute isn't in the schema and setting it
# throws, so this reports rather than fails.
$serverHeaderOutcome = Invoke-CcdcSafe -Target $thisHost -Action 'check whether the Server header can be suppressed' -ScriptBlock {
    (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -ErrorAction Stop).Value
}
if (-not $serverHeaderOutcome.Success) {
    Write-CcdcLog -Level INFO -Message "This IIS version doesn't support suppressing the Server header (that arrived in IIS 10). Leaving it -- it's a small information leak, not a way in."
} elseif ($serverHeaderOutcome.Value -eq $true) {
    Write-CcdcLog -Level OK -Message "The Server response header is already suppressed."
} elseif ($PSCmdlet.ShouldProcess($thisHost, 'Suppress the Server response header')) {
    Invoke-CcdcSafe -Target $thisHost -Action 'suppress the Server response header' -ScriptBlock {
        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -Value $true -ErrorAction Stop
    } | Out-Null
}

# ---------------------------------------------------------------------------
# 7. Request filtering (opt-in).
# ---------------------------------------------------------------------------
if ($BlockRiskyExtensions) {
    Write-CcdcLog -Level INFO -Message "-- 7. Request filtering: refusing $($RiskyExtensions.Count) file extension(s) --"
    Write-CcdcLog -Level WARN -Message "This is the change most likely to break a real site. If the scored application actually serves one of these extensions, this takes it down: $($RiskyExtensions -join ', ')"
    foreach ($site in $sites) {
        $psPath = "IIS:\Sites\$($site.Name)"
        foreach ($ext in $RiskyExtensions) {
            if (-not $PSCmdlet.ShouldProcess("$($site.Name) $ext", 'Deny requests for this file extension')) { continue }
            Invoke-CcdcSafe -Target "$($site.Name) $ext" -Action 'deny requests for this file extension' -ScriptBlock {
                $existing = @(Get-WebConfiguration -Filter '/system.webServer/security/requestFiltering/fileExtensions/add' -PSPath $psPath -ErrorAction SilentlyContinue |
                    Where-Object { "$($_.fileExtension)" -eq $ext })
                if ($existing.Count -eq 0) {
                    Add-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering/fileExtensions' -Name '.' `
                        -Value @{ fileExtension = $ext; allowed = $false } -PSPath $psPath -ErrorAction Stop
                }
            } | Out-Null
        }
    }
} else {
    Write-CcdcLog -Level INFO -Message "-- 7. Request filtering: skipped (pass -BlockRiskyExtensions to deny scripting extensions this site shouldn't serve) --"
}

# ---------------------------------------------------------------------------
# 8. Anonymous FTP (opt-in).
# ---------------------------------------------------------------------------
if ($DisableAnonymousFtp -and $ftpSites.Count -gt 0) {
    Write-CcdcLog -Level INFO -Message "-- 8. Anonymous FTP --"
    foreach ($site in $ftpSites) {
        if (-not $PSCmdlet.ShouldProcess($site.Name, 'Turn off anonymous FTP authentication')) { continue }
        Invoke-CcdcSafe -Target $site.Name -Action 'turn off anonymous FTP authentication' -ScriptBlock {
            Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false -ErrorAction Stop
        } | Out-Null
    }
    Write-CcdcLog -Level WARN -Message "Anonymous FTP is off. If your packet scores an anonymous login, that check will start failing now -- undo with: Restore-WebConfiguration -Name '$backupName'"
} elseif ($ftpSites.Count -gt 0) {
    Write-CcdcLog -Level INFO -Message "-- 8. Anonymous FTP: left as-is (pass -DisableAnonymousFtp to turn it off) --"
}

if ($backupName) {
    Write-CcdcLog -Level INFO -Message "Done. To undo every IIS change above in one step: Restore-WebConfiguration -Name '$backupName'"
}
Write-CcdcLog -Level INFO -Message "Check the site still works before you move on -- open it in a browser, and if FTP is scored, log in and list a directory (that exercises the passive port range)."

} finally {
    Show-CcdcSummary
    Stop-CcdcSession
}
