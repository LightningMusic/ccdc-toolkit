#Requires -Version 5.1
<#
.SYNOPSIS
    Pure helper functions shared by the toolkit's modules. Dot-sourced by
    Common.psm1 (so everything here is exported from there) -- not run
    directly.

.DESCRIPTION
    Everything in this file is deliberately free of side effects: no
    prompts, no logging, no cmdlets that change the system, no reads of
    machine state (with two clearly-labeled exceptions noted below). That
    is what makes it testable: tests\*.Tests.ps1 import Common.psm1 and call
    these functions directly with made-up inputs, on any machine, without
    needing AD, a firewall, or admin rights.

    Before this file existed, several of these lived as private functions
    inside individual module scripts (and two of them, the service-to-port
    table and the scored-services host matcher, were copy-pasted into two
    modules). Functions inside a script body can't be loaded without
    running the whole script, so they could not be tested at all.

    Keep this file ASCII-only. Windows PowerShell 5.1 reads a script that
    has no byte-order mark as ANSI, and the UTF-8 bytes of an em dash end
    in 0x94, which PowerShell 5.1 treats as a closing double-quote character
    -- that breaks parsing of whatever string it appears in. (Every script
    in the repo now also carries a BOM as a second line of defense, and
    tests\Repo.Policy.Tests.ps1 fails if that ever regresses.)

    The one exception is Invoke-CcdcPingSweep, which sends ICMP echo
    requests. It lives here because it's a small, self-contained replacement
    for a PowerShell-7-only construct, and it's tested against the loopback
    address.
#>

# ---------------------------------------------------------------------------
# Service name -> port tables.
#
# Two tables because a service can need both protocols (DNS is TCP+UDP 53)
# or only UDP (NTP, DHCP). The firewall module used to have TCP only, which
# would leave every UDP-based scored service to be carried by whatever
# built-in rules happen to be enabled on the box once the default flips to
# Block. Keys are upper-case; lookups upper-case the caller's input.
# ---------------------------------------------------------------------------
$script:CcdcTcpServicePorts = @{
    'DNS'      = @(53)
    'LDAP'     = @(389, 636)
    'KERBEROS' = @(88)
    'HTTP'     = @(80)
    'HTTPS'    = @(443)
    'SMB'      = @(445)
    'RDP'      = @(3389)
    'WINRM'    = @(5985, 5986)
    'FTP'      = @(21)
    'SSH'      = @(22)
    'SMTP'     = @(25)
    'POP3'     = @(110)
    'IMAP'     = @(143)
    'MSSQL'    = @(1433)
}
$script:CcdcUdpServicePorts = @{
    'DNS'      = @(53)
    'LDAP'     = @(389)     # CLDAP (DC locator pings)
    'KERBEROS' = @(88)
    'DHCP'     = @(67, 68)  # DHCP is UDP-only; earlier versions listed it under TCP by mistake
    'NTP'      = @(123)
}

function Resolve-CcdcServicePorts {
    <#
    .SYNOPSIS
        Ports (as integers) a well-known service name uses for one
        protocol. Returns an empty array for a name this toolkit doesn't
        know, OR for a known name with nothing on that protocol -- use
        Get-CcdcServiceRuleSpecs to tell those two cases apart.
    #>
    [CmdletBinding()]
    param(
        [string]$ServiceName,
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol = 'TCP'
    )
    if (-not $ServiceName) { return @() }
    $key = $ServiceName.Trim().ToUpperInvariant()
    $table = if ($Protocol -eq 'UDP') { $script:CcdcUdpServicePorts } else { $script:CcdcTcpServicePorts }
    if ($table.ContainsKey($key)) { return @($table[$key]) }
    return @()
}

function Get-CcdcServiceRuleSpecs {
    <#
    .SYNOPSIS
        Every (Protocol, Port) pair a well-known service name needs
        allowed. An EMPTY result means "this toolkit doesn't know that
        service name" -- the caller should ask for a custom port instead.
    #>
    [CmdletBinding()]
    param([string]$ServiceName)

    $specs = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Resolve-CcdcServicePorts -ServiceName $ServiceName -Protocol TCP)) {
        $specs.Add([pscustomobject]@{ Protocol = 'TCP'; Port = [string]$p })
    }
    foreach ($p in (Resolve-CcdcServicePorts -ServiceName $ServiceName -Protocol UDP)) {
        $specs.Add([pscustomobject]@{ Protocol = 'UDP'; Port = [string]$p })
    }
    return $specs.ToArray()
}

function Get-CcdcScoredServicesForHost {
    <#
    .SYNOPSIS
        ScoredServices entries look like "HOSTNAME:ServiceName". Returns
        just the service names that match $HostName (case-insensitive), plus
        any bare entries with no host prefix (treated as "every host").
    #>
    [CmdletBinding()]
    param(
        [string[]]$ScoredServices,
        [string]$HostName
    )

    # NOTE: deliberately not named $matches -- PowerShell variable names are
    # case-insensitive, so that IS the automatic $Matches variable that
    # -match overwrites on every successful match, which would silently
    # wipe out the accumulator.
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($entry in @($ScoredServices)) {
        if (-not $entry) { continue }
        if ($entry -match '^(?<hostpart>[^:]+):(?<svcpart>.+)$') {
            if ($Matches.hostpart.Trim() -eq $HostName) { $found.Add($Matches.svcpart.Trim()) }
        } else {
            $found.Add($entry.Trim())
        }
    }
    return $found.ToArray()
}

function Test-CcdcValidPort {
    [CmdletBinding()]
    param([string]$PortText)
    if ($PortText -notmatch '^\d{1,5}$') { return $false }
    $p = [int]$PortText
    return ($p -ge 1 -and $p -le 65535)
}

function ConvertFrom-CcdcPortSpec {
    <#
    .SYNOPSIS
        Parses a custom-service port answer such as '8443', '8443,9443',
        '50000-50100', or 'udp:5060,tcp:5061' into rule specs.

    .OUTPUTS
        An object with .Specs (Protocol + Port, where Port is a single
        number or a "lo-hi" range, as text -- New-NetFirewallRule's
        -LocalPort accepts both) and .Invalid (the tokens that didn't
        parse, so the caller can say exactly what it ignored).
    #>
    [CmdletBinding()]
    param(
        [string]$Spec,
        [ValidateSet('TCP', 'UDP')]
        [string]$DefaultProtocol = 'TCP'
    )

    $specs = New-Object System.Collections.Generic.List[object]
    $invalid = New-Object System.Collections.Generic.List[string]

    foreach ($rawToken in @($Spec -split ',')) {
        $token = $rawToken.Trim()
        if (-not $token) { continue }

        $proto = $DefaultProtocol
        $body = $token
        if ($token -match '^(?<p>tcp|udp)\s*[:/]\s*(?<b>.+)$') {
            $proto = $Matches.p.ToUpperInvariant()
            $body = $Matches.b.Trim()
        }

        if (Test-CcdcValidPort $body) {
            $specs.Add([pscustomobject]@{ Protocol = $proto; Port = [string][int]$body })
        } elseif ($body -match '^(?<lo>\d{1,5})\s*-\s*(?<hi>\d{1,5})$') {
            $lo = $Matches.lo
            $hi = $Matches.hi
            if ((Test-CcdcValidPort $lo) -and (Test-CcdcValidPort $hi) -and ([int]$lo -lt [int]$hi)) {
                $specs.Add([pscustomobject]@{ Protocol = $proto; Port = "$([int]$lo)-$([int]$hi)" })
            } else {
                $invalid.Add($token)
            }
        } else {
            $invalid.Add($token)
        }
    }

    return [pscustomobject]@{ Specs = $specs.ToArray(); Invalid = $invalid.ToArray() }
}

function Test-CcdcValidIPv4 {
    [CmdletBinding()]
    param([string]$IPText)
    if ($IPText -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    foreach ($octet in ($IPText -split '\.')) {
        if ([int]$octet -gt 255) { return $false }
    }
    return $true
}

function Test-CcdcValidFileSystemRight {
    [CmdletBinding()]
    param([string]$RightText)
    $valid = @('ReadAndExecute', 'Read', 'Write', 'Modify', 'FullControl')
    return $valid -contains $RightText
}

function Get-CcdcCidrAddresses {
    <#
    .SYNOPSIS
        Expands a CIDR block into host addresses using real bit math (not a
        ".1-.254" assumption), so a /24, a /27 and a /31 all work.

    .OUTPUTS
        An object with .Valid, .Message (why it's not valid, or a
        truncation note), and .Addresses (dotted-quad strings). A /32 is
        one address; a /31 is both; anything wider skips the network and
        broadcast addresses. Blocks wider than -MinPrefix are refused
        (a mistyped /8 shouldn't sweep for an hour), and the result is
        capped at -MaxHosts.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][AllowNull()][string]$Cidr,
        [int]$MaxHosts = 1024,
        [int]$MinPrefix = 22
    )

    $result = [pscustomobject]@{ Valid = $false; Message = ''; Addresses = @() }

    if ("$Cidr".Trim() -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') {
        $result.Message = "Couldn't parse '$Cidr' as CIDR (expected form like 10.10.10.0/24)."
        return $result
    }
    $o = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    $prefix = [int]$Matches[5]
    if (@($o | Where-Object { $_ -gt 255 }).Count -gt 0 -or $prefix -gt 32) {
        $result.Message = "'$Cidr' has an octet above 255 or a prefix above 32."
        return $result
    }
    if ($prefix -lt $MinPrefix) {
        $result.Message = "/$prefix is a $([math]::Pow(2, 32 - $prefix)) address block -- way bigger than any CCDC subnet should be. Refusing to expand it; double-check the CIDR you entered."
        return $result
    }

    [long]$ip = ([long]$o[0] * 16777216) + ([long]$o[1] * 65536) + ([long]$o[2] * 256) + [long]$o[3]
    $hostBits = 32 - $prefix
    [long]$size = [long][math]::Pow(2, $hostBits)
    [long]$network = $ip - ($ip % $size)

    if ($hostBits -eq 0) {
        [long]$first = $network; [long]$last = $network
    } elseif ($hostBits -eq 1) {
        [long]$first = $network; [long]$last = $network + 1
    } else {
        [long]$first = $network + 1; [long]$last = $network + $size - 2
    }

    $count = $last - $first + 1
    if ($count -gt $MaxHosts) {
        $last = $first + $MaxHosts - 1
        $result.Message = "Block has $count usable addresses; expanding only the first $MaxHosts."
    }

    $addresses = New-Object System.Collections.Generic.List[string]
    for ([long]$n = $first; $n -le $last; $n++) {
        $addresses.Add(('{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255)))
    }
    $result.Valid = $true
    $result.Addresses = $addresses.ToArray()
    return $result
}

function Invoke-CcdcPingSweep {
    <#
    .SYNOPSIS
        Concurrent ICMP sweep that works on Windows PowerShell 5.1 (the
        default on Server 2019/2022 and Windows 11). Replaces
        ForEach-Object -Parallel and Test-Connection -TimeoutSeconds,
        which only exist in PowerShell 7+.

    .OUTPUTS
        The addresses that answered, as strings.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Addresses,
        [int]$TimeoutMs = 1000,
        [int]$BatchSize = 64
    )

    $alive = New-Object System.Collections.Generic.List[string]
    $all = @($Addresses | Where-Object { $_ })
    for ($i = 0; $i -lt $all.Count; $i += $BatchSize) {
        $end = [math]::Min($i + $BatchSize, $all.Count) - 1
        $pings = New-Object System.Collections.Generic.List[System.Net.NetworkInformation.Ping]
        $tasks = New-Object System.Collections.Generic.List[System.Threading.Tasks.Task]
        for ($j = $i; $j -le $end; $j++) {
            $p = New-Object System.Net.NetworkInformation.Ping
            $pings.Add($p)
            try {
                $tasks.Add($p.SendPingAsync($all[$j], $TimeoutMs))
            } catch {
                # A malformed address throws synchronously; keep the batch
                # aligned by adding a completed-faulted placeholder.
                $tcs = New-Object 'System.Threading.Tasks.TaskCompletionSource[bool]'
                $tcs.SetException($_.Exception)
                $tasks.Add($tcs.Task)
            }
        }
        try { [System.Threading.Tasks.Task]::WaitAll($tasks.ToArray()) } catch { }
        for ($k = 0; $k -lt $tasks.Count; $k++) {
            $t = $tasks[$k]
            if ($t.Status -eq 'RanToCompletion' -and $null -ne $t.Result -and $t.Result.Status -eq 'Success') {
                $alive.Add($all[$i + $k])
            }
        }
        foreach ($p in $pings) { $p.Dispose() }
    }
    return $alive.ToArray()
}

# ---------------------------------------------------------------------------
# Threat-hunt helpers
# ---------------------------------------------------------------------------

function Get-CcdcNewItems {
    <#
    .SYNOPSIS
        Returns entries present in $Current but not in $Previous
        (case-insensitive, null/empty-safe). This is the whole "only tell
        me what's NEW since last time" mechanism.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Previous,
        [string[]]$Current
    )
    $prevSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @($Previous)) { if ($p) { [void]$prevSet.Add([string]$p) } }
    $new = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Current)) {
        if ($c -and -not $prevSet.Contains([string]$c)) { $new.Add([string]$c) }
    }
    return $new.ToArray()
}

function Get-CcdcServiceExePath {
    <#
    .SYNOPSIS
        A service's PathName often carries arguments after the executable
        (quoted or not) -- this strips those off so the result is safe to
        pass to a file-existence check or a signature check.
    #>
    [CmdletBinding()]
    param([string]$PathName)
    if (-not $PathName) { return '' }
    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        if ($trimmed -match '^"([^"]+)"') { return $Matches[1] }
        return $trimmed.Trim('"')
    }
    return ($trimmed -split '\s+')[0]
}

function Test-CcdcSuspiciousPath {
    <#
    .SYNOPSIS
        Does $Path match any of the given regex fragments?
    #>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string[]]$Patterns
    )
    if (-not $Path) { return $false }
    foreach ($pat in @($Patterns)) {
        if ($Path -match $pat) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# IIS / FTP helpers
# ---------------------------------------------------------------------------

# Extensions the web server will EXECUTE rather than just hand back. A web shell
# has to be one of these to do anything, so they are what a hunt looks at.
# .config is in the list for a different reason: web.config is executable-ish
# (it can add handlers and modules), so a changed one matters just as much.
$script:CcdcExecutableWebExtensions = @(
    '.aspx', '.asp', '.ashx', '.asmx', '.axd', '.cshtml', '.vbhtml',
    '.php', '.php3', '.php4', '.php5', '.phtml',
    '.jsp', '.jspx', '.cfm', '.cgi', '.pl', '.py', '.rb', '.sh',
    '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.jar', '.war', '.config'
)

function Test-CcdcExecutableWebExtension {
    <#
    .SYNOPSIS
        Would a web server treat a file with this name as something to run
        (or, for web.config, as configuration) rather than static content?
    #>
    [CmdletBinding()]
    param([string]$FileName)
    if (-not $FileName) { return $false }
    $ext = [System.IO.Path]::GetExtension($FileName)
    if (-not $ext) { return $false }
    return ($script:CcdcExecutableWebExtensions -contains $ext.ToLowerInvariant())
}

function Get-CcdcWebShellFlags {
    <#
    .SYNOPSIS
        Why is this file under a web root worth a second look? Returns zero or
        more plain-English flags. Zero flags means nothing stood out -- it does
        NOT mean the file is safe, and a flagged file is not necessarily
        malicious (real applications legitimately do most of these things).
        This narrows what a human reads; it does not decide anything.

    .PARAMETER FileName
        Just the file name, e.g. "images.aspx".

    .PARAMETER RelativePath
        Path under the site root, used to notice files sitting in a folder
        that exists to receive uploads.

    .PARAMETER LastWriteTime
        When the file last changed.

    .PARAMETER ReferenceTime
        Anything modified after this counts as recent. Usually "when the
        competition started" or "an hour ago".

    .PARAMETER ContentIndicators
        Indicator strings that were found inside the file (the caller does the
        reading; the indicator list is data, in configs\iis\).

    .PARAMETER SiteBaselineTime
        Optional. When the rest of the site was published (say, the oldest file
        in it). A lone executable file much newer than everything around it is
        the classic dropped-web-shell shape.
    #>
    [CmdletBinding()]
    param(
        [string]$FileName,
        [string]$RelativePath,
        [Nullable[datetime]]$LastWriteTime,
        [Nullable[datetime]]$ReferenceTime,
        [string[]]$ContentIndicators,
        [Nullable[datetime]]$SiteBaselineTime
    )

    $flags = New-Object System.Collections.Generic.List[string]
    if (-not (Test-CcdcExecutableWebExtension -FileName $FileName)) { return $flags.ToArray() }

    if ($null -ne $LastWriteTime -and $null -ne $ReferenceTime -and $LastWriteTime -gt $ReferenceTime) {
        $flags.Add('RECENTLY MODIFIED')
    }
    # A folder whose job is to accept uploads should not contain anything the
    # server will execute -- that combination is the classic web-shell drop.
    if ($RelativePath -match '(?i)(^|\\|/)(upload|uploads|files|temp|tmp|images|img|media|attachments|userfiles|fileupload)(\\|/)') {
        $flags.Add('EXECUTABLE FILE IN AN UPLOAD/CONTENT FOLDER')
    }
    foreach ($hit in @($ContentIndicators | Where-Object { $_ })) {
        $flags.Add("CONTENT LOOKS LIKE A SHELL: $hit")
    }
    if ($null -ne $SiteBaselineTime -and $null -ne $LastWriteTime -and
        ($LastWriteTime - $SiteBaselineTime).TotalDays -gt 30) {
        $flags.Add('MUCH NEWER THAN THE REST OF THE SITE')
    }
    return $flags.ToArray()
}

function Test-CcdcRiskyFtpAuthorization {
    <#
    .SYNOPSIS
        Does this FTP authorization rule let anyone at all write? An FTP root
        that everyone can write to is how a file gets planted, and it is one of
        the first things worth checking on a scored FTP server.

    .PARAMETER Users
        The rule's users attribute ("*" means everyone, "?" means anonymous).

    .PARAMETER Roles
        The rule's roles attribute.

    .PARAMETER Permissions
        IIS permissions: 1 = Read, 2 = Write, 3 = both. Accepts the number or
        the words.
    #>
    [CmdletBinding()]
    param([string]$Users, [string]$Roles, [string]$Permissions)

    $writes = $false
    if ($Permissions -match '^\d+$') { $writes = (([int]$Permissions) -band 2) -eq 2 }
    elseif ($Permissions -match '(?i)write') { $writes = $true }
    if (-not $writes) { return $false }

    # "*" = all users, "?" = anonymous. Either one writing is the risky case.
    return (($Users -eq '*') -or ($Users -eq '?') -or ($Roles -eq '*'))
}

function Get-CcdcIisAnswerSuggestion {
    <#
    .SYNOPSIS
        Turns what was found on an IIS box into the exact lines to paste into
        config\answers.local.psd1, so the firewall module opens the right
        ports. Getting FTP's passive range in here is the whole point: it is
        the piece people miss until a scored transfer hangs.

    .PARAMETER HostName
        This host's name, used as the ScoredServices prefix.

    .PARAMETER Bindings
        Objects with .Protocol ('http', 'https', 'ftp') and .Port.

    .PARAMETER FtpPassiveRange
        "low-high" from IIS, or "0-0" meaning the Windows ephemeral range.

    .OUTPUTS
        An object with .ScoredServices (the comma-separated value) and
        .ExtraLines (any Port_<name> lines needed alongside it).
    #>
    [CmdletBinding()]
    param(
        [string]$HostName,
        [object[]]$Bindings,
        [string]$FtpPassiveRange
    )

    $services = New-Object System.Collections.Generic.List[string]
    $extra = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($b in @($Bindings)) {
        if (-not $b) { continue }
        $proto = "$($b.Protocol)".ToUpperInvariant()
        $port = "$($b.Port)"
        $name = $null
        switch ($proto) {
            'HTTP'  { $name = if ($port -eq '80') { 'HTTP' } else { "HTTP$port" } }
            'HTTPS' { $name = if ($port -eq '443') { 'HTTPS' } else { "HTTPS$port" } }
            'FTP'   { $name = if ($port -eq '21') { 'FTP' } else { "FTP$port" } }
        }
        # Checked here rather than with a `default { continue }` inside the
        # switch: `continue` there leaves the switch, not this loop, so an
        # unrecognised protocol would fall through and emit a nameless entry.
        if (-not $name) { continue }
        if (-not $seen.Add($name)) { continue }
        $services.Add("$HostName`:$name")
        # A non-standard port needs its own Port_ line, since the name is one
        # the toolkit's service table doesn't know.
        if ($name -notin 'HTTP', 'HTTPS', 'FTP') { $extra.Add("Port_$name = '$port'") }
    }

    if ($FtpPassiveRange) {
        $range = $FtpPassiveRange
        if ($range -eq '0-0') { $range = '49152-65535' }   # what "use the ephemeral range" means on Windows
        if ($seen.Add('FTPPassive')) {
            $services.Add("$HostName`:FTPPassive")
            $extra.Add("Port_FTPPassive = '$range'")
        }
    }

    return [pscustomobject]@{
        ScoredServices = ($services -join ',')
        ExtraLines     = $extra.ToArray()
    }
}

# ---------------------------------------------------------------------------
# Health verdicts for the dashboard (ui\Start-CcdcConsole.ps1)
#
# Each of these turns raw facts into a status and one plain-English line. They
# are pure so the rules can be tested, and so the same rules could be reused by
# anything else that wants a health summary. Status is one of:
#   Good     nothing to do
#   Warn     worth knowing, not urgent
#   Bad      act on this now
#   Unknown  could not be determined -- NOT the same as Good, and shown as such
# ---------------------------------------------------------------------------

function New-CcdcHealthCard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Good', 'Warn', 'Bad', 'Unknown')][string]$Status = 'Unknown',
        [string]$Value = '',
        [string]$Detail = ''
    )
    return [pscustomobject]@{ Title = $Title; Status = $Status; Value = $Value; Detail = $Detail }
}

function Get-CcdcFirewallVerdict {
    <#
    .SYNOPSIS
        Is the host firewall actually defaulting to Block on every profile?
        A profile left on Allow is the one that will be serving whatever red
        team starts listening on.
    #>
    [CmdletBinding()]
    param([string[]]$DefaultInboundActions)

    $actions = @($DefaultInboundActions | Where-Object { $_ })
    if ($actions.Count -eq 0) { return (New-CcdcHealthCard -Title 'Firewall' -Status Unknown -Value 'unknown' -Detail 'Could not read the firewall profiles. On Windows that usually means the NetSecurity module is missing or this session cannot query it.') }

    $blocking = @($actions | Where-Object { $_ -eq 'Block' }).Count
    if ($blocking -eq $actions.Count) {
        return (New-CcdcHealthCard -Title 'Firewall' -Status Good -Value 'default Block' -Detail "All $($actions.Count) profile(s) default to Block. Only what has an explicit allow rule is reachable.")
    }
    if ($blocking -gt 0) {
        return (New-CcdcHealthCard -Title 'Firewall' -Status Warn -Value "$blocking of $($actions.Count) Block" -Detail 'Some profiles still default to Allow. The profile a network adapter is actually on is the one that matters, so this may be wide open in practice.')
    }
    return (New-CcdcHealthCard -Title 'Firewall' -Status Bad -Value 'default Allow' -Detail 'Every profile defaults to Allow: anything listening on this box is reachable. Run the firewall baseline (menu 4 to preview, 5 to apply).')
}

function Get-CcdcServiceVerdict {
    <#
    .SYNOPSIS
        Is a service this toolkit cares about installed and running?
        -Optional means "not installed" is a normal answer, not a problem.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Status,
        [string]$WhenMissing = '',
        [switch]$Optional
    )
    if (-not $Status) {
        $s = if ($Optional) { 'Warn' } else { 'Bad' }
        return (New-CcdcHealthCard -Title $Title -Status $s -Value 'not installed' -Detail $WhenMissing)
    }
    if ($Status -eq 'Running') { return (New-CcdcHealthCard -Title $Title -Status Good -Value 'running' -Detail "The $Title service is installed and running.") }
    return (New-CcdcHealthCard -Title $Title -Status Bad -Value $Status.ToLowerInvariant() -Detail "The $Title service is installed but $($Status.ToLowerInvariant()). It is not doing anything for you in that state.")
}

function Get-CcdcFailedLogonVerdict {
    <#
    .SYNOPSIS
        Failed logons in a recent window. A handful is someone mistyping; a
        lot in a short window is something trying passwords.
    #>
    [CmdletBinding()]
    param(
        [Nullable[int]]$Count,
        [int]$Minutes = 30,
        [int]$WarnAt = 5,
        [int]$BadAt = 25
    )
    if ($null -eq $Count) { return (New-CcdcHealthCard -Title 'Failed logons' -Status Unknown -Value 'unknown' -Detail 'Could not read the Security event log. It may need elevation, or logon auditing may be off.') }
    if ($Count -ge $BadAt) { return (New-CcdcHealthCard -Title 'Failed logons' -Status Bad -Value "$Count in $Minutes min" -Detail 'That is a lot of failures in a short window -- something is guessing passwords. Find the source account and workstation in event 4625.') }
    if ($Count -ge $WarnAt) { return (New-CcdcHealthCard -Title 'Failed logons' -Status Warn -Value "$Count in $Minutes min" -Detail 'More failures than a person mistyping usually produces. Worth a look at event 4625.') }
    return (New-CcdcHealthCard -Title 'Failed logons' -Status Good -Value "$Count in $Minutes min" -Detail 'Nothing unusual in the recent Security log.')
}

function Get-CcdcC2PortVerdict {
    <#
    .SYNOPSIS
        Is anything listening on a port that is a well-known default for
        remote-access tooling? Suspicious on sight, not just when it is new.
    #>
    [CmdletBinding()]
    param(
        [int[]]$ListeningPorts,
        [int[]]$FlagPorts = @(4444, 2222)
    )
    if ($null -eq $ListeningPorts) { return (New-CcdcHealthCard -Title 'Listening ports' -Status Unknown -Value 'unknown' -Detail 'Could not list listening TCP ports.') }
    $hits = @($ListeningPorts | Where-Object { $FlagPorts -contains $_ } | Sort-Object -Unique)
    if ($hits.Count -gt 0) {
        return (New-CcdcHealthCard -Title 'Listening ports' -Status Bad -Value "$($hits -join ', ') open" -Detail 'Those are common default ports for remote-access tooling, and nothing you run should be on them. Find the owning process now.')
    }
    return (New-CcdcHealthCard -Title 'Listening ports' -Status Good -Value "$(@($ListeningPorts).Count) listening" -Detail 'Nothing on the well-known remote-access default ports. That is not the same as "all of these are meant to be open" -- read the list.')
}

function Get-CcdcProtectedAccountsVerdict {
    <#
    .SYNOPSIS
        Is the list of accounts that must never be rotated filled in? Empty is
        the single most common way to score yourself an outage.
    #>
    [CmdletBinding()]
    param([int]$Count)
    if ($Count -gt 0) { return (New-CcdcHealthCard -Title 'Protected accounts' -Status Good -Value "$Count listed" -Detail 'Credential hardening will leave these alone.') }
    return (New-CcdcHealthCard -Title 'Protected accounts' -Status Warn -Value 'none listed' -Detail 'If any account feeds a scored login check, rotating it fails that check instantly. Fill in ProtectedAccounts in config\answers.local.psd1 before rotating credentials.')
}

function Get-CcdcInventoryVerdict {
    [CmdletBinding()]
    param([Nullable[int]]$AgeMinutes, [int]$StaleAt = 120)
    if ($null -eq $AgeMinutes) { return (New-CcdcHealthCard -Title 'Inventory' -Status Warn -Value 'not run' -Detail 'Run discovery so the other modules know what is here instead of asking you.') }
    if ($AgeMinutes -gt $StaleAt) { return (New-CcdcHealthCard -Title 'Inventory' -Status Warn -Value "$AgeMinutes min old" -Detail 'Stale enough that hosts or accounts may have changed since. Re-run discovery.') }
    return (New-CcdcHealthCard -Title 'Inventory' -Status Good -Value "$AgeMinutes min old" -Detail 'Recent enough for the other modules to rely on.')
}

function Get-CcdcScoredServiceStatus {
    <#
    .SYNOPSIS
        The point of the whole toolkit, checked directly: for each service the
        packet says is scored on this host, is the port it needs actually
        listening right now?

        This is a local check -- a port can be listening while a firewall in
        front of it drops the traffic, so "Up" here means "the service is
        running", not "the scoring engine can reach it".

    .PARAMETER ScoredServices
        The raw ScoredServices entries (HOST:Service).

    .PARAMETER HostName
        This host, used to pick the entries that apply here.

    .PARAMETER CustomPorts
        Port_<Name> answers, as a hashtable of name -> spec, for services the
        built-in table does not know.

    .PARAMETER ListeningTcp / ListeningUdp
        Ports currently listening.

    .OUTPUTS
        One row per service: Service, Protocol, Port, Status (Up/Down/Unknown), Detail.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ScoredServices,
        [string]$HostName,
        [hashtable]$CustomPorts,
        [int[]]$ListeningTcp,
        [int[]]$ListeningUdp
    )

    # "Not supplied" and "supplied but empty" mean very different things here:
    # the first is "I could not check", the second is "nothing is listening at
    # all", which is exactly the emergency this function exists to report. They
    # have to be told apart before any assignment, because `$x = if (...) { @() }`
    # collapses an empty array to $null and would turn a real outage into a shrug.
    $haveTcp = $PSBoundParameters.ContainsKey('ListeningTcp') -and $null -ne $ListeningTcp
    $haveUdp = $PSBoundParameters.ContainsKey('ListeningUdp') -and $null -ne $ListeningUdp
    $tcpPorts = @($ListeningTcp)
    $udpPorts = @($ListeningUdp)

    $rows = New-Object System.Collections.Generic.List[object]
    $services = @(Get-CcdcScoredServicesForHost -ScoredServices $ScoredServices -HostName $HostName)
    foreach ($svc in $services) {
        $specs = @(Get-CcdcServiceRuleSpecs -ServiceName $svc)
        if ($specs.Count -eq 0 -and $CustomPorts -and $CustomPorts.ContainsKey($svc)) {
            $parsed = ConvertFrom-CcdcPortSpec -Spec ([string]$CustomPorts[$svc])
            $specs = @($parsed.Specs)
        }
        if ($specs.Count -eq 0) {
            $rows.Add([pscustomobject]@{ Service = $svc; Protocol = ''; Port = ''; Status = 'Unknown'
                Detail = "No port known for '$svc'. Add Port_$svc to config\answers.local.psd1." })
            continue
        }
        foreach ($spec in $specs) {
            $isUdp = ($spec.Protocol -eq 'UDP')
            $listening = @()
            $checked = $false
            if ($isUdp) { $listening = $udpPorts; $checked = $haveUdp } else { $listening = $tcpPorts; $checked = $haveTcp }
            if (-not $checked) {
                $rows.Add([pscustomobject]@{ Service = $svc; Protocol = $spec.Protocol; Port = $spec.Port; Status = 'Unknown'; Detail = "Could not list listening $($spec.Protocol) ports." })
                continue
            }
            # A range (50000-50100) is up if anything in it is listening --
            # passive FTP only opens a port when a transfer is in progress, so
            # an idle range being quiet is normal, not a fault.
            $isRange = $spec.Port -match '^(?<lo>\d+)-(?<hi>\d+)$'
            if ($isRange) {
                $lo = [int]$Matches.lo; $hi = [int]$Matches.hi
                $hits = @($listening | Where-Object { $_ -ge $lo -and $_ -le $hi })
                $rows.Add([pscustomobject]@{ Service = $svc; Protocol = $spec.Protocol; Port = $spec.Port
                    Status = 'Unknown'
                    Detail = "$($hits.Count) port(s) in this range are listening right now. A range like this is only in use during a transfer, so quiet is normal -- what matters is that the firewall allows it." })
                continue
            }
            $port = [int]$spec.Port
            if ($listening -contains $port) {
                $rows.Add([pscustomobject]@{ Service = $svc; Protocol = $spec.Protocol; Port = $spec.Port; Status = 'Up'; Detail = "Something is listening on $($spec.Protocol)/$port." })
            } else {
                $rows.Add([pscustomobject]@{ Service = $svc; Protocol = $spec.Protocol; Port = $spec.Port; Status = 'Down'
                    Detail = "NOTHING is listening on $($spec.Protocol)/$port. If this is scored, you are losing points right now -- start the service." })
            }
        }
    }
    return $rows.ToArray()
}

function Get-CcdcOverallHealth {
    <#
    .SYNOPSIS
        One word for a set of cards: the worst status present. Bad beats Warn
        beats Unknown beats Good, so nothing hides behind an average.
    #>
    [CmdletBinding()]
    param([object[]]$Cards)
    $statuses = @($Cards | ForEach-Object { $_.Status })
    if ($statuses -contains 'Bad') { return 'Bad' }
    if ($statuses -contains 'Warn') { return 'Warn' }
    if ($statuses -contains 'Unknown') { return 'Unknown' }
    if ($statuses.Count -eq 0) { return 'Unknown' }
    return 'Good'
}

# ---------------------------------------------------------------------------
# AD hardening helper
# ---------------------------------------------------------------------------

function Test-CcdcStaleAccount {
    <#
    .SYNOPSIS
        Is this account a stale-account audit candidate? Excludes disabled
        accounts, anything in the protected/built-in exclusion set, and
        anyone who's logged on recently. A null LastLogonDate (never logged
        on) counts as stale.
    #>
    [CmdletBinding()]
    param(
        [bool]$Enabled,
        [string]$SamAccountName,
        [Nullable[datetime]]$LastLogonDate,
        [datetime]$Now,
        [int]$StaleDaysThreshold,
        [string[]]$ExcludedNames
    )
    if (-not $Enabled) { return $false }
    if ($ExcludedNames -contains $SamAccountName) { return $false }
    if ($null -eq $LastLogonDate) { return $true }
    return ($Now - $LastLogonDate).TotalDays -gt $StaleDaysThreshold
}

# ---------------------------------------------------------------------------
# Incident-report helpers
# ---------------------------------------------------------------------------

function Get-CcdcLogLinesNearTime {
    <#
    .SYNOPSIS
        Write-CcdcLog lines only carry a time-of-day (HH:mm:ss), not a
        date, so the file's own date (from its session_<date>_<time>.log
        name) is what anchors each line to a real point in time before
        it's compared against the window.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Lines,
        [datetime]$FileDate,
        [datetime]$CenterTime,
        [int]$WindowMinutes = 30
    )
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($line in @($Lines)) {
        if ($line -match '^\[(?<t>\d{2}:\d{2}:\d{2})\]\s+\[(?<lvl>WARN|ERROR|ACTION|OK)\]') {
            $parts = $Matches.t -split ':'
            # Built from the file's date at midnight plus the line's
            # time-of-day, so there is no sub-second component to drift
            # past an exact window boundary.
            $full = $FileDate.Date.Add((New-TimeSpan -Hours ([int]$parts[0]) -Minutes ([int]$parts[1]) -Seconds ([int]$parts[2])))
            if ([math]::Abs(($full - $CenterTime).TotalMinutes) -le $WindowMinutes) {
                $found.Add($line)
            }
        }
    }
    return $found.ToArray()
}

function Get-CcdcBackupFoldersNearTime {
    <#
    .SYNOPSIS
        Backup folder names ARE full timestamps (yyyy-MM-dd_HHmmss, set by
        Start-CcdcSession), so these parse and compare directly.
    #>
    [CmdletBinding()]
    param(
        [string[]]$FolderNames,
        [datetime]$CenterTime,
        [int]$WindowMinutes = 30
    )
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($FolderNames)) {
        $parsed = [datetime]::MinValue
        $ok = [datetime]::TryParseExact(
            $n, 'yyyy-MM-dd_HHmmss', $null,
            [System.Globalization.DateTimeStyles]::None, [ref]$parsed
        )
        if ($ok -and [math]::Abs(($parsed - $CenterTime).TotalMinutes) -le $WindowMinutes) {
            $found.Add($n)
        }
    }
    return $found.ToArray()
}

function Get-CcdcCaptureFilesNearTime {
    <#
    .SYNOPSIS
        Invoke-PacketCapture.ps1 names its files
        <host>_<yyyy-MM-dd_HHmmss>.pcapng -- the timestamp is embedded
        rather than being the whole filename (unlike the backup folders
        above), so this pulls it out with a regex before comparing.
    #>
    [CmdletBinding()]
    param(
        [string[]]$FileNames,
        [datetime]$CenterTime,
        [int]$WindowMinutes = 30
    )
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($FileNames)) {
        if ($n -match '_(?<ts>\d{4}-\d{2}-\d{2}_\d{6})\.pcapng$') {
            $parsed = [datetime]::MinValue
            $ok = [datetime]::TryParseExact(
                $Matches.ts, 'yyyy-MM-dd_HHmmss', $null,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsed
            )
            if ($ok -and [math]::Abs(($parsed - $CenterTime).TotalMinutes) -le $WindowMinutes) {
                $found.Add($n)
            }
        }
    }
    return $found.ToArray()
}

function Get-CcdcEvidenceFoldersNearTime {
    <#
    .SYNOPSIS
        Invoke-EvidenceCollection.ps1 names its folders
        <host>_<yyyy-MM-dd_HHmmss> -- same embedded-timestamp shape as the
        capture filenames above, just with no extension to strip.
    #>
    [CmdletBinding()]
    param(
        [string[]]$FolderNames,
        [datetime]$CenterTime,
        [int]$WindowMinutes = 30
    )
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($FolderNames)) {
        if ($n -match '_(?<ts>\d{4}-\d{2}-\d{2}_\d{6})$') {
            $parsed = [datetime]::MinValue
            $ok = [datetime]::TryParseExact(
                $Matches.ts, 'yyyy-MM-dd_HHmmss', $null,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsed
            )
            if ($ok -and [math]::Abs(($parsed - $CenterTime).TotalMinutes) -le $WindowMinutes) {
                $found.Add($n)
            }
        }
    }
    return $found.ToArray()
}

function Test-CcdcAnyNonBlank {
    [CmdletBinding()]
    param([string[]]$Values)
    foreach ($v in @($Values)) {
        if ($v -and $v.Trim()) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# External-tool argument builders (nmap / tshark)
# ---------------------------------------------------------------------------

function Get-CcdcNmapArgs {
    <#
    .SYNOPSIS
        Builds the nmap argument list for a given profile/target/
        credentials, so the actual command-building logic can be verified
        without nmap installed.

        The SMB credential is NEVER put on the command line: a process's
        arguments are visible to anything that can list processes, and to
        Sysmon's own process-creation logging. It goes into a short-lived
        file that nmap reads via --script-args-file instead (the caller
        creates and deletes that file; this function only needs its path).
    #>
    [CmdletBinding()]
    param(
        [string]$ScanProfileName,
        [string]$TargetHost,
        [string]$OutputBase,
        [string]$SmbUser,
        [string]$ScriptArgsFilePath
    )
    $nmapArgs = New-Object System.Collections.Generic.List[string]
    switch ($ScanProfileName) {
        'Quick' { $nmapArgs.AddRange([string[]]@('-T4', '-F')) }
        'Full'  { $nmapArgs.AddRange([string[]]@('-T4', '-p-')) }
        'Vuln'  { $nmapArgs.AddRange([string[]]@('-T4', '-p-', '--script', 'default,vuln')) }
    }
    if ($SmbUser -and $ScriptArgsFilePath) {
        $nmapArgs.AddRange([string[]]@('--script-args-file', $ScriptArgsFilePath))
    }
    $nmapArgs.AddRange([string[]]@('-oN', "$OutputBase.txt", '-oX', "$OutputBase.xml"))
    $nmapArgs.Add($TargetHost)
    return $nmapArgs.ToArray()
}

function Test-CcdcUnexpectedOpenPort {
    <#
    .SYNOPSIS
        Given a discovered open port and the set of expected (scored +
        standard management) ports, is it worth flagging?
    #>
    [CmdletBinding()]
    param(
        [int]$Port,
        [int[]]$ExpectedPorts
    )
    return ($ExpectedPorts -notcontains $Port)
}

function Get-CcdcTsharkArgs {
    <#
    .SYNOPSIS
        Builds the tshark argument list for a given duration/interface/
        filter/output path.
    #>
    [CmdletBinding()]
    param(
        [int]$Duration,
        [string]$Iface,
        [string]$Filter,
        [string]$OutputPath
    )
    $tsharkArgs = New-Object System.Collections.Generic.List[string]
    $tsharkArgs.AddRange([string[]]@('-i', $Iface, '-a', "duration:$Duration", '-w', $OutputPath))
    if ($Filter) { $tsharkArgs.AddRange([string[]]@('-f', $Filter)) }
    return $tsharkArgs.ToArray()
}

# ===========================================================================
# Configuration baseline: "what it should look like" vs "what it looks like"
# ===========================================================================

function Get-CcdcNameTamperFlag {
    <#
    .SYNOPSIS
        Flags a file or object name that has been altered in a way designed
        not to be noticed. Returns an array of short reason strings; an
        empty array means the name looks ordinary.

    .DESCRIPTION
        This exists because of a specific attack a returning competitor
        described: their AD went down because a file the DNS server loads
        was renamed with a space added to the end. Nothing was deleted, so
        nothing looked missing, and a trailing space is invisible in
        Explorer, in a directory listing, and in most of a log line.

        A DNS zone that fails to load takes the domain's SRV records with
        it, so a one-character rename on one file can stop authentication
        for the whole environment. The same trick works on anything
        referenced by path: a scheduled task's script, a service binary, a
        GPO startup script, a web config include.

        Checked here, in order of how often they actually show up:
          - leading or trailing whitespace (the reported attack)
          - a trailing dot, which Windows also silently tolerates
          - two or more spaces in a row
          - a non-ASCII character in a name that is otherwise ASCII, which
            covers Cyrillic/Greek homoglyphs (a Cyrillic 'a' in "database")
          - bidirectional-override characters, which reverse how the rest
            of the name renders and can make "exe.txt" read as "txt.exe"
          - a double extension ending in something executable

        No baseline is needed for any of this, which matters: it works on
        the first run, on a box you have never seen before, mid-incident.
    #>
    [CmdletBinding()]
    param([string]$Name)

    $flags = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Name -or $Name.Length -eq 0) { return $flags.ToArray() }

    if ($Name -ne $Name.Trim()) {
        # Reported separately because which end it is tells you something:
        # a trailing space is the classic "break the reference" move.
        if ($Name.EndsWith(' ') -or $Name.EndsWith("`t")) { $flags.Add('ends with whitespace') }
        if ($Name.StartsWith(' ') -or $Name.StartsWith("`t")) { $flags.Add('starts with whitespace') }
    }
    if ($Name.EndsWith('.')) { $flags.Add('ends with a dot') }
    if ($Name -match '  ') { $flags.Add('contains a double space') }

    $nonAscii = New-Object System.Collections.Generic.List[string]
    foreach ($ch in $Name.ToCharArray()) {
        if ([int]$ch -gt 127) {
            $code = 'U+{0:X4}' -f [int]$ch
            if (-not $nonAscii.Contains($code)) { $nonAscii.Add($code) }
        }
    }
    if ($nonAscii.Count -gt 0) {
        $flags.Add('contains non-ASCII character(s): ' + ($nonAscii -join ', '))
    }

    # U+202E RIGHT-TO-LEFT OVERRIDE and friends. Already caught by the
    # non-ASCII check, but called out by name because the consequence is
    # different in kind: the name you read is not the name that is stored.
    foreach ($bidi in @([char]0x202A, [char]0x202B, [char]0x202D, [char]0x202E, [char]0x200F, [char]0x200E)) {
        if ($Name.IndexOf($bidi) -ge 0) {
            $flags.Add('contains a text-direction override character, so the displayed name is not the real one')
            break
        }
    }

    if ($Name -match '\.(txt|log|pdf|doc|docx|jpg|png|csv|xml)\.(exe|dll|ps1|bat|cmd|vbs|scr|js)$') {
        $flags.Add('double extension ending in an executable one')
    }

    return $flags.ToArray()
}

function Compare-CcdcBaselineSet {
    <#
    .SYNOPSIS
        Diffs a captured baseline against what is there now. Items are
        keyed pairs -- @{ Key = 'name'; Value = 'hash or state' } -- and
        the result separates Added, Removed and Changed.

    .DESCRIPTION
        Deliberately a pure function over two flat lists so the same
        comparison serves every area of the baseline: zone files by hash,
        services by start mode, firewall rules by action, local
        administrators by membership.

        Key comparison is case-insensitive because Windows paths and
        account names are. Value comparison is case-SENSITIVE, because a
        SHA-256 hash that differs only in case is still the same hash, but
        a path or a start mode that changed case has genuinely changed and
        we would rather show a harmless diff than hide a real one.

        Missing keys are reported, not treated as errors: a baseline
        captured on a DC and verified on a web server SHOULD show
        everything as removed, and saying so plainly is more useful than
        guessing that the operator picked the wrong file.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Baseline,
        [object[]]$Current
    )

    $baseMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($b in @($Baseline)) {
        if ($null -eq $b) { continue }
        $k = [string]$b.Key
        if (-not $k) { continue }
        $baseMap[$k] = [string]$b.Value
    }

    $added = New-Object System.Collections.Generic.List[object]
    $changed = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($c in @($Current)) {
        if ($null -eq $c) { continue }
        $k = [string]$c.Key
        if (-not $k) { continue }
        [void]$seen.Add($k)
        $now = [string]$c.Value
        if (-not $baseMap.ContainsKey($k)) {
            $added.Add([pscustomobject]@{ Key = $k; Value = $now })
        } elseif ($baseMap[$k] -cne $now) {
            $changed.Add([pscustomobject]@{ Key = $k; Was = $baseMap[$k]; Now = $now })
        }
    }

    $removed = New-Object System.Collections.Generic.List[object]
    foreach ($k in $baseMap.Keys) {
        if (-not $seen.Contains($k)) {
            $removed.Add([pscustomobject]@{ Key = $k; Value = $baseMap[$k] })
        }
    }

    return [pscustomobject]@{
        Added        = $added.ToArray()
        Removed      = $removed.ToArray()
        Changed      = $changed.ToArray()
        DriftCount   = $added.Count + $removed.Count + $changed.Count
        BaselineSize = $baseMap.Count
        CurrentSize  = $seen.Count
    }
}

function Get-CcdcBaselineAreaVerdict {
    <#
    .SYNOPSIS
        Turns one area's diff into a severity and a sentence a person can
        act on.

    .DESCRIPTION
        Severity is by area, not by count, because the areas are not
        equally alarming. One new local administrator matters more than
        twenty changed file hashes on a web server somebody is actively
        patching, and a zone file that DISAPPEARED is worse than one that
        changed.

        Areas marked high-stakes here escalate any drift at all to ERROR:
        privileged group membership, DNS zone files, DHCP scope config,
        services and scheduled tasks. Everything else reports WARN, because on a box
        being actively hardened some drift is your own work and crying
        ERROR at all of it trains people to ignore the output.
    #>
    [CmdletBinding()]
    param(
        [string]$Area,
        $Diff
    )

    if ($null -eq $Diff) {
        return [pscustomobject]@{ Area = $Area; Level = 'INFO'; Message = "$Area : nothing captured to compare." }
    }
    if ($Diff.DriftCount -eq 0) {
        return [pscustomobject]@{ Area = $Area; Level = 'OK'; Message = "$Area : matches the baseline ($($Diff.BaselineSize) item(s))." }
    }

    $highStakes = @('DnsZoneFiles', 'DnsZones', 'DhcpScopes', 'DhcpScopeOptions', 'DhcpAuthorizedServers', 'LocalAdministrators', 'DomainAdmins', 'EnterpriseAdmins', 'Services', 'ScheduledTasks')
    $level = if ($highStakes -contains $Area) { 'ERROR' } else { 'WARN' }

    $parts = New-Object System.Collections.Generic.List[string]
    if ($Diff.Added.Count -gt 0) { $parts.Add("$($Diff.Added.Count) added") }
    if ($Diff.Removed.Count -gt 0) { $parts.Add("$($Diff.Removed.Count) missing") }
    if ($Diff.Changed.Count -gt 0) { $parts.Add("$($Diff.Changed.Count) changed") }

    # A removal in a high-stakes area is the specific shape of the attack
    # this module was built for, so it gets said out loud rather than left
    # as a number to interpret.
    $tail = ''
    if ($Diff.Removed.Count -gt 0 -and ($Area -eq 'DnsZoneFiles' -or $Area -eq 'DnsZones')) {
        $tail = " Something the DNS server expects is no longer there -- check for a renamed file before assuming it was deleted."
    }

    return [pscustomobject]@{
        Area    = $Area
        Level   = $level
        Message = "$Area : $($parts -join ', ') versus the baseline.$tail"
    }
}

# ===========================================================================
# Known-exposure audit: the pure parts
# ===========================================================================

# ===========================================================================
# DNS hardening: the pure parts
# ===========================================================================

function Get-CcdcDnsZoneTransferVerdict {
    <#
    .SYNOPSIS
        Reads a zone's SecureSecondaries setting and says whether the zone
        can be copied by someone who should not have it.

    .DESCRIPTION
        A zone transfer hands over every hostname and address in the zone
        in one request. Microsoft's own guidance grades it: transfers to
        any server is the low-security setting, transfers limited to the
        zone's name servers is medium, and limiting to named addresses is
        high. In a competition nothing legitimately pulls a transfer, so
        NoTransfer is both the most secure and the least disruptive.

        TransferToZoneNameServer is treated as acceptable rather than
        ideal: it is the Windows default, it is not wide open, and
        changing it is not where the time goes.
    #>
    [CmdletBinding()]
    param([string]$SecureSecondaries)

    switch ("$SecureSecondaries") {
        'NoTransfer' {
            return [pscustomobject]@{ Vulnerable = $false; State = 'NoTransfer'; Detail = 'Zone transfers are refused outright.' }
        }
        'TransferAnyServer' {
            return [pscustomobject]@{ Vulnerable = $true; State = 'TransferAnyServer'; Detail = 'ANY server can pull this entire zone -- every hostname and address in one request. This is the footprinting shortcut.' }
        }
        'TransferToZoneNameServer' {
            return [pscustomobject]@{ Vulnerable = $false; State = 'TransferToZoneNameServer'; Detail = 'Transfers are limited to the zone name servers, which is the Windows default and not wide open.' }
        }
        'TransferToSecureServers' {
            return [pscustomobject]@{ Vulnerable = $false; State = 'TransferToSecureServers'; Detail = 'Transfers are limited to a named list of servers.' }
        }
        default {
            return [pscustomobject]@{ Vulnerable = $true; State = "unknown ($SecureSecondaries)"; Detail = 'Could not read the zone transfer setting, so this is untested rather than safe.' }
        }
    }
}

function Get-CcdcDnsDynamicUpdateVerdict {
    <#
    .SYNOPSIS
        Reads a zone's DynamicUpdate mode and returns both the verdict and
        the value this zone can actually be set to.

    .DESCRIPTION
        Nonsecure dynamic update lets an unauthenticated host overwrite
        records in the zone -- including the ones clients use to find the
        domain controller. That is not a theoretical problem: repointing a
        name is how traffic gets redirected without touching the host it
        was going to.

        The target value DEPENDS ON THE ZONE TYPE, which is the trap here.
        'Secure' requires Active Directory integration and the cmdlet
        rejects it on a file-backed zone, so a hardening script that sets
        Secure everywhere fails on exactly the zones that most need
        attention. For a file-backed zone the secure value is 'None', and
        that is NOT safe to apply blindly: it stops clients registering
        themselves at all.
    #>
    [CmdletBinding()]
    param(
        [string]$DynamicUpdate,
        [bool]$IsDsIntegrated
    )

    $mode = "$DynamicUpdate"
    if ($mode -eq 'None' -or $mode -eq 'Secure') {
        return [pscustomobject]@{
            Vulnerable = $false; State = $mode; Target = $mode; SafeToChange = $false
            Detail = "Dynamic update is set to $mode, which does not accept unauthenticated updates."
        }
    }
    if ($mode -eq 'NonsecureAndSecure') {
        if ($IsDsIntegrated) {
            return [pscustomobject]@{
                Vulnerable = $true; State = $mode; Target = 'Secure'; SafeToChange = $true
                Detail = 'Unauthenticated hosts can overwrite records in this zone. It is AD-integrated, so Secure is available and domain members keep registering normally.'
            }
        }
        return [pscustomobject]@{
            Vulnerable = $true; State = $mode; Target = 'None'; SafeToChange = $false
            Detail = 'Unauthenticated hosts can overwrite records in this zone. It is file-backed, so Secure is NOT available -- only None is, and that stops every client registering itself. Decide deliberately, or convert the zone to AD-integrated first.'
        }
    }
    return [pscustomobject]@{
        Vulnerable = $true; State = "unknown ($mode)"; Target = ''; SafeToChange = $false
        Detail = 'Could not read the dynamic update mode, so this is untested rather than safe.'
    }
}

function Get-CcdcDnsRecordDataText {
    <#
    .SYNOPSIS
        A human-readable rendering of what a DNS record actually points
        at -- never the CIM type name.

    .DESCRIPTION
        Found on the real lab DC. Get-DnsServerResourceRecord's
        .RecordData is a CimInstance, and a CimInstance's own ToString()
        returns its CLASS name ("DnsServerResourceRecordA"), not the data
        it holds. A caller that does $record.RecordData.ToString() gets
        exactly that class name back, which is how the threat hunt
        reported a freshly planted A record as:

            DNS record added or changed since last check: update A DnsServerResourceRecordA

        -- confirming something changed, never WHERE it points, which is
        the one fact that actually matters for a DNS hijack (a red team
        repointing an A or CNAME record at their own box). A test that
        plants a known record and checks for its IP address in the hunt's
        own output is what caught this -- nothing about the class-name
        string looks wrong on casual reading, so it had never been
        noticed by eye either.

        Tries the property each common record type actually stores its
        payload in (A/AAAA -> address, CNAME -> alias, TXT -> text,
        MX/NS/PTR/SRV -> the target name), then falls back to every other
        non-empty simple property, SORTED BY NAME for a repeatable
        result -- CIM does not guarantee property enumeration order is
        stable across calls, and an unstable rendering would make a
        record that never changed look "new" on every single pass of a
        diff-based hunt.

    .PARAMETER RecordData
        The .RecordData value from one Get-DnsServerResourceRecord result
        (a CimInstance), or anything else -- degrades to .ToString() for a
        plain value, and to 'unknown' for $null or an object with nothing
        readable on it.
    #>
    [CmdletBinding()]
    param($RecordData)

    if ($null -eq $RecordData) { return 'unknown' }

    # A plain string already IS the answer -- do not walk its .NET
    # properties below (a string's .Length, for instance, which is real
    # but is noise, not DNS data). Only a composite object -- a
    # CimInstance, in practice -- needs the property search.
    if ($RecordData -is [string]) {
        return $(if ("$RecordData".Trim()) { "$RecordData" } else { 'unknown' })
    }

    $payloadProps = 'IPv4Address', 'IPv6Address', 'HostNameAlias', 'DescriptiveText',
    'MailExchange', 'NameServer', 'PtrDomainName', 'DomainName', 'PrimaryServer'
    try {
        foreach ($name in $payloadProps) {
            $p = $RecordData.PSObject.Properties[$name]
            if ($p -and $null -ne $p.Value -and "$($p.Value)".Trim()) { return "$($p.Value)" }
        }
        $rest = @($RecordData.PSObject.Properties |
                Where-Object {
                    $_.Value -isnot [Microsoft.Management.Infrastructure.CimInstance] -and
                    $null -ne $_.Value -and "$($_.Value)".Trim()
                } |
                Sort-Object Name |
                ForEach-Object { "$($_.Value)" })
        if ($rest.Count -gt 0) { return ($rest -join ' ') }
    } catch { }

    try {
        $s = "$($RecordData.ToString())"
        if ($s -and $s -ne $RecordData.GetType().Name) { return $s }
    } catch { }
    return 'unknown'
}

function Get-CcdcSuspiciousDnsRecordFlag {
    <#
    .SYNOPSIS
        Flags a DNS record worth a human look. Returns reason strings; an
        empty array means nothing stood out.

    .DESCRIPTION
        Not "this is malicious" -- a narrowing tool. A zone has hundreds of
        records and a person has minutes, so this picks out the handful
        with the shapes that get used:

          wildcard    one record answers every name that is not defined,
                      which quietly catches typos and anything you forgot
          TXT / NULL  the usual carriers for tunnelled data; NULL has
          / HINFO     essentially no legitimate modern use
          short TTL   a TTL under a minute is how a destination gets moved
                      faster than anyone notices
          off-subnet  an A record inside your zone pointing somewhere that
                      is not your network at all

        Record types that are normal in volume (A, AAAA, SRV, NS, SOA,
        CNAME, PTR) are not flagged on type alone.
    #>
    [CmdletBinding()]
    param(
        [string]$HostName,
        [string]$RecordType,
        [int]$TtlSeconds = 3600,
        [string]$RecordData,
        [string]$ExpectedSubnetPrefix
    )

    $flags = New-Object System.Collections.Generic.List[string]

    if ("$HostName" -eq '*' -or "$HostName".StartsWith('*.')) {
        $flags.Add('wildcard record: answers every name that is not explicitly defined')
    }
    if ("$RecordType" -in 'TXT', 'NULL', 'HINFO') {
        $flags.Add("$RecordType record: the usual carrier for tunnelled data")
    }
    if ($TtlSeconds -gt 0 -and $TtlSeconds -lt 60) {
        $flags.Add("TTL of ${TtlSeconds}s: short enough to move a destination faster than anyone would notice")
    }
    if ($ExpectedSubnetPrefix -and "$RecordType" -eq 'A' -and $RecordData) {
        if (-not ("$RecordData".StartsWith($ExpectedSubnetPrefix))) {
            $flags.Add("points to $RecordData, which is outside $ExpectedSubnetPrefix")
        }
    }

    return $flags.ToArray()
}

function Select-CcdcCredentialTarget {
    <#
    .SYNOPSIS
        The accounts to actually rotate, with the same principal never
        listed twice.

    .DESCRIPTION
        Found on the real lab domain controller, not in a test. Credential
        hardening builds its list from two places -- enabled local accounts
        and enabled directory accounts -- and on a DC those are THE SAME
        OBJECTS, because a domain controller has no local SAM and
        Get-LocalUser returns directory objects there. The preview said:

            10 account(s) queued for a password reset:
            alice, bob, carol, olduser, itadmin, alice, bob, carol, olduser, itadmin

        For real, that resets every account TWICE, to two different random
        passwords. The first is what gets recorded and handed to the team;
        the second is what the account actually has. The result is a
        credential sheet on which every single entry is wrong, discovered
        when nobody can log in -- in the middle of a round, caused by the
        tool that was supposed to be helping.

        The de-duplication is deliberately NOT unconditional. On a member
        server or a workstation, LABWEB\alice and LAB\alice are different
        principals that genuinely both need rotating, and collapsing them
        would quietly skip one. So local entries are only dropped in favour
        of a same-named domain entry when this box is a domain controller,
        where they provably describe one object.

        Exact (Name, Scope) duplicates are always collapsed -- those are
        never two principals, just the same one enumerated twice. Order is
        preserved so the log reads in the order the accounts were found.

    .PARAMETER Candidate
        Objects with .Name and .Scope ('Local' or 'Domain').

    .PARAMETER IsDomainController
        True when this box is a DC (Win32_ComputerSystem.DomainRole 4 or 5).

    .OUTPUTS
        The candidates to keep, in their original order.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Candidate,
        [bool]$IsDomainController
    )

    $kept = New-Object System.Collections.Generic.List[object]
    if (-not $Candidate) { return $kept.ToArray() }

    $domainNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Candidate) {
        if ($c -and "$($c.Scope)" -eq 'Domain') { [void]$domainNames.Add("$($c.Name)") }
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Candidate) {
        if (-not $c) { continue }
        $name = "$($c.Name)"
        $scope = "$($c.Scope)"
        if (-not $name) { continue }

        # The same principal enumerated twice in one scope.
        if (-not $seen.Add("$scope|$name")) { continue }

        # On a DC only, a 'Local' hit is the directory object the 'Domain'
        # pass already has.
        if ($IsDomainController -and $scope -eq 'Local' -and $domainNames.Contains($name)) { continue }

        $kept.Add($c)
    }
    return $kept.ToArray()
}

function Test-CcdcRotatableAccountName {
    <#
    .SYNOPSIS
        False for an account whose password must never be rotated by this
        toolkit: a computer account or a trust account.

    .DESCRIPTION
        Found on a real domain controller, not in a test. On a DC,
        Get-LocalUser does not return local accounts -- a DC has none --
        it returns directory objects, and that includes COMPUTER accounts.
        The credential-hardening preview on the lab DC duly queued:

            Reset Local account password on target "LABDC$"
            Reset Local account password on target "LABFTP$"

        Resetting a computer account's password breaks that machine's
        secure channel with the domain. Doing it to a member server stops
        it authenticating, which takes its scored service down; doing it
        to the domain controller's own account is worse. Either is an
        unrecoverable-looking failure in the middle of a round, caused by
        the tool that was supposed to be helping.

        A computer or trust account's sAMAccountName always ends in '$',
        and an ordinary user's never does, so the test is exact rather
        than heuristic.
    #>
    [CmdletBinding()]
    param([string]$Name)

    if ($null -eq $Name) { return $false }
    $n = $Name.Trim()
    if (-not $n) { return $false }
    if ($n.EndsWith('$')) { return $false }
    return $true
}

function Test-CcdcExposureApplies {
    <#
    .SYNOPSIS
        Does a catalogue entry apply to this host? Keeps a DC-only check off
        a web server and vice versa.

    .DESCRIPTION
        Role is what the box IS, not what it runs: 'DC', 'Member', 'Client'.
        An entry's Applies is one of those, or 'Server' (any non-client), or
        'Any'.

        A check aimed at the wrong box is worse than no check: it either
        errors, or it reports a clean result that means nothing, and both
        teach whoever reads the output to stop reading it.
    #>
    [CmdletBinding()]
    param(
        [string]$Applies,
        [string]$HostRole
    )
    if (-not $Applies) { return $false }
    if ($Applies -eq 'Any') { return $true }
    if ($Applies -eq 'Server') { return ($HostRole -eq 'DC' -or $HostRole -eq 'Member') }
    return ($Applies -eq $HostRole)
}

function Test-CcdcUnquotedServicePath {
    <#
    .SYNOPSIS
        True when a service's ImagePath is exploitable through the unquoted
        service path trick.

    .DESCRIPTION
        Windows resolves an unquoted path by trying each space-separated
        prefix with .exe appended, so

            C:\Program Files\My App\svc.exe

        makes Windows try C:\Program.exe, then "C:\Program Files\My.exe",
        before the real binary. A writable parent folder therefore decides
        what runs as SYSTEM.

        Only genuinely risky paths return true:
          - a quoted path is fine, however many spaces it has
          - a path with no space is fine
          - a path under C:\Windows is excluded, because an attacker who can
            write there has already won and every box would otherwise report
            a pile of Microsoft services
          - arguments after the executable are ignored; only the image path
            can be hijacked
    #>
    [CmdletBinding()]
    param([string]$PathName)

    if (-not $PathName) { return $false }
    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) { return $false }

    # Deliberately NOT Get-CcdcServiceExePath: that splits an unquoted
    # string on the first space, which is precisely the ambiguity this
    # vulnerability exploits -- it would turn
    # "C:\Program Files\My App\svc.exe" into "C:\Program" and report the
    # exploitable case as safe. Cut at the first .exe instead: everything
    # up to and including it is the image path Windows has to resolve,
    # and anything after it is arguments, which cannot be hijacked.
    $exe = $trimmed
    $idx = $trimmed.IndexOf('.exe', [System.StringComparison]::OrdinalIgnoreCase)
    if ($idx -ge 0) { $exe = $trimmed.Substring(0, $idx + 4) }

    if (-not $exe) { return $false }
    if ($exe -notmatch '\s') { return $false }

    # Drive-relative paths only; a service with a bare command name is not
    # the shape this attack needs.
    if ($exe -notmatch '^[A-Za-z]:\\') { return $false }

    $systemRoot = 'C:\Windows'
    if ($env:SystemRoot) { $systemRoot = $env:SystemRoot }
    if ($exe.StartsWith($systemRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }

    return $true
}

function Get-CcdcLmCompatibilityVerdict {
    <#
    .SYNOPSIS
        Reads LmCompatibilityLevel and says whether NTLMv1 or LM can still
        be used.

    .DESCRIPTION
        Levels 0-2 send LM and/or NTLMv1 responses, which are crackable in
        minutes. Level 3 sends only NTLMv2 but still ACCEPTS the weaker
        ones as a server. Only 5 refuses them outright.

        An absent value is not the same as a safe one: the default differs
        by Windows version, so "not set" is reported as unknown rather than
        quietly assumed good.
    #>
    [CmdletBinding()]
    param($Level)

    if ($null -eq $Level -or "$Level" -eq '') {
        return [pscustomobject]@{ Vulnerable = $true; State = 'not set'; Detail = 'LmCompatibilityLevel is not set, so the default for this Windows version applies. Set it to 5 rather than relying on that.' }
    }
    $n = 0
    if (-not [int]::TryParse("$Level", [ref]$n)) {
        return [pscustomobject]@{ Vulnerable = $true; State = "unreadable ($Level)"; Detail = 'Could not read LmCompatibilityLevel as a number.' }
    }
    if ($n -le 2) {
        return [pscustomobject]@{ Vulnerable = $true; State = "level $n"; Detail = 'LM and/or NTLMv1 responses are SENT by this box. Those crack in minutes.' }
    }
    if ($n -le 4) {
        return [pscustomobject]@{ Vulnerable = $true; State = "level $n"; Detail = 'This box sends NTLMv2 but still accepts NTLMv1 from others. Level 5 refuses it.' }
    }
    return [pscustomobject]@{ Vulnerable = $false; State = "level $n"; Detail = 'NTLMv2 only, in both directions.' }
}

function Get-CcdcMachineAccountQuotaVerdict {
    <#
    .SYNOPSIS
        Reads ms-DS-MachineAccountQuota and says whether an ordinary user
        can still create computer accounts.

    .DESCRIPTION
        The default of 10 is what makes sAMAccountName spoofing (noPac)
        work from a single ordinary domain account. Zero closes it, and in
        a competition nothing should be joining the domain anyway.
    #>
    [CmdletBinding()]
    param($Quota)

    if ($null -eq $Quota -or "$Quota" -eq '') {
        return [pscustomobject]@{ Vulnerable = $true; State = 'unknown'; Detail = 'Could not read ms-DS-MachineAccountQuota from the domain.' }
    }
    $n = -1
    if (-not [int]::TryParse("$Quota", [ref]$n)) {
        return [pscustomobject]@{ Vulnerable = $true; State = "unreadable ($Quota)"; Detail = 'ms-DS-MachineAccountQuota did not read as a number.' }
    }
    if ($n -gt 0) {
        return [pscustomobject]@{ Vulnerable = $true; State = "$n"; Detail = "Any domain user can create up to $n computer account(s). That is the precondition for sAMAccountName spoofing." }
    }
    return [pscustomobject]@{ Vulnerable = $false; State = '0'; Detail = 'Ordinary users cannot create computer accounts.' }
}

function Get-CcdcExposureSummary {
    <#
    .SYNOPSIS
        Counts an audit's findings by severity and returns the headline
        sentence.

    .DESCRIPTION
        Only findings that are actually VULNERABLE count. A box where
        everything was checked and nothing was found should say so
        plainly, because "0 findings" and "nothing could be checked" are
        very different answers and get confused constantly.
    #>
    [CmdletBinding()]
    param([object[]]$Findings)

    $all = @($Findings)
    $vuln = @($all | Where-Object { $_.Vulnerable })
    $unknown = @($all | Where-Object { -not $_.Vulnerable -and $_.State -match 'unknown|unreadable' })

    $critical = @($vuln | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = @($vuln | Where-Object { $_.Severity -eq 'High' }).Count
    $medium = @($vuln | Where-Object { $_.Severity -eq 'Medium' }).Count

    $message = if ($all.Count -eq 0) {
        'Nothing was checked -- no catalogue entries applied to this host.'
    } elseif ($vuln.Count -eq 0) {
        "Checked $($all.Count) known exposure(s); none are present on this box."
    } else {
        "$($vuln.Count) of $($all.Count) checked exposure(s) are present: $critical critical, $high high, $medium medium."
    }

    return [pscustomobject]@{
        Checked      = $all.Count
        Vulnerable   = $vuln.Count
        Critical     = $critical
        High         = $high
        Medium       = $medium
        Unknown      = $unknown.Count
        Message      = $message
    }
}

function Get-CcdcModuleLaunchArgs {
    <#
    .SYNOPSIS
        The powershell.exe argument list for opening one toolkit module in
        its own window.

    .DESCRIPTION
        Pulled out of the UI and made pure because of a bug that killed
        eleven of the thirteen buttons on the window's Modules tab. The
        old line was:

            @('-NoProfile', ..., '-File', $path) + @($Module.Args)

        and most module entries have no Args key at all. `@($null)` is not
        an empty array -- it is an array containing one $null -- so the
        list ended with a null element and Start-Process refused the whole
        call:

            Cannot validate argument on parameter 'ArgumentList'. The
            argument is null, empty, or an element of the argument
            collection contains a null value.

        Every card without extra arguments therefore did nothing at all,
        and said so in red, over and over. Nulls and empty strings are
        filtered here so that cannot come back.

        The script path is quoted because nothing stops the repo being
        cloned to a path with a space in it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string[]]$ExtraArgs
    )

    $launch = New-Object System.Collections.Generic.List[string]
    $launch.AddRange([string[]]@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"' + $ScriptPath + '"')))
    foreach ($a in @($ExtraArgs)) {
        if ($null -eq $a) { continue }
        $t = "$a"
        if ($t.Trim().Length -eq 0) { continue }
        $launch.Add($t)
    }
    return $launch.ToArray()
}

function ConvertFrom-CcdcNetLocalGroupOutput {
    <#
    .SYNOPSIS
        Pulls the member names out of `net localgroup <name>` output.

    .DESCRIPTION
        The last-resort way to read the Administrators group, used when
        neither Get-LocalGroupMember (which fails on a domain controller)
        nor Get-ADGroupMember is available or working. net.exe has behaved
        the same way since NT and needs no module, which is exactly what
        you want from a fallback.

        Its output looks like:

            Alias name     Administrators
            Comment        Administrators have complete and unrestricted...

            Members

            ----------------------------------------------------------
            Administrator
            LAB\Domain Admins
            The command completed successfully.

        So: everything after the dashed rule, stopping at the trailing
        "The command completed successfully." line, ignoring blanks. The
        header block above the rule is skipped rather than parsed,
        because its wording is localized and its field names are not.

        Kept pure and separate so the parsing can be tested without
        running net.exe or faking an external program.
    #>
    [CmdletBinding()]
    param([string[]]$Lines)

    $members = New-Object System.Collections.Generic.List[string]
    $inList = $false
    foreach ($line in @($Lines)) {
        if ($null -eq $line) { continue }
        if ($line -match '^-{5,}') { $inList = $true; continue }
        if (-not $inList) { continue }
        $t = ([string]$line).Trim()
        if (-not $t) { continue }
        # Localized Windows says something else here, so the English
        # string is a best-effort stop, not the only one: the line is also
        # the last one net.exe prints, so anything after it is nothing.
        if ($t -like 'The command completed*') { break }
        $members.Add($t)
    }
    return $members.ToArray()
}

function ConvertTo-CcdcHtmlText {
    <#
    .SYNOPSIS
        Escapes a string for safe inclusion in HTML, and turns blank lines
        into paragraph breaks.

    .DESCRIPTION
        Incident reports quote attacker-controlled material by their very
        nature: filenames, user agents, process command lines, the contents
        of a web shell. Dropping that into an HTML report unescaped means a
        report that renders wrong at best, and at worst carries the payload
        into whatever opens it.

        Ampersand is replaced first; doing it later would double-escape the
        entities produced by the other replacements.

        Written by hand rather than with [System.Web.HttpUtility] because
        that lives in an assembly that is not loaded by default on Server
        Core, and this has to work on a stripped-down box.
    #>
    [CmdletBinding()]
    param([string]$Text)

    if ($null -eq $Text -or $Text.Length -eq 0) { return '' }
    $out = $Text.Replace('&', '&amp;')
    $out = $out.Replace('<', '&lt;')
    $out = $out.Replace('>', '&gt;')
    $out = $out.Replace('"', '&quot;')
    $out = $out.Replace("'", '&#39;')
    return $out
}

function Get-CcdcIncidentReportGap {
    <#
    .SYNOPSIS
        Names the required incident-report fields that are still blank.

    .DESCRIPTION
        The required set is not a matter of taste. The competition packet
        says a report must contain source and destination IP addresses, a
        timeline of activity, any passwords cracked, what was affected and
        a remediation plan; the incident-reporting inject adds scope,
        delivery mechanism, damage, and supporting evidence. Reports are
        scored on clarity, thoroughness and accuracy, so a blank required
        field is a scored gap rather than a stylistic one.

        Returned as field names so the caller can both warn and show what
        is still missing before anything gets submitted.
    #>
    [CmdletBinding()]
    param([hashtable]$Fields)

    $required = [ordered]@{
        Description  = 'a clear description of what happened'
        Scope        = 'scope: which systems, applications and services were affected'
        Timeline     = 'the time window and sequence of activity'
        SourceIp     = 'the source IP address of the attack'
        DestIp       = 'the destination IP address that was targeted'
        Delivery     = 'the delivery mechanism -- how they got in'
        Impact       = 'the damage or business impact'
        Evidence     = 'supporting evidence: logs, files, captures'
        Remediation  = 'the remediation performed'
        Prevention   = 'how this vector is closed for good'
    }

    $missing = New-Object System.Collections.Generic.List[object]
    foreach ($key in $required.Keys) {
        $value = $null
        if ($Fields -and $Fields.ContainsKey($key)) { $value = $Fields[$key] }
        if (-not (Test-CcdcAnyNonBlank -Values @($value))) {
            $missing.Add([pscustomobject]@{ Field = $key; Needs = $required[$key] })
        }
    }
    return $missing.ToArray()
}

function Get-CcdcPatchStatusVerdict {
    <#
    .SYNOPSIS
        Health verdict for how far behind a box's patching is.

    .DESCRIPTION
        A returning competitor's summary was that keeping machines updated
        is one of the better things you can do to keep red team out, and
        the reasoning holds: competition images start deliberately
        unpatched, and an unpatched box is exploitable from a public
        write-up rather than from original work.

        The counter-pressure is that patching reboots, and a reboot is
        downtime against the uptime score. So this reports and does not
        act: it says how old the newest installed patch is, and whether a
        reboot is already pending, and leaves the timing to a person who
        knows what else is going on.
    #>
    [CmdletBinding()]
    param(
        [datetime]$NewestHotfixDate,
        [bool]$RebootPending,
        [datetime]$Now = (Get-Date)
    )

    if ($RebootPending) {
        return New-CcdcHealthCard -Title 'Patching' -Status Warn -Value 'Reboot pending' `
            -Detail 'Updates are installed but not in effect until this box reboots. Plan the reboot deliberately -- it is downtime against the uptime score, so pick the moment rather than being surprised by it.'
    }
    if ($NewestHotfixDate -eq [datetime]::MinValue) {
        return New-CcdcHealthCard -Title 'Patching' -Status Unknown -Value 'No update history' `
            -Detail 'No installed-update history was readable here. That can mean a genuinely unpatched image, which is the normal starting state for a competition box.'
    }

    $ageDays = [int]($Now - $NewestHotfixDate).TotalDays
    if ($ageDays -ge 180) {
        return New-CcdcHealthCard -Title 'Patching' -Status Bad -Value "$ageDays days behind" `
            -Detail "Newest installed update is from $($NewestHotfixDate.ToString('yyyy-MM-dd')). At this age the box is exploitable from published write-ups rather than original work, which is exactly the cheap way in."
    }
    if ($ageDays -ge 60) {
        return New-CcdcHealthCard -Title 'Patching' -Status Warn -Value "$ageDays days behind" `
            -Detail "Newest installed update is from $($NewestHotfixDate.ToString('yyyy-MM-dd'))."
    }
    return New-CcdcHealthCard -Title 'Patching' -Status Good -Value "$ageDays days behind" `
        -Detail "Newest installed update is from $($NewestHotfixDate.ToString('yyyy-MM-dd'))."
}
