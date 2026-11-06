#Requires -Version 5.1
<#
.SYNOPSIS
    Runs one scenario against the domain-join helpers in
    lab\guest\LabGuestCommon.ps1, with fake DNS and a fake Add-Computer, and
    prints one machine-readable result line. Used by tests\LabGuest.Tests.ps1.

.DESCRIPTION
    These functions normally only ever run inside a lab VM. They are worth
    testing anyway: the waiting-for-the-domain logic exists because both member
    servers failed their first domain join on the first real lab build, and a
    regression there would put that failure straight back.

    Nothing here touches a real domain. Add-Computer is faked; the LDAP
    reachability check is pointed at a loopback listener the harness starts.

.PARAMETER Scenario
    reachable       SRV record resolves and something is listening -> joins
    never-answers   SRV record never resolves -> must NOT attempt a join
    dns-only        SRV record resolves but nothing is listening on LDAP (a
                    domain controller part-way through coming up) -> must NOT
                    attempt a join
    already-joined  this machine is already a member -> no work, returns false
    join-retries    reachable, but the first Add-Computer fails -> retries
#>
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)][ValidateSet('reachable', 'never-answers', 'dns-only', 'already-joined', 'join-retries')][string]$Scenario
)

$ErrorActionPreference = 'Continue'
$global:Scenario = $Scenario
$global:Calls = New-Object System.Collections.Generic.List[string]
$global:JoinAttempts = 0

# A real listener, so the helper's TCP check is genuinely exercised rather than
# faked away. Port 0 lets the OS pick a free one; the fake SRV record points at it.
$listener = $null
$portBusy = $false
if ($Scenario -notin 'never-answers', 'dns-only') {
    try {
        $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 389
        $listener.Start()
    } catch {
        # Port 389 busy or blocked: fall back to reporting that so the test can skip.
        $listener = $null
    }
} elseif ($Scenario -eq 'dns-only') {
    # This scenario proves the LDAP check matters, so it only means anything if
    # nothing else on this machine happens to be listening on 389.
    $probe = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $probe.BeginConnect('127.0.0.1', 389, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(1000)) { $probe.EndConnect($iar); $portBusy = $true }
    } catch { } finally { $probe.Close() }
}

function global:Write-LabStep { param([string]$Message) Write-Host "[lab] $Message" }
function global:Clear-DnsClientCache { param($ErrorAction) $global:Calls.Add('Clear-DnsClientCache') }
function global:Get-CimInstance {
    param($ClassName, $Namespace, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_ComputerSystem') {
        if ($global:Scenario -eq 'already-joined') { return [pscustomobject]@{ PartOfDomain = $true; Domain = 'lab.local'; DomainRole = 3 } }
        return [pscustomobject]@{ PartOfDomain = $false; Domain = 'WORKGROUP'; DomainRole = 2 }
    }
    return $null
}
function global:Resolve-DnsName {
    param($Name, $Type, $Server, [switch]$DnsOnly, $ErrorAction)
    $global:Calls.Add("Resolve-DnsName|$Name|$Type|$Server")
    if ($global:Scenario -eq 'never-answers') { throw 'DNS name does not exist' }
    return @([pscustomobject]@{ QueryType = 'SRV'; NameTarget = '127.0.0.1' })
}
function global:Add-Computer {
    param($DomainName, $Credential, [switch]$Force, $ErrorAction)
    $global:JoinAttempts++
    $global:Calls.Add("Add-Computer|$DomainName|attempt$($global:JoinAttempts)")
    if ($global:Scenario -eq 'join-retries' -and $global:JoinAttempts -lt 3) { throw 'The specified domain either does not exist or could not be contacted.' }
}
function global:Start-Sleep { param($Seconds) $global:Calls.Add("Sleep|$Seconds") }

. (Join-Path $RepoRoot 'lab\guest\LabGuestCommon.ps1')

$pw = ConvertTo-SecureString 'Lab#Pass2026x' -AsPlainText -Force
$cred = New-LabCredential -UserName 'LAB\Administrator' -Password $pw

$joined = $null
$threw = $false
$message = ''
try {
    # A short reach timeout so "never answers" fails in seconds, not 15 minutes.
    $joined = Join-LabDomain -DomainName 'lab.local' -Credential $cred -DnsServer '10.10.10.10' -ReachTimeoutMinutes 1 -Attempts 5
} catch {
    $threw = $true
    $message = $_.Exception.Message
}

if ($listener) { $listener.Stop() }

$result = [pscustomobject]@{
    Joined        = $joined
    Threw         = $threw
    Message       = $message
    JoinAttempts  = $global:JoinAttempts
    ListenerReady = [bool]$listener
    PortBusy      = $portBusy
    Calls         = @($global:Calls)
}
'@@RESULT@@' + ($result | ConvertTo-Json -Compress -Depth 4)
