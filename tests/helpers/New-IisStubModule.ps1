#Requires -Version 5.1
<#
.SYNOPSIS
    Writes a stand-in WebAdministration module so modules\Invoke-IISHardening.ps1
    can be run for real on a machine with no IIS. Used by
    tests\helpers\ModuleHarness.ps1; not a test by itself.

.DESCRIPTION
    A stub MODULE rather than a set of loose fake functions, so the real code
    path is exercised: the script's own `Get-Module -ListAvailable` check and
    its `Import-Module WebAdministration` both genuinely succeed, and the
    functions the stub exports take precedence the same way the real cmdlets
    would.

    The stub keeps the fake IIS state in global variables so a test can look at
    what changed, and appends one line per state-changing call to $global:Calls.

    Get-ChildItem, Get-ItemProperty and Set-ItemProperty are overridden only for
    IIS:\ paths; anything else is handed to the real cmdlet, because the module
    under test also walks real folders on disk to hunt for web shells.

.PARAMETER Root
    Folder to create the stub module in (a "WebAdministration" subfolder is made).

.PARAMETER Spec
    The Iis section of the harness spec (sites, app pools, FTP settings).
#>
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)]$Spec
)

$moduleDir = Join-Path $Root 'WebAdministration'
New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null

# --- the fake IIS state, built from the spec ---------------------------------------------------
$global:IisSites = [ordered]@{}
foreach ($s in @($Spec.Sites)) {
    $bindings = @($s.Bindings | ForEach-Object { [pscustomobject]@{ protocol = $_.protocol; bindingInformation = $_.bindingInformation } })
    $global:IisSites[$s.Name] = [pscustomobject]@{
        Name              = $s.Name
        State             = $(if ($s.State) { $s.State } else { 'Started' })
        PhysicalPath      = $s.PhysicalPath
        ApplicationPool   = $(if ($s.ApplicationPool) { $s.ApplicationPool } else { 'DefaultAppPool' })
        bindings          = [pscustomobject]@{ Collection = $bindings }
        DirectoryBrowsing = [bool]$s.DirectoryBrowsing
        XPoweredBy        = [bool]$s.XPoweredBy
        FtpAnonymous      = [bool]$s.FtpAnonymous
        FtpAuthz          = @($s.FtpAuthz | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ users = "$($_.users)"; roles = "$($_.roles)"; permissions = "$($_.permissions)" } })
        DeniedExtensions  = New-Object System.Collections.Generic.List[string]
    }
}
$global:IisAppPools = @($Spec.AppPools | Where-Object { $_ } | ForEach-Object {
    [pscustomobject]@{
        Name         = $_.Name
        processModel = [pscustomobject]@{ identityType = "$($_.IdentityType)"; userName = "$($_.UserName)" }
    }
})
$global:IisFtpLow = $(if ($null -ne $Spec.FtpLow) { $Spec.FtpLow } else { 0 })
$global:IisFtpHigh = $(if ($null -ne $Spec.FtpHigh) { $Spec.FtpHigh } else { 0 })
$global:IisRemoveServerHeader = [bool]$Spec.RemoveServerHeader
$global:IisServerHeaderSupported = ($Spec.ServerHeaderUnsupported -ne $true)
$global:IisBackupFails = ($Spec.BackupFails -eq $true)

$psm1 = @'
# Stand-in WebAdministration for tests. See tests\helpers\New-IisStubModule.ps1.
function script:Record { param([string]$Line) if ($null -ne $global:Calls) { $global:Calls.Add($Line) } }
function script:SiteFromPath {
    param([string]$PSPath)
    if ("$PSPath" -match 'IIS:\\Sites\\(?<n>.+?)$') { $name = $Matches.n } else { return $null }
    if ($global:IisSites.Contains($name)) { return $global:IisSites[$name] }
    return $null
}

function Get-Website { param([string]$Name) if ($Name) { return $global:IisSites[$Name] } return @($global:IisSites.Values) }

function Backup-WebConfiguration {
    param([string]$Name, $ErrorAction)
    if ($global:IisBackupFails) { throw 'simulated failure taking an IIS configuration backup' }
    Record "Backup-WebConfiguration|$Name"
    return [pscustomobject]@{ Name = $Name }
}

function Get-WebConfigurationProperty {
    param([string]$Filter, [string]$Name, [string]$PSPath, [string]$Location, $ErrorAction)
    if ($Filter -match 'directoryBrowse') {
        $site = SiteFromPath $PSPath
        if (-not $site) { throw "no such site: $PSPath" }
        return [pscustomobject]@{ Value = $site.DirectoryBrowsing }
    }
    if ($Filter -match 'firewallSupport') {
        if ($Name -eq 'lowDataChannelPort') { return [pscustomobject]@{ Value = $global:IisFtpLow } }
        return [pscustomobject]@{ Value = $global:IisFtpHigh }
    }
    if ($Filter -match 'requestFiltering' -and $Name -eq 'removeServerHeader') {
        if (-not $global:IisServerHeaderSupported) { throw "the attribute 'removeServerHeader' is not supported on this version of IIS" }
        return [pscustomobject]@{ Value = $global:IisRemoveServerHeader }
    }
    throw "stub: unhandled Get-WebConfigurationProperty filter '$Filter' name '$Name'"
}

function Set-WebConfigurationProperty {
    param([string]$Filter, [string]$Name, $Value, [string]$PSPath, [string]$Location, $ErrorAction)
    if ($Filter -match 'directoryBrowse') {
        $site = SiteFromPath $PSPath
        $site.DirectoryBrowsing = [bool]$Value
        Record "Set-DirectoryBrowsing|$($site.Name)|$Value"
        return
    }
    if ($Filter -match 'requestFiltering' -and $Name -eq 'removeServerHeader') {
        if (-not $global:IisServerHeaderSupported) { throw "the attribute 'removeServerHeader' is not supported on this version of IIS" }
        $global:IisRemoveServerHeader = [bool]$Value
        Record "Set-RemoveServerHeader|$Value"
        return
    }
    throw "stub: unhandled Set-WebConfigurationProperty filter '$Filter' name '$Name'"
}

function Get-WebConfiguration {
    param([string]$Filter, [string]$PSPath, [string]$Location, $ErrorAction)
    if ($Filter -match 'customHeaders') {
        $site = SiteFromPath $PSPath
        if ($site -and $site.XPoweredBy) { return @([pscustomobject]@{ name = 'X-Powered-By'; value = 'ASP.NET' }) }
        return @()
    }
    if ($Filter -match 'ftpServer/security/authorization') {
        if ($Location -and $global:IisSites.Contains($Location)) { return @($global:IisSites[$Location].FtpAuthz) }
        return @()
    }
    if ($Filter -match 'fileExtensions') {
        $site = SiteFromPath $PSPath
        if ($site) { return @($site.DeniedExtensions | ForEach-Object { [pscustomobject]@{ fileExtension = $_; allowed = $false } }) }
        return @()
    }
    throw "stub: unhandled Get-WebConfiguration filter '$Filter'"
}

function Remove-WebConfigurationProperty {
    param([string]$Filter, [string]$Name, $AtElement, [string]$PSPath, $ErrorAction)
    if ($Filter -match 'customHeaders') {
        $site = SiteFromPath $PSPath
        $site.XPoweredBy = $false
        Record "Remove-XPoweredBy|$($site.Name)"
        return
    }
    throw "stub: unhandled Remove-WebConfigurationProperty filter '$Filter'"
}

function Add-WebConfigurationProperty {
    param([string]$Filter, [string]$Name, $Value, [string]$PSPath, $ErrorAction)
    if ($Filter -match 'fileExtensions') {
        $site = SiteFromPath $PSPath
        $site.DeniedExtensions.Add("$($Value.fileExtension)")
        Record "Deny-Extension|$($site.Name)|$($Value.fileExtension)"
        return
    }
    throw "stub: unhandled Add-WebConfigurationProperty filter '$Filter'"
}

# -- overridden only for IIS:\ paths; everything else goes to the real cmdlet --
function Get-ChildItem {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)][string[]]$Path,
        [string]$LiteralPath, [string]$Filter, [switch]$File, [switch]$Directory,
        [switch]$Recurse, [switch]$Force, [int]$Depth
    )
    if ($Path -and "$Path" -like 'IIS:\AppPools*') { return @($global:IisAppPools) }
    $forward = @{}
    foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
    return & (Get-Command Get-ChildItem -CommandType Cmdlet) @forward
}

function Get-ItemProperty {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [Parameter(Position = 1)][string]$Name)
    if ("$Path" -like 'IIS:\*') {
        $site = SiteFromPath $Path
        if (-not $site) { throw "no such site: $Path" }
        if ($Name -match 'anonymousAuthentication') { return [pscustomobject]@{ Value = $site.FtpAnonymous } }
        throw "stub: unhandled Get-ItemProperty name '$Name'"
    }
    $forward = @{}
    foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
    return & (Get-Command Get-ItemProperty -CommandType Cmdlet) @forward
}

function Set-ItemProperty {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [Parameter(Position = 1)][string]$Name, [Parameter(Position = 2)]$Value)
    if ("$Path" -like 'IIS:\*') {
        $site = SiteFromPath $Path
        if ($Name -match 'anonymousAuthentication') {
            $site.FtpAnonymous = [bool]$Value
            Record "Set-FtpAnonymous|$($site.Name)|$Value"
            return
        }
        throw "stub: unhandled Set-ItemProperty name '$Name'"
    }
    $forward = @{}
    foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
    return & (Get-Command Set-ItemProperty -CommandType Cmdlet) @forward
}

Export-ModuleMember -Function Get-Website, Backup-WebConfiguration, Get-WebConfigurationProperty,
    Set-WebConfigurationProperty, Get-WebConfiguration, Remove-WebConfigurationProperty,
    Add-WebConfigurationProperty, Get-ChildItem, Get-ItemProperty, Set-ItemProperty
'@

Set-Content -Path (Join-Path $moduleDir 'WebAdministration.psm1') -Value $psm1 -Encoding UTF8
$psd1 = @"
@{
    ModuleVersion = '1.0'
    GUID = '$([guid]::NewGuid())'
    Author = 'test stub'
    Description = 'Stand-in WebAdministration for tests.'
    RootModule = 'WebAdministration.psm1'
    FunctionsToExport = @('Get-Website','Backup-WebConfiguration','Get-WebConfigurationProperty','Set-WebConfigurationProperty','Get-WebConfiguration','Remove-WebConfigurationProperty','Add-WebConfigurationProperty','Get-ChildItem','Get-ItemProperty','Set-ItemProperty')
}
"@
Set-Content -Path (Join-Path $moduleDir 'WebAdministration.psd1') -Value $psd1 -Encoding UTF8

# Put the stub ahead of anything real on the module path.
$env:PSModulePath = "$Root;$env:PSModulePath"
