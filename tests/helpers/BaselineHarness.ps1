#Requires -Version 5.1
<#
    Drives modules\Invoke-ConfigBaseline.ps1 through a full capture ->
    tamper -> verify cycle against a scratch copy of the repo and a
    throwaway folder of files. Run as a child Windows PowerShell 5.1
    process by tests\ConfigBaseline.Tests.ps1.

    The module is read-only by design, so unlike the firewall harness this
    needs no fake cmdlets -- it only has to control what the watched
    folder contains between the two runs.

    Emits @@RESULT@@<json> on the last line.
#>
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)]
    [ValidateSet('clean', 'trailing-space', 'content-change', 'same-size-change', 'new-file', 'deleted-file', 'no-baseline', 'homoglyph', 'auto-watch', 'auto-watch-off')]
    [string]$Scenario
)

$ErrorActionPreference = 'Continue'

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('cbh-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
foreach ($item in 'modules', 'config', 'configs') {
    Copy-Item -Path (Join-Path $RepoRoot $item) -Destination (Join-Path $work $item) -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $work 'logs') -Force | Out-Null
Set-Content -Path (Join-Path $work 'config\answers.local.psd1') -Value @('@{', "    ArtifactPrefix = 'Test'", '}') -Encoding UTF8

$watch = Join-Path $work 'watched'
New-Item -ItemType Directory -Path $watch -Force | Out-Null
Set-Content -Path (Join-Path $watch 'index.html') -Value '<h1>hello</h1>' -Encoding UTF8
Set-Content -Path (Join-Path $watch 'site.conf') -Value 'listen 80;' -Encoding UTF8
# Needed by the homoglyph scenario, which swaps an ASCII 'a' for a
# Cyrillic one -- neither of the two names above actually contains an 'a'.
Set-Content -Path (Join-Path $watch 'app.config') -Value '<configuration/>' -Encoding UTF8

$mod = Join-Path $work 'modules\Invoke-ConfigBaseline.ps1'

# The auto-watch scenarios need IIS cmdlets, which no dev box has. Faking
# them globally is the only way to exercise that path at all -- without
# this, code that runs by DEFAULT on every capture has zero coverage,
# which is how the "WatchedFiles: 0 on an FTP server" gap happened in the
# first place.
$autoRoot = Join-Path $work 'wwwroot'
$autoFtp = Join-Path $work 'ftproot'
if ($Scenario -like 'auto-watch*') {
    New-Item -ItemType Directory -Path $autoRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $autoFtp -Force | Out-Null
    Set-Content -Path (Join-Path $autoRoot 'default.htm') -Value '<h1>site</h1>' -Encoding UTF8
    Set-Content -Path (Join-Path $autoFtp 'readme.txt') -Value 'ftp root' -Encoding UTF8
    $global:AutoRoot = $autoRoot
    $global:AutoFtp = $autoFtp
    function global:Get-Website {
        param($ErrorAction)
        [pscustomobject]@{ Name = 'Default Web Site'; PhysicalPath = $global:AutoRoot }
    }
    function global:Get-WebFtpSite {
        param($ErrorAction)
        [pscustomobject]@{ Name = 'Default FTP Site'; PhysicalPath = $global:AutoFtp }
    }
}

# *>&1 rather than 2>&1: Write-CcdcLog goes through Write-Host, which
# since PowerShell 5.0 writes to the INFORMATION stream (6). Redirecting
# only stderr captures none of the module's actual output, and the result
# is an empty log that looks like the module never ran.
$captureLog = @()
if ($Scenario -eq 'auto-watch') {
    # No -WatchPath at all: auto-discovery is the only source of paths.
    $captureLog = @(& $mod -Action Capture *>&1 | ForEach-Object { "$_" })
} elseif ($Scenario -eq 'auto-watch-off') {
    $captureLog = @(& $mod -Action Capture -NoAutoWatch *>&1 | ForEach-Object { "$_" })
} elseif ($Scenario -ne 'no-baseline') {
    $captureLog = @(& $mod -Action Capture -WatchPath $watch *>&1 | ForEach-Object { "$_" })
}

switch ($Scenario) {
    'trailing-space' {
        # The \\?\ prefix is mandatory: without it Win32 path normalization
        # strips the trailing space and the rename silently does nothing,
        # which would make this test pass for the wrong reason.
        $src = '\\?\' + (Join-Path $watch 'site.conf')
        $dst = '\\?\' + (Join-Path $watch 'site.conf ')
        [System.IO.File]::Move($src, $dst)
    }
    'homoglyph' {
        # Cyrillic small a (U+0430) in place of the ASCII one. app.config
        # is the file used here because it is the only one in the set that
        # contains an 'a' at all -- swapping on a name without one is a
        # silent no-op that makes the test pass nothing through the check.
        $src = Join-Path $watch 'app.config'
        $dst = Join-Path $watch ('app.config'.Replace('a', [string][char]0x0430))
        [System.IO.File]::Move($src, $dst)
    }
    'content-change' {
        Set-Content -Path (Join-Path $watch 'index.html') -Value '<h1>defaced</h1>' -Encoding UTF8
    }
    'same-size-change' {
        # Byte-for-byte the same LENGTH as the original '<h1>hello</h1>',
        # so anything comparing file size alone sees no change at all.
        # Only a content hash catches this, and it is not a contrived
        # case: flipping a value in a config file or padding a web shell
        # to its original length both look exactly like this.
        Set-Content -Path (Join-Path $watch 'index.html') -Value '<h1>w0rld</h1>' -Encoding UTF8
    }
    'new-file' {
        Set-Content -Path (Join-Path $watch 'shell.aspx') -Value 'x' -Encoding UTF8
    }
    'deleted-file' {
        [System.IO.File]::Delete((Join-Path $watch 'site.conf'))
    }
    'auto-watch' {
        # Deface a file inside a folder nobody asked for by name. This is
        # the whole point of auto-discovery: on a web or FTP server the
        # content root should be fingerprinted without being configured.
        Set-Content -Path (Join-Path $autoRoot 'default.htm') -Value '<h1>owned</h1>' -Encoding UTF8
    }
}

$verifyLog = @(& $mod -Action Verify *>&1 | ForEach-Object { "$_" })

$reportDir = Join-Path $work 'logs\baselines'
$reports = @()
if (Test-Path -LiteralPath $reportDir) {
    $reports = @(Get-ChildItem -LiteralPath $reportDir -Filter 'verify-*.md' -File | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) })
}
$baselineExists = Test-Path -LiteralPath (Join-Path $reportDir ((($env:COMPUTERNAME) -replace '[^a-zA-Z0-9_\-]', '_') + '-baseline.json'))

$result = [pscustomobject]@{
    WorkDir        = $work
    CaptureLog     = $captureLog
    VerifyLog      = $verifyLog
    Reports        = $reports
    BaselineExists = $baselineExists
}
'@@RESULT@@' + ($result | ConvertTo-Json -Compress -Depth 5)
