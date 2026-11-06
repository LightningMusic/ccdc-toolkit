#Requires -Version 5.1
# Shared client code for tests that use tests\helpers\ModuleHarness.ps1.
# Dot-source it from a test file:   . (Join-Path $PSScriptRoot 'helpers\HarnessClient.ps1')

$script:HarnessRepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # this file lives in <repo>\tests\helpers
$script:HarnessPath = Join-Path $PSScriptRoot 'ModuleHarness.ps1'
$script:HarnessEngine = $null
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if ($env:OS -eq 'Windows_NT' -and (Test-Path $ps51)) { $script:HarnessEngine = $ps51 }

function Invoke-ModuleHarness {
    <#
    .SYNOPSIS
        Runs a module script in the harness (child Windows PowerShell 5.1
        process, scratch repo copy) and returns Log / Calls / Prompts / Files /
        ReadBack. Returns $null when this isn't a Windows box with 5.1.
    #>
    param([Parameter(Mandatory)][hashtable]$Spec)
    if (-not $script:HarnessEngine) { return $null }
    $specFile = Join-Path ([System.IO.Path]::GetTempPath()) ("spec-" + [guid]::NewGuid() + '.json')
    ($Spec | ConvertTo-Json -Depth 6) | Set-Content -Path $specFile -Encoding UTF8
    try {
        $lines = @(& $script:HarnessEngine -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:HarnessPath -SpecPath $specFile -RepoRoot $script:HarnessRepoRoot 2>&1 | ForEach-Object { "$_" })
    } finally { Remove-Item $specFile -Force -ErrorAction SilentlyContinue }
    $resultLine = $lines | Where-Object { $_ -like '@@RESULT@@*' } | Select-Object -Last 1
    $result = $null
    if ($resultLine) { $result = $resultLine.Substring(10) | ConvertFrom-Json }
    $out = [pscustomobject]@{
        Completed = [bool]$result
        Log       = @($lines | Where-Object { $_ -notlike '@@RESULT@@*' })
        Calls     = @($result.Calls)
        Prompts   = @($result.Prompts)
        InputsLeft = $result.InputsLeft
        Files     = @($result.Files)
        ReadBack  = $result.ReadBack
        WorkDir   = $result.WorkDir
        HyperV    = $result.HyperV
        Iis       = $result.Iis
    }
    if ($result -and $result.WorkDir -and (Test-Path $result.WorkDir)) { Remove-Item -Path $result.WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    return $out
}

function Test-HarnessLog { param($Run, [string]$Pattern) (@($Run.Log | Where-Object { $_ -match $Pattern }).Count -gt 0) }
