<#
.SYNOPSIS
    Turns an HTML (or Markdown) file into a PDF, which is the only format
    the inject scoring engine accepts.

.DESCRIPTION
    The team packet is unambiguous: "Responses to inject tasks must be in
    the form of an attached PDF file", and the inject guidance adds that
    other formats "will not be accepted and the inject not scored". So
    every deliverable ends up going through a step like this one.

    Three engines are tried in order, and the first one present wins:

      1. Microsoft Edge, headless. Present on every modern Windows
         install, needs no configuration, and renders the print stylesheet
         properly -- which matters, because the incident report's HTML is
         styled for paper.
      2. Google Chrome, headless. Identical mechanism.
      3. Microsoft Word. Slower and reflows the layout its own way, but it
         is there on a lot of machines that have been stripped of other
         things.

    Markdown input is wrapped in a minimal HTML shell first. That is a
    convenience for quickly turning a .md working copy into something
    presentable; it is not a full Markdown renderer, and for anything
    being submitted you want the .html the report generator already wrote.

    WHERE TO RUN THIS: on the machine you submit from, not on a
    competition server. A stripped Windows Server may have none of these
    three, and the submission portal is reached from your own workstation
    anyway.

.PARAMETER Path
    The .html or .md file to convert. Accepts several.

.PARAMETER OutputPath
    Where the PDF goes. Defaults to the same folder and base name.

.PARAMETER Engine
    Force one engine instead of auto-detecting: Edge, Chrome or Word.

.EXAMPLE
    .\prep\ConvertTo-Pdf.ps1 -Path .\logs\incident-reports\WEB01_2026-01-31_143200.html

.EXAMPLE
    Get-ChildItem .\logs\incident-reports\*.html | ForEach-Object { .\prep\ConvertTo-Pdf.ps1 -Path $_.FullName }
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,
    [string]$OutputPath,
    [ValidateSet('Edge', 'Chrome', 'Word')]
    [string]$Engine
)

$ErrorActionPreference = 'Stop'

function Find-Browser {
    param([string]$Which)
    $candidates = if ($Which -eq 'Chrome') {
        @(
            (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
            (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
        )
    } else {
        @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
            (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
        )
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

function ConvertTo-PdfWithBrowser {
    param([string]$Exe, [string]$InputFile, [string]$OutFile)

    # --headless=new is the supported mode in current Edge/Chrome; the old
    # --headless silently does nothing to print in recent builds.
    # --user-data-dir is a throwaway: without it, a browser the user
    # already has open makes the headless invocation exit immediately
    # without ever rendering, which looks exactly like success.
    $profileDir = Join-Path ([System.IO.Path]::GetTempPath()) ('pdfconv-' + [guid]::NewGuid().ToString('N'))
    $uri = ([uri]('file:///' + $InputFile.Replace('\', '/'))).AbsoluteUri

    # Every path-bearing switch is quoted, and the whole thing is passed as
    # ONE pre-joined string. Handing Start-Process an array lets it join
    # the elements without quoting, so a path containing a space (which
    # "C:\Users\First Last\..." always does) splits into extra arguments
    # and the browser reports "Multiple targets are not supported in
    # headless mode" -- a confusing error for what is really a quoting bug.
    $browserArgs = @(
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        ('--user-data-dir="{0}"' -f $profileDir),
        '--print-to-pdf-no-header',
        ('--print-to-pdf="{0}"' -f $OutFile),
        ('"{0}"' -f $uri)
    ) -join ' '

    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $browserArgs -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -ne 0) { Write-Verbose "Browser exited with code $($p.ExitCode)." }
    } finally {
        if (Test-Path -LiteralPath $profileDir) {
            try { [System.IO.Directory]::Delete($profileDir, $true) } catch { }
        }
    }
    return (Test-Path -LiteralPath $OutFile)
}

function ConvertTo-PdfWithWord {
    param([string]$InputFile, [string]$OutFile)
    $word = $null
    $doc = $null
    try {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = 0
        $doc = $word.Documents.Open($InputFile, $false, $true, $false)
        $doc.SaveAs([ref]$OutFile, [ref]17)   # 17 = wdFormatPDF
        return $true
    } catch {
        Write-Warning "Word conversion failed: $($_.Exception.Message)"
        return $false
    } finally {
        if ($doc) { try { $doc.Close($false) } catch { } }
        if ($word) {
            try { $word.Quit() } catch { }
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) } catch { }
        }
    }
}

# Work out which engine to use once, not per file.
$engineExe = $null
$engineName = $null
if ($Engine -eq 'Word') {
    $engineName = 'Word'
} elseif ($Engine) {
    $engineExe = Find-Browser -Which $Engine
    if (-not $engineExe) { throw "$Engine was requested with -Engine but is not installed here." }
    $engineName = $Engine
} else {
    foreach ($try in 'Edge', 'Chrome') {
        $engineExe = Find-Browser -Which $try
        if ($engineExe) { $engineName = $try; break }
    }
    if (-not $engineName) {
        $engineName = 'Word'
        Write-Verbose 'No Edge or Chrome found; falling back to Word.'
    }
}
Write-Host "Using $engineName to render PDFs."

$ok = 0
$failed = New-Object System.Collections.Generic.List[string]

foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Warning "Not found, skipping: $p"
        continue
    }
    $item = Get-Item -LiteralPath $p
    $out = if ($OutputPath) {
        if (Test-Path -LiteralPath $OutputPath -PathType Container) {
            Join-Path $OutputPath ($item.BaseName + '.pdf')
        } else { $OutputPath }
    } else {
        Join-Path $item.DirectoryName ($item.BaseName + '.pdf')
    }

    if (-not $PSCmdlet.ShouldProcess($item.FullName, "Convert to $out")) { continue }

    # Markdown gets a minimal HTML shell. Not a renderer -- just enough
    # that headings and line breaks survive and the text is legible.
    $sourceFile = $item.FullName
    $tempHtml = $null
    if ($item.Extension -ieq '.md') {
        $tempHtml = Join-Path ([System.IO.Path]::GetTempPath()) ($item.BaseName + '-' + [guid]::NewGuid().ToString('N') + '.html')
        $body = [System.IO.File]::ReadAllText($item.FullName)
        $body = $body.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
        $shell = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>$($item.BaseName)</title>
<style>body{font-family:Georgia,serif;font-size:11pt;line-height:1.45;max-width:7.2in;margin:0.6in auto;padding:0 16px;white-space:pre-wrap;}</style>
</head><body>$body</body></html>
"@
        [System.IO.File]::WriteAllText($tempHtml, $shell, (New-Object System.Text.UTF8Encoding($false)))
        $sourceFile = $tempHtml
    }

    try {
        $done = if ($engineName -eq 'Word') {
            ConvertTo-PdfWithWord -InputFile $sourceFile -OutFile $out
        } else {
            ConvertTo-PdfWithBrowser -Exe $engineExe -InputFile $sourceFile -OutFile $out
        }
        if ($done) {
            Write-Host "  [ok] $($item.Name) -> $out"
            $ok++
        } else {
            Write-Warning "  [fail] $($item.Name): no PDF was produced."
            $failed.Add($item.Name)
        }
    } finally {
        if ($tempHtml -and (Test-Path -LiteralPath $tempHtml)) {
            try { [System.IO.File]::Delete($tempHtml) } catch { }
        }
    }
}

Write-Host ''
Write-Host "Converted $ok file(s), failed $($failed.Count)."
if ($failed.Count -gt 0) { Write-Host "Failed: $($failed -join ', ')" }
