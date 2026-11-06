<#
.SYNOPSIS
    Turns a folder of PDF / Word / RTF documents into plain .txt files.

.DESCRIPTION
    Dev-time helper, not a competition module. It exists because injects
    arrive as PDFs and past-inject archives are a pile of PDF and .docx
    files -- none of which can be read, diffed, or searched as-is.

    Conversion goes through Microsoft Word's COM automation, which is
    already on most Windows boxes and handles PDF, .docx, .doc and .rtf
    without installing anything. Word opens each file READ-ONLY and this
    script never writes back to the source; the only thing it creates is
    a .txt next to it (or under -OutputPath).

    Table cells come out separated by ' | ' so an inject's
    Description/Deliverables/Reference table stays readable as text
    instead of collapsing into one run-on line.

    If Word isn't installed this stops with a clear message rather than a
    COM error -- in that case, attach the PDFs directly in a chat instead.

.PARAMETER Path
    A folder to scan, or one or more specific files. Defaults to the
    current directory.

.PARAMETER OutputPath
    Where the .txt files land. Defaults to a 'text' subfolder inside the
    source folder, so the originals stay untouched and un-mixed.

.PARAMETER Recurse
    Also convert documents in subfolders.

.PARAMETER Force
    Re-convert even when an up-to-date .txt already exists.

.EXAMPLE
    .\tools\Convert-DocumentToText.ps1 -Path .\injects-archive -Recurse
    Converts every PDF/Word document under injects-archive into
    injects-archive\text\*.txt.

.EXAMPLE
    .\tools\Convert-DocumentToText.ps1 -Path .\some-inject.pdf -OutputPath .
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Path = '.',
    [string]$OutputPath,
    [switch]$Recurse,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$convertible = @('.pdf', '.docx', '.doc', '.rtf', '.odt')

# ---------------------------------------------------------------------------
# Work out the file list first, so we never start Word for nothing.
# ---------------------------------------------------------------------------
$files = New-Object System.Collections.Generic.List[object]
foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Warning "Not found, skipping: $p"
        continue
    }
    $item = Get-Item -LiteralPath $p
    if ($item.PSIsContainer) {
        $childArgs = @{ Path = $item.FullName; File = $true }
        if ($Recurse) { $childArgs['Recurse'] = $true }
        foreach ($f in (Get-ChildItem @childArgs)) {
            if ($convertible -contains $f.Extension.ToLower()) { $files.Add($f) }
        }
    } elseif ($convertible -contains $item.Extension.ToLower()) {
        $files.Add($item)
    } else {
        Write-Warning "Not a document this can convert, skipping: $($item.Name)"
    }
}

if ($files.Count -eq 0) {
    Write-Host "Nothing to convert. Looked for: $($convertible -join ', ')"
    return
}

Write-Host "Found $($files.Count) document(s) to convert."

# ---------------------------------------------------------------------------
# Start Word once for the whole batch. Everything after this point runs
# inside try/finally so a mid-batch failure still shuts Word down -- an
# orphaned invisible WINWORD.EXE holding a file open is a genuinely
# annoying thing to leave behind.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# The PDF trap, dealt with BEFORE Word launches. Opening a PDF makes Word
# show "Word will now convert your PDF to an editable Word document" -- a
# modal dialog that neither DisplayAlerts nor Open()'s ConfirmConversions
# argument suppresses. An invisible Word plus a modal dialog means the batch
# hangs forever with WINWORD.EXE sitting at ~0% CPU, which is exactly how it
# presents: it looks like a slow conversion, not a stuck one.
#
# The only switch for it is this per-user Word preference, and Word reads it
# at startup -- setting it on an already-running instance does nothing, which
# is worth knowing because that failure looks identical to not setting it at
# all. We set it just for this run and put the previous value back in the
# finally below, so Word behaves afterwards exactly as it did before.
# ---------------------------------------------------------------------------
$pdfWarnKey = $null
$pdfWarnRegPath = $null
$pdfWarnPrev = $null
$pdfWarnSet = $false
if (@($files | Where-Object { $_.Extension -ieq '.pdf' }).Count -gt 0) {
    foreach ($ver in '16.0', '15.0', '14.0') {
        $candidate = "HKCU:\Software\Microsoft\Office\$ver\Word\Options"
        if (Test-Path -LiteralPath $candidate) {
            $pdfWarnKey = $candidate
            $pdfWarnRegPath = "HKEY_CURRENT_USER\Software\Microsoft\Office\$ver\Word\Options"
            break
        }
    }
    if ($pdfWarnKey) {
        $existingProp = Get-ItemProperty -Path $pdfWarnKey -Name 'DisableConvertPdfWarning' -ErrorAction SilentlyContinue
        if ($existingProp) { $pdfWarnPrev = $existingProp.DisableConvertPdfWarning }
        # Written through the .NET registry API rather than
        # Set-ItemProperty -Type. -Type is a provider-DYNAMIC parameter, so
        # it only exists when the path happens to be on the registry
        # provider -- true here, but invisible to static analysis and to
        # anyone reading the line cold. This spells out the value kind.
        [Microsoft.Win32.Registry]::SetValue($pdfWarnRegPath, 'DisableConvertPdfWarning', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $pdfWarnSet = $true
        Write-Verbose "Temporarily suppressed Word's PDF conversion prompt via $pdfWarnKey."
    } else {
        Write-Warning "Couldn't find Word's options key under HKCU, so the PDF conversion prompt can't be suppressed. If this run hangs with WINWORD.exe idle, that dialog is why."
    }
}

$word = $null
try {
    try {
        $word = New-Object -ComObject Word.Application
    } catch {
        throw "Microsoft Word isn't available on this machine, so PDF/Word text extraction can't run here. Either install Word, or attach the documents directly in a Claude chat instead of converting them locally. (COM error: $($_.Exception.Message))"
    }
    $word.Visible = $false
    $word.DisplayAlerts = 0   # wdAlertsNone: never stop the batch on a dialog

    $converted = 0
    $skipped = 0
    $failed = New-Object System.Collections.Generic.List[string]

    foreach ($f in $files) {
        $destDir = if ($OutputPath) { $OutputPath } else { Join-Path $f.DirectoryName 'text' }
        if (-not (Test-Path -LiteralPath $destDir)) {
            if ($PSCmdlet.ShouldProcess($destDir, 'Create output folder')) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
        }
        $dest = Join-Path $destDir ($f.BaseName + '.txt')

        if ((Test-Path -LiteralPath $dest) -and -not $Force) {
            $existing = Get-Item -LiteralPath $dest
            if ($existing.LastWriteTime -ge $f.LastWriteTime) {
                Write-Verbose "Up to date, skipping: $($f.Name)"
                $skipped++
                continue
            }
        }

        if (-not $PSCmdlet.ShouldProcess($f.FullName, "Extract text to $dest")) { continue }

        $doc = $null
        $scratch = $null
        try {
            # Second trap, same symptom as the PDF dialog: a file that came
            # from the internet (a downloaded zip, an email attachment, a
            # Discord export) carries a mark-of-the-web alternate data
            # stream, and Word opens it in Protected View. Protected View
            # under invisible COM automation blocks forever at ~0% CPU.
            #
            # Rather than unblock the user's original file or weaken Word's
            # Protected View settings, convert an unblocked COPY and throw
            # the copy away afterwards. The source is never modified.
            $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('doc2txt-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $scratch -Force | Out-Null
            $working = Join-Path $scratch $f.Name
            Copy-Item -LiteralPath $f.FullName -Destination $working -Force
            Unblock-File -LiteralPath $working -ErrorAction SilentlyContinue

            # FileName, ConfirmConversions=$false, ReadOnly=$true,
            # AddToRecentFiles=$false.
            $doc = $word.Documents.Open($working, $false, $true, $false)
            $text = $doc.Content.Text

            # Word's internal text uses control characters as structure:
            #   BEL  (7)  ends a table cell AND a table row
            #   VT   (11) is a manual line break
            #   CR   (13) ends a paragraph
            # Left alone these all read as one unbroken line.
            # Both arguments are cast to [string] on purpose: given a [char]
            # first argument PowerShell picks String.Replace(char, char) and
            # then fails to convert ' | ' to a single character.
            $text = $text.Replace([string][char]7, ' | ')
            $text = $text.Replace([string][char]11, "`r`n")
            $text = $text.Replace([string][char]13, "`r`n")
            $text = $text.Replace([string][char]12, "`r`n")   # form feed / page break

            [System.IO.File]::WriteAllText($dest, $text, (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "  [ok] $($f.Name) -> $dest"
            $converted++
        } catch {
            Write-Warning "  [fail] $($f.Name): $($_.Exception.Message)"
            $failed.Add($f.Name)
        } finally {
            if ($doc) {
                try { $doc.Close($false) } catch { }
                try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc) } catch { }
            }
            if ($scratch -and (Test-Path -LiteralPath $scratch)) {
                try { [System.IO.Directory]::Delete($scratch, $true) } catch { }
            }
        }
    }

    Write-Host ''
    Write-Host "Converted $converted, skipped $skipped (already current), failed $($failed.Count)."
    if ($failed.Count -gt 0) { Write-Host "Failed: $($failed -join ', ')" }
} finally {
    if ($word) {
        try { $word.Quit() } catch { }
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) } catch { }
    }
    # Put Word's PDF prompt back exactly as we found it -- including
    # removing the value entirely if it wasn't there before.
    if ($pdfWarnSet) {
        try {
            if ($null -eq $pdfWarnPrev) {
                Remove-ItemProperty -Path $pdfWarnKey -Name 'DisableConvertPdfWarning' -ErrorAction Stop
            } else {
                [Microsoft.Win32.Registry]::SetValue($pdfWarnRegPath, 'DisableConvertPdfWarning', [int]$pdfWarnPrev, [Microsoft.Win32.RegistryValueKind]::DWord)
            }
        } catch {
            Write-Warning "Couldn't restore Word's DisableConvertPdfWarning setting: $($_.Exception.Message)"
        }
    }
}
