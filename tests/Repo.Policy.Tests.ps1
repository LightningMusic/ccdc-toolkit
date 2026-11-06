#Requires -Version 5.1
# Repo-policy tests: the rules this project sets for itself (docs/SECURITY.md,
# docs/ARCHITECTURE.md), checked mechanically so they can't quietly regress
# before the repo goes public. Run from the repo root: Invoke-Pester .\tests

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

# By default this returns only SHIPPED files (what a teammate clones and runs);
# the tests\ folder is deliberately excluded because it legitimately holds fake
# data (made-up IPs, temp-name prefixes). Structural checks -- does it parse,
# does it have a BOM, are the line endings consistent -- pass -IncludeTests.
function script:Get-RepoFile {
    param([string[]]$Extension, [switch]$IncludeTests)
    Get-ChildItem -Path $script:RepoRoot -Recurse -File |
        Where-Object {
            $_.FullName -notmatch '\\(logs|tools|\.git)\\' -and
            $Extension -contains $_.Extension -and
            ($IncludeTests -or $_.FullName -notmatch '\\tests\\')
        }
}
function script:Get-RelativeName { param($File) $File.FullName.Substring($script:RepoRoot.Length + 1) }

Describe 'every script parses' {
    It 'under the engine running these tests' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1', '.psd1' -IncludeTests)) {
            $tok = $null; $err = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            if ($err.Count -gt 0) { $bad += "$(Get-RelativeName $f) line $($err[0].Extent.StartLineNumber): $($err[0].Message)" }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'under Windows PowerShell 5.1 -- the engine the competition boxes run (this is what a PowerShell 7-only check misses)' {
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ($env:OS -ne 'Windows_NT' -or -not (Test-Path $ps51)) { return }
        $checker = @'
param([string]$Root)
$bad = @()
Get-ChildItem $Root -Recurse -File | Where-Object { $_.FullName -notmatch '\\(logs|tools|\.git)\\' -and $_.Extension -in '.ps1','.psm1','.psd1' } | ForEach-Object {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$t, [ref]$e)
    if ($e.Count -gt 0) { $bad += ("{0} line {1}: {2}" -f $_.Name, $e[0].Extent.StartLineNumber, $e[0].Message) }
}
if ($bad.Count -eq 0) { 'PARSE-OK' } else { $bad }
'@
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("parse51-" + [guid]::NewGuid() + '.ps1')
        Set-Content -Path $tmp -Value $checker -Encoding UTF8
        try {
            $out = @(& $ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tmp -Root $script:RepoRoot 2>&1 | ForEach-Object { "$_" })
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        ($out -join '; ') | Should Be 'PARSE-OK'
    }
}

Describe 'every cmdlet parameter used actually exists on the target engine' {
    It 'in Windows PowerShell 5.1, checked against the real cmdlet definitions (catches PowerShell-7-only parameters and typos in calls that are hard to run, like Hyper-V). Commands whose module is not installed on this machine are skipped.' {
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ($env:OS -ne 'Windows_NT' -or -not (Test-Path $ps51)) { return }
        $checker = @'
param([string]$Root)
$files = @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' -and $_.FullName -notmatch '\\(logs|tools|\.git|tests)\\' })
$ours = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$asts = @{}
foreach ($f in $files) {
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    $asts[$f.FullName] = $ast
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$ours.Add($fn.Name) }
}
$cache = @{}
$offenders = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
    $ast = $asts[$f.FullName]
    foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $c.GetCommandName()
        if (-not $name -or $ours.Contains($name)) { continue }
        if (-not $cache.ContainsKey($name)) {
            $cmd = $null
            try { $cmd = Get-Command -Name $name -ArgumentList $env:SystemRoot -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { }
            if ($cmd -and $cmd.CommandType -eq 'Alias') { $cmd = $cmd.ResolvedCommand }
            if ($cmd -and $cmd.CommandType -notin 'Cmdlet', 'Function') { $cmd = $null }
            $cache[$name] = $cmd
        }
        $cmd = $cache[$name]
        if (-not $cmd) { continue }
        if (@($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted }).Count -gt 0) { continue }
        foreach ($el in $c.CommandElements) {
            if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
            $pn = $el.ParameterName
            $keys = @($cmd.Parameters.Keys)
            $ok = (@($keys | Where-Object { $_ -ieq $pn })).Count -gt 0
            if (-not $ok) { foreach ($k in $keys) { if (@($cmd.Parameters[$k].Aliases) -contains $pn) { $ok = $true; break } } }
            if (-not $ok) { $ok = (@($keys | Where-Object { $_ -like "$pn*" })).Count -gt 0 }   # unambiguous prefix
            if (-not $ok) { $offenders.Add("$($f.Name):$($el.Extent.StartLineNumber) $name -$pn") }
        }
    }
}
if ($offenders.Count -eq 0) { 'PARAMS-OK' } else { $offenders }
'@
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("params51-" + [guid]::NewGuid() + '.ps1')
        Set-Content -Path $tmp -Value $checker -Encoding UTF8
        try {
            $out = @(& $ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $tmp -Root $script:RepoRoot 2>&1 | ForEach-Object { "$_" })
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        ($out -join '; ') | Should Be 'PARAMS-OK'
    }
}

Describe 'PowerShell traps that only bite at runtime' {
    It 'no -f format expression sits directly inside a method call''s argument list (the commas belong to the METHOD, so -f gets only the first value and throws "Error formatting a string")' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1' -IncludeTests)) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            foreach ($call in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
                if (-not $call.Arguments -or $call.Arguments.Count -lt 2) { continue }
                foreach ($a in $call.Arguments) {
                    if ($a -is [System.Management.Automation.Language.BinaryExpressionAst] -and $a.Operator -eq 'Format') {
                        $bad += "$(Get-RelativeName $f):$($call.Extent.StartLineNumber)"
                    }
                }
            }
        }
        ($bad -join '; ') | Should Be ''
    }
}

Describe 'file encoding and line endings' {
    It 'a script containing any non-ASCII character has a UTF-8 BOM (Windows PowerShell 5.1 reads BOM-less files as ANSI, and an em dash then breaks string parsing)' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1', '.psd1' -IncludeTests)) {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count -gt 0
            if ($nonAscii -and -not $hasBom) { $bad += (Get-RelativeName $f) }
        }
        ($bad -join ', ') | Should Be ''
    }
    It 'CcdcLogic.ps1 stays pure ASCII' {
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:RepoRoot 'modules\CcdcLogic.ps1'))
        # a BOM (EF BB BF) is allowed at the very start; nothing else above 127
        $body = if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $bytes[3..($bytes.Length - 1)] } else { $bytes }
        @($body | Where-Object { $_ -gt 127 }).Count | Should Be 0
    }
    It 'line endings are consistent within each file (no CRLF/LF mix)' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1', '.psd1', '.md' -IncludeTests)) {
            $text = [System.IO.File]::ReadAllText($f.FullName)
            $crlf = ([regex]::Matches($text, "`r`n")).Count
            $lf = ([regex]::Matches($text, "(?<!`r)`n")).Count
            if ($crlf -gt 0 -and $lf -gt 0) { $bad += (Get-RelativeName $f) }
        }
        ($bad -join ', ') | Should Be ''
    }
}

Describe 'nothing environment-specific or fingerprintable in a public repo' {
    It 'no IPv4 literals in code or docs other than documentation examples (10.10.10.x, the lab''s 172.20.240.x/172.17.0.x/172.16.0.x, loopback, 0.0.0.0)' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1', '.psd1', '.md')) {
            if ($f.Name -eq 'CCDC_Competition_Compendium.md') { continue }
            $n = 0
            foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
                $n++
                foreach ($m in [regex]::Matches($line, '\b(\d{1,3}\.){3}\d{1,3}\b')) {
                    # 10.10.10.x was the old lab's made-up subnet; 172.20.240.x /
                    # 172.17.0.x / 172.16.0.x are the real-topology rebuild's
                    # (lab\LabCommon.psm1's Get-CcdcLabPlan) -- all fake, lab-only
                    # addresses, same exemption as before, just three ranges now
                    # instead of one.
                    if ($m.Value -match '^(10\.10\.10\.\d{1,3}|172\.20\.240\.\d{1,3}|172\.17\.0\.\d{1,3}|172\.16\.0\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0)$') { continue }
                    if ($f.Name -eq 'Invoke-FirewallBaseline.ps1' -and $line -match '\\d\{1,3\}') { continue }
                    $bad += "$(Get-RelativeName $f):$n $($m.Value)"
                }
            }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'no literal "ccdc-"/"ccdc_" names in code (a grep-able fingerprint on the live box); the one internal env var is allow-listed. The dev-only practice lab (lab\) is exempt: it never runs on a competition box.' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1' | Where-Object { (Get-RelativeName $_) -notlike 'lab\*' })) {
            $n = 0
            foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
                $n++
                if ($line -match '(?i)ccdc[-_][a-z]' -and $line -notmatch 'CCDC_TARGET_SHOWN') { $bad += "$(Get-RelativeName $f):$n" }
            }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'never disables a Windows optional feature by a hardcoded name -- the name must be one just confirmed present on THIS box' {
        # Found on the real lab. The fix hardcoded
        # 'MicrosoftWindowsPowerShellV2Root', which exists only on client
        # Windows, so on Server 2019 and 2022 it died with "Feature name ...
        # is unknown" while the audit went on reporting the finding -- a
        # module that flags something it can never clear. The workstation
        # passed, which is exactly why no amount of faking caught it.
        # Disabling by a literal means assuming an edition; look it up first.
        $src = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'modules\Invoke-ExploitAudit.ps1'))
        $bad = @()
        foreach ($m in [regex]::Matches($src, '(?i)Disable-WindowsOptionalFeature[^\r\n]*?-FeatureName\s+(''[^'']+''|"[^"]+")')) {
            $bad += $m.Groups[1].Value
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'knows BOTH names the PowerShell v2 engine goes by, because Server and client disagree' {
        # Server 2019/2022 have 'MicrosoftWindowsPowerShellV2'; client
        # Windows also has the 'Root' parent. Dropping either name leaves one
        # edition unfixable, which is the bug that was actually shipped.
        # Read the names out of the LOOP, not out of the surrounding prose.
        # A first attempt at this test searched the whole fix block and was
        # satisfied by its own explanatory comment, so it passed happily
        # while the code underneath handled only one name.
        $src = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'modules\Invoke-ExploitAudit.ps1'))
        $fixAt = $src.LastIndexOf("'POWERSHELL_V2' = {", [System.StringComparison]::OrdinalIgnoreCase)
        ($fixAt -ge 0) | Should Be $true
        $block = $src.Substring($fixAt, [Math]::Min(2500, $src.Length - $fixAt))
        $code = ($block -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $loop = [regex]::Match($code, '(?i)foreach\s*\(\s*\$\w+\s+in\s+([^)]+)\)')
        $loop.Success | Should Be $true
        $names = @([regex]::Matches($loop.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        ($names -contains 'MicrosoftWindowsPowerShellV2Root') | Should Be $true
        ($names -contains 'MicrosoftWindowsPowerShellV2') | Should Be $true
    }
    It 'no well-known offensive-tool names in script SOURCE (antivirus/AMSI reacts to them and has blocked this repo''s own threat hunter as "malicious content"); they belong in the data file' {
        # Assembled from fragments so this test file itself never contains them.
        $names = @(('mimi' + 'katz'), ('rube' + 'us'), ('sharp' + 'hound'), ('power' + 'sploit'), ('meter' + 'preter'), ('seat' + 'belt'), ('win' + 'peas'), ('lin' + 'peas'))
        $rx = '(?i)(' + ($names -join '|') + ')'
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1', '.psd1')) {
            $n = 0
            foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
                $n++
                if ($line -match $rx) { $bad += "$(Get-RelativeName $f):$n" }
            }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'no script (shipped or test) is flagged by the antivirus scan interface (AMSI) -- each file''s text is scanned, never executed. A detection here means Defender would block it at runtime as "malicious content".' {
        if ($env:OS -ne 'Windows_NT') { return }
        if (-not ('CcdcAmsiProbe' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class CcdcAmsiProbe {
    [DllImport("amsi.dll")] static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr ctx);
    [DllImport("amsi.dll")] static extern int AmsiOpenSession(IntPtr ctx, out IntPtr session);
    [DllImport("amsi.dll")] static extern int AmsiScanString(IntPtr ctx, [MarshalAs(UnmanagedType.LPWStr)] string s, [MarshalAs(UnmanagedType.LPWStr)] string name, IntPtr session, out int result);
    [DllImport("amsi.dll")] static extern void AmsiCloseSession(IntPtr ctx, IntPtr session);
    [DllImport("amsi.dll")] static extern void AmsiUninitialize(IntPtr ctx);
    // 0/1 = clean, >= 32768 = detected, -1/-2 = no AMSI provider / probe error
    public static int Scan(string content, string name) {
        try {
            IntPtr ctx; IntPtr sess; int result;
            if (AmsiInitialize("repo-policy-test", out ctx) != 0) return -1;
            AmsiOpenSession(ctx, out sess);
            int hr = AmsiScanString(ctx, content, name, sess, out result);
            AmsiCloseSession(ctx, sess); AmsiUninitialize(ctx);
            return hr != 0 ? -2 : result;
        } catch (Exception) { return -1; }
    }
}
"@
        }
        $flagged = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1', '.psd1' -IncludeTests)) {
            $r = [CcdcAmsiProbe]::Scan([System.IO.File]::ReadAllText($f.FullName), $f.Name)
            if ($r -ge 32768) { $flagged += "$(Get-RelativeName $f) (AMSI result $r)" }
        }
        ($flagged -join '; ') | Should Be ''
    }
    It 'the shipped known-tool-names data file exists and covers the core names' {
        $file = Join-Path $script:RepoRoot 'configs\threat-hunt\known-tool-names.txt'
        (Test-Path $file) | Should Be $true
        $entries = @(Get-Content $file | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -and -not $_.StartsWith('#') })
        ($entries -contains ('mimi' + 'katz')) | Should Be $true
        ($entries -contains 'psexec') | Should Be $true
        ($entries -contains 'nc') | Should Be $true
        $entries.Count | Should BeGreaterThan 10
    }
    It 'no fetch-and-execute: Invoke-Expression only in the admin console escape hatch, Invoke-WebRequest only in the Sysmon downloader (and the lab service health check, which just GETs a page)' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1')) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = $c.GetCommandName()
                if ($name -in 'Invoke-Expression', 'iex' -and $f.Name -ne 'Invoke-AdminConsole.ps1') { $bad += "$($f.Name): $name" }
                if ($name -in 'Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm' -and $f.Name -notin 'Install-Sysmon.ps1', 'Test-LabServices.ps1') { $bad += "$($f.Name): $name" }   # Test-LabServices only GETs a page to check it works
            }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'a secret is never read with a bare Read-Host (Start-Transcript records plain input verbatim): prompts mentioning password/secret/token/key need -AsSecureString' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1')) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Read-Host' }, $true)) {
                $text = $c.Extent.Text
                if ($text -match '(?i)password|passphrase|secret|token|api[ _-]?key' -and $text -notmatch '(?i)-AsSecureString') {
                    $bad += "$($f.Name):$($c.Extent.StartLineNumber)"
                }
            }
        }
        ($bad -join '; ') | Should Be ''
    }
}

Describe 'structure' {
    It 'every module script imports Common.psm1' {
        $bad = @()
        $modules = Get-ChildItem -Path (Join-Path $script:RepoRoot 'modules') -Filter '*.ps1' | Where-Object { $_.Name -ne 'CcdcLogic.ps1' }
        foreach ($f in $modules) {
            if (([System.IO.File]::ReadAllText($f.FullName)) -notmatch 'Common\.psm1') { $bad += $f.Name }
        }
        ($bad -join ', ') | Should Be ''
    }
    It 'every module script documents each of its own parameters in its comment-based help (docs drift when a parameter is added without one)' {
        $bad = @()
        $modules = Get-ChildItem -Path (Join-Path $script:RepoRoot 'modules') -Filter '*.ps1' | Where-Object { $_.Name -ne 'CcdcLogic.ps1' }
        $labScripts = @(Get-ChildItem -Path (Join-Path $script:RepoRoot 'lab') -Filter '*.ps1' -Recurse -File | Where-Object { $_.Name -ne 'LabGuestCommon.ps1' })
        foreach ($f in @($modules) + @($labScripts) + @(Get-Item (Join-Path $script:RepoRoot 'Invoke-CCDCToolkit.ps1'))) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            if (-not $ast.ParamBlock) { continue }
            $text = [System.IO.File]::ReadAllText($f.FullName)
            if ($text -notmatch '(?s)<#.*?\.SYNOPSIS') { $bad += "$($f.Name): no comment-based help"; continue }
            foreach ($p in $ast.ParamBlock.Parameters) {
                $name = $p.Name.VariablePath.UserPath
                if ($text -notmatch "(?m)^\s*\.PARAMETER\s+$([regex]::Escape($name))\s*$") { $bad += "$($f.Name): -$name" }
            }
        }
        ($bad -join '; ') | Should Be ''
    }
    It 'no function is defined in two places (the service-port table used to be copy-pasted into two modules)' {
        $seen = @{}
        $dups = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1')) {
            $tok = $null; $err = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
            foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                if ($seen.ContainsKey($fn.Name)) { $dups += "$($fn.Name) ($($seen[$fn.Name]) and $($f.Name))" } else { $seen[$fn.Name] = $f.Name }
            }
        }
        ($dups -join '; ') | Should Be ''
    }
    It 'the service-to-port table lives only in CcdcLogic.ps1' {
        $bad = @()
        foreach ($f in (Get-RepoFile '.ps1', '.psm1')) {
            if ($f.Name -eq 'CcdcLogic.ps1') { continue }
            if (([System.IO.File]::ReadAllText($f.FullName)) -match '\$servicePortMap') { $bad += $f.Name }
        }
        ($bad -join ', ') | Should Be ''
    }
    It 'every function Common.psm1 exports really exists (a typo in Export-ModuleMember fails silently)' {
        Import-Module (Join-Path $script:RepoRoot 'modules\Common.psm1') -Force
        $text = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'modules\Common.psm1'))
        $block = [regex]::Match($text, '(?s)Export-ModuleMember -Function(.*)$').Groups[1].Value
        $names = @($block -split '[,\s`]+' | Where-Object { $_ -match '^[A-Za-z]+-[A-Za-z]+$' })
        $exported = @((Get-Command -Module Common).Name)
        $missing = @($names | Where-Object { $exported -notcontains $_ })
        ($missing -join ', ') | Should Be ''
        $names.Count | Should BeGreaterThan 30
    }
}
