<#
.SYNOPSIS
    Ground-truth leak test: scrubs realistic log corpora and checks the output against a manifest that lists
    every planted sensitive value (must disappear) and text that must survive unchanged.

.DESCRIPTION
    Each corpus is a folder under tests\corpus\<name>\ with a manifest tests\corpus\<name>.manifest.json:
      {
        "secrets":       [ { "value": "...", "type": "hostname|fqdn|username|ipv4|mac|secret|..." } ],
        "must_preserve": [ { "file": "<file name>", "text": "exact text that must not change" } ],
        "known_gaps":    { "leaks": [ { "value": "...", "reason": "..." } ], "preserve": [ { "text": "...", "reason": "..." } ] }
      }
    A leak is a planted value found in the output with letter/digit boundaries on both sides (case-insensitive).
    Known gaps are reported but do not fail the run.

.PARAMETER CorpusPath
    One corpus folder. Default: every folder under tests\corpus that has a manifest.

.PARAMETER ManifestPath
    Manifest for -CorpusPath. Default: <CorpusPath>.manifest.json

.EXAMPLE
    pwsh -File .\tests\Invoke-ScenarioTest.ps1
    Exit code 0 = no unexpected leaks and no unexpected changes in any corpus.
#>
[CmdletBinding()]
param(
    [string]$CorpusPath,
    [string]$ManifestPath,
    [hashtable]$ScrubberArgs = @{},
    [switch]$KeepOutput
)

$ErrorActionPreference = 'Stop'
$scrubber = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-LogScrub.ps1'

function Read-Decoded([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B) {
        $ms = New-Object IO.MemoryStream(, $bytes)
        $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)
        $o = New-Object IO.MemoryStream
        $gz.CopyTo($o); $gz.Dispose()
        $bytes = $o.ToArray()
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2) }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) }
    try { return (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes) }
    catch { return [Text.Encoding]::GetEncoding(28591).GetString($bytes) }
}

function Read-Manifest([string]$path) {
    $json = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    if ($PSVersionTable.PSVersion.Major -lt 6) { return ($json | ConvertFrom-Json) }
    # PowerShell 7's ConvertFrom-Json turns ISO-8601 strings into dates; read with date parsing off instead
    $settings = New-Object Newtonsoft.Json.JsonSerializerSettings
    $settings.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
    $jo = [Newtonsoft.Json.JsonConvert]::DeserializeObject($json, [Newtonsoft.Json.Linq.JObject], $settings)
    function Convert-Token($t) {
        if ($t -is [Newtonsoft.Json.Linq.JObject]) {
            $h = [ordered]@{}
            foreach ($p in $t.Properties()) { $h[$p.Name] = Convert-Token $p.Value }
            return [pscustomobject]$h
        }
        if ($t -is [Newtonsoft.Json.Linq.JArray]) { return , @($t | ForEach-Object { Convert-Token $_ }) }
        return $t.Value
    }
    return (Convert-Token $jo)
}

function Get-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value } else { return $null }
}

function Test-Corpus([string]$corpus, [string]$manifestFile) {
    $manifest = Read-Manifest $manifestFile
    $gaps = Get-Prop $manifest 'known_gaps'
    $gapLeaks = @{}; foreach ($g in @(Get-Prop $gaps 'leaks')) { if ($g) { $gapLeaks[[string]$g.value] = [string]$g.reason } }
    $gapKeep = @{}; foreach ($g in @(Get-Prop $gaps 'preserve')) { if ($g) { $gapKeep[[string]$g.text] = [string]$g.reason } }

    $work = Join-Path ([IO.Path]::GetTempPath()) ("LogScrubScenario_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $out = Join-Path $work 'out'
    $map = Join-Path $work 'map.csv'
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $result = & $scrubber -Path $corpus -Recurse -OutputPath $out -CorrelationFile $map -KeepFileNames @ScrubberArgs -WarningAction SilentlyContinue 6>$null
        $sw.Stop()
        $outRoot = Join-Path $out (Split-Path -Leaf $corpus)
        $texts = @{}
        foreach ($f in Get-ChildItem -LiteralPath $outRoot -Recurse -File) {
            $texts[$f.FullName.Substring($outRoot.Length).TrimStart('\', '/')] = Read-Decoded $f.FullName
        }

        $leaks = New-Object System.Collections.Generic.List[object]
        $known = New-Object System.Collections.Generic.List[object]
        foreach ($s in $manifest.secrets) {
            $v = [string]$s.value
            if (-not $v) { continue }
            $forms = @($v)
            if ($s.type -eq 'mac') {
                $hex = ($v -replace '[^0-9A-Fa-f]', '')
                if ($hex.Length -eq 12) {
                    $pairs = ($hex -split '(..)' | Where-Object { $_ })
                    $forms += @(($pairs -join ':'), ($pairs -join '-'), ($hex.Substring(0, 4) + '.' + $hex.Substring(4, 4) + '.' + $hex.Substring(8, 4)), $hex)
                }
            }
            foreach ($form in ($forms | Select-Object -Unique)) {
                $rx = '(?<![A-Za-z0-9])' + [regex]::Escape($form) + '(?![A-Za-z0-9])'
                $hit = $null
                foreach ($k in $texts.Keys) {
                    $m = [regex]::Match($texts[$k], $rx, 'IgnoreCase')
                    if ($m.Success) {
                        $a = [Math]::Max(0, $m.Index - 50); $b = [Math]::Min($texts[$k].Length, $m.Index + $m.Length + 50)
                        $hit = [pscustomobject]@{ Type = $s.type; Value = $form; File = $k; Context = ($texts[$k].Substring($a, $b - $a) -replace '\s+', ' ') }
                        break
                    }
                }
                if ($hit) {
                    if ($gapLeaks.ContainsKey($v) -or $gapLeaks.ContainsKey($form)) { $known.Add($hit) } else { $leaks.Add($hit) }
                    break
                }
            }
        }

        $broken = New-Object System.Collections.Generic.List[object]
        $knownBroken = 0
        foreach ($p in $manifest.must_preserve) {
            $key = ([string]$p.file) -replace '/', [IO.Path]::DirectorySeparatorChar
            $t = $texts[$key]
            $ok = ($null -ne $t) -and ($t.IndexOf([string]$p.text, [StringComparison]::Ordinal) -ge 0)
            if ($ok) { continue }
            if ($gapKeep.ContainsKey([string]$p.text)) { $knownBroken++; continue }
            $broken.Add([pscustomobject]@{ File = $p.file; Text = $p.text })
        }

        $total = @($manifest.secrets).Count
        $caught = $total - $leaks.Count - $known.Count
        Write-Host ''
        Write-Host ("=== {0}: {1} files, {2:n1}s, audit findings {3}" -f (Split-Path -Leaf $corpus), $result.FilesScrubbed, $sw.Elapsed.TotalSeconds, $result.AuditFindings) -ForegroundColor Cyan
        Write-Host ("Planted sensitive values : {0}  removed: {1} ({2:p1})" -f $total, $caught, ($caught / [double]$total))
        Write-Host ("Unexpected leaks         : {0}" -f $leaks.Count) -ForegroundColor $(if ($leaks.Count) { 'Red' } else { 'Green' })
        foreach ($l in $leaks) { Write-Host ("   LEAK [{0}] {1}  ({2}) ...{3}..." -f $l.Type, $l.Value, $l.File, $l.Context) -ForegroundColor Red }
        Write-Host ("Known gaps (accepted)    : {0}" -f $known.Count) -ForegroundColor $(if ($known.Count) { 'Yellow' } else { 'Green' })
        foreach ($l in $known) { Write-Host ("   gap  [{0}] {1}: {2}" -f $l.Type, $l.Value, $gapLeaks[[string]$l.Value]) -ForegroundColor DarkYellow }
        Write-Host ("Must-preserve            : {0} checked, {1} changed unexpectedly, {2} known" -f @($manifest.must_preserve).Count, $broken.Count, $knownBroken) -ForegroundColor $(if ($broken.Count) { 'Red' } else { 'Green' })
        foreach ($b in $broken) { Write-Host ("   CHANGED {0}: {1}" -f $b.File, $b.Text) -ForegroundColor Red }
        # stability: same correlation sheet -> identical output; scrubbing scrubbed output -> no change
        $unstable = 0
        $out2 = Join-Path $work 'out2'
        $null = & $scrubber -Path $corpus -Recurse -OutputPath $out2 -CorrelationFile $map -KeepFileNames @ScrubberArgs -WarningAction SilentlyContinue 6>$null
        $out3 = Join-Path $work 'out3'
        $null = & $scrubber -Path $outRoot -Recurse -OutputPath $out3 -CorrelationFile (Join-Path $work 'map3.csv') -KeepFileNames @ScrubberArgs -WarningAction SilentlyContinue 6>$null
        foreach ($f in Get-ChildItem -LiteralPath $outRoot -Recurse -File) {
            $rel = $f.FullName.Substring($outRoot.Length).TrimStart('\', '/')
            $a = [IO.File]::ReadAllBytes($f.FullName)
            foreach ($other in @((Join-Path (Join-Path $out2 (Split-Path -Leaf $corpus)) $rel), (Join-Path (Join-Path $out3 (Split-Path -Leaf $outRoot)) $rel))) {
                $same = (Test-Path -LiteralPath $other)
                if ($same) {
                    $b = [IO.File]::ReadAllBytes($other)
                    if ($f.Extension -eq '.gz') { $same = (Read-Decoded $f.FullName) -eq (Read-Decoded $other) }
                    else { $same = ($a.Length -eq $b.Length) -and ([Convert]::ToBase64String($a) -eq [Convert]::ToBase64String($b)) }
                }
                if (-not $same) { $unstable++; Write-Host "   UNSTABLE $rel ($other)" -ForegroundColor Red }
            }
        }
        Write-Host ("Re-run / re-scrub stable : {0}" -f $(if ($unstable) { "NO ($unstable file(s) differ)" } else { 'yes' })) -ForegroundColor $(if ($unstable) { 'Red' } else { 'Green' })
        if ($KeepOutput) { Write-Host "Output kept in $work" }
        return ($leaks.Count + $broken.Count + $unstable)
    }
    finally {
        if (-not $KeepOutput) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

$pairs = @()
if ($CorpusPath) {
    if (-not $ManifestPath) { $ManifestPath = $CorpusPath.TrimEnd('\', '/') + '.manifest.json' }
    $pairs += , @($CorpusPath, $ManifestPath)
}
else {
    foreach ($d in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'corpus') -Directory) {
        $mf = Join-Path $d.Parent.FullName ($d.Name + '.manifest.json')
        if (Test-Path -LiteralPath $mf) { $pairs += , @($d.FullName, $mf) }
    }
}
$problems = 0
foreach ($p in $pairs) { $problems += (Test-Corpus $p[0] $p[1]) }
Write-Host ''
Write-Host $(if ($problems) { "FAILED: $problems unexpected leak(s)/change(s)" } else { 'PASSED: no unexpected leaks or changes' }) -ForegroundColor $(if ($problems) { 'Red' } else { 'Green' })
exit [int]($problems -gt 0)
