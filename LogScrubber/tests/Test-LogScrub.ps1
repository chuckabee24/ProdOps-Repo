<#
.SYNOPSIS
    Self-test for Invoke-LogScrub.ps1. Runs the scrubber against ..\samples (plus generated encoding
    test files) and verifies that no discovered value leaks into the output, that common false
    positives are left alone, and that re-runs with the same correlation sheet are stable.

.EXAMPLE
    pwsh -File .\tests\Test-LogScrub.ps1
    powershell.exe -ExecutionPolicy Bypass -File .\tests\Test-LogScrub.ps1

    Exit code 0 = all checks passed.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scrubber = Join-Path $root 'Invoke-LogScrub.ps1'
$samples = Join-Path $root 'samples'
$work = Join-Path ([IO.Path]::GetTempPath()) ("LogScrubTest_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
[void](New-Item -ItemType Directory -Path $work)

$script:failures = 0
$script:passes = 0
function Assert([bool]$condition, [string]$message) {
    if ($condition) { $script:passes++; Write-Host "  PASS  $message" -ForegroundColor Green }
    else { $script:failures++; Write-Host "  FAIL  $message" -ForegroundColor Red }
}
function Read-All([string]$dir) {
    $sb = New-Object Text.StringBuilder
    foreach ($f in (Get-ChildItem -LiteralPath $dir -Recurse -File)) { [void]$sb.AppendLine([IO.File]::ReadAllText($f.FullName)) }
    return $sb.ToString()
}
function Test-Contains([string]$text, [string]$value) {
    $rx = '(?<![A-Za-z0-9])' + [regex]::Escape($value) + '(?![A-Za-z0-9])'
    return [regex]::IsMatch($text, $rx, 'IgnoreCase')
}

try {
    # ---------------------------------------------------------------------------------------------
    Write-Host "`n[1] Scrub the sample logs" -ForegroundColor Cyan
    $in = Join-Path $work 'in'
    Copy-Item -LiteralPath $samples -Destination $in -Recurse

    # extra inputs: UTF-16 LE with BOM, ANSI (non UTF-8) with an accented character, a binary file
    $utf16 = "Computer: HR-PC-0007`r`nUser: CORP\mlopez logged on from 172.16.5.9`r`n"
    [IO.File]::WriteAllText((Join-Path $in 'utf16.log'), $utf16, (New-Object Text.UnicodeEncoding($false, $true)))
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    [IO.File]::WriteAllBytes((Join-Path $in 'ansi.log'), $latin1.GetBytes("Caf$([char]0xE9) kiosk host=KIOSK-12 ip 172.16.5.10`n"))
    [IO.File]::WriteAllBytes((Join-Path $in 'blob.bin'), [byte[]](0, 1, 2, 3, 0, 0, 255, 0, 10, 0, 0, 7))
    Set-Content -LiteralPath (Join-Path $in 'known.log') -Value 'Ticket opened by Contoso Ltd for LEGACY-BOX and Project Falcon'

    $out1 = Join-Path $work 'out1'
    $map = Join-Path $work 'map.csv'
    $result = & $scrubber -Path $in -OutputPath $out1 -CorrelationFile $map `
        -CustomTerm 'Contoso Ltd', 'Project Falcon=PROJECT-X' -Hostname 'LEGACY-BOX=OLD-SERVER' -WarningAction SilentlyContinue 6>$null
    Assert ($result.FilesScrubbed -eq 10) "10 text files scrubbed (got $($result.FilesScrubbed))"
    Assert ($result.FilesSkipped -eq 1) "binary file skipped"
    Assert (Test-Path -LiteralPath $map) "correlation sheet written"

    $rows = @(Import-Csv -LiteralPath $map)
    $output = Read-All $out1
    $byOriginal = @{}
    foreach ($r in $rows) { $byOriginal["$($r.Type)|$($r.Original)"] = $r.Replacement }

    # ---------------------------------------------------------------------------------------------
    Write-Host "`n[2] No discovered value may survive in the output" -ForegroundColor Cyan
    $leaks = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        switch ($r.Type) {
            { $_ -in 'HostLabel', 'IPv4Subnet' } { continue }                     # by design not replaced on their own
            'DomainLabel' { if ($r.Original.Length -lt 3) { continue } }
            'MAC' {
                $hex = $r.Original -replace ':', ''
                foreach ($form in @($r.Original, ($r.Original -replace ':', '-'), ($hex.Substring(0, 4) + '.' + $hex.Substring(4, 4) + '.' + $hex.Substring(8, 4)), $hex)) {
                    if (Test-Contains $output $form) { $leaks.Add("MAC $form") }
                }
                continue
            }
        }
        if (Test-Contains $output $r.Original) { $leaks.Add("$($r.Type) $($r.Original)") }
    }
    Assert ($leaks.Count -eq 0) ("no leaks of {0} mapped values{1}" -f $rows.Count, $(if ($leaks.Count) { ': ' + ($leaks -join '; ') } else { '' }))

    foreach ($secret in 'WEB01', 'SQLPROD01', 'APP02', 'FS01', 'DC01', 'FIN-LT-0042', 'edge-fw01', 'HR-PC-0007', 'KIOSK-12',
        'contoso', 'CORP', 'jdoe', 'amartinez', 'svc_sql', 'svc_backup', 'bwayne', 'netadmin', 'mlopez', 'alice.smith',
        '10.20.30.45', '172.16.5.9', '203.0.113.99', '2001:470:1f0b:7a9::25', 'fe80::1c2b:3aff:fe4d:5e6f',
        '00-50-56-A1-B2-C3', '0050.56a1.b2c3', '3c:52:82:1a:2b:3c', '3623811015', 'Contoso Ltd', 'LEGACY-BOX', 'Project Falcon') {
        Assert (-not (Test-Contains $output $secret)) "'$secret' removed"
    }

    # ---------------------------------------------------------------------------------------------
    Write-Host "`n[3] Things that must NOT be touched" -ForegroundColor Cyan
    foreach ($keep in 'System.Net.Mail.SmtpException', 'Version=4.0.0.0', 'HKLM\SOFTWARE\Microsoft\MSSQLServer', 'C:\Windows\System32\config',
        '[Math]::Round result 12:30:45', 'mask 255.255.255.0', 'build 2019.1201.0001', '127.0.0.1', 'localhost', '#Fields: date time',
        'S-1-5-18', '7f3c2a1e-9b4d-4e2f-8a61-0c5d9e7b3f12', 'time.windows.com', 'Microsoft-Windows-Security-Auditing',
        'Account Name:		user-0001', 'D:\MSSQL15.MSSQLSERVER\MSSQL\Log\ERRORLOG', 'schemas.microsoft.com', 'Workstation Name:	-') {
        Assert ($output.Contains($keep)) "'$keep' preserved"
    }

    # ---------------------------------------------------------------------------------------------
    Write-Host "`n[4] Consistency and replacement format" -ForegroundColor Cyan
    $webToken = $byOriginal['Hostname|WEB01']
    Assert ($webToken -match '^HOST-\d{4}$') "WEB01 -> $webToken"
    $iis = [IO.File]::ReadAllText((Get-ChildItem -LiteralPath $out1 -Recurse -Filter 'u_ex261118.log').FullName)
    Assert ($iis.Contains("W3SVC1 $webToken ")) "same token for WEB01 in the IIS log"
    Assert ($output -match "Computer:\s+$webToken\.domain-\d{4}\.domain-\d{4}\.com") "FQDN WEB01.corp.contoso.com composed from the same host token"
    Assert ($byOriginal['IPv4|10.20.30.45'] -match '^198\.18\.\d+\.45$') "IPv4 keeps last octet in 198.18/15 ($($byOriginal['IPv4|10.20.30.45']))"
    $a = $byOriginal['IPv4|10.20.30.45'] -replace '\.\d+$', ''; $b = $byOriginal['IPv4|10.20.30.77'] -replace '\.\d+$', ''
    Assert ($a -eq $b) "addresses in the same /24 stay in the same /24"
    Assert ($byOriginal['MAC|00:50:56:A1:B2:C3'] -match '^02:00:00:') "MAC replaced with locally administered address"
    Assert ($output.Contains('Physical Address. . . . . . . . . : 02-00-00-')) "MAC keeps dash separator style"
    Assert ($output -match 'hw 0200\.0000\.00[0-9a-f]{2}') "MAC keeps Cisco dotted style"
    Assert ($byOriginal['IPv6|2001:470:1f0b:7a9::25'] -like '2001:db8:*') "IPv6 replaced from 2001:db8::/32 ($($byOriginal['IPv6|2001:470:1f0b:7a9::25']))"
    Assert ($output -match 'S-1-5-21-1111111111-2222222222-3\d{9}-1104') "SID domain part replaced, RID kept"
    Assert ($output.Contains('Ticket opened by REDACTED-0001 for OLD-SERVER and PROJECT-X')) "custom terms and user-chosen replacements"
    $names = (Get-ChildItem -LiteralPath $out1 -Recurse -File).Name
    Assert (($names -like 'HOST-*_Security.txt').Count -eq 1 -and -not ($names -like 'WEB01*')) "file names scrubbed ($($names -join ', '))"

    # ---------------------------------------------------------------------------------------------
    Write-Host "`n[5] Encodings" -ForegroundColor Cyan
    $u16 = [IO.File]::ReadAllBytes((Get-ChildItem -LiteralPath $out1 -Recurse -Filter 'utf16.log').FullName)
    Assert ($u16[0] -eq 0xFF -and $u16[1] -eq 0xFE) "UTF-16 LE BOM preserved"
    $u16text = [Text.Encoding]::Unicode.GetString($u16, 2, $u16.Length - 2)
    Assert ($u16text -notmatch 'HR-PC-0007|mlopez|172\.16\.5\.9' -and $u16text -match 'HOST-\d{4}') "UTF-16 content scrubbed"
    $ansi = [IO.File]::ReadAllBytes((Get-ChildItem -LiteralPath $out1 -Recurse -Filter 'ansi.log').FullName)
    Assert ($ansi[3] -eq 0xE9) "ANSI byte 0xE9 round-trips unchanged"
    Assert ($latin1.GetString($ansi) -notmatch 'KIOSK-12|172\.16\.5\.10') "ANSI content scrubbed"

    # ---------------------------------------------------------------------------------------------
    Write-Host "`n[6] Re-run with the same correlation sheet is stable" -ForegroundColor Cyan
    $out2 = Join-Path $work 'out2'
    $null = & $scrubber -Path $in -OutputPath $out2 -CorrelationFile $map `
        -CustomTerm 'Contoso Ltd', 'Project Falcon=PROJECT-X' -Hostname 'LEGACY-BOX=OLD-SERVER' -WarningAction SilentlyContinue 6>$null
    $rows2 = @(Import-Csv -LiteralPath $map)
    Assert ($rows2.Count -eq $rows.Count) "same number of mappings ($($rows.Count) -> $($rows2.Count))"
    $diff = @(Compare-Object ($rows | ForEach-Object { "$($_.Type)|$($_.Original)|$($_.Replacement)" }) ($rows2 | ForEach-Object { "$($_.Type)|$($_.Original)|$($_.Replacement)" }))
    Assert ($diff.Count -eq 0) "identical mappings"
    Assert ((Read-All $out1) -eq (Read-All $out2)) "identical scrubbed output"

    # a new batch reuses existing tokens and only adds new ones
    $in3 = Join-Path $work 'in3'
    [void](New-Item -ItemType Directory -Path $in3)
    Set-Content -LiteralPath (Join-Path $in3 'later.log') -Value "Computer: WEB01`nComputer: NEWBOX01`nclient 10.20.30.45"
    $out3 = Join-Path $work 'out3'
    $null = & $scrubber -Path $in3 -OutputPath $out3 -CorrelationFile $map -WarningAction SilentlyContinue 6>$null
    $later = Read-All $out3
    Assert ($later.Contains("Computer: $webToken")) "existing token reused in a later batch"
    Assert ($later.Contains("client $($byOriginal['IPv4|10.20.30.45'])")) "existing IP mapping reused in a later batch"
    Assert (-not $later.Contains('NEWBOX01') -and @(Import-Csv $map | Where-Object Original -eq 'NEWBOX01').Count -eq 1) "new value added to the sheet"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n{0} passed, {1} failed" -f $script:passes, $script:failures) -ForegroundColor $(if ($script:failures) { 'Red' } else { 'Green' })
exit [int]($script:failures -gt 0)
