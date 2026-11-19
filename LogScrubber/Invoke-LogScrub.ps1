<#
.SYNOPSIS
    Scrubs hostnames, IP addresses, MAC addresses, domain names, user names, e-mail addresses and
    domain SIDs out of log files, writes sanitized copies, and produces a correlation sheet
    (real value -> replacement).

.DESCRIPTION
    Two passes are made over the input:

      1. Discovery - every file is scanned for sensitive values. Each unique value gets a stable
         replacement token (WEB01 -> HOST-0001, corp -> DOMAIN-0001, 10.20.30.45 -> 198.18.0.45 ...).
      2. Replacement - every discovered value is replaced everywhere it appears in every file, so the
         same machine has the same token in all scrubbed logs, including bare mentions of a name that
         was only *discovered* in an FQDN, UNC path or "Computer:" field.

    Replacement values are chosen from ranges that can never be real:
      IPv4  198.18.0.0/15 then 240.0.0.0/4 (one /24 per real /24, last octet kept so subnets still line up)
      IPv6  2001:db8::/32 (documentation prefix)
      MAC   02:00:00:xx:xx:xx (locally administered), same separator style as the original
      SID   S-1-5-21-1111111111-2222222222-30000000NN (RID kept)
      Names HOST-0001, DOMAIN-0001, USER-0001, REDACTED-0001 (case style of the original is kept)

    The correlation sheet is a CSV with columns Type, Original, Replacement, MatchesThisRun, FirstSeenIn.
    Pass the same -CorrelationFile on later runs to keep replacements stable across batches of logs.

    THE CORRELATION SHEET CONTAINS THE REAL VALUES. Store it securely and never send it along with the
    scrubbed logs. By default it is written next to (not inside) the output folder for that reason.

.PARAMETER Path
    One or more files or folders (wildcards allowed). Accepts pipeline input (e.g. from Get-ChildItem).

.PARAMETER OutputPath
    Folder that receives the scrubbed copies. Default: .\Scrubbed_<timestamp>
    Folder inputs keep their sub-folder structure under OutputPath\<folder name>\.

.PARAMETER CorrelationFile
    CSV correlation sheet. If the file exists it is loaded first (so existing mappings are reused) and
    then rewritten with any new values. Default: ScrubCorrelation_<timestamp>.csv beside OutputPath.

.PARAMETER Recurse
    Include sub-folders of folder inputs.

.PARAMETER Include
    File name wildcards to include from folder inputs. Default: * (binary files are skipped automatically).

.PARAMETER Exclude
    File name wildcards to skip from folder inputs (e.g. *.evtx, *.zip).

.PARAMETER SkipType
    Categories to leave untouched: IPv4, IPv6, MAC, Hostname, Domain, User, Email, SID.

.PARAMETER Hostname
    Host names you already know are sensitive. Use "NAME=REPLACEMENT" to choose the replacement yourself.

.PARAMETER Domain
    Domain names / NetBIOS domains you already know are sensitive ("contoso", "corp.contoso.com").

.PARAMETER User
    User names you already know are sensitive. "NAME=REPLACEMENT" is supported.

.PARAMETER CustomTerm
    Any other text to redact (company name, project code names, ...). Phrases with spaces are allowed.
    "TEXT=REPLACEMENT" is supported.

.PARAMETER TermsFile
    Text file with one entry per line, optionally prefixed with a type:
        # comment
        host: SQLPROD01            (or host: SQLPROD01 = DB-SERVER-A)
        domain: contoso
        user: jdoe
        term: Project Falcon       (also: lines with no prefix are custom terms)
        keep: 10.1.1.1             (never scrub this value)
        pattern: \b(?:NYC|LAX)-[A-Z]{2,4}\d{2,4}\b   (host name regex; use (?<host>...) to capture part)
        tld: contoso               (treat as an extra top-level domain)

.PARAMETER HostnamePattern
    Regular expressions matching your naming convention, e.g. '\b(?:NYC|LAX)-(?:WEB|SQL|DC)\d{2}\b'.
    Every match is treated as a host name. Use a named group (?<host>...) to capture only part of a match.

.PARAMETER ExtraTld
    Extra top-level / internal suffixes to recognise for automatic FQDN detection (e.g. "contoso", "ad").

.PARAMETER KeepValue
    Exact values that must never be scrubbed (e.g. a public NTP server IP).

.PARAMETER KeepDomain
    Domains (and their sub-domains) that must never be scrubbed, added to the built-in vendor list
    (microsoft.com, windowsupdate.com, digicert.com, ...).

.PARAMETER IgnoreName
    Words that look like names in your logs but are not sensitive (prevents over-scrubbing).

.PARAMETER NoDefaultExclusions
    Do not use the built-in ignore list (localhost, administrator, www, ...), vendor-domain list or
    default kept values (127.0.0.1, 0.0.0.0, ...).

.PARAMETER IncludeLocalIdentity
    Also treat this machine's name, domain and current user name as sensitive.

.PARAMETER KeepFileNames
    Keep output file / folder names exactly as the input. By default names are scrubbed too
    (WEB01_System.log -> HOST-0001_System.log).

.PARAMETER MinNameLength
    Host / user / domain names shorter than this are not replaced when they appear on their own
    (they are still replaced inside FQDNs, e-mail addresses, etc). Default 3.

.PARAMETER Force
    Overwrite existing output files.

.EXAMPLE
    .\Invoke-LogScrub.ps1 -Path C:\Logs\app.log

    Scrubs one file into .\Scrubbed_<timestamp>\app.log and writes .\ScrubCorrelation_<timestamp>.csv.

.EXAMPLE
    .\Invoke-LogScrub.ps1 -Path C:\Cases\1234\logs -Recurse -OutputPath C:\Cases\1234\to-vendor `
        -CorrelationFile C:\Secure\case1234-map.csv -Exclude *.evtx,*.etl -CustomTerm 'Contoso Ltd'

    Scrubs a folder tree. Running again later with the same -CorrelationFile reuses the same tokens.

.EXAMPLE
    Get-ChildItem C:\inetpub\logs -Filter *.log -Recurse | .\Invoke-LogScrub.ps1 -SkipType Email -HostnamePattern '\bNYC-\w+\d{2}\b'

.NOTES
    Works on Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS).
    Requires LogScrubEngine.cs in the same folder as this script.
    Text files only: export .evtx with  wevtutil qe Security /f:text > security.txt  (or Get-WinEvent | Format-List)
    and scrub the text output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName', 'PSPath')]
    [string[]]$Path,

    [Parameter(Position = 1)]
    [string]$OutputPath,

    [string]$CorrelationFile,

    [switch]$Recurse,

    [string[]]$Include = @('*'),

    [string[]]$Exclude = @(),

    [ValidateSet('IPv4', 'IPv6', 'MAC', 'Hostname', 'Domain', 'User', 'Email', 'SID')]
    [string[]]$SkipType = @(),

    [string[]]$Hostname = @(),
    [string[]]$Domain = @(),
    [string[]]$User = @(),
    [string[]]$CustomTerm = @(),
    [string]$TermsFile,
    [string[]]$HostnamePattern = @(),
    [string[]]$ExtraTld = @(),
    [string[]]$KeepValue = @(),
    [string[]]$KeepDomain = @(),
    [string[]]$IgnoreName = @(),
    [switch]$NoDefaultExclusions,
    [switch]$IncludeLocalIdentity,
    [switch]$KeepFileNames,

    [ValidateRange(1, 64)]
    [int]$MinNameLength = 3,

    [switch]$Force
)

begin {
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $inputPaths = New-Object System.Collections.Generic.List[string]
}

process {
    foreach ($p in $Path) { if ($p) { $inputPaths.Add($p) } }
}

end {
    # ---------------------------------------------------------------------------------------------
    # Load engine
    # ---------------------------------------------------------------------------------------------
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $engineFile = Join-Path $scriptDir 'LogScrubEngine.cs'
    if (-not ('LogScrub.ScrubEngine' -as [type])) {
        if (-not (Test-Path -LiteralPath $engineFile)) { throw "Engine source not found: $engineFile (keep it next to this script)." }
        Add-Type -Path $engineFile
    }
    $engineSource = Get-Content -LiteralPath $engineFile -Raw -ErrorAction SilentlyContinue
    if ($engineSource -and $engineSource -match 'EngineVersion = "([^"]+)"' -and $Matches[1] -ne [LogScrub.ScrubEngine]::EngineVersion) {
        Write-Warning ("LogScrubEngine.cs changed (v{0}) but v{1} is already loaded in this session. Start a new PowerShell session to load the new engine." -f $Matches[1], [LogScrub.ScrubEngine]::EngineVersion)
    }

    function Resolve-FullPath([string]$p) {
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
    }

    function Test-NameMatch([string]$name, [string[]]$patterns) {
        foreach ($pat in $patterns) { if ($name -like $pat) { return $true } }
        return $false
    }

    function Split-Replacement([string]$value) {
        # "NAME=REPLACEMENT" -> @(NAME, REPLACEMENT); "NAME" -> @(NAME, $null)
        $i = $value.IndexOf('=')
        if ($i -gt 0) { return @($value.Substring(0, $i).Trim(), $value.Substring($i + 1).Trim()) }
        return @($value.Trim(), $null)
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).ProviderPath "Scrubbed_$timestamp" }
    $OutputPath = Resolve-FullPath $OutputPath
    if (-not $CorrelationFile) {
        $CorrelationFile = Join-Path (Split-Path -Parent $OutputPath) "ScrubCorrelation_$timestamp.csv"
    }
    $CorrelationFile = Resolve-FullPath $CorrelationFile
    $sep = [IO.Path]::DirectorySeparatorChar
    $outPrefix = $OutputPath.TrimEnd('\', '/') + $sep
    $pathComparison = if ($sep -eq '\') { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }

    if ($CorrelationFile.StartsWith($outPrefix, $pathComparison)) {
        Write-Warning "The correlation file is inside the output folder. It contains the REAL values - do not share it with the scrubbed logs."
    }

    # ---------------------------------------------------------------------------------------------
    # Collect input files
    # ---------------------------------------------------------------------------------------------
    $files = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($p in $inputPaths) {
        $resolved = @(Resolve-Path -Path $p -ErrorAction SilentlyContinue)
        if ($resolved.Count -eq 0) { Write-Error "Path not found: $p" -ErrorAction Continue; continue }
        foreach ($r in $resolved) {
            $full = $r.ProviderPath
            if (Test-Path -LiteralPath $full -PathType Container) {
                $root = $full.TrimEnd('\', '/')
                $rootName = Split-Path -Leaf $root
                if (-not $rootName) { $rootName = 'root' }
                foreach ($f in (Get-ChildItem -LiteralPath $root -File -Recurse:$Recurse -Force -ErrorAction SilentlyContinue)) {
                    if (-not (Test-NameMatch $f.Name $Include)) { continue }
                    if ($Exclude.Count -gt 0 -and (Test-NameMatch $f.Name $Exclude)) { continue }
                    if ($f.FullName.StartsWith($outPrefix, $pathComparison)) { continue }
                    if ($f.FullName -eq $CorrelationFile) { continue }
                    if ($seen.ContainsKey($f.FullName)) { continue }
                    $seen[$f.FullName] = $true
                    $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
                    $files.Add([pscustomobject]@{ FullName = $f.FullName; Relative = (Join-Path $rootName $rel); Info = $null })
                }
            }
            else {
                if ($seen.ContainsKey($full)) { continue }
                $seen[$full] = $true
                $files.Add([pscustomobject]@{ FullName = $full; Relative = (Split-Path -Leaf $full); Info = $null })
            }
        }
    }
    if ($files.Count -eq 0) { throw 'No input files found.' }

    # ---------------------------------------------------------------------------------------------
    # Configure engine
    # ---------------------------------------------------------------------------------------------
    $engine = New-Object LogScrub.ScrubEngine
    $engine.ScrubIPv4 = $SkipType -notcontains 'IPv4'
    $engine.ScrubIPv6 = $SkipType -notcontains 'IPv6'
    $engine.ScrubMac = $SkipType -notcontains 'MAC'
    $engine.ScrubHostnames = $SkipType -notcontains 'Hostname'
    $engine.ScrubDomains = $SkipType -notcontains 'Domain'
    $engine.ScrubUsers = $SkipType -notcontains 'User'
    $engine.ScrubEmails = $SkipType -notcontains 'Email'
    $engine.ScrubSids = $SkipType -notcontains 'SID'
    $engine.MinBareLength = $MinNameLength

    if ($NoDefaultExclusions) { $engine.ClearDefaultExclusions() }
    foreach ($v in $ExtraTld) { $engine.AddTld($v) }
    foreach ($v in $KeepValue) { $engine.AddExcludeValue($v) }
    foreach ($v in $KeepDomain) { $engine.AddExcludeDomain($v) }
    foreach ($v in $IgnoreName) { $engine.AddIgnoreName($v) }
    foreach ($v in $HostnamePattern) { $engine.AddHostnamePattern($v) }

    $loaded = 0
    if (Test-Path -LiteralPath $CorrelationFile) {
        $loaded = $engine.LoadCorrelationCsv($CorrelationFile)
        Write-Verbose "Loaded $loaded existing mappings from $CorrelationFile"
    }

    foreach ($v in $Hostname) { $kv = Split-Replacement $v; $engine.AddKnown('Hostname', $kv[0], $kv[1]) }
    foreach ($v in $Domain) { $kv = Split-Replacement $v; $engine.AddKnown('Domain', $kv[0], $kv[1]) }
    foreach ($v in $User) { $kv = Split-Replacement $v; $engine.AddKnown('User', $kv[0], $kv[1]) }
    foreach ($v in $CustomTerm) { $kv = Split-Replacement $v; $engine.AddKnown('Custom', $kv[0], $kv[1]) }

    if ($TermsFile) {
        foreach ($line in (Get-Content -LiteralPath $TermsFile)) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            if ($t -match '^(?<k>host|hostname|computer|domain|user|username|term|custom|keep|pattern|tld)\s*:\s*(?<v>.+)$') {
                $k = $Matches['k'].ToLowerInvariant(); $v = $Matches['v'].Trim()
                switch ($k) {
                    'keep' { $engine.AddExcludeValue($v) }
                    'pattern' { $engine.AddHostnamePattern($v) }
                    'tld' { $engine.AddTld($v) }
                    default {
                        $kv = Split-Replacement $v
                        $type = switch ($k) { { $_ -in 'host', 'hostname', 'computer' } { 'Hostname' } { $_ -in 'user', 'username' } { 'User' } 'domain' { 'Domain' } default { 'Custom' } }
                        $engine.AddKnown($type, $kv[0], $kv[1])
                    }
                }
            }
            else {
                $kv = Split-Replacement $t
                $engine.AddKnown('Custom', $kv[0], $kv[1])
            }
        }
    }

    if ($IncludeLocalIdentity) {
        $localHost = [Environment]::MachineName
        if ($localHost) { $engine.AddKnown('Hostname', $localHost, $null) }
        if ($env:USERDNSDOMAIN) { $engine.AddKnown('Domain', $env:USERDNSDOMAIN, $null) }
        if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $localHost) { $engine.AddKnown('Domain', $env:USERDOMAIN, $null) }
        $localUser = [Environment]::UserName
        if ($localUser) { $engine.AddKnown('User', $localUser, $null) }
    }

    # ---------------------------------------------------------------------------------------------
    # Pass 1 - discovery
    # ---------------------------------------------------------------------------------------------
    $skipped = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($f in $files) {
        $i++
        Write-Progress -Activity 'Scrubbing logs (1/2: discovering values)' -Status $f.Relative -PercentComplete ([int](100 * $i / $files.Count))
        try {
            $info = [LogScrub.ScrubEngine]::Inspect($f.FullName)
            if ($info.IsBinary) {
                Write-Warning "Skipping binary file: $($f.FullName)"
                $skipped.Add($f.FullName)
                continue
            }
            $engine.ScanFile($f.FullName, $info, $f.Relative)
            $f.Info = $info
        }
        catch {
            Write-Warning "Skipping $($f.FullName): $($_.Exception.Message)"
            $skipped.Add($f.FullName)
        }
    }
    Write-Progress -Activity 'Scrubbing logs (1/2: discovering values)' -Completed

    # ---------------------------------------------------------------------------------------------
    # Pass 2 - replacement
    # ---------------------------------------------------------------------------------------------
    [void][IO.Directory]::CreateDirectory($OutputPath)
    $written = New-Object System.Collections.Generic.List[object]
    $todo = @($files | Where-Object { $null -ne $_.Info })
    $i = 0
    foreach ($f in $todo) {
        $i++
        Write-Progress -Activity 'Scrubbing logs (2/2: writing scrubbed copies)' -Status $f.Relative -PercentComplete ([int](100 * $i / $todo.Count))
        $rel = $f.Relative
        if (-not $KeepFileNames) {
            $parts = $rel -split '[\\/]'
            $rel = ($parts | ForEach-Object { $engine.ScrubText($_) }) -join $sep
        }
        $outFile = Join-Path $OutputPath $rel
        if ($outFile -eq $f.FullName) { Write-Warning "Refusing to overwrite the input file $outFile"; $skipped.Add($f.FullName); continue }
        if ((Test-Path -LiteralPath $outFile) -and -not $Force) {
            Write-Warning "Output exists (use -Force to overwrite): $outFile"
            $skipped.Add($f.FullName)
            continue
        }
        try {
            $engine.ScrubFile($f.FullName, $outFile, $f.Info)
            $written.Add([pscustomobject]@{ Source = $f.FullName; Output = $outFile; Encoding = $f.Info.EncodingName })
        }
        catch {
            Write-Warning "Failed to scrub $($f.FullName): $($_.Exception.Message)"
            $skipped.Add($f.FullName)
        }
    }
    Write-Progress -Activity 'Scrubbing logs (2/2: writing scrubbed copies)' -Completed

    # ---------------------------------------------------------------------------------------------
    # Correlation sheet
    # ---------------------------------------------------------------------------------------------
    $corrDir = Split-Path -Parent $CorrelationFile
    if ($corrDir) { [void][IO.Directory]::CreateDirectory($corrDir) }
    $mappingCount = $engine.WriteCorrelationCsv($CorrelationFile)

    # ---------------------------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------------------------
    $byType = [ordered]@{}
    foreach ($kv in $engine.GetTypeCounts()) { $byType[$kv.Key] = $kv.Value }
    $typeSummary = ($byType.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join ', '

    Write-Host ''
    Write-Host ("Scrubbed {0} file(s) -> {1}" -f $written.Count, $OutputPath) -ForegroundColor Green
    if ($skipped.Count -gt 0) { Write-Host ("Skipped {0} file(s) (see warnings above)" -f $skipped.Count) -ForegroundColor Yellow }
    Write-Host ("Correlation sheet ({0} entries: {1}) -> {2}" -f $mappingCount, $typeSummary, $CorrelationFile)
    Write-Host 'The correlation sheet contains the REAL values. Keep it private; share only the scrubbed folder.' -ForegroundColor Yellow

    [pscustomobject]@{
        OutputPath      = $OutputPath
        CorrelationFile = $CorrelationFile
        FilesScrubbed   = $written.Count
        FilesSkipped    = $skipped.Count
        Mappings        = $mappingCount
        MappingsByType  = [pscustomobject]$byType
        Files           = $written
    }
}
