# LogScrubber

A PowerShell tool with a .NET engine that removes infrastructure identifiers from log files before you
send them to a vendor, post them in a ticket or attach them to a case. It writes scrubbed copies of
the logs and a **correlation sheet** that maps each real value to its replacement (for example
`WEB01 -> HOST-0007`). You can then translate the vendor's answer back to your real systems.

- Runs on **Windows PowerShell 5.1** and **PowerShell 7+** (Windows, Linux, macOS). Nothing to install.
- Replacements are **consistent across every file in a run**, and across runs if you reuse the correlation sheet.
- Fast: the matching engine is C# compiled on the fly with `Add-Type`. In testing, a 176 MB log containing 847k unique values took about 30 s.

## Files

| File | Purpose |
|---|---|
| `Invoke-LogScrub.ps1` | The command you run |
| `LogScrubEngine.cs` | Detection and replacement engine. **It must stay in the same folder as the script.** |
| `samples\` | Example logs (Windows Security, IIS, ipconfig, JSON, XML event export, SQL ERRORLOG, syslog/DHCP) |
| `tests\Test-LogScrub.ps1` | Self-test: scrubs the samples and checks for leaks, false positives, encodings and stable re-runs |

## Quick start

```powershell
# One file -> .\Scrubbed_<timestamp>\app.log  +  .\ScrubCorrelation_<timestamp>.csv
.\Invoke-LogScrub.ps1 -Path C:\Logs\app.log

# A folder tree, with a correlation sheet you keep for the whole case
.\Invoke-LogScrub.ps1 -Path C:\Cases\1234\logs -Recurse `
    -OutputPath C:\Cases\1234\to-vendor `
    -CorrelationFile C:\Secure\case1234-correlation.csv `
    -Exclude *.evtx, *.etl, *.zip `
    -CustomTerm 'Contoso Ltd', 'Project Falcon'

# Pipeline input
Get-ChildItem C:\inetpub\logs\LogFiles -Recurse -Filter *.log | .\Invoke-LogScrub.ps1 -OutputPath D:\iis-scrubbed
```

If the script was downloaded, unblock it first with `Get-ChildItem .\LogScrubber | Unblock-File`, or run it as
`powershell -ExecutionPolicy Bypass -File .\Invoke-LogScrub.ps1 ...`.

> **The correlation sheet contains the real values.** Store it somewhere secure and never send it with the
> scrubbed logs. By default it is written *next to* the output folder, not inside it, so you can zip and
> send the output folder on its own.

## What gets scrubbed

| Type | Detected from | Replacement |
|---|---|---|
| Host names | `Computer:`, `Host Name . . :`, `Workstation Name:`, `ComputerName=`, `Server=`/`Data Source=`, XML `<Computer>`, JSON keys, UNC paths `\\FS01\share`, URLs `http://app02:8080`, syslog headers, computer accounts `WEB01$`, the host part of FQDNs, your `-HostnamePattern` | `HOST-0001` |
| FQDNs | `web01.corp.contoso.com`, built label by label | `HOST-0001.domain-0001.domain-0002.com` |
| Domain names | DNS suffixes, `Account Domain:`, `DOMAIN\user`, e-mail domains, FQDN suffixes | `DOMAIN-0001` per label (the TLD is kept) |
| User names | `Account Name:`, `TargetUserName`, `User:`/`user=`, `User ID=`, `DOMAIN\user`, `Login failed for user '...'`, sshd `Accepted ... for X`, e-mail local parts | `USER-0001` |
| E-mail addresses | `name@domain.tld` | `user-0001@domain-0002.com` |
| IPv4 | Any valid dotted quad | Each real /24 maps to a /24 in `198.18.0.0/15`, then `240.0.0.0/4`. **The last octet is kept**, so hosts in the same subnet stay in the same subnet: `10.20.30.45 -> 198.18.0.45` |
| IPv6 | Full, compressed, zone-indexed (`%12`) and IPv4-mapped (`::ffff:10.1.2.3`) addresses | `2001:db8::N` (documentation prefix) |
| MAC addresses | `00:50:56:A1:B2:C3`, `00-50-56-...`, `0050.56a1.b2c3`, and bare `005056A1B2C3` after `MAC`/`Physical Address` | `02:00:00:xx:xx:xx` (locally administered) in the **same separator style** |
| Domain SIDs | `S-1-5-21-a-b-c-RID` | `S-1-5-21-1111111111-2222222222-30000000NN-RID` (the RID is kept) |
| Custom terms | `-CustomTerm`, `-TermsFile` (phrases with spaces are allowed) | `REDACTED-0001`, or a replacement you choose |
| File names | Output file and folder names get the same replacements (`WEB01_Security.txt -> HOST-0007_Security.txt`) | Turn off with `-KeepFileNames` |

How the replacements are formed:

- Once a value has been discovered **anywhere**, it is replaced **everywhere**. For example, if
  `WEB01.corp.contoso.com` appears in one file, a bare `WEB01` in another file is also replaced.
- The case style is kept: `jdoe` becomes `user-0001` and `JDOE` becomes `USER-0001`.
- Every replacement comes from a range that can never be real, so a scrubbed value can't be confused with a live system.
- These values are **left alone on purpose** so the logs stay useful: `127.0.0.1`, `0.0.0.0`, masks like
  `255.255.255.0`, multicast addresses, `S-1-5-18` and other well-known SIDs, `localhost`, `SYSTEM`,
  `Administrator`, and similar built-in names. Vendor domains such as `microsoft.com`, `windows.com` and
  `digicert.com` are also kept, as are version strings (`Version=4.0.0.0`), .NET/Java namespaces
  (`System.Net.Mail`), registry and file paths, times, and GUIDs.

## The correlation sheet

CSV, UTF-8 with a BOM, so it opens correctly in Excel:

| Type | Original | Replacement | MatchesThisRun | FirstSeenIn |
|---|---|---|---|---|
| Hostname | WEB01 | HOST-0007 | 6 | samples/WEB01_Security.txt |
| FQDN | WEB01.corp.contoso.com | HOST-0007.domain-0001.domain-0003.com | 2 | samples/WEB01_Security.txt |
| DomainLabel | contoso | DOMAIN-0003 | 0 | samples/Security-Export.xml |
| User | jdoe | USER-0001 | 3 | samples/app-2026-11-18.json |
| IPv4 | 10.20.30.45 | 198.18.0.45 | 4 | samples/app-2026-11-18.json |
| IPv4Subnet | 10.20.30.0/24 | 198.18.0.0/24 | 0 | samples/app-2026-11-18.json |
| MAC | 00:50:56:A1:B2:C3 | 02:00:00:00:00:03 | 2 | samples/dhcp-syslog.log |

- **Reuse it.** Pass the same `-CorrelationFile` on later runs. Existing mappings load first, so `WEB01` stays
  `HOST-0007` for the whole case, and new values are appended.
- **Reverse lookup.** To translate a vendor's reply back to real names, filter on the `Replacement` column:
  `Import-Csv C:\Secure\case1234-correlation.csv | Where-Object Replacement -eq 'HOST-0007'`.
- `HostLabel` rows are words seen only as the first part of an automatically detected FQDN that don't look
  like machine names (no digit or `-`), such as `time` in `time.contoso.com`. They are replaced inside the FQDN
  but not as standalone words, so ordinary words like "time" stay intact.
- `MatchesThisRun` is the number of times that exact string was replaced. A name that appears only inside
  FQDNs shows 0 on its own row and is counted on the FQDN row instead.

## Parameters

| Parameter | Description |
|---|---|
| `-Path` | Files or folders (wildcards allowed). Pipeline input works too. |
| `-OutputPath` | Output folder. Default: `.\Scrubbed_<timestamp>`. Folder inputs keep their structure under `OutputPath\<folder>\`. |
| `-CorrelationFile` | Correlation CSV. Loaded first if it exists, then rewritten. Default: `ScrubCorrelation_<timestamp>.csv` next to the output folder. |
| `-Recurse` | Include subfolders of folder inputs. |
| `-Include` / `-Exclude` | File-name wildcards for folder inputs. Binary files are always skipped. |
| `-SkipType` | Categories to leave untouched: `IPv4 IPv6 MAC Hostname Domain User Email SID`. |
| `-Hostname`, `-Domain`, `-User`, `-CustomTerm` | Values you already know are sensitive. Use `NAME=REPLACEMENT` to choose the replacement, e.g. `-Hostname 'SQLPROD01=DB-PRIMARY'`. |
| `-TermsFile` | A reusable list of the above (format below). |
| `-HostnamePattern` | Regexes for your naming convention, e.g. `'\b(?:NYC\|LAX)-(?:WEB\|SQL\|DC)\d{2}\b'`. Every match is treated as a host. Use `(?<host>...)` to capture only part of the match. |
| `-ExtraTld` | Extra internal suffixes to recognise for automatic FQDN detection, e.g. `contoso` if you use `server.contoso`. |
| `-KeepValue` | Exact values that must never be scrubbed, such as a public NTP server IP. |
| `-KeepDomain` | Domains (and their subdomains) that must never be scrubbed. Added to the built-in vendor list. |
| `-IgnoreName` | Words that the tool mistakes for names in your logs. |
| `-NoDefaultExclusions` | Turn off the built-in ignore lists (`localhost`, `administrator`, `www`, vendor domains, `127.0.0.1`, ...). |
| `-IncludeLocalIdentity` | Also scrub this machine's name and domain and the current user name. |
| `-KeepFileNames` | Don't scrub output file and folder names. |
| `-MinNameLength` | Host, user and domain names shorter than this (default 3) are only replaced inside FQDNs and e-mail addresses, not on their own. |
| `-Force` | Overwrite existing output files. |

The script returns a summary object (`OutputPath`, `CorrelationFile`, `FilesScrubbed`, `FilesSkipped`,
`Mappings`, `MappingsByType`, `Files`), so you can use it from other scripts.

### Terms file

```text
# One entry per line; lines with no prefix are custom terms
host: SQLPROD01
host: LEGACY-BOX = OLD-SERVER
domain: contoso
user: jdoe
term: Project Falcon
Contoso Ltd
keep: 203.0.113.10
pattern: \b(?:NYC|LAX)-[A-Z]{2,4}\d{2,4}\b
tld: contoso
```

## Tuning tips

- **Run it once on real data and review the correlation sheet.** Each row of the sheet is something the
  tool decided was sensitive.
  - Something scrubbed that shouldn't be: add it to `-IgnoreName`, `-KeepValue` or `-KeepDomain`.
  - Something missed: add it to `-Hostname`, `-User` or `-CustomTerm`, or add a `-HostnamePattern` that
    matches your naming convention.
- Host names that appear **only in free text**, with no key, FQDN, UNC path or URL around them (for example
  `connecting to SQLPROD01 now`), are found only once the name has been seen somewhere else or is supplied.
  A `-HostnamePattern` for your naming standard is the most reliable fix.
- **Binary logs** (`.evtx`, `.etl`) are skipped. Export them to text first:
  `wevtutil qe Security /f:text > Security.txt` or
  `Get-WinEvent -Path .\Security.evtx | Format-List * | Out-File Security.txt`.
- **Encodings** are kept: UTF-8 with or without a BOM, UTF-16 LE/BE and UTF-32. Files that aren't valid UTF-8
  (ANSI) are processed byte for byte, so accented characters survive unchanged.

## Limitations

- It is pattern-based. It greatly reduces what you expose, but it is not a guarantee. **Always skim the output
  before sending it.**
- It does not look for passwords, API keys or connection-string secrets. Remove those separately.
- People's display names (`John Doe`) are not detected unless you supply them as custom terms.

## Testing

```powershell
pwsh -File .\tests\Test-LogScrub.ps1                               # PowerShell 7
powershell -ExecutionPolicy Bypass -File .\tests\Test-LogScrub.ps1 # Windows PowerShell 5.1
```

The test scrubs the samples plus generated UTF-16, ANSI and binary files, then checks four things:

- No value listed in the correlation sheet survives in the output.
- Known false-positive traps are left untouched.
- The replacement formats are correct.
- A re-run with the same correlation sheet gives identical results.
