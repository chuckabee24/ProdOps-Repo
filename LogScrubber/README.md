# LogScrubber

LogScrubber is a PowerShell tool with a .NET engine. It removes infrastructure and identity data from log files
before you send them to a vendor, attach them to a ticket or post them in a case. It does three things:

1. **Writes scrubbed copies** of your logs.
2. **Writes a correlation sheet** (CSV) that maps each real value to its replacement, for example
   `NWT-SQL-P01 → HOST-0007`. Use it to translate the vendor's answer back.
3. **Audits its own output.** After scrubbing it searches for every original value again, runs fresh detectors
   over the result, and lists anything that still looks sensitive.

Key properties:

- Runs on **Windows PowerShell 5.1** and **PowerShell 7+** (Windows, Linux, macOS). There is nothing to install.
- **Detection is measured** against two blind red-team corpora (98.8 % and 99.7 % of planted values removed,
  with no unintended changes). See *How it was tested*.
- Replacements are **consistent across every file in a run**, and across runs when you reuse the correlation sheet.
  Re-running with the same sheet gives byte-identical output, and scrubbing already-scrubbed output changes nothing.
- The detection engine is C# compiled at run time with `Add-Type`, and its detectors run on all CPU cores. A
  176 MB log with 847,000 unique values takes about 85 s, including the audit, on 4 cores.

## Files

| File | Purpose |
|---|---|
| `Invoke-LogScrub.ps1` | The command you run |
| `LogScrubEngine.cs` | Detection, replacement and audit engine. **It must stay in the same folder as the script.** |
| `samples\` | A few small example logs |
| `tests\Test-EngineCases.ps1` | 42 focused edge cases (each has text that must disappear and look-alikes that must stay), plus a detector performance guard |
| `tests\Test-LogScrub.ps1` | End-to-end regression test: encodings, file names, re-runs, known terms |
| `tests\Invoke-ScenarioTest.ps1` | Ground-truth test against the realistic corpora in `tests\corpus\` |
| `tests\corpus\northwind\`, `tests\corpus\tailspin\` | Two realistic corpora (35 + 30 logs) written by separate red-team agents that never saw the code, each with a manifest of planted values (497 + 396) and must-preserve text (333 + 373). **All data and credentials in them are fake.** |

## Quick start

```powershell
# One file -> .\Scrubbed_<timestamp>\app.log, .\ScrubCorrelation_<timestamp>.csv (+ _audit.csv if anything was found)
.\Invoke-LogScrub.ps1 -Path C:\Logs\app.log

# A folder tree, with one correlation sheet kept for the whole case
.\Invoke-LogScrub.ps1 -Path C:\Cases\1234\logs -Recurse `
    -OutputPath C:\Cases\1234\to-vendor `
    -CorrelationFile C:\Secure\case1234-correlation.csv `
    -CustomTerm 'Contoso Ltd', 'Project Falcon'

# Review what would be replaced before writing anything
.\Invoke-LogScrub.ps1 -Path C:\Cases\1234\logs -Recurse -DiscoverOnly -CorrelationFile C:\Secure\review.csv

# In automation: fail if the audit finds anything
.\Invoke-LogScrub.ps1 -Path .\logs -Recurse -FailOnAuditFinding
```

If the script was downloaded, unblock it first with `Get-ChildItem .\LogScrubber -Recurse | Unblock-File`, or run it as
`powershell -ExecutionPolicy Bypass -File .\Invoke-LogScrub.ps1 ...`.

> **The correlation sheet and the audit file contain the real values.** Keep them somewhere secure and never send
> them with the scrubbed logs. By default both are written *next to* the output folder, not inside it.
> Secrets are never written to the sheet; only a SHA-256 fingerprint is recorded for each one.

## Recommended workflow

1. **Run the tool.** Check the audit summary it prints at the end.
2. **If the audit lists anything,** open the `_audit.csv` and look at each finding:
   - `Leak:*` means an original value is still in the output, usually inside a word.
   - `Embedded:*` means an original value is embedded in a longer token.
   - `Detected:*` means fresh detectors found something that is not a replacement value.
3. **Fix each finding** with `-Hostname` / `-User` / `-CustomTerm` (missed values) or `-IgnoreName` / `-KeepValue`
   (over-scrubbing), then run again with the same `-CorrelationFile`.
4. **Skim the output** before sending it. The tool is thorough, but it is pattern-based (see *Limitations*).

## What gets scrubbed

| Category | Detected from (examples) | Replacement |
|---|---|---|
| **Host names** | `Computer:`, `Workstation Name`, `ComputerName=`, `Server=`, `Data Source=`, XML `<Computer>`, JSON / ECS `host.name`, CEF `shost=`, FortiGate `devname=`, UNC `\\FS01\share`, URLs, syslog headers, Cisco `hostname` and prompts, SPNs `MSSQLSvc/host`, klist, `WEB01$`, `name [10.1.2.3]`, `host/10.1.2.3:8080`, "could not resolve host", Postfix `client=`, Azure VM resource IDs | `HOST-0001` |
| … *learned* | **Naming conventions:** once `NWT-WEB01` is known, `NWT-WEB02` in free text is a host too. **Organisation prefixes:** a prefix used by 3+ hosts (`NWT-`) marks names such as `NWT-Server-Hardening` or `GP-NWT-VPN` | `HOST-…` / `REDACTED-…` |
| **FQDNs / domains** | Any FQDN with a known TLD, DNS suffixes, `Account Domain`, `DOMAIN\user`, realms, LDAP `DC=` parts, Windows DNS debug `(5)web01(4)corp(0)`. For cloud services (`*.blob.core.windows.net`, `*.amazonaws.com` …) only the customer's own label is replaced | `HOST-0001.domain-0001.domain-0002.com` |
| **User names** | `Account Name`, `TargetUserName`, `user=`, `User ID=`, `DOMAIN\user`, `.\user`, `user@realm`, profile paths `C:\Users\jsmith.CORP\`, `/home/jsmith`, sshd / sudo / su lines, Apache auth user, Cisco `username`, AWS ARNs, URL credentials, `net use /user:` | `USER-0001` |
| **People's names** | `DisplayName`, `Manager`, `Owner`, `Registered Owner`, `From: Jane Smith <…>`, `CN=Smith\, Jane` in DNs, given-name / surname fields. Matches `Jane Smith`, `Smith, Jane`, `Jane+Smith` and `Smith%2C%20Jane` | `PERSON-0001`, `NAME-0001` |
| **PII** | Street address, postal code, office, phone and mobile fields; phone numbers such as `+1 (206) 555-0147`; employee and badge IDs | `PII-0001` |
| **E-mail** | `name@domain` (also `%40` URL-encoded) | `user-0001@domain-0002.com` |
| **Organisation / OU / location** | `O=`, `Registered Organization`, company names ending in Inc / Ltd / GmbH …; `OU=` (inside DNs only); `L=`, `ST=`, AD site names, `City` | `ORG-0001`, `OU-0001`, `LOCATION-0001` |
| **IPv4** | Every valid address, including leading zeros, `10.1.2.3:443`, CIDR and ranges. Reverse DNS names (`3.2.1.10.in-addr.arpa`) are also handled | Each real /24 maps to a fake /24 in `198.18.0.0/15`, then `240.0.0.0/4`. **The last octet is kept**, so subnets still line up |
| **IPv6** | Full, compressed, `%zone`, `[addr]:port`, IPv4-mapped | One fake `2001:db8:x:y::/64` per real /64; `fe80::` stays link-local. **The interface ID is replaced**, because it can contain the MAC |
| **MAC** | `aa:bb:…`, `aa-bb-…`, `aabb.ccdd.eeff`, `aa bb cc …`, bare 12-hex in MAC fields and columns, inside DHCPv6 DUIDs, kernel `ll header` and UFW `MAC=` | `02:00:00:xx:xx:xx` in the **same notation**. `-KeepMacVendor` keeps the vendor OUI |
| **SIDs** | Domain SIDs `S-1-5-21-…` (RID kept), Entra SIDs `S-1-12-1-…`, binary `objectSid::` in LDIF | `S-1-5-21-1111111111-2222222222-30000000NN-RID` |
| **Cloud IDs** | Tenant / subscription / directory / object / client / device GUIDs (by key), `/subscriptions/<guid>`, AD domain / forest GUIDs, AWS account IDs and ARNs, Azure resource groups and resources, S3 buckets, forest-specific AD CS OIDs, serial numbers and asset tags | `00000000-0000-4000-8000-…`, `1000000000NN`, `REDACTED-…` |
| **Secrets** | `password=` / `pwd=` / `secret=` / `token=` / `api_key=` and similar keys, connection strings, `Authorization:` headers, Bearer tokens, JWTs, AWS key IDs, SAS signatures, PEM blocks (line count kept), cookies and session IDs, `ConvertTo-SecureString '…'`, `-Password …`, `/p:`, `mysql -p…`, `net use … password`, URL credentials, Cisco `secret` / `key 7` / `community`, `.config` `<add key="…Secret" value="…">`, SSH keys | `SECRET-0001` (only a fingerprint goes in the sheet) |
| **Custom terms** | `-CustomTerm`, `-TermsFile` (phrases allowed) | `REDACTED-0001` or a replacement you choose |
| **File names** | Output file and folder names get the same replacements | Turn off with `-KeepFileNames` |

**Formats handled.** Plain text and logs, CSV / TSV (columns are classified by their header), IIS / W3C (`#Fields:`),
PowerShell Format-List (including wrapped values) and Format-Table (including `...` / `…` truncation), XML and
event-log exports, JSON and NDJSON (including escaped `\n`, `\\` and `\u00e9`), URL-encoded query strings and
LDIF base64 values.

**Encodings handled.** UTF-8 with or without a BOM, UTF-16 LE/BE and UTF-32. ANSI files are processed byte for
byte, so `José Müller` survives intact. `.gz` files are decompressed, scrubbed and re-compressed.

**Left alone on purpose,** to keep the logs useful:

- Loopback, `0.0.0.0`, masks, multicast, `169.254.169.254`, public DNS resolvers (8.8.8.8, 1.1.1.1, …), and the
  RFC 1918 range boundaries.
- Well-known SIDs (`S-1-5-18`) and built-in accounts and groups (`SYSTEM`, `Administrator`, `Domain Admins`, …).
- Vendor domains (microsoft.com, windowsupdate.com, digicert.com, amazon.com, kubernetes.io, …) and Microsoft
  first-party app IDs.
- Correlation, request and trace GUIDs. Use `-ScrubAllGuids` to replace every GUID.
- Version strings and OIDs, .NET / Java namespaces, registry and system paths, timestamps, error codes and ports.

## The correlation sheet

CSV, UTF-8 with a BOM (opens correctly in Excel), with the columns
`Type, Original, Replacement, MatchesThisRun, FirstSeenIn`. Values that start with `= + - @` are prefixed with `'` so
that Excel does not run them as formulas.

| Type | Meaning |
|---|---|
| `Hostname`, `FQDN`, `DomainLabel`, `DomainName`, `User`, `Email` | As named. FQDNs are built label by label from host and domain tokens |
| `HostLabel`, `DomainWord` | Common words (`time`, `nexus`, `core`) seen only inside FQDNs. They are replaced inside the FQDN but not on their own, so the word "time" elsewhere stays intact |
| `DomainLabel` / `DomainPart` | Domain labels from a domain context such as a NetBIOS domain or realm, versus labels seen only inside FQDNs (both replaced everywhere; the type keeps re-runs identical) |
| `Person`, `NamePart`, `PII`, `Organization`, `OrgUnit`, `Location` | People and organisation data |
| `IPv4`, `IPv4Subnet`, `IPv6`, `IPv6Prefix`, `MAC`, `SID`, `Guid`, `CloudAccount`, `ForestOid` | Network and identity values |
| `Secret` | `sha256:<fingerprint>` only; the secret itself is never stored |
| `Custom` | Your terms, plus learned organisation-prefixed names, Azure resource names and S3 buckets |

**Reverse lookup.** `Import-Csv C:\Secure\case1234-correlation.csv | Where-Object Replacement -eq 'HOST-0007'`

**Reuse.** Pass the same `-CorrelationFile` again, and existing mappings load first.

## Parameters

| Parameter | Description |
|---|---|
| `-Path` | Files or folders (wildcards allowed). Pipeline input works too. |
| `-OutputPath` | Output folder. Default: `.\Scrubbed_<timestamp>`. |
| `-CorrelationFile` | Correlation CSV. Loaded first if it exists, then rewritten. The audit report is written as `<name>_audit.csv` next to it. |
| `-Recurse`, `-Include`, `-Exclude` | Folder enumeration. Binary files (`.evtx`, `.zip`, …) are always skipped. |
| `-SkipType` | Leave whole categories alone: `IPv4 IPv6 MAC Hostname Domain User Email SID Person Secret OrgUnit CloudId`. |
| `-Hostname`, `-Domain`, `-User`, `-Person`, `-CustomTerm` | Known sensitive values. Use `NAME=REPLACEMENT` to choose the replacement yourself. |
| `-TermsFile` | A reusable list of the above (`host:`, `domain:`, `user:`, `person:`, `org:`, `term:`, `keep:`, `pattern:`, `tld:`). |
| `-HostnamePattern` | Regexes for your naming convention. Use `(?<host>...)` to capture only part of the match. |
| `-ExtraTld`, `-KeepValue`, `-KeepDomain`, `-IgnoreName` | Tuning: extra internal TLDs; values, domains and words never to scrub. |
| `-NoDefaultExclusions` | Turn off the built-in keep and ignore lists. |
| `-ScrubAllGuids` | Replace every GUID, not only identity / tenant GUIDs. |
| `-KeepMacVendor` | Keep the vendor OUI of MAC addresses. |
| `-NoNamingPatterns` | Turn off naming-convention and organisation-prefix learning. |
| `-IncludeLocalIdentity` | Also scrub this machine's name and domain and the current user. |
| `-KeepFileNames` | Don't scrub output file and folder names. |
| `-MinNameLength` | Names shorter than this (default 3) are replaced only inside FQDNs and e-mail addresses. |
| `-DiscoverOnly` | Write only the correlation sheet, so you can review it before scrubbing. |
| `-SkipAudit`, `-FailOnAuditFinding` | Turn the audit off, or throw when it finds anything. |
| `-Force` | Overwrite existing output files. |

The script returns a summary object: `OutputPath`, `CorrelationFile`, `AuditFile`, `FilesScrubbed`, `FilesSkipped`,
`Mappings`, `MappingsByType`, `AuditFindings`, `Findings` and `Files`. The `Files` entries include line counts in
and out; a warning is printed if they ever differ.

## How it was tested

The tool was measured against realistic logs that were written **by agents that never saw the code**, so the
scenarios are not shaped around how the detectors work:

| Test | What it covers | Result |
|---|---|---|
| `Test-EngineCases.ps1` | 42 targeted cases plus a guard that fails if any detector becomes pathologically slow. The cases cover:<br>• Event text, AD DNs and certificates, Kerberos, profile paths, PowerShell table/list formatting, the DNS debug wire format<br>• URL-encoded, JSON-escaped, base64, hex and LDIF content<br>• Secrets: command-line, Cisco, PEM, XML config, cookies<br>• MAC address forms, IPv4/IPv6 forms, cloud IDs, ECS JSON, CEF<br>• People, PII and organisations, naming conventions and organisation prefixes<br>• Look-alikes that must stay: versions, OIDs, namespaces, ordinary English words | 43 / 43 |
| `Test-LogScrub.ps1` | End-to-end on `samples\`: encodings, file names, re-runs, known terms, later batches | 75 / 75 |
| `Invoke-ScenarioTest.ps1` on **Northwind Traders** | 35 logs across Windows events (four formats), AD tooling, DNS / DHCP / firewall, IIS, SQL, .NET / Java, Linux, k8s, Cisco / ASA / Palo Alto / FortiGate / CEF, Azure / AWS / ECS, Exchange and a support bundle. Encodings: UTF-16, ANSI and BOM | 491 / 497 removed (98.8 %); 0 must-preserve text changed; re-run and re-scrub identical |
| `Invoke-ScenarioTest.ps1` on **Tailspin Toys** (hold-out) | 30 logs: Sysmon, Defender, auditd, journald, Ansible, Terraform, Okta / Entra / M365 / GitHub / Google, k8s audit, VPC flow, Zeek, Juniper / Aruba / WLC / RADIUS / Check Point / Squid, Jenkins, ServiceNow, e-mail. Also gzip, UTF-16, Windows-1252 and 57 KB single-line JSON | 395 / 396 removed (99.7 %); 0 must-preserve text changed; re-run and re-scrub identical |

**First-contact versus tuned scores.** The Tailspin corpus was generated *after* the tool had been tuned on
Northwind, as a hold-out. Its first-contact score was **86.1 %** removed, with 49 must-preserve strings altered and
unstable re-runs. The failures were fixed with general rules rather than special cases:

- English and product stop words
- A guard so public TLDs are never domain labels
- base64 and hex decoding, new log formats and new naming shapes
- Stable typing of domain labels

So 99.7 % is the score *after* learning from that corpus. Expect first contact with a new environment to land
between these two numbers, which is why the audit and the review step exist.

**Known gaps.** The remaining known gaps are listed in each manifest. All are values with no detectable context:

- A name that appears only in a free-text JSON value
- Phone extensions
- An opaque JSON ID
- A bare group name
- A partner name that appears only URL-encoded inside a file path

Public vendor IP addresses are replaced by design.

**Speed.** A 176 MB log with 847,000 unique values takes about 85 s end to end on 4 cores, including the audit.

To run every test:

```powershell
pwsh -File .\tests\Test-EngineCases.ps1
pwsh -File .\tests\Test-LogScrub.ps1
pwsh -File .\tests\Invoke-ScenarioTest.ps1
```

On Windows PowerShell 5.1, run the same files with `powershell -ExecutionPolicy Bypass -File …`.

> The test corpora contain **fake** credentials on purpose: AWS key IDs, GitHub / GitLab tokens, Stripe- and
> Slack-format keys, an Azure account key and RSA keys. GitHub push protection may block a push until they are
> marked as test data.

## Limitations

- **It is pattern-based.** It removes the vast majority of identifiers, but it cannot promise to remove all of
  them. Use the audit and skim the output.
- **Free-text names need something to anchor on.** A word that is a name only in free text (`please call Will`),
  with no field, path, FQDN, naming pattern or earlier sighting to identify it, cannot be told apart from ordinary
  words. Supply such names with `-Person` / `-Hostname` / `-CustomTerm`.
- **Encoded identities stay encoded.** Identities inside JWT payloads, Basic-auth base64 or other opaque encodings
  are only caught when the whole token is detected as a secret (which is the common case).
- **Binary formats are skipped.** Export `.evtx` / `.etl` to text first
  (`wevtutil qe Security /f:text > Security.txt`) and extract `.zip` archives.
- **Public IP addresses are replaced too,** including vendor ones. Use `-KeepValue` for any you want to keep.
