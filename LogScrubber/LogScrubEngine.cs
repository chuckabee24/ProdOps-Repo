// ---------------------------------------------------------------------------------------------
// LogScrubEngine.cs - core engine used by Invoke-LogScrub.ps1
//
// Compiled at runtime with Add-Type. Written to C# 5 / .NET Framework 4.5 level so it compiles
// under Windows PowerShell 5.1 as well as PowerShell 7+ (.NET 6/8). Avoid newer language features
// (string interpolation, ?. , out var, expression bodies, etc.) and System.Core-only types
// (HashSet, LINQ) when editing this file. Keep the file pure ASCII (use \uXXXX escapes).
//
// How it works
//   Pass 1 (ScanFile / ScanText): ~60 detectors discover sensitive values and assign each a stable
//          replacement token. Each block is also scanned in decoded variants (URL-encoded, JSON-
//          escaped, PowerShell Format-List line-wrapped) and CSV / W3C / Format-Table columns are
//          classified by their header.
//   Pass 2 (ScrubFile / ScrubText): every discovered value is replaced everywhere it occurs
//          (including bare mentions, URL-encoded, truncated "WEB01.con..." and wrapped values).
//   Audit  (CreateAudit): the output is re-scanned with fresh detectors plus an Aho-Corasick
//          search for every original name, and anything left over is reported.
// ---------------------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace LogScrub
{
    /// <summary>One row of the correlation sheet.</summary>
    public sealed class MapEntry
    {
        public string Type;
        public string Original;
        public string Replacement;
        public long Matches;
        public string FirstSeenIn;
    }

    /// <summary>Encoding / binary detection result for one input file.</summary>
    public sealed class TextFileInfo
    {
        public bool IsBinary;
        public bool IsGzip;
        public bool CanFallBack;
        public string EncodingName;
        public Encoding ReadEncoding;
        public Encoding WriteEncoding;
    }

    public sealed class ScrubFileResult
    {
        public long LinesIn;
        public long LinesOut;
    }

    public sealed class AuditFinding
    {
        public string File;
        public long Line;
        public string Kind;
        public string Value;
        public string Context;
    }

    internal sealed class Table
    {
        public readonly string Type;
        public readonly Dictionary<string, MapEntry> Map = new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase);
        public readonly List<MapEntry> Order = new List<MapEntry>();
        public readonly Dictionary<string, bool> Used = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        public int Counter;
        private readonly Func<int, string> make;

        public Table(string type, Func<int, string> make)
        {
            Type = type;
            this.make = make;
        }

        public MapEntry Find(string key)
        {
            MapEntry e;
            return Map.TryGetValue(key, out e) ? e : null;
        }

        public MapEntry GetOrAdd(string key, string original, string source)
        {
            MapEntry e;
            if (Map.TryGetValue(key, out e)) return e;
            string r;
            do { Counter++; r = make(Counter); } while (Used.ContainsKey(r));
            return Put(key, original, r, source);
        }

        /// <summary>Adds an entry with a fixed replacement. An existing entry always wins.</summary>
        public MapEntry Put(string key, string original, string replacement, string source)
        {
            MapEntry e;
            if (Map.TryGetValue(key, out e)) return e;
            e = new MapEntry();
            e.Type = Type;
            e.Original = original;
            e.Replacement = replacement;
            e.FirstSeenIn = source;
            Map[key] = e;
            Order.Add(e);
            Used[replacement] = true;
            return e;
        }
    }

    internal sealed class Literal
    {
        public const int Atomic = 0;   // replacement = Fixed ?? Entry.Replacement, case-adjusted
        public const int Dotted = 1;   // FQDN / dotted domain, composed label by label at match time
        public const int Email = 2;    // local@domain, composed at match time
        public int Kind;
        public bool NameLike;          // names may not touch a '-' (WEB01 must not match WEB01-OLD)
        public bool IpLike;            // IPs may not touch a '.'+digit (10.0.0.1 must not match in 1.10.0.0.1)
        public MapEntry Entry;
        public string Fixed;
        public bool FirstIsHost;
    }

    internal sealed class PrefixHit
    {
        public Literal Lit;
        public string FullKey;
    }

    internal sealed class DottedObs
    {
        public bool Loaded;
        public string Raw;
        public int Hint;
        public bool FirstIsHost;
        public string Source;
        public MapEntry Entry;
    }

    internal sealed class EmailObs
    {
        public string Raw;
        public string Source;
        public MapEntry Entry;
    }

    internal sealed class ColumnState
    {
        public int Mode;          // 0 none, 1 delimited, 2 W3C, 3 fixed width (Format-Table)
        public char Delim;
        public int FieldCount;
        public int[] Roles;
        public int[] Starts;
        public string PrevLine;
    }

    /// <summary>Case-insensitive multi-pattern search used by the audit.</summary>
    internal sealed class AhoCorasick
    {
        private readonly List<Dictionary<char, int>> next = new List<Dictionary<char, int>>();
        private readonly List<int> fail = new List<int>();
        private readonly List<List<int>> outputs = new List<List<int>>();
        private readonly List<string> patterns = new List<string>();
        private bool built;

        public AhoCorasick() { NewNode(); }

        public int Count { get { return patterns.Count; } }
        public string Pattern(int i) { return patterns[i]; }

        private int NewNode()
        {
            next.Add(new Dictionary<char, int>());
            fail.Add(0);
            outputs.Add(null);
            return next.Count - 1;
        }

        public void Add(string pattern)
        {
            string p = pattern.ToLowerInvariant();
            int node = 0;
            foreach (char c in p)
            {
                int n;
                if (!next[node].TryGetValue(c, out n)) { n = NewNode(); next[node][c] = n; }
                node = n;
            }
            if (outputs[node] == null) outputs[node] = new List<int>();
            outputs[node].Add(patterns.Count);
            patterns.Add(p);
            built = false;
        }

        private void Build()
        {
            Queue<int> q = new Queue<int>();
            foreach (KeyValuePair<char, int> kv in next[0]) { fail[kv.Value] = 0; q.Enqueue(kv.Value); }
            while (q.Count > 0)
            {
                int r = q.Dequeue();
                foreach (KeyValuePair<char, int> kv in next[r])
                {
                    int s = kv.Value;
                    q.Enqueue(s);
                    int st = fail[r];
                    int t;
                    while (st != 0 && !next[st].ContainsKey(kv.Key)) st = fail[st];
                    fail[s] = next[st].TryGetValue(kv.Key, out t) && t != s ? t : 0;
                    if (outputs[fail[s]] != null)
                    {
                        if (outputs[s] == null) outputs[s] = new List<int>();
                        outputs[s].AddRange(outputs[fail[s]]);
                    }
                }
            }
            built = true;
        }

        /// <summary>Calls onMatch(patternIndex, endExclusive) for every occurrence in lowerText.</summary>
        public void Search(string lowerText, Action<int, int> onMatch)
        {
            if (!built) Build();
            int node = 0;
            for (int i = 0; i < lowerText.Length; i++)
            {
                char c = lowerText[i];
                int n;
                while (node != 0 && !next[node].ContainsKey(c)) node = fail[node];
                if (next[node].TryGetValue(c, out n)) node = n;
                if (outputs[node] != null) foreach (int p in outputs[node]) onMatch(p, i + 1);
            }
        }
    }

    public sealed class ScrubEngine
    {
        public const string EngineVersion = "2.0.0";

        // ----- options (set from PowerShell) -----
        public bool ScrubIPv4 = true;
        public bool ScrubIPv6 = true;
        public bool ScrubMac = true;
        public bool ScrubHostnames = true;
        public bool ScrubDomains = true;
        public bool ScrubUsers = true;
        public bool ScrubEmails = true;
        public bool ScrubSids = true;
        public bool ScrubPersons = true;
        public bool ScrubSecrets = true;
        public bool ScrubOrgUnits = true;
        public bool ScrubCloudIds = true;
        public bool ScrubAllGuids = false;
        public bool KeepMacVendor = false;
        public bool LearnNamingPatterns = true;
        /// <summary>Names shorter than this are mapped (for FQDN composition) but not replaced on their own.</summary>
        public int MinBareLength = 3;
        /// <summary>Parse PowerShell Format-Table output by column position (off for the audit: replacements shift columns).</summary>
        public bool ParseFixedWidthTables = true;
        /// <summary>Run the detectors of a block on all CPU cores.</summary>
        public bool UseParallel = true;
        public readonly List<string> Warnings = new List<string>();

        private const int HintAuto = 0, HintHost = 1, HintDomain = 2;
        private const RegexOptions RxOpt = RegexOptions.Compiled | RegexOptions.CultureInvariant;
        private const RegexOptions RxOptI = RxOpt | RegexOptions.IgnoreCase;
        private const RegexOptions RxOptIM = RxOptI | RegexOptions.Multiline;
        private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(30);

        private static Regex R(string pattern, RegexOptions options) { return new Regex(pattern, options, RxTimeout); }

        // =========================================================================================
        // Detectors
        // =========================================================================================
        // Key/value separator: optional closing quote, ipconfig-style dot leaders, then : = or > (XML), optional opening quote.
        private const string Sep = @"[""']?[ \t.]*[:=>][ \t]*[""'\[(]?";
        private const string GuidPat = @"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}";
        private const string HostVal = @"(?:\\\\)?(?:tcp:|np:|lpc:|admin:)?(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?![_@=])";
        private const string UserVal = @"(?:(?<d>[A-Za-z0-9][A-Za-z0-9.-]{0,62})\\{1,2})?(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))(?![/\\=])";

        // ---- secrets ----
        private static readonly Regex PemRx = R(@"-----BEGIN (?<t>[A-Z0-9 ]{1,40})-----(?<body>[\s\S]{1,20000}?)-----END \k<t>-----", RxOpt);
        // Context detectors start with the key word (fast first-character search); the text in front of the key is checked in code.
        private const string SecretKeys = @"password|passwd|pwd|passphrase|pass|client[ _.-]?secret|app[ _.-]?secret|secret[ _.-]?key|secret|api[ _.-]?key|apikey|api[ _.-]?token|access[ _.-]?key|private[ _.-]?key|auth[ _.-]?token|access[ _.-]?token|refresh[ _.-]?token|id[ _.-]?token|bearer[ _.-]?token|session[ _.-]?token|sas[ _.-]?token|token|account[ _.-]?key|shared[ _.-]?access[ _.-]?key|aws[ _.-]?secret[ _.-]?access[ _.-]?key|aws[ _.-]?session[ _.-]?token|psk|pre[ _.-]?shared[ _.-]?key|community[ _.-]?string|community|encryption[ _.-]?key|signing[ _.-]?key|webhook[ _.-]?secret|session[ _.-]?id|sessionid|jsessionid|phpsessid|csrf[ _.-]?token|xsrf[ _.-]?token|x-api-key|x-auth-token|private[ _.-]?token|personal[ _.-]?access[ _.-]?token|pat";
        private static readonly Regex SecretCtxRx = R(
            @"(?<key>" + SecretKeys + @")[""']?[ \t]*(?:=[ \t]*|:[ \t]+|:(?=[""']))(?:""(?<v>[^""\r\n]{1,8192})""|'(?<v>[^'\r\n]{1,8192})'|(?<v>[^\s;,&""'<>]{1,8192}))", RxOptI);
        private static readonly Regex XmlKvSecretRx = R(
            @"key=[""'](?<k>[^""']{1,80})[""'][ \t]+value=[""'](?<v>[^""']{1,1024})[""']", RxOptI);
        private static readonly Regex XmlSecretKeyRx = R(@"password|passwd|pwd|secret|api[_-]?key|token|accountkey|sharedaccesskey|sas|credential", RxOptI);
        private static readonly Regex CookieRx = R(@"(?:^|[\r\n ""'])(?:Set-)?Cookie[""']?[ \t]*:[ \t]*(?<pairs>[^\r\n""]{1,4096})", RxOptI);
        private static readonly Regex CmdSecretRx = R(
            @"(?<![A-Za-z0-9])-(?:Password|Passwd|Pwd|Pass|Secret|ClientSecret|Token|ApiKey|AccessKey|SecretKey|AuthToken|SasToken)[ \t]+(?:'(?<v>[^'\r\n]{1,256})'|""(?<v>[^""\r\n]{1,256})""|(?<v>[^\s$'""(][^\s]{0,8191})(?![^\s]))", RxOptI);
        private static readonly Regex SlashSecretRx = R(@"(?<![A-Za-z0-9])/(?:p|pass|password|pwd|passwd)[:=](?<v>[^\s""']{1,256})", RxOptI);
        private static readonly Regex SecureStringRx = R(@"ConvertTo-SecureString[ \t]+(?:-String[ \t]+)?(?:'(?<v>[^'\r\n]{1,256})'|""(?<v>[^""\r\n]{1,256})"")", RxOptI);
        private static readonly Regex AuthHeaderRx = R(
            @"(?<![A-Za-z0-9])(?:proxy-)?authorization[""']?[ \t]*[:=][ \t]*[""']?(?:Bearer|Basic|Negotiate|NTLM|Token|SharedKey|SAS|SharedAccessSignature|ApiKey|Key|Digest)[ \t]+(?<v>[A-Za-z0-9+/=._~:%-]{6,4096})", RxOptI);
        private static readonly Regex BearerRx = R(@"(?<![A-Za-z0-9])Bearer[ \t]+(?<v>[A-Za-z0-9+/=._~-]{16,4096})", RxOpt);
        private static readonly Regex SasSigRx = R(@"[?&;]sig=(?<v>[A-Za-z0-9%+/=]{16,512})", RxOptI);
        private static readonly Regex MysqlPassRx = R(@"(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\r\n]*?[ \t]-p(?<v>[^\s'""-][^\s]{2,127})", RxOptI);
        private static readonly Regex CiscoLineSecretRx = R(@"^[ \t]*(?:key|password|secret)(?: [0-9])? (?<v>[^\s]{4,})[ \t]*\r?$", RxOptIM);
        private static readonly Regex CiscoSecretRx = R(
            @"(?<![A-Za-z0-9-])(?:snmp-server community|enable secret(?: [0-9])?|enable password(?: [0-9])?|username \S+(?: privilege [0-9]+)? (?:secret|password)(?: [0-9])?|(?:tacacs-server|radius-server|tacacs|radius) key(?: [0-9])?|key-string(?: [0-9])?|(?:ikev[12] )?pre-shared-key(?: [0-9])?|authentication-key(?: [0-9])?|set password|set psksecret|set passwd|ppp chap password(?: [0-9])?|ntp authentication-key [0-9]+ md5)[ \t]+(?<v>\S+)", RxOptI);
        private static readonly Regex UrlCredRx = R(@"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9+.-]{1,15}://(?<u>[^:@/\s""'<>]{1,128}):(?<v>[^@/\s""'<>]{1,256})@", RxOpt);
        private static readonly Regex NetUseRx = R(@"\bnet[ \t]+use\b[^\r\n]*?/user:(?<u>\S+)[ \t]+(?<v>[^\s/*][^\s]{0,255})", RxOptI);
        private static readonly Regex JwtRx = R(@"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", RxOpt);
        private static readonly Regex AwsKeyRx = R(@"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16,20}(?![A-Z0-9])", RxOpt);
        private static readonly Regex SshKeyRx = R(@"(?<![A-Za-z0-9])(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp[0-9]+) (?<key>AAAA[A-Za-z0-9+/=]{20,})(?: (?<u>[A-Za-z0-9._-]+)@(?<h>[A-Za-z0-9][A-Za-z0-9.-]*))?", RxOpt);
        private static readonly Regex CryptHashRx = R(@"^\$[0-9a-z]{1,2}\$[^\s$]{1,64}(?:\$[^\s]{1,256})?$", RxOptI);
        private static readonly Regex NonSecretKeyRx = R(@"^[""']?(?:PublicKeyToken|hashed[ _.-]?token|token[ _.-]?hash|password[ _.-]?hash|token[ _.-]?type|token[ _.-]?expir\w*|token[ _.-]?(?:count|length|usage|limit)s?|max[ _.-]?tokens?|password[ _.-]?(?:last[ _.-]?set|expir\w*|age|policy|length|complexity|history|never[ _.-]?expires|required|not[ _.-]?required|changeable)|passwordlastset)\b", RxOptI);
        private static readonly Regex[] SecretValueRxs = new Regex[] { SecretCtxRx, CmdSecretRx, SlashSecretRx, SecureStringRx, AuthHeaderRx, BearerRx, SasSigRx, CiscoSecretRx, CiscoLineSecretRx, MysqlPassRx, UrlCredRx, NetUseRx, XmlKvSecretRx };

        // ---- identifiers ----
        private static readonly Regex SidRx = R(@"(?<![A-Za-z0-9-])S-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})(?![0-9])", RxOptI);
        private static readonly Regex AadSidRx = R(@"(?<![A-Za-z0-9-])S-1-12-1-(\d{1,10})-(\d{1,10})-(\d{1,10})-(\d{1,10})(?![0-9])", RxOptI);
        private static readonly Regex GuidCtxRx = R(
            @"(?<key>tenant[ _.-]?id|tenant|tid|directory[ _.-]?id|subscription[ _.-]?id|subscription|object[ _.-]?guid|object[ _.-]?id|oid|client[ _.-]?id|app[ _.-]?id|application[ _.-]?id|appid|principal[ _.-]?id|service[ _.-]?principal[ _.-]?id|managed[ _.-]?identity[ _.-]?id|user[ _.-]?id|device[ _.-]?id|account[ _.-]?id|workspace[ _.-]?id|customer[ _.-]?id|org[ _.-]?id|organization[ _.-]?id|caller[ _.-]?id|actor[ _.-]?id|dom(?:ain)?[ _.-]?guid|forest[ _.-]?guid|dsa[ _.-]?guid|site[ _.-]?guid|invocation[ _.-]?id)"
            + @"[""']?[ \t.]*[:=][ \t]*[""'{]?(?<v>" + GuidPat + @")(?![0-9A-Fa-f-])", RxOptI);
        private static readonly Regex NonIdentityGuidKeyRx = R(@"correlation|request|event|activity|trace|operation|transaction|session|run|job|message|instance|tracking|batch|span|parent|claim|nonce", RxOptI);
        private static readonly Regex CompanySuffixRx = R(@"^\p{Lu}[\p{L}&.' -]{1,50} (?:Inc|Inc\.|Ltd|Ltd\.|LLC|L\.L\.C\.|GmbH|AG|PLC|plc|Corp|Corp\.|Corporation|Company|Co\.|S\.A\.|SA|BV|B\.V\.|NV|Pty|Limited|SARL|S\.p\.A\.|Oy|AB|ASA|KG|LLP|LP)$", RxOpt);
        // more context patterns
        private static readonly Regex HaproxyRx = R(@"\] \S+ [A-Za-z0-9_.-]+/(?<v>[A-Za-z0-9][A-Za-z0-9._-]{0,62}) -?\d+/", RxOpt);
        private static readonly Regex ShellPromptRx = R(@"(?:\[(?<u>[a-z_][a-z0-9._-]{0,31})@(?<h>[A-Za-z][A-Za-z0-9.-]{0,62})[ :]|(?<![A-Za-z0-9.@-])(?<u>[a-z_][a-z0-9._-]{0,31})@(?<h>[A-Za-z][A-Za-z0-9.-]{0,62}):[~/])", RxOpt);
        private static readonly Regex RadiusCliRx = R(@"(?:\bcli |Calling-Station-Id[ \t]*=?[ \t]*""?)(?<mac>[0-9A-Fa-f]{2}(?:[-:]?[0-9A-Fa-f]{2}){5})(?![0-9A-Za-z])", RxOptI);
        private static readonly Regex CliPassRx = R(@"(?:\b(?:sqlcmd|bcp|osql|isql|psql|redis-cli|mongo|mongosh|mysql|mysqldump|mysqladmin|mariadb|docker[ \t]+login|podman[ \t]+login|helm[ \t]+registry[ \t]+login|smbclient|net[ \t]+user)\b)[^\r\n]*?[ \t](?:-P|-p|-a|--password(?:=|[ \t]+)|--pass(?:=|[ \t]+))[ \t]*(?<v>[^\s""'-][^\s""']{2,8191})(?![^\s""'])", RxOpt);
        private static readonly Regex AwsCliRx = R(@"aws[ \t]+configure[ \t]+set[ \t]+(?:aws_secret_access_key|aws_session_token|aws_access_key_id)[ \t]+(?<v>\S+)", RxOptI);
        private static readonly Regex SmbPassRx = R(@"(?:-U|--user(?:=|[ \t]+))[ \t]*['""]?(?:[A-Za-z0-9.-]+[\\/])?(?<u>[A-Za-z0-9._$-]+)%(?<v>[^\s'""]{3,128})", RxOpt);
        private static readonly Regex BitLockerRx = R(@"(?<![0-9-])\d{6}(?:-\d{6}){7}(?![0-9-])", RxOpt);
        private static readonly Regex AwsResIdRx = R(@"(?<![A-Za-z0-9-])(?:eni|vpc|subnet|sg|i|vol|snap|igw|nat|rtb|acl|tgw|tgw-attach|vpce|eipalloc|eipassoc|lt|fs|fsap|pcx|dopt|cgw|vgw|vpn|elb|r|sir|db)-[0-9a-f]{8}(?:[0-9a-f]{9})?(?![A-Za-z0-9-])", RxOpt);
        private static readonly Regex FlowLogRx = R(@"^[ \t]*\d{1,2} (?<acct>\d{12}) (?:eni-|-)", RxOpt | RegexOptions.Multiline);
        private static readonly Regex OktaIdRx = R(@"(?<![A-Za-z0-9])00[ugp][0-9A-Za-z]{15,18}(?![A-Za-z0-9])", RxOpt);
        private static readonly Regex PanSerialRx = R(@"(?:^|[\s>])1,\d{4}/\d\d/\d\d \d\d:\d\d:\d\d,(?<v>\d{9,15}),", RxOpt | RegexOptions.Multiline);
        private static readonly Regex CircuitRx = R(@"(?:\bCID|circuit[ _-]?id)[:#= \t]+(?<v>[A-Za-z0-9][A-Za-z0-9/._-]{4,63})", RxOptI);
        private static readonly Regex SccmSiteRx = R(@"\b(?:site|site code|sitecode)[ \t]*[:=]?[ \t]*['""](?<v>[A-Z0-9]{3})['""]", RxOptI);
        private static readonly Regex CompanyAnyRx = R(@"(?<![\p{L}])(?<v>(?:\p{Lu}[\p{L}&'-]+ ){1,4}(?:Inc|Ltd|LLC|GmbH|PLC|Corporation|Limited|Pty Ltd|S\.A\.|B\.V\.|AG|SE|SAS|SARL|Oy|AB|ASA)\b\.?)", RxOpt);
        // UK postcode or US "City, ST 12345"; the address line is taken from the start of the field in code
        private static readonly Regex PostalLineRx = R(@"\b(?:[A-Z]{1,2}\d[A-Z\d]? \d[A-Z]{2}|[A-Z][a-z]+(?: [A-Z][a-z]+)?, [A-Z]{2} \d{5}(?:-\d{4})?)\b", RxOpt);
        private static readonly Regex HexFieldRx = R(@"(?<![A-Za-z0-9_])(?:proctitle|cmd|comm|exe|data|cwd|name|acct|hostname|addr|terminal)=(?<v>(?:[0-9A-F]{2}){4,})(?![0-9A-Za-z])", RxOpt);
        private static readonly Regex SockaddrRx = R(@"saddr=(?<v>0200[0-9A-Fa-f]{4}(?<ip>[0-9A-Fa-f]{8})[0-9A-Fa-f]*)", RxOpt);
        private static readonly Regex B64Rx = R(@"(?<![A-Za-z0-9+/_-])(?<v>[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=_-])", RxOpt);
        private static readonly Regex OwnerUserRx = R(@"(?<key>owner|created[ _.-]?by|modified[ _.-]?by|assignee|assigned[ _.-]?to|requester|requested[ _.-]?by|approver|maintainer|contact)[""']?[ \t]*[:=][ \t]*[""'](?<v>[a-z][a-z0-9]*[._][a-z0-9._-]{1,40})[""'](?:[ \t]*->[ \t]*[""'](?<v2>[a-z][a-z0-9]*[._][a-z0-9._-]{1,40})[""'])?", RxOptI);
        private static readonly Regex VendorOrgRx = R(@"^(?:Microsoft|DigiCert|Sectigo|Comodo|GlobalSign|Entrust|GoDaddy|IdenTrust|Let'?s Encrypt|ISRG|Internet Security Research Group|Google|Amazon|Cloudflare|Apple|Mozilla|Oracle|Cisco|VMware|Red Hat|Canonical|Okta|Fortinet|Palo Alto Networks|Juniper|Citrix|Adobe|Symantec|Thawte|GeoTrust|QuoVadis|Starfield|Baltimore|USERTrust|COMODO|Go Daddy|Verisign|Atlassian|GitHub|Slack|Zoom|Salesforce|ServiceNow)\b", RxOptI);
        private static readonly Regex IdCtxRx = R(
            @"(?<key>puid|profile[ _.-]?id|customer[ _.-]?id|external[ _.-]?id|immutable[ _.-]?id|devid|device[ _.-]?serial|serial[ _.-]?number|serial[ _.-]?no|serial|asset[ _.-]?tag|hardware[ _.-]?id|bios[ _.-]?serial|service[ _.-]?tag|svc[ _.-]?tag|employee[ _.-]?id|employee[ _.-]?number|badge[ _.-]?id|badge[ _.-]?number)"
            + Sep + @"(?<v>[A-Za-z0-9][A-Za-z0-9._:/-]{3,63})(?![A-Za-z0-9])", RxOptI);
        private static readonly Regex ForestOidRx = R(@"1\.3\.6\.1\.4\.1\.311\.21\.8\.(?<v>\d{1,10}\.\d{1,10}\.\d{1,10}\.\d{1,10}\.\d{1,10}\.\d{1,10})", RxOpt);
        private static readonly Regex GuidPathRx = R(@"/(?:subscriptions|tenants|directories|managementGroups)/(?<v>" + GuidPat + @")(?![0-9A-Fa-f-])", RxOptI);
        private static readonly Regex AnyGuidRx = R(@"(?<![0-9A-Fa-f-])(?<v>" + GuidPat + @")(?![0-9A-Fa-f-])", RxOpt);
        private static readonly Regex AwsAcctRx = R(
            @"(?:arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(?<v>\d{12}):|(?<![A-Za-z0-9])(?:account[ _.-]?id|recipient[ _.-]?account[ _.-]?id|aws[ _.-]?account(?:[ _.-]?id)?|owner[ _.-]?id|source[ _.-]?account)[""']?[ \t]*[:=][ \t]*[""']?(?<v>\d{12})(?![0-9]))", RxOptI);
        private static readonly Regex ArnUserRx = R(@"arn:aws[a-z-]*:(?:iam|sts)::\d{12}:(?:user|role|assumed-role|group)/(?:[A-Za-z0-9+=,.@_-]+/)?(?<v>[A-Za-z0-9+=,.@_-]{2,64})", RxOpt);
        private static readonly Regex ArnBucketRx = R(@"arn:aws[a-z-]*:s3:::(?<v>[a-z0-9][a-z0-9.-]{2,62})", RxOpt);
        // Azure resource IDs: /subscriptions/{id}/resourceGroups/{rg}/providers/{ns}/{type}/{name}[/{subtype}/{subname}]
        private static readonly Regex AzureResRx = R(@"/subscriptions/[^/\s""']{1,64}/resourceGroups/(?<rg>[A-Za-z0-9._()-]{1,90})(?:/providers/[A-Za-z0-9.]{1,60}/(?<k>[A-Za-z]{2,60})/(?<v>[A-Za-z0-9][A-Za-z0-9._()-]{0,89})(?:/(?<k2>[A-Za-z]{2,60})/(?<v2>[A-Za-z0-9][A-Za-z0-9._()-]{0,89}))?)?", RxOptI);
        private static readonly Regex AzureRgCtxRx = R(@"(?<key>resource[ _.-]?group[ _.-]?name|resource[ _.-]?group|management[ _.-]?group[ _.-]?(?:name|id))[""']?[ \t]*[:=][ \t]*[""']?(?<v>[A-Za-z0-9][A-Za-z0-9._()-]{1,89})", RxOptI);

        private static readonly Regex EmailRx = R(
            @"(?<![A-Za-z0-9._-])(?<local>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9_])?)@(?<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-]|\.[A-Za-z0-9])", RxOpt);
        private static readonly Regex EmailNameRx = R(
            @"(?:""(?<v>[^""<>\r\n]{3,60})""|(?<![\p{L}])(?<v>\p{Lu}[\p{L}'.,\- ]{2,58}?))[ \t]*<[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+>", RxOpt);

        private static readonly Regex MacRx = R(
            @"(?<![A-Za-z0-9:.-])(?<mac>[0-9A-Fa-f]{2}(?<sep>[:-])[0-9A-Fa-f]{2}(?:\k<sep>[0-9A-Fa-f]{2}){4}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![A-Za-z0-9:-]|\.[0-9A-Za-z])", RxOpt);
        private static readonly Regex MacCtxRx = R(
            @"(?<key>mac|mac[ _.-]?addr(?:ess)?|physical[ _.-]?address|hw[ _.-]?addr(?:ess)?|hardware[ _.-]?address|chaddr|client[ _.-]?mac)" + Sep + @"(?<mac>[0-9A-Fa-f]{12})(?![A-Za-z0-9])", RxOptI);
        // 6 hex bytes separated by spaces (route print "00 50 56 a1 2b 77"), and runs of hex bytes that embed MACs
        private static readonly Regex MacSpaceRx = R(@"(?<![0-9A-Fa-f] |[0-9A-Za-z])(?<mac>[0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2}){5})(?! [0-9A-Fa-f]{2}(?![0-9A-Za-z])|[0-9A-Za-z])", RxOpt);
        private static readonly Regex ByteRunRx = R(@"(?<![0-9A-Za-z])(?:0x)?(?:[0-9A-Fa-f]{2}(?<sep>[-: ])){7,}[0-9A-Fa-f]{2}(?![0-9A-Za-z])|(?<![0-9A-Za-z])(?:0x)?[0-9A-Fa-f]{16,}(?![0-9A-Za-z])", RxOpt);
        private static readonly Regex DuidRx = R(@"(?<![0-9A-Za-z-])00-0[13]-00-01-(?:[0-9A-Fa-f]{2}-){4}?(?<mac>[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})(?![0-9A-Za-z-])", RxOpt);
        private static readonly Regex LinkHeaderRx = R(@"(?:ll header: [0-9a-f]+: |MAC=)(?<a>[0-9a-f]{2}(?<s>[: ])[0-9a-f]{2}(?:\k<s>[0-9a-f]{2}){4})\k<s>(?<b>[0-9a-f]{2}\k<s>[0-9a-f]{2}(?:\k<s>[0-9a-f]{2}){4})", RxOptI);

        private static readonly Regex IPv4Rx = R(
            @"(?<![A-Za-z0-9.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?![A-Za-z0-9]|\.[0-9])", RxOpt);
        private static readonly Regex VersionCtxRx = R(
            @"(?:version|ver|build|release|rev|revision|firmware|oid|assemblyversion|fileversion|productversion)[ \t]*[=:]?[ \t]*[""']?(?:\d{1,5}(?:\.\d{1,5}){1,3}[ \t]*-[ \t]*)?$", RxOptI);
        private static readonly Regex InAddrRx = R(@"(?<![0-9.])(?<o>(?:\d{1,3}\.){1,4})in-addr\.arpa", RxOptI);
        private static readonly Regex IPv6Rx = R(
            @"(?<![A-Za-z0-9:.])(?<v>(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?)(?:%[A-Za-z0-9_.-]+)?(?![A-Za-z0-9:])", RxOpt);
        private static readonly Regex DnsWireRx = R(@"(?<![A-Za-z0-9)])(?:\(\d{1,2}\)[A-Za-z0-9_-]{1,63}){2,}\(0\)", RxOpt);
        private static readonly Regex DnsWireLabelRx = R(@"\((\d{1,2})\)([A-Za-z0-9_-]{1,63})", RxOpt);

        // LDAP distinguished names (CN=..,OU=..,DC=..) and X.500 certificate subjects (CN=.., O=.., L=.., C=..)
        private const string DnComp =
            @"(?<k>DC)=(?<v>[A-Za-z0-9_-]{1,63})|(?<k>C)=(?<v>[A-Za-z]{2})(?![A-Za-z])|(?<k>CN|OU|O|L|ST|S|E|UID|STREET)=(?<v>(?:\\.|[^,;+\r\n""<>=\\()\]])+?)(?=[ \t]*[,;+]|[ \t]*$|[""<>)\]\r\n]|'(?![\p{L}])|(?-i:[ \t]+[a-z(]))";
        private static readonly Regex DnRx = R(@"(?<![A-Za-z0-9])(?:" + DnComp + @")(?:[ \t]*[,;+][ \t]*(?:" + DnComp + @"))+", RxOptI);
        private static readonly Regex DnCompRx = R(DnComp, RxOptI);

        // ---- host names ----
        private static readonly Regex HostCtxRx = R(
            @"(?<key>host[ _.-]?name|host|computer[ _.-]?name|computer|machine[ _.-]?name|machine|server[ _.-]?name|server|workstation[ _.-]?name|workstation|device[ _.-]?name|device[ _.-]?id|dev[ _.-]?name|node[ _.-]?name|node|dc[ _.-]?name|domain[ _.-]?controller|logon[ _.-]?server|kdc[ _.-]?called|dns[ _.-]?host[ _.-]?name|fqdn|netbios[ _.-]?name|sys[ _.-]?name|system[ _.-]?name|data[ _.-]?source|src[ _.-]?name|dst[ _.-]?name|vm[ _.-]?name|endpoint[ _.-]?name|asset[ _.-]?name|nas[ _.-]?identifier)"
            + Sep + HostVal, RxOptI);
        private static readonly Regex CiscoServerRx = R(@"^[ \t]*(?:(?:tacacs|radius)(?:-server)? server|server name|aaa-server) (?<v>[A-Za-z0-9][A-Za-z0-9._-]{1,62})[ \t]*\r?$", RxOptIM);
        private static readonly Regex NltestDcRx = R(@"^[ \t]*DC:[ \t]*\\\\(?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,253})", RxOptIM);
        private static readonly Regex UncRx = R(
            @"(?<![\\A-Za-z0-9$%._:/-])\\{2,4}(?:\?\\UNC\\)?(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?=[\\""'\s,;:)\]]|$)", RxOpt);
        private static readonly Regex UrlRx = R(
            @"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9+.-]{1,15}://(?:[^@/\s""']+@)?(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?=[:/\s""'?#)\]]|$)", RxOpt);
        // RFC 3164 "Nov 18 14:10:01 host prog[pid]:" / ISO-timestamp variants, and RFC 5424 "<34>1 2026-... host app ..."
        private static readonly Regex SyslogRx = R(
            @"^(?:<\d{1,3}>(?:[A-Z][a-z]{2} +\d{1,2}|\d{4}-\d\d-\d\d)[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?(?: \d{4})? (?<v>[A-Za-z][A-Za-z0-9.-]{1,253}) (?=\S)|(?:<\d{1,3}>)?(?:[A-Z][a-z]{2} +\d{1,2}|\d{4}-\d\d-\d\d)[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?(?: \d{4})? (?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,253}) (?=(?:(?:emerg|alert|crit|err|error|warning|warn|notice|info|debug) )?[A-Za-z0-9_./()-]+(?:\[\d+\])?:)|<\d{1,3}>1 \S+ (?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,253}) )",
            RxOpt | RegexOptions.Multiline);
        private static readonly Regex CiscoHostnameRx = R(@"^[ \t]*(?:hostname|switchname|set[ \t]+hostname|sysname|set[ \t]+system[ \t]+host-name)[ \t]+[""']?(?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,62})[""']?[ \t]*\r?$", RxOptIM);
        private static readonly Regex CiscoPromptRx = R(
            @"^(?<v>[A-Za-z][A-Za-z0-9._-]{1,62})(?:\([a-z0-9-]+\))?[#>][ \t]*(?:sh(?:ow)?|conf(?:ig(?:ure)?)?|ping|traceroute|copy|wr(?:ite)?|exit|end|term(?:inal)?|enable|reload|debug|clear|dir|more|interface|int|no)\b", RxOptIM);
        private static readonly Regex SpnRx = R(
            @"(?<svc>HOST|HTTP|HTTPS|MSSQLSvc|MSSQL|ldap|GC|cifs|RestrictedKrbHost|TERMSRV|WSMAN|DNS|exchangeMDB|exchangeAB|exchangeRFR|SMTP|SMTPSVC|IMAP|IMAP4|POP|POP3|nfs|RPC|RPCSS|MSServerCluster|MSServerClusterMgmtAPI|Hyper-V Replica Service|Microsoft Virtual Console Service|Microsoft Virtual System Migration Service|krbtgt|kadmin|ftp|postgres|MySQL|mongodb|oracle|vnc|afs|iSCSITarget|FIMService|SAP|sip|DFSR-12F9A27C-BF97-4787-9364-D31B6C55EB04|E3514235-4B06-11D1-AB04-00C04FC2DCD2)/(?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,253})",
            RxOptI);
        private static readonly Regex KlistRx = R(
            @"^[ \t]*(?:#\d+>[ \t]*)?(?:Client|Server)[ \t]*:[ \t]*(?<v>[^\s@]+)[ \t]+@[ \t]+(?<r>[A-Za-z0-9][A-Za-z0-9.-]*)", RxOptIM);
        private static readonly Regex ComputerAcctRx = R(@"(?<![A-Za-z0-9\\$%._/-])(?<v>[A-Za-z][A-Za-z0-9-]{1,14})\$(?=[@\s""',;:)\]}<]|$)", RxOpt | RegexOptions.Multiline);
        private static readonly Regex HostIpRx = R(
            @"(?<![A-Za-z0-9._/-])(?<v>[A-Za-z][A-Za-z0-9-]{1,62}(?:\.[A-Za-z0-9-]{1,63})*)(?:/|[ \t]*[\[(])(?:\d{1,3}\.){3}\d{1,3}(?:[\])]|:\d+|(?![0-9.]))", RxOpt);
        private static readonly Regex ResolveRx = R(
            @"(?:could not resolve(?: host(?:name)?)?|cannot resolve(?: host(?:name)?)?|unable to resolve(?: host(?:name)?)?|failed to resolve(?: host(?:name)?)?|unknown host|no such host(?: is known)?|UnknownHostException|NoRouteToHostException|getaddrinfo [A-Z_]+|lookup|Pinging|Tracing route to|PING|traceroute to|connecting to|connected to|connection to|resolving)[ \t]*[:=]?[ \t]*[""'(\[]?(?<v>[A-Za-z0-9][A-Za-z0-9.-]{1,252})",
            RxOptI);
        private static readonly Regex PostfixHostRx = R(@"(?:(?<![A-Za-z0-9])(?:client|helo|relay|host)=|(?:connect|disconnect|lost connection after \S+) from )(?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,252})\[", RxOptI);
        private static readonly Regex NestedHostRx = R(
            @"""(?:host|agent|observer|computer|device|source|destination|client|server|node)""\s*:\s*\{[^{}]{0,800}?""(?:name|hostname|host_name|hostName)""\s*:\s*""(?<v>[^""\\]{1,253})""", RxOptI);

        // ---- users ----
        private static readonly Regex UserCtxRx = R(
            @"(?<key>user[ _.-]?name|user[ _.-]?id|user|account[ _.-]?name|account|logon[ _.-]?name|login[ _.-]?name|login|logon[ _.-]?account|sam[ _.-]?account[ _.-]?name|upn|user[ _.-]?principal[ _.-]?name|principal|uname|usr|logname)"
            + Sep + UserVal, RxOptI);
        private static readonly Regex ForUserRx = R(
            @"(?<![A-Za-z0-9])(?:for|by|of)[ \t]+(?:invalid[ \t]+)?user[ \t]+[""'\[]?" + UserVal, RxOptI);
        private static readonly Regex SshUserRx = R(
            @"(?<![A-Za-z0-9])(?:(?:Accepted|Failed) [a-z-]+ for (?:invalid user )?|Invalid user |session (?:opened|closed) for user |new user: name=|delete user '|password changed for |changed password for |sudo:[ \t]+(?=[A-Za-z0-9._$-]+ : )|su: \(to [^)]+\) |authentication failure for )(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))",
            RxOpt);
        private static readonly Regex AngleUserRx = R(@"(?<![A-Za-z0-9])(?:user(?:name)?|usr)[ \t]*<(?<v>[A-Za-z0-9][^<>\s]{0,63})>", RxOptI);
        private static readonly Regex DomainUserRx = R(
            @"(?<![A-Za-z0-9\\/.:$%-])(?<d>[A-Za-z][A-Za-z0-9-]{1,14})\\{1,2}(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))(?![\\/A-Za-z0-9])", RxOpt);
        private static readonly Regex LocalAcctRx = R(@"(?<![A-Za-z0-9\\.])\.\\(?<v>[A-Za-z0-9][A-Za-z0-9._$-]{0,63})(?![\\/A-Za-z0-9])", RxOpt);
        private static readonly Regex UserPathRx = R(
            @"(?:(?<![A-Za-z0-9])(?:[A-Z]:|%SystemDrive%))?\\{1,2}(?:Users\$?|Home\$?|Homes\$?|Profiles\$?|RedirectedFolders\$?|Documents and Settings)\\{1,2}(?<v>[A-Za-z0-9][A-Za-z0-9._$ -]{0,63}?)(?=\\|[""',;)\]]|[ \t]*\r?$)", RxOptIM);
        private static readonly Regex HomePathRx = R(@"(?<![A-Za-z0-9])/(?:home|Users)/(?<v>[A-Za-z0-9][A-Za-z0-9._-]{0,63})(?=/|[\s""',;:)\]]|$)", RxOpt | RegexOptions.Multiline);
        private static readonly Regex ApacheRx = R(
            @"^(?<h>[0-9A-Fa-f:.]+|[A-Za-z0-9][A-Za-z0-9.-]*) (?<id>\S+) (?<v>[^\s\[]+) \[\d{1,2}/[A-Za-z]{3}/\d{4}:", RxOpt | RegexOptions.Multiline);
        private static readonly Regex CiscoUserRx = R(@"^[ \t]*username[ \t]+(?<v>\S+)[ \t]+(?:privilege|secret|password|role|view|nopassword|algorithm-type)", RxOptIM);
        private static readonly Regex NestedUserRx = R(@"""user""\s*:\s*\{[^{}]{0,800}?""(?<k>name|domain|email|full_name)""\s*:\s*""(?<v>[^""\\]{1,128})""", RxOptI);

        // ---- people / organisations / locations ----
        private const string PersonVal =
            @"(?-i:(?<v>\p{Lu}[\p{Ll}'\u2019-]+(?: \p{Lu}\.)?(?: (?:(?:van|de|del|da|von|le|la|di|du|dos|der) )?\p{Lu}[\p{L}'\u2019-]+){1,2}|\p{Lu}[\p{L}'\u2019-]+, ?\p{Lu}[\p{Ll}'\u2019-]+(?: \p{Lu}\.)?))(?![\p{L}])";
        private static readonly Regex PersonCtxRx = R(
            @"(?<key>display[ _.-]?name|full[ _.-]?name|real[ _.-]?name|common[ _.-]?name|manager|owner|created[ _.-]?by|modified[ _.-]?by|last[ _.-]?modified[ _.-]?by|requested[ _.-]?by|requester|requestor|assigned[ _.-]?to|approved[ _.-]?by|approver|submitted[ _.-]?by|reported[ _.-]?by|contact|employee|name|from|to|cc|sender|recipient|caller|author)"
            + Sep + PersonVal, RxOptI);
        private static readonly Regex NamePartCtxRx = R(
            @"(?<key>given[ _.-]?name|givenname|first[ _.-]?name|surname|last[ _.-]?name|family[ _.-]?name|middle[ _.-]?name|sn)" + Sep + @"(?-i:(?<v>\p{Lu}[\p{L}'\u2019-]{1,30}))(?![\p{L}0-9'\u2019-])", RxOptI);
        private static readonly Regex PiiCtxRx = R(
            @"(?<key>street[ _.-]?address|street|postal[ _.-]?code|zip[ _.-]?code|zip|physical[ _.-]?delivery[ _.-]?office[ _.-]?name|office[ _.-]?phone|office|telephone[ _.-]?number|telephone|phone[ _.-]?number|phone|mobile[ _.-]?phone|mobile|home[ _.-]?phone|ip[ _.-]?phone|fax|pager|home[ _.-]?directory|home[ _.-]?drive|profile[ _.-]?path|script[ _.-]?path)"
            + Sep + @"(?<v>[^\r\n""<>=|]{2,80}?)(?=[ \t]*(?:[""'<|\r\n]|$)|[ \t]+[A-Za-z_]{2,30}=)", RxOptI | RegexOptions.Multiline);
        private static readonly Regex PhoneRx = R(
            @"(?<![\w+])(?:\+\d{1,3}[ .-]?)?\(\d{2,4}\)[ .-]?\d{3,4}[ .-]\d{3,4}(?!\d)|(?<![\w+])\+\d{1,3}[ .-]\d{2,4}[ .-]\d{3,4}[ .-]\d{3,4}(?!\d)|(?<![\w+])\+\d{1,3}[ .-]\d{2,5}[ .-]\d{5,8}(?!\d)", RxOpt);
        private static readonly Regex LdifB64Rx = R(@"^(?<k>[A-Za-z][A-Za-z0-9;-]{0,60}):: ?(?<v>[A-Za-z0-9+/]{4,}={0,2})[ \t]*\r?$", RxOpt | RegexOptions.Multiline);
        private static readonly Regex OrgCtxRx = R(
            @"(?<key>organization|organisation|company|company[ _.-]?name|org[ _.-]?name|tenant[ _.-]?name|customer[ _.-]?name|tenant[ _.-]?display[ _.-]?name|company[ _.-]?display[ _.-]?name)"
            + Sep + @"(?<v>[A-Za-z0-9][A-Za-z0-9&.' -]{1,60}?)(?=[ \t]*(?:[""'<,;\r\n]|$))", RxOptI | RegexOptions.Multiline);
        private static readonly Regex SiteCtxRx = R(
            @"(?<key>site[ _.-]?name|site|city|l)" + Sep + @"(?<v>[A-Za-z0-9][A-Za-z0-9_-]{1,62})(?![A-Za-z0-9_.-])", RxOptI);

        // ---- domains ----
        private static readonly Regex DomainCtxRx = R(
            @"(?<key>domain[ _.-]?name|domain|dom[ _.-]?name|dns[ _.-]?suffix[ _.-]?search[ _.-]?list|dns[ _.-]?suffix|realm[ _.-]?name|realm|workgroup|forest[ _.-]?name|forest|ntdom)"
            + Sep + @"(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?![/\\@=])", RxOptI);
        private static readonly Regex FqdnRx = R(
            @"(?<![A-Za-z0-9._-])(?<v>(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.){1,20}[A-Za-z]{2,24})(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", RxOpt);

        // only tokens that contain a digit or a hyphen can be host-name siblings / organisation-prefixed names
        private static readonly Regex SiblingCandRx = R(@"(?<![A-Za-z0-9_.\\-])[A-Za-z](?=[A-Za-z0-9-]*[0-9-])[A-Za-z0-9]*(?:-[A-Za-z0-9]+){0,5}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", RxOpt);
        private static readonly Regex AwsRegionRx = R(@"^(?:us|eu|ap|sa|ca|me|af|cn|il|mx)-(?:gov-)?(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d$", RxOptI);
        private static readonly Regex FormatListLineRx = R(@"^(?<k>[A-Za-z][A-Za-z0-9 ()/._-]{0,60}?) +: (?<v>.*)$", RxOpt);
        private static readonly Regex IgnoredUserRx = R(@"^(?:DWM-\d+|UMFD-\d+|S-1-[0-9-]+|IUSR_.*|\d+|MSSQL\$.*|SQLAgent\$.*|.*\$\$|i-[0-9a-f]{8,17}|ami-[0-9a-f]{8,17})$", RxOptI);
        private static readonly Regex FileExtRx = R(
            @"\.(?:log|txt|exe|dll|sys|ps1|psm1|psd1|bat|cmd|vbs|js|xml|json|csv|ini|cfg|conf|config|evtx|etl|dmp|zip|msi|msu|cab|inf|cat|mui|htm|html|tmp|bak|old|dat|db|mdf|ldf|pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|reg|pol|lnk|ocx|drv|cpl|scr|aspx|asmx|ashx|php|jsp|py|sh|yml|yaml|md|gz|tar|7z|iso|vhdx?|vmdk)$", RxOptI);
        private static readonly Regex TokenValueRx = R(
            @"^(?:HOST|DOMAIN|USER|PERSON|NAME|PII|REDACTED|ORG|OU|LOCATION|SECRET)-\d{4,}$", RxOptI);

        private static Dictionary<string, bool> Words(string spaceSeparated)
        {
            Dictionary<string, bool> d = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (string w in spaceSeparated.Split(' ')) if (w.Length > 0) d[w] = true;
            return d;
        }
        private static readonly Dictionary<string, bool> EmptyPrefixes = Words("");
        private static readonly Dictionary<string, bool> NetworkSchemes = Words("http https ftp ftps sftp scp smb cifs nfs ldap ldaps ws wss rdp ssh telnet tcp udp jdbc mysql postgres postgresql mongodb mongodb+srv redis rediss amqp amqps mqtt sql sqlserver oracle file net.tcp kerberos krb5 radius syslog snmp vnc git svn");
        private static readonly Dictionary<string, bool> HostPrefixes = Words("src source dst dest destination remote client server target peer origin caller calling called dvc device agent observer sys system dns netbios full primary upstream downstream orig original old new from to sending receiving smtp mail relay proxy gateway sql db database web app file print worker master cluster vm virtual physical parent child reported logon auth kdc s d r cs c backup member managed node");
        private static readonly Dictionary<string, bool> UserPrefixes = Words("subject target src source dst dest destination client caller calling remote old new member logon effective real original orig requesting requested requester auth authenticated proxy db sql os windows win ad nt runas as cs s d r x login end local domain primary supplied service connected current last admin administrator mail smtp ftp vpn sa run");
        private static readonly Dictionary<string, bool> DomainPrefixes = Words("subject target src dst s d user logon account caller client dns ad netbios primary specific connection default search parent child root forest tree nt win windows computer machine member joined supplied dc our trusted trusting dom");
        private static readonly Dictionary<string, bool> PersonPrefixes = Words("registered primary account record business technical system user employee contact object");
        private static readonly Dictionary<string, bool> OrgPrefixes = Words("registered");
        private static readonly Dictionary<string, bool> SitePrefixes = Words("dc our client ad computer user server");

        // ----- configuration sets -----
        private readonly Dictionary<string, bool> tlds = NewSet();
        private readonly Dictionary<string, bool> ignoreNames = NewSet();
        private readonly Dictionary<string, bool> commonWords = NewSet();
        private readonly Dictionary<string, bool> ignoreDomainPrefixes = NewSet();
        private readonly Dictionary<string, bool> adBuiltins = NewSet();
        private readonly Dictionary<string, bool> personStopWords = NewSet();
        private readonly Dictionary<string, bool> secretNonValues = NewSet();
        private readonly Dictionary<string, bool> siblingDeny = NewSet();
        private readonly Dictionary<string, bool> excludeValues = NewSet();
        private readonly List<string> excludeDomains = new List<string>();
        private readonly List<string> hostPatternSources = new List<string>();
        private readonly List<Regex> hostPatterns = new List<Regex>();

        // ----- mapping tables -----
        private readonly Table hosts, domains, users, persons, nameParts, pii, orgs, ous, locations, custom, secrets, guids, accounts, forestOids;
        private readonly Dictionary<string, bool> strongDomains = NewSet();
        private readonly Dictionary<string, bool> publicTlds = NewSet();
        private readonly Dictionary<string, bool> publicSuffixes = NewSet();
        private readonly Dictionary<string, MapEntry> pemBodies = new Dictionary<string, MapEntry>(StringComparer.Ordinal);
        private Regex namePartRx;
        private Dictionary<string, MapEntry> namePartMap = new Dictionary<string, MapEntry>(StringComparer.Ordinal);
        private readonly Table ipv4, subnets, ipv6, v6prefixes, macs, sids;
        private readonly Dictionary<string, MapEntry> ipv4Raw = NewMap();
        private readonly Dictionary<string, MapEntry> ipv6Raw = NewMap();
        private readonly Dictionary<string, MapEntry> macRaw = NewMap();
        private readonly Dictionary<string, MapEntry> secretRaw = new Dictionary<string, MapEntry>(StringComparer.Ordinal);
        private readonly Dictionary<string, MapEntry> personAlias = NewMap();
        private readonly Dictionary<string, long> v6IidCounters = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DottedObs> dotted = new Dictionary<string, DottedObs>(StringComparer.OrdinalIgnoreCase);
        private readonly List<DottedObs> dottedOrder = new List<DottedObs>();
        private readonly Dictionary<string, EmailObs> emails = new Dictionary<string, EmailObs>(StringComparer.OrdinalIgnoreCase);
        private readonly List<EmailObs> emailOrder = new List<EmailObs>();
        // Host labels seen only as the first label of an automatically detected FQDN that are common words
        // ("time" in time.contoso.com). They are replaced inside FQDNs but not as bare words.
        private readonly Dictionary<string, bool> weakHosts = NewSet();
        private readonly Dictionary<string, string> siblingCandidates = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private const int MaxSiblingCandidates = 400000;

        // ----- pass-2 index -----
        private Dictionary<string, Literal> literals = new Dictionary<string, Literal>(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, PrefixHit> prefixIndex = new Dictionary<string, PrefixHit>(StringComparer.OrdinalIgnoreCase);
        private bool[] literalLengths = new bool[1];
        private int maxLiteralLength;
        private Regex phraseRx, phraseTruncRx, secretBareRx;
        private readonly Dictionary<string, MapEntry> phraseMap = NewMap();
        private readonly Dictionary<string, string> phraseTruncMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private bool dirty = true;

        public ScrubEngine()
        {
            hosts = new Table("Hostname", Tok("HOST"));
            domains = new Table("DomainLabel", Tok("DOMAIN"));
            users = new Table("User", Tok("USER"));
            persons = new Table("Person", Tok("PERSON"));
            nameParts = new Table("NamePart", Tok("NAME"));
            pii = new Table("PII", Tok("PII"));
            forestOids = new Table("ForestOid", delegate(int n) { return "1000000.1000000.1000000.1000000.1000000." + n.ToString(CultureInfo.InvariantCulture); });
            orgs = new Table("Organization", Tok("ORG"));
            ous = new Table("OrgUnit", Tok("OU"));
            locations = new Table("Location", Tok("LOCATION"));
            custom = new Table("Custom", Tok("REDACTED"));
            secrets = new Table("Secret", Tok("SECRET"));
            guids = new Table("Guid", delegate(int n) { return "00000000-0000-4000-8000-" + n.ToString("x12", CultureInfo.InvariantCulture); });
            accounts = new Table("CloudAccount", delegate(int n) { return (100000000000L + n).ToString(CultureInfo.InvariantCulture); });
            ipv4 = new Table("IPv4", null);
            subnets = new Table("IPv4Subnet", delegate(int n) { return PoolSubnet(n - 1) + ".0/24"; });
            ipv6 = new Table("IPv6", null);
            v6prefixes = new Table("IPv6Prefix", delegate(int n) { return "2001:db8:" + ((n >> 16) & 0xffff).ToString("x", CultureInfo.InvariantCulture) + ":" + (n & 0xffff).ToString("x", CultureInfo.InvariantCulture) + "::/64"; });
            macs = new Table("MAC", MacFromIndex);
            sids = new Table("SID", null);
            LoadDefaults();
        }

        private static Func<int, string> Tok(string prefix)
        {
            return delegate(int n) { return prefix + "-" + n.ToString("D4", CultureInfo.InvariantCulture); };
        }

        // =========================================================================================
        // Configuration
        // =========================================================================================

        private static Dictionary<string, bool> NewSet() { return new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase); }
        private static Dictionary<string, MapEntry> NewMap() { return new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase); }

        private static void AddAll(Dictionary<string, bool> set, string spaceSeparated)
        {
            foreach (string s in spaceSeparated.Split(new char[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                set[s] = true;
        }

        private static void AddAllPipe(Dictionary<string, bool> set, string pipeSeparated)
        {
            foreach (string s in pipeSeparated.Split('|')) if (s.Trim().Length > 0) set[s.Trim()] = true;
        }

        private void LoadDefaults()
        {
            // TLDs recognised for automatic FQDN detection. Deliberately conservative: TLDs that are also common
            // words or code identifiers (info, name, app, int, in, it, is, to, me ...) are left out to avoid
            // false positives such as "logging.info". Add more with AddTld / -ExtraTld.
            AddAll(tlds, "com net org edu gov mil biz io co us uk ca de fr nl au jp cn eu ch se dk fi es nz br mx za sg hk kr tw ru pl cz il ie at be no "
                       + "local lan corp internal intranet intra home private localdomain ad priv arpa");

            // Never treated as sensitive on their own (well-known accounts, generic DNS labels, platform words).
            AddAll(ignoreNames,
                  "localhost localdomain local www www2 mail smtp imap pop pop3 ftp sftp api web app apps vpn dns ns mx autodiscover "
                + "login portal owa sts adfs cdn static wpad isatap prod dev test stage staging qa uat internal intranet lan "
                + "dc gc pdc _msdcs _tcp _udp _ldap _kerberos _gc _sites domaindnszones forestdnszones "
                + "workgroup builtin nt authority system administrator administrators admin guest guests users everyone "
                + "localsystem localservice networkservice root krbtgt defaultaccount wdagutilityaccount anonymous nobody daemon "
                + "www-data sshd null none unknown n/a na true false yes no on off enabled disabled failed failure success successful "
                + "server host client computer machine user account domain default service services network sa dbo public private "
                + "noreply no-reply postmaster support info webmaster help abuse security hostmaster "
                + "microsoft windows nginx apache iis kestrel tomcat x64 x86 amd64 arm64 ia64 win32 win64 wow64 mssqlserver sqlexpress "
                + "unix linux ubuntu debian centos redhat rhel suse kernel systemd cron sudo bin sys adm lp sync games man mail news uucp "
                + "proxy backup list irc gnats messagebus syslog uuidd tss _apt postfix dovecot mysql postgres ntp chrony polkitd "
                + "ec2-user ubuntu azureuser centos tcp udp icmp http https ssl tls ssh rdp smb ldap ldaps "
                + "kerberos ntlm negotiate any all self me - -- ? any-source inside outside dmz mgmt management untrust trust "
                + "loopback lo eth0 eth1 ens160 ens192 wlan0 docker0 bridge host-only nat "
                + "name names value values type id key data info error status result source target instance label high medium low "
                + "mandatory level person group oracle pi ftpuser git hadoop nagios zabbix vagrant ansible minecraft steam teamspeak ts3 "
                + "operator ntds settings schema configuration partitions container object top sql mssql uid gid euid pid tty pts "
                + "westus westus2 westus3 eastus eastus2 centralus northcentralus southcentralus westcentralus northeurope westeurope "
                + "uksouth ukwest francecentral germanywestcentral switzerlandnorth norwayeast swedencentral eastasia southeastasia "
                + "japaneast japanwest australiaeast australiasoutheast canadacentral canadaeast brazilsouth koreacentral centralindia "
                + "global none");

            // Public top-level domains are never treated as an organisation's domain label.
            AddAll(publicTlds, "com net org edu gov mil biz info io co us uk ca de fr nl au jp cn eu ch se dk fi es nz br mx za sg hk kr tw ru pl cz il ie at be no "
                + "in it me tv cc ly ai app dev cloud online site tech xyz");

            // Ordinary English and IT words: never treated as a host / user / domain / person name on their own.
            AddAll(ignoreNames,
                  "a an the and or but nor not no yes for to of in on at by with from into onto upon over under about after before "
                + "is are was were be been being am has have had having do does did done will would shall should can could may might must "
                + "this that these those it its he she they them their there here who whom whose which what when where why how "
                + "all any both each few more most other some such only own same so than too very just also again then once "
                + "new old now via per out off up down if else while until because since though although get got set put see "
                + "use used using run running ran start started stop stopped open opened close closed found missing failed fail "
                + "error errors warning warnings info debug trace notice critical fatal success ok okay done pending ready "
                + "session sessions process processes service services task tasks job jobs event events log logs logger logging "
                + "file files folder folders path paths share shares drive drives disk disks volume volumes "
                + "net network networks internet web site sites page pages app apps application applications api apis "
                + "client clients server servers host hosts node nodes cluster clusters pod pods container containers "
                + "user users group groups role roles member members owner owners admin admins account accounts "
                + "profile profiles policy policies rule rules setting settings config configuration option options "
                + "request requests response responses connection connections socket sockets port ports protocol "
                + "message messages mail email inbox report reports export import backup backups restore update updates "
                + "install installer setup upgrade patch version versions release build builds deploy deployment "
                + "test tests testing dev prod staging local remote internal external public private shared common "
                + "default system systems kernel module modules driver drivers device devices hardware software "
                + "security audit auth authentication authorization login logon logoff logout signin sign token tokens "
                + "key keys cert certs certificate certificates secret secrets password passwords "
                + "data database databases table tables query queries index cache queue queues stream streams "
                + "finance legal sales marketing payroll operations engineering facilities procurement hr it support helpdesk "
                + "kube-system kube-public kube-node-lease kubernetes serviceaccount serviceaccounts "
                + "logwatch cron crond anacron mailer-daemon do-not-reply donotreply notifications alerts alert monitoring "
                + "anonymous guest everyone authenticated interactive network batch dialup unknown none null nobody "
                + "jenkins gitlab-runner docker containerd podman nginx apache tomcat postgres mysql redis mongodb elasticsearch kibana "
                + "grafana prometheus alertmanager splunk squid haproxy bind named dnsmasq junos fortigate okta oauth oauth2 saml oidc "
                + "openid sso mfa radius tacacs kerberos ntlm digicert sectigo globalsign letsencrypt");

            // Common words that are also used as the first label of a host name (time.contoso.com). They stay
            // inside FQDN replacements but are not replaced on their own.
            AddAll(commonWords,
                  "time files file docs doc wiki extranet sso id ids accounts auth webmail assets img images media video blog news shop store "
                + "helpdesk status monitor monitoring metrics grafana kibana elastic search git gitlab github jenkins ci build builds artifacts "
                + "nexus repo repos registry docker k8s kube vault gateway gw remote rdp citrix lyncdiscover sip meet teams crm erp hr finance "
                + "sales marketing production demo sandbox beta alpha old new backups archive db sql cache queue mq kafka ldap ad kdc pki crl "
                + "ocsp ca cert certs print printer printers scan fax voip phone calendar contacts chat update updates download downloads "
                + "upload uploads cloud console dashboard manage mgmt external secure ssl m mobile data analytics report reports reporting bi "
                + "log logs logging events track tracking share shares sharepoint my home about en us eu uk apac emea amer na la cluster "
                + "node nodes edge core dist access lb vip ns1 ns2 dns1 dns2 mx1 mx2 smtp1 relay mailhost exchange owa2 ntp1 ntp2 pool "
                + "storage nas san backup1 mirror cdn1 static1 origin internet intra corp office remoteapp rds rdweb rdgateway rdg "
                + "selfservice password passwordreset sspr fs adfs1 sts1 federation identity iam directory developer developers "
                + "manage management graph login signin account myaccount myapps portal admin support help docs status "
                + "core compute azure aws amazon kubernetes blob queue table vault database documents redis servicebus cloudapp "
                + "azurewebsites region zone s3 ec2 elb rds lambda api-gateway sqs sns dynamodb cloudfront");

            // Things that look like DOMAIN\user but are not.
            AddAll(ignoreDomainPrefixes,
                  "HKLM HKCU HKCR HKU HKCC HKEY APPPOOL SERVICE MACHINE MANAGER HOST AUTHORITY BUILTIN WINDOWS SYSTEM SYSTEM32 SYSWOW64 "
                + "PROGRAM USERS TEMP TMP LOGS LOG DATA APPDATA LOCAL LOCALLOW ROAMING SOFTWARE MICROSOFT DRIVERS ETC SYSTEMROOT "
                + "CURRENTCONTROLSET CONTROLSET001 CONTROLSET002 SERVICES POLICIES CLASSES DEVICE GLOBALROOT HARDDISKVOLUME "
                + "SHARE SHARES INETPUB WWWROOT DOCUMENTS DESKTOP DOWNLOADS BIN OBJ DEBUG RELEASE SRC LIB INCLUDE CONFIG UNC "
                + "MICROSOFTACCOUNT AZUREAD WORKGROUP EVERYONE NT ASPNET IUSR IIS LOCALHOST PIPE MAILSLOT REGISTRY USER "
                + "LABEL MANDATORY NAMES INSTANCE SERVER SQL ORACLE PROGRAMDATA COMMON FILES VOLUME CLUSTER STORAGE");

            // Active Directory built-in containers / groups: never a person, host or user name.
            AddAllPipe(adBuiltins,
                  "Users|Computers|Builtin|System|Configuration|Schema|Sites|Services|Program Data|Microsoft|Policies|ForeignSecurityPrincipals|"
                + "Managed Service Accounts|Domain Controllers|Default-First-Site-Name|Servers|NTDS Settings|Inter-Site Transports|IP|Subnets|"
                + "Partitions|Extended-Rights|Display-Specifiers|WellKnown Security Principals|Public Key Services|Enrollment Services|"
                + "Certification Authorities|AIA|CDP|KRA|OID|Certificate Templates|MicrosoftDNS|DomainDnsZones|ForestDnsZones|AdminSDHolder|"
                + "Deleted Objects|LostAndFound|Infrastructure|Keys|TPM Devices|Domain Admins|Domain Users|Domain Computers|Domain Guests|"
                + "Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|Server Operators|Print Operators|"
                + "Remote Desktop Users|Group Policy Creator Owners|DnsAdmins|DnsUpdateProxy|Protected Users|Cert Publishers|"
                + "Cloneable Domain Controllers|Read-only Domain Controllers|Enterprise Read-only Domain Controllers|Key Admins|"
                + "Enterprise Key Admins|Denied RODC Password Replication Group|Allowed RODC Password Replication Group|RAS and IAS Servers|"
                + "Event Log Readers|Hyper-V Administrators|Access Control Assistance Operators|Remote Management Users|"
                + "Storage Replica Administrators|Distributed COM Users|Performance Monitor Users|Performance Log Users|Cryptographic Operators|"
                + "Network Configuration Operators|IIS_IUSRS|Pre-Windows 2000 Compatible Access|Incoming Forest Trust Builders|"
                + "Windows Authorization Access Group|Terminal Server License Servers|Certificate Service DCOM Access|Guests|Replicator|"
                + "Microsoft Exchange Security Groups|Default Domain Policy|Default Domain Controllers Policy|krbtgt|Guest|Administrator|"
                + "DefaultAccount|WDAGUtilityAccount|Local System|Local Service|Network Service|Authenticated Users|Interactive|Anonymous Logon|"
                + "Enterprise Domain Controllers|This Organization|Creator Owner|Self|Dialup|Batch|Restricted|Terminal Server User");
            foreach (string k in new List<string>(adBuiltins.Keys)) ignoreNames[k] = true;

            AddAll(personStopWords,
                  "Windows Microsoft Update Updates Service Services Server Servers Policy Policies Default Domain Local Network Connection Adapter "
                + "Group Groups Admins Administrators Users Computers Controllers Task Event Events Log Logs Security System Application "
                + "Driver Device Manager Agent Center Configuration Management Account Accounts Operators Directory Active Remote Desktop "
                + "Certificate Authority Internet Explorer Edge Office Exchange Online Team Support Admin Corporation Inc Ltd LLC Corp "
                + "Company Holdings GmbH PLC Error Warning Information Critical Verbose Audit Success Failure Logon Logoff Object Access "
                + "Kerberos Authentication Package Process Thread Module Source Target Subject New Old Event ID Task Category Level Keywords "
                + "Opcode Info Start Stop Started Stopped Running Pending Enabled Disabled Failed Succeeded True False Unknown Monday Tuesday "
                + "Wednesday Thursday Friday Saturday Sunday January February March April May June July August September October November "
                + "December Daylight Standard Time Pacific Eastern Central Mountain Coordinated Universal Defender Firewall Antivirus Health "
                + "Monitor Monitoring Backup Restore Storage Volume Disk File Files Folder Share Print Printer Spooler Remote Procedure Call "
                + "Data Base Database Instance Engine Report Reporting Analysis Integration Browser Agent Job Jobs Step Schedule Scheduler "
                + "Google Amazon Apple Oracle Cisco Linux Ubuntu Debian Azure Cloud Web Site Sites Portal Global Catalog Primary Secondary "
                + "Internal External Public Private Trusted Untrusted Inside Outside Access Control List Rule Rules Allow Deny Drop Block "
                + "The A An Of And For To In On At By With From Is Was Not No Yes Contains Name Value Type Mode Status Result Version Build "
                + "Apache Tomcat Nginx Jetty Spring Boot Jenkins Docker Kubernetes Java Python Node Ruby Rails Django Flask Redis Mongo MongoDB "
                + "Postgres PostgreSQL MySQL MariaDB Elastic Elasticsearch Kibana Grafana Prometheus Okta Slack Teams Zoom GitHub GitLab "
                + "Atlassian Jira Confluence ServiceNow Salesforce Workday SAP Citrix VMware vSphere ESXi Hyper Veeam Splunk Sentinel "
                + "DigiCert Sectigo GlobalSign Entrust GoDaddy IdenTrust Encrypt Trust Services CA Root Intermediate TLS SSL RSA ECC SHA "
                + "VPN Profile Portal Gateway Agent Client Console Studio Visual Code Edge Chrome Firefox Safari Mozilla "
                + "Finance Legal Sales Marketing Payroll Operations Engineering Facilities Procurement Accounting Payable Receivable "
                + "Human Resources Support Desk Help Infrastructure Platform Team Department Division Office Building Floor Suite Unit "
                + "Street Road Avenue Lane Park Drive Court Place Square North South East West Central Upper Lower Inc Ltd GmbH");

            AddAll(secretNonValues,
                  "true false yes no null none nil n/a na - -- ? * ** *** **** ***** ****** ******** (null) <null> <none> <redacted> [redacted] "
                + "redacted hidden masked required optional enabled disabled empty notset not-set unset changeme public private default "
                + "<password> <secret> <token> password secret token xxx xxxx xxxxx xxxxxx xxxxxxxx ... string value bearer basic jwt "
                + "negotiate ntlm kerberos oauth oauth2 sha1 sha256 md5 aes aes256 rsa plaintext plain cleartext encrypted hashed");

            AddAll(siblingDeny,
                  "WIN WINDOWS HTTP HTTPS TLS TLSV SSL SSLV SHA MD AES DES RSA RC KB CVE RFC SMB SMBV UTF ISO IPV IP MS ERR ID NT X AMD ARM IA CU SP "
                + "RTM NET NETFX DOTNET VC VS PS PSV PWSH TCP UDP PORT ETH GI GIG FA TE VLAN PO LO ENS ENO EM WLAN LAN WAN COM LPT USB PCI ACPI "
                + "HID DISK VOLUME HARDDISKVOLUME PARTITION CPU CORE GEN DNS W3SVC APPPOOL PID TID SESSION EVENT RULE LINE ROW ITEM STEP PHASE "
                + "ERROR CODE BUILD VER VERSION REL RELEASE BETA ALPHA PATCH UPDATE Q FY WEEK DAY JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC "
                + "SQL MSSQL ORACLE NODE POD PVC TASK JOB THREAD WORKER SHARD PART CHUNK BLOCK PAGE TABLE COLUMN INDEX KEY OBJ OBJECT FILE "
                + "TEMP TMP LOG LOGS BACKUP SNAP SNAPSHOT VM VMNIC VNIC NIC HBA LUN RAID MIRROR SLOT BAY PSU FAN SENSOR GPU");

            // Public / vendor domains that are not sensitive and keep logs readable.
            foreach (string d in new string[] {
                "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "msftconnecttest.com", "live.com", "office.com",
                "office365.com", "microsoftonline.com", "msedge.net", "akamai.net", "akamaiedge.net", "digicert.com",
                "verisign.com", "globalsign.com", "entrust.net", "letsencrypt.org", "google.com", "googleapis.com",
                "gstatic.com", "apple.com", "mozilla.org", "ubuntu.com", "debian.org", "redhat.com", "w3.org",
                "xmlsoap.org", "openxmlformats.org", "example.com", "example.net", "example.org", "asp.net", "ado.net", "vb.net",
                "outlook.com", "hotmail.com", "gmail.com", "yahoo.com", "icloud.com", "protonmail.com", "aol.com", "msn.com",
                "amazon.com", "kubernetes.io", "k8s.io", "rsyslog.com", "elastic.co", "suricata.io", "emergingthreats.net", "f5.com",
                "splunk.com", "crowdstrike.com", "management.core.windows.net", "management.azure.com", "login.windows.net",
                "graph.windows.net", "msauth.net", "msftauth.net", "cloudflare.com", "github.com", "nuget.org", "npmjs.org", "pypi.org", "docker.io", "docker.com",
                "in-addr.arpa", "ip6.arpa", "schema.org", "purl.org", "openssl.org", "apache.org", "oracle.com", "java.com", "sun.com",
                "vmware.com", "cisco.com", "fortinet.com", "paloaltonetworks.com" })
                excludeDomains.Add(d);

            // Values that are never scrubbed (loopback, unspecified, broadcast, well-known public resolvers).
            AddAll(excludeValues, "0.0.0.0 127.0.0.1 255.255.255.255 :: ::1 localhost 8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 "
                + "2001:4860:4860::8888 2001:4860:4860::8844 2606:4700:4700::1111 2606:4700:4700::1001 "
                + "208.67.222.222 208.67.220.220 4.2.2.2 4.2.2.1 169.254.169.254 168.63.129.16 10.0.0.0 10.255.255.255 172.16.0.0 172.31.255.255 "
                + "192.168.0.0 192.168.255.255 100.64.0.0 "
                // Microsoft first-party application IDs (Azure CLI, Azure PowerShell, Portal, Graph Explorer, Teams, Office, VS ...)
                + "04b07795-8ddb-461a-bbee-02f9e1bf7b46 1950a258-227b-4e31-a9cf-717495945fc2 c44b4083-3bb0-49c1-b47d-974e53cbdf3c "
                + "de8bc8b5-d9f9-48b1-a8ad-b748da725064 1fec8e78-bce4-4aaf-ab1b-5451cc387264 d3590ed6-52b3-4102-aeff-aad2292ab01c "
                + "872cd9fa-d31f-45e0-9eab-6e460a02d1f1 29d9ed98-a469-4536-ade2-f981bc1d605e 0000000c-0000-0000-c000-000000000000 "
                + "797f4846-ba00-4fd7-ba43-dac1f8f63013 cf36b471-5b44-428c-9ce7-313bf84528de 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223");

            // Cloud service suffixes: only the customer's own label in front of these is scrubbed.
            AddAll(publicSuffixes,
                  "core.windows.net blob.core.windows.net file.core.windows.net queue.core.windows.net table.core.windows.net dfs.core.windows.net "
                + "web.core.windows.net database.windows.net servicebus.windows.net redis.cache.windows.net vault.azure.net azurewebsites.net "
                + "scm.azurewebsites.net cloudapp.net cloudapp.azure.com azure-devices.net azurecr.io documents.azure.com atp.azure.com "
                + "azurefd.net trafficmanager.net onmicrosoft.com sharepoint.com mail.protection.outlook.com azuredatalakestore.net "
                + "privatelink.blob.core.windows.net mail.protection.outlook.com amazonaws.com compute.amazonaws.com compute-1.amazonaws.com s3.amazonaws.com "
                + "elb.amazonaws.com rds.amazonaws.com execute-api.amazonaws.com ec2.internal compute.internal cloudfront.net "
                + "appspot.com googleusercontent.com herokuapp.com github.io gitlab.io okta.com auth0.com atlassian.net slack.com");
        }

        /// <summary>Removes the built-in ignore / exclusion lists (TLD list is kept).</summary>
        public void ClearDefaultExclusions()
        {
            ignoreNames.Clear();
            commonWords.Clear();
            excludeDomains.Clear();
            excludeValues.Clear();
        }

        public void AddTld(string tld) { if (!string.IsNullOrEmpty(tld)) tlds[tld.Trim().TrimStart('.')] = true; }
        public void AddIgnoreName(string name) { if (!string.IsNullOrEmpty(name)) ignoreNames[name.Trim()] = true; }
        public void AddExcludeValue(string value) { if (!string.IsNullOrEmpty(value)) excludeValues[value.Trim()] = true; }
        public void AddExcludeDomain(string domain) { if (!string.IsNullOrEmpty(domain)) excludeDomains.Add(domain.Trim().Trim('.').ToLowerInvariant()); }

        public void AddHostnamePattern(string pattern)
        {
            hostPatterns.Add(R(pattern, RxOptI));
            hostPatternSources.Add(pattern);
        }

        /// <summary>
        /// Registers a value the user knows is sensitive. type = Hostname | Domain | User | Person | Organization | Custom.
        /// replacement may be null to auto-generate a token.
        /// </summary>
        public void AddKnown(string type, string value, string replacement)
        {
            if (string.IsNullOrEmpty(value)) return;
            value = value.Trim();
            if (value.Length == 0) return;
            if (string.IsNullOrEmpty(replacement)) replacement = null; else replacement = replacement.Trim();
            string t = (type ?? "Custom").Trim().ToLowerInvariant();
            const string src = "(user supplied)";
            dirty = true;

            if (t == "hostname" || t == "host" || t == "computer")
            {
                string v = TrimDots(value);
                if (v.IndexOf('.') >= 0 && replacement == null) { AddDottedObs(v, HintHost, src); return; }
                if (v.IndexOf('.') >= 0) { PutTable(custom, v, replacement, src); return; }
                ignoreNames.Remove(v);
                commonWords.Remove(v);
                weakHosts.Remove(v);
                PutTable(hosts, v, replacement, src);
            }
            else if (t == "domain" || t == "domainlabel")
            {
                string v = TrimDots(value);
                if (v.IndexOf('.') >= 0 && replacement == null)
                {
                    foreach (string l in v.Split('.')) ignoreNames.Remove(l);
                    AddDottedObs(v, HintDomain, src);
                    return;
                }
                if (v.IndexOf('.') >= 0) { PutTable(custom, v, replacement, src); return; }
                ignoreNames.Remove(v);
                strongDomains[v] = true;
                PutTable(domains, v, replacement, src);
            }
            else if (t == "user" || t == "username")
            {
                ignoreNames.Remove(value);
                PutTable(users, value, replacement, src);
            }
            else if (t == "person" || t == "name")
            {
                MapEntry e = RegisterPerson(value, src, true);
                if (e != null && replacement != null) e.Replacement = replacement;
            }
            else if (t == "organization" || t == "org")
            {
                PutTable(orgs, value, replacement, src);
            }
            else
            {
                PutTable(custom, value, replacement, src);
            }
        }

        private static void PutTable(Table t, string value, string replacement, string src)
        {
            if (replacement != null) t.Put(value, value, replacement, src); else t.GetOrAdd(value, value, src);
        }

        /// <summary>Restores one row of an existing correlation sheet so replacements stay stable between runs.</summary>
        public void LoadEntry(string type, string original, string replacement, string firstSeenIn)
        {
            if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(original) || string.IsNullOrEmpty(replacement)) return;
            string src = string.IsNullOrEmpty(firstSeenIn) ? "(correlation file)" : firstSeenIn;
            if (original.Length > 1 && original[0] == '\'' && (original[1] == '=' || original[1] == '+' || original[1] == '@' || original[1] == '-')) original = original.Substring(1);
            dirty = true;
            switch (type.Trim())
            {
                case "Hostname": hosts.Put(original, original, replacement, src); weakHosts.Remove(original); break;
                case "HostLabel":
                    if (hosts.Find(original) == null) { hosts.Put(original, original, replacement, src); weakHosts[original] = true; }
                    break;
                case "DomainLabel": domains.Put(original, original, replacement, src); strongDomains[original] = true; break;
                case "DomainWord":
                case "DomainPart": domains.Put(original, original, replacement, src); break;
                case "NamePart": nameParts.Put(original, original, replacement, src); break;
                case "PII": pii.Put(original, original, replacement, src); break;
                case "ForestOid": forestOids.Put(original, original, replacement, src); break;
                case "User": users.Put(original, original, replacement, src); break;
                case "Person":
                    {
                        MapEntry e = persons.Put(original, original, replacement, src);
                        AddPersonAliases(original, e);
                        break;
                    }
                case "Organization": orgs.Put(original, original, replacement, src); break;
                case "OrgUnit": ous.Put(original, original, replacement, src); break;
                case "Location": locations.Put(original, original, replacement, src); break;
                case "Custom": custom.Put(original, original, replacement, src); break;
                case "Secret": secrets.Put(original, original, replacement, src); break;
                case "Guid": guids.Put(original, original, replacement, src); break;
                case "CloudAccount": accounts.Put(original, original, replacement, src); break;
                case "IPv4": ipv4.Put(CanonicalIPv4(original) ?? original, original, replacement, src); break;
                case "IPv4Subnet":
                    {
                        string key = SubnetKeyFromDisplay(original);
                        if (key != null) subnets.Put(key, original, replacement, src);
                        break;
                    }
                case "IPv6":
                    {
                        IPAddress a;
                        if (IPAddress.TryParse(original, out a)) ipv6.Put(Canonical6(a), original, replacement, src);
                        break;
                    }
                case "IPv6Prefix":
                    {
                        string key = V6PrefixKeyFromDisplay(original);
                        if (key != null) v6prefixes.Put(key, original, replacement, src);
                        break;
                    }
                case "MAC":
                    {
                        string hex = MacHex(original);
                        if (hex != null) macs.Put(hex, DisplayMac(hex), replacement, src);
                        break;
                    }
                case "SID":
                    {
                        Match m = SidRx.Match(original);
                        if (m.Success) { sids.Put(SidKey(m), original, replacement, src); break; }
                        m = AadSidRx.Match(original);
                        if (m.Success) sids.Put(AadSidKey(m), original, replacement, src);
                        break;
                    }
                case "FQDN":
                case "DomainName":
                    {
                        DottedObs o = AddDottedObs(original, type == "FQDN" ? HintHost : HintDomain, src);
                        if (o != null) o.Loaded = true;
                        if (o != null && o.Entry == null)
                        {
                            o.Entry = new MapEntry();
                            o.Entry.Type = type; o.Entry.Original = original; o.Entry.Replacement = replacement; o.Entry.FirstSeenIn = src;
                        }
                        break;
                    }
                case "Email":
                    {
                        int at = original.IndexOf('@');
                        if (at > 0) AddEmailObs(original, original.Substring(0, at), original.Substring(at + 1), src);
                        break;
                    }
            }
        }

        /// <summary>A new engine with the same options, ignore lists and exclusions but no mappings (used by the audit).</summary>
        public ScrubEngine CloneConfiguration()
        {
            ScrubEngine c = new ScrubEngine();
            c.ScrubIPv4 = ScrubIPv4; c.ScrubIPv6 = ScrubIPv6; c.ScrubMac = ScrubMac; c.ScrubHostnames = ScrubHostnames;
            c.ScrubDomains = ScrubDomains; c.ScrubUsers = ScrubUsers; c.ScrubEmails = ScrubEmails; c.ScrubSids = ScrubSids;
            c.ScrubPersons = ScrubPersons; c.ScrubSecrets = ScrubSecrets; c.ScrubOrgUnits = ScrubOrgUnits; c.ScrubCloudIds = ScrubCloudIds;
            c.ScrubAllGuids = ScrubAllGuids; c.KeepMacVendor = KeepMacVendor; c.MinBareLength = MinBareLength;
            c.LearnNamingPatterns = false;
            c.ParseFixedWidthTables = false;
            c.tlds.Clear(); CopySet(tlds, c.tlds);
            c.ignoreNames.Clear(); CopySet(ignoreNames, c.ignoreNames);
            c.commonWords.Clear(); CopySet(commonWords, c.commonWords);
            c.excludeValues.Clear(); CopySet(excludeValues, c.excludeValues);
            c.excludeDomains.Clear(); c.excludeDomains.AddRange(excludeDomains);
            return c;
        }

        private static void CopySet(Dictionary<string, bool> from, Dictionary<string, bool> to)
        {
            foreach (string k in from.Keys) to[k] = true;
        }

        // =========================================================================================
        // File handling
        // =========================================================================================

        public static TextFileInfo Inspect(string path)
        {
            byte[] buf = new byte[65536];
            int read = 0;
            bool gz = false;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                byte[] magic = new byte[2];
                int m = fs.Read(magic, 0, 2);
                gz = m == 2 && magic[0] == 0x1F && magic[1] == 0x8B;
                fs.Position = 0;
                Stream s = gz ? (Stream)new GZipStream(fs, CompressionMode.Decompress) : fs;
                try
                {
                    int n;
                    while (read < buf.Length && (n = s.Read(buf, read, buf.Length - read)) > 0) read += n;
                }
                catch (InvalidDataException)
                {
                    TextFileInfo bad = new TextFileInfo();
                    bad.IsBinary = true; bad.EncodingName = "corrupt gzip";
                    return bad;
                }
            }
            TextFileInfo info = DetectEncoding(buf, read);
            info.IsGzip = gz;
            if (gz) info.EncodingName = "gzip/" + info.EncodingName;
            return info;
        }

        private static TextFileInfo DetectEncoding(byte[] buf, int read)
        {
            TextFileInfo info = new TextFileInfo();
            if (read >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
            {
                info.EncodingName = "UTF-8 (BOM)";
                info.ReadEncoding = new UTF8Encoding(true, true);
                info.WriteEncoding = new UTF8Encoding(true);
                info.CanFallBack = true;
                return info;
            }
            if (read >= 4 && buf[0] == 0xFF && buf[1] == 0xFE && buf[2] == 0 && buf[3] == 0)
            {
                info.EncodingName = "UTF-32 LE";
                info.ReadEncoding = info.WriteEncoding = new UTF32Encoding(false, true);
                return info;
            }
            if (read >= 2 && buf[0] == 0xFF && buf[1] == 0xFE)
            {
                info.EncodingName = "UTF-16 LE";
                info.ReadEncoding = info.WriteEncoding = new UnicodeEncoding(false, true);
                return info;
            }
            if (read >= 2 && buf[0] == 0xFE && buf[1] == 0xFF)
            {
                info.EncodingName = "UTF-16 BE";
                info.ReadEncoding = info.WriteEncoding = new UnicodeEncoding(true, true);
                return info;
            }

            int zeroOdd = 0, zeroEven = 0, control = 0;
            for (int i = 0; i < read; i++)
            {
                byte b = buf[i];
                if (b == 0) { if ((i & 1) == 1) zeroOdd++; else zeroEven++; }
                else if (b < 0x09 || (b > 0x0D && b < 0x20 && b != 0x1B)) control++;
            }
            if (zeroOdd + zeroEven > 0)
            {
                int half = read / 2;
                if (half > 0 && zeroOdd > half / 3 && zeroEven <= half / 50)
                {
                    info.EncodingName = "UTF-16 LE (no BOM)";
                    info.ReadEncoding = info.WriteEncoding = new UnicodeEncoding(false, false);
                    return info;
                }
                if (half > 0 && zeroEven > half / 3 && zeroOdd <= half / 50)
                {
                    info.EncodingName = "UTF-16 BE (no BOM)";
                    info.ReadEncoding = info.WriteEncoding = new UnicodeEncoding(true, false);
                    return info;
                }
                info.IsBinary = true;
                info.EncodingName = "binary";
                return info;
            }
            if (read > 0 && control > read / 20)
            {
                info.IsBinary = true;
                info.EncodingName = "binary";
                return info;
            }

            info.EncodingName = "UTF-8";
            info.ReadEncoding = new UTF8Encoding(false, true);
            info.WriteEncoding = new UTF8Encoding(false);
            info.CanFallBack = true;
            return info;
        }

        private static void FallBackToLatin1(TextFileInfo info)
        {
            // Latin-1 maps every byte to one char and back, so non-UTF-8 (ANSI) files round-trip byte for byte.
            Encoding latin1 = Encoding.GetEncoding(28591);
            info.ReadEncoding = latin1;
            info.WriteEncoding = latin1;
            info.CanFallBack = false;
            info.EncodingName = (info.IsGzip ? "gzip/" : "") + "ANSI/Latin-1 (not valid UTF-8)";
        }

        private static Stream OpenRead(string path, TextFileInfo info)
        {
            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            if (info.IsGzip) return new GZipStream(fs, CompressionMode.Decompress);
            return fs;
        }

        private static void ReadBlocks(string path, TextFileInfo info, Action<string> onBlock)
        {
            const int MaxPending = 8 * 1024 * 1024;
            using (Stream st = OpenRead(path, info))
            using (StreamReader sr = new StreamReader(st, info.ReadEncoding, false, 1 << 16))
            {
                char[] buf = new char[1 << 20];
                StringBuilder pending = new StringBuilder();
                int n;
                while ((n = sr.Read(buf, 0, buf.Length)) > 0)
                {
                    int lastNl = -1;
                    for (int k = n - 1; k >= 0; k--) { if (buf[k] == '\n') { lastNl = k; break; } }
                    if (lastNl < 0)
                    {
                        pending.Append(buf, 0, n);
                        if (pending.Length > MaxPending)
                        {
                            // very long line: cut at the last whitespace / separator so a value is not split
                            string p = pending.ToString();
                            int cut = -1;
                            for (int k = p.Length - 1; k > p.Length - 65536 && k > 0; k--)
                            {
                                char c = p[k];
                                if (c == ' ' || c == '\t' || c == ',' || c == ';' || c == '}' || c == '>') { cut = k + 1; break; }
                            }
                            if (cut < 0) cut = p.Length;
                            onBlock(p.Substring(0, cut));
                            pending.Length = 0;
                            pending.Append(p, cut, p.Length - cut);
                        }
                        continue;
                    }
                    pending.Append(buf, 0, lastNl + 1);
                    onBlock(pending.ToString());
                    pending.Length = 0;
                    pending.Append(buf, lastNl + 1, n - lastNl - 1);
                }
                if (pending.Length > 0) onBlock(pending.ToString());
            }
        }

        /// <summary>Pass 1 for one file.</summary>
        public void ScanFile(string path, TextFileInfo info, string sourceLabel)
        {
            string src = sourceLabel ?? Path.GetFileName(path);
            try
            {
                ColumnState cs = new ColumnState();
                ReadBlocks(path, info, delegate(string b) { ScanBlock(b, src, cs); });
            }
            catch (DecoderFallbackException)
            {
                if (!info.CanFallBack) throw;
                FallBackToLatin1(info);
                ColumnState cs = new ColumnState();
                ReadBlocks(path, info, delegate(string b) { ScanBlock(b, src, cs); });
            }
        }

        /// <summary>Pass 2 for one file.</summary>
        public ScrubFileResult ScrubFile(string inPath, string outPath, TextFileInfo info)
        {
            string dir = Path.GetDirectoryName(outPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            ScrubFileResult r = new ScrubFileResult();
            using (FileStream fs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.Read))
            using (Stream st = info.IsGzip ? (Stream)new GZipStream(fs, CompressionMode.Compress) : fs)
            using (StreamWriter sw = new StreamWriter(st, info.WriteEncoding, 1 << 16))
            {
                ReadBlocks(inPath, info, delegate(string b)
                {
                    string o = ScrubText(b);
                    r.LinesIn += CountLines(b);
                    r.LinesOut += CountLines(o);
                    sw.Write(o);
                });
            }
            return r;
        }

        private static long CountLines(string s)
        {
            long n = 0;
            for (int i = 0; i < s.Length; i++) if (s[i] == '\n') n++;
            return n;
        }

        // =========================================================================================
        // Pass 1 - discovery
        // =========================================================================================

        private sealed class Job
        {
            public Regex Rx;
            public Action<Match> Act;
        }

        /// <summary>Detectors queued by the current ScanCore call; matched in parallel, handled sequentially in order.</summary>
        private List<Job> queued;

        private void Each(Regex rx, string text, Action<Match> act)
        {
            Job j = new Job();
            j.Rx = rx;
            j.Act = act;
            queued.Add(j);
        }

        private List<Match> Collect(Regex rx, string text)
        {
            List<Match> found = new List<Match>();
            try
            {
                for (Match m = rx.Match(text); m.Success; m = m.NextMatch()) found.Add(m);
            }
            catch (RegexMatchTimeoutException)
            {
                lock (Warnings)
                    if (Warnings.Count < 50) Warnings.Add("Detector timed out on a block (pattern starts: " + rx.ToString().Substring(0, Math.Min(40, rx.ToString().Length)) + ")");
            }
            return found;
        }

        private void ScanCore(string text, string source)
        {
            List<Job> saved = queued;
            List<Job> jobs = new List<Job>();
            queued = jobs;
            try { QueueDetectors(text, source); }
            finally { queued = saved; }

            // regex matching is read-only and runs on all cores; registration stays sequential so tokens are deterministic
            List<Match>[] found = new List<Match>[jobs.Count];
            if (UseParallel && text.Length >= 32768 && jobs.Count > 1)
                System.Threading.Tasks.Parallel.For(0, jobs.Count, delegate(int i) { found[i] = Collect(jobs[i].Rx, text); });
            else
                for (int i = 0; i < jobs.Count; i++) found[i] = Collect(jobs[i].Rx, text);
            for (int i = 0; i < jobs.Count; i++)
                foreach (Match m in found[i]) jobs[i].Act(m);
        }

        /// <summary>Pass 1 for a stand-alone piece of text (column headers must be inside the same text).</summary>
        public void ScanText(string text, string source)
        {
            ScanBlock(text, source, new ColumnState());
        }

        internal void ScanBlock(string text, string source, ColumnState columns)
        {
            if (string.IsNullOrEmpty(text)) return;
            dirty = true;
            if (columns != null) ScanColumns(text, columns, source);
            ScanCore(text, source);
            string v;
            if (text.IndexOf('%') >= 0 && (v = UrlDecode(text)) != null) ScanCore(v, source);
            if (text.IndexOf('\\') >= 0 && (v = JsonUnescapeLines(text)) != null) ScanCore(v, source);
            if ((v = UnwrapFormatList(text)) != null) ScanCore(v, source);
        }

        private static bool Has(string text, string needle)
        {
            return text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Context detectors match the key word anywhere; this checks what is attached in front of it:
        /// nothing ("Computer:"), an allowed prefix ("TargetUserName", "src_host", "Caller Computer Name") or, when
        /// allowed is null, anything at all.
        /// </summary>
        private static bool KeyPrefixOk(string text, int k, Dictionary<string, bool> allowed)
        {
            if (allowed == null || k == 0) return true;
            char p = text[k - 1];
            if (IsAlnum(p))
            {
                int s = k;
                while (s > 0 && IsAlnum(text[s - 1])) s--;
                return allowed.ContainsKey(text.Substring(s, k - s));
            }
            return true; // "src_host", "Caller Computer Name", "kiosk host=" - only glued prefixes are checked
        }

        /// <summary>Whole key (identifier) that ends where the matched key word ends, e.g. "PublicKeyToken".</summary>
        private static string FullKey(string text, Group key)
        {
            int s = key.Index;
            while (s > 0 && (IsAlnum(text[s - 1]) || text[s - 1] == '_' || text[s - 1] == '-' || text[s - 1] == '.')) s--;
            return text.Substring(s, key.Index + key.Length - s);
        }

        /// <summary>True when DOMAIN\user is really part of a path such as "Microsoft SQL Server\Instance Names\SQL".</summary>
        private static bool InPathContext(string text, int index)
        {
            int i = index - 1, tokens = 0;
            while (i >= 0 && tokens < 3)
            {
                char c = text[i];
                if (c == '\n' || c == '\r' || c == '"' || c == '\'' || c == '=' || c == '(' || c == '>' || c == '|' || c == '\t' || c == ',') return false;
                if (c == '\\' || c == '/') return true;
                if (c == ' ') { tokens++; while (i > 0 && text[i - 1] == ' ') i--; }
                i--;
            }
            return false;
        }

        private void QueueDetectors(string text, string source)
        {
            string src = source;
            bool hasColonSlash = text.IndexOf("://", StringComparison.Ordinal) >= 0;
            bool hasBackslash = text.IndexOf('\\') >= 0;

            // ---------- secrets ----------
            if (ScrubSecrets)
            {
                if (text.IndexOf("-----BEGIN ", StringComparison.Ordinal) >= 0)
                    Each(PemRx, text, delegate(Match m) { RegisterSecret(m.Groups["body"].Value, src); });
                Each(SecretCtxRx, text, delegate(Match m)
                {
                    if (NonSecretKeyRx.IsMatch(FullKey(text, m.Groups["key"]))) return; // PublicKeyToken=..., token_type=Bearer
                    RegisterSecret(m.Groups["v"].Value, src);
                });
                if (Has(text, "-pass") || Has(text, "-pwd") || Has(text, "-secret") || Has(text, "-token") || Has(text, "-apikey") || Has(text, "-accesskey") || Has(text, "-authtoken") || Has(text, "-sastoken") || Has(text, "-clientsecret") || Has(text, "-secretkey"))
                    Each(CmdSecretRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (text.IndexOf("/p", StringComparison.OrdinalIgnoreCase) >= 0) Each(SlashSecretRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "SecureString")) Each(SecureStringRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "uthorization")) Each(AuthHeaderRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (text.IndexOf("Bearer", StringComparison.Ordinal) >= 0) Each(BearerRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "sig=")) Each(SasSigRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "secret") || Has(text, "community") || Has(text, "key") || Has(text, "password") || Has(text, "passwd") || Has(text, "psk"))
                    Each(CiscoSecretRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                Each(CiscoLineSecretRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "mysql") || Has(text, "mariadb")) Each(MysqlPassRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (hasColonSlash) Each(UrlCredRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); RegisterUserValue(SafeUnescape(m.Groups["u"].Value), src); });
                if (Has(text, "net use")) Each(NetUseRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); RegisterUserValue(m.Groups["u"].Value, src); });
                if (Has(text, "value=")) Each(XmlKvSecretRx, text, delegate(Match m) { if (XmlSecretKeyRx.IsMatch(m.Groups["k"].Value)) RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "cookie")) Each(CookieRx, text, delegate(Match m) { RegisterCookie(m.Groups["pairs"].Value, src); });
                if (text.IndexOf("eyJ", StringComparison.Ordinal) >= 0) Each(JwtRx, text, delegate(Match m) { RegisterSecret(m.Value, src); });
                Each(AwsKeyRx, text, delegate(Match m) { RegisterSecret(m.Value, src); });
                if (text.IndexOf("AAAA", StringComparison.Ordinal) >= 0)
                    Each(SshKeyRx, text, delegate(Match m)
                    {
                        RegisterSecret(m.Groups["key"].Value, src);
                        if (m.Groups["u"].Success) RegisterUser(m.Groups["u"].Value, src);
                        if (m.Groups["h"].Success) RegisterHostValue(m.Groups["h"].Value, src);
                    });
            }

            if (ScrubSecrets)
            {
                Each(CliPassRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (Has(text, "aws configure")) Each(AwsCliRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); });
                if (text.IndexOf('%') >= 0) Each(SmbPassRx, text, delegate(Match m) { RegisterSecret(m.Groups["v"].Value, src); RegisterUser(m.Groups["u"].Value, src); });
                if (text.IndexOf('-') >= 0) Each(BitLockerRx, text, delegate(Match m) { RegisterSecret(m.Value, src); });
            }
            // encoded content: base64 text blobs and auditd hex fields are decoded and scanned too
            Each(B64Rx, text, delegate(Match m) { string d = DecodeB64Text(m.Groups["v"].Value); if (d != null) ScanCore(d, src); });
            if (text.IndexOf('=') >= 0)
            {
                Each(HexFieldRx, text, delegate(Match m) { string d = DecodeHexText(m.Groups["v"].Value); if (d != null) ScanCore(d, src); });
                if (ScrubIPv4) Each(SockaddrRx, text, delegate(Match m) { RegisterIPv4(HexToIPv4(m.Groups["ip"].Value), src); });
            }

            // ---------- identifiers ----------
            if (ScrubSids && text.IndexOf("S-1-", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Each(SidRx, text, delegate(Match m) { RegisterSidKey(SidKey(m), "S-1-5-21-" + SidKey(m), false, src); });
                Each(AadSidRx, text, delegate(Match m) { RegisterSidKey(AadSidKey(m), "S-1-12-1-" + AadSidKey(m).Substring(4), true, src); });
            }

            if (ScrubCloudIds)
            {
                Each(GuidCtxRx, text, delegate(Match m)
                {
                    Group k = m.Groups["key"];
                    string full = FullKey(text, k).ToLowerInvariant();
                    if ((k.Length <= 3 && full.Length > k.Length) || NonIdentityGuidKeyRx.IsMatch(full)) return; // eventID, correlationId ...
                    RegisterGuid(m.Groups["v"].Value, src);
                });
                if (Has(text, "/subscriptions/") || Has(text, "/tenants/") || Has(text, "managementGroups/"))
                    Each(GuidPathRx, text, delegate(Match m) { RegisterGuid(m.Groups["v"].Value, src); });
                if (Has(text, "arn:") || Has(text, "ccount"))
                    Each(AwsAcctRx, text, delegate(Match m) { if (!IsExcludedValue(m.Groups["v"].Value)) accounts.GetOrAdd(m.Groups["v"].Value, m.Groups["v"].Value, src); });
                if (Has(text, "arn:"))
                {
                    Each(ArnUserRx, text, delegate(Match m) { RegisterUserValue(m.Groups["v"].Value, src); });
                    Each(ArnBucketRx, text, delegate(Match m) { RegisterCustom(m.Groups["v"].Value, src); });
                }
                if (Has(text, "/resourceGroups/"))
                    Each(AzureResRx, text, delegate(Match m)
                    {
                        RegisterCustom(m.Groups["rg"].Value, src);
                        RegisterAzureResource(m.Groups["k"], m.Groups["v"], src);
                        RegisterAzureResource(m.Groups["k2"], m.Groups["v2"], src);
                    });
                Each(AzureRgCtxRx, text, delegate(Match m) { RegisterCustom(m.Groups["v"].Value, src); });
                Each(IdCtxRx, text, delegate(Match m)
                {
                    string v = m.Groups["v"].Value;
                    if (!HasDigit(v) && v.Length < 6) return;
                    if (m.Groups["key"].Value.StartsWith("employee", StringComparison.OrdinalIgnoreCase) || m.Groups["key"].Value.StartsWith("badge", StringComparison.OrdinalIgnoreCase)) RegisterPii(v, src);
                    else RegisterCustom(v, src);
                });
                Each(AwsResIdRx, text, delegate(Match m) { RegisterCustom(m.Value, src); });
                Each(FlowLogRx, text, delegate(Match m) { if (!IsExcludedValue(m.Groups["acct"].Value)) accounts.GetOrAdd(m.Groups["acct"].Value, m.Groups["acct"].Value, src); });
                if (text.IndexOf("00", StringComparison.Ordinal) >= 0) Each(OktaIdRx, text, delegate(Match m) { RegisterCustom(m.Value, src); });
                Each(PanSerialRx, text, delegate(Match m) { RegisterCustom(m.Groups["v"].Value, src); });
                Each(CircuitRx, text, delegate(Match m) { RegisterCustom(m.Groups["v"].Value, src); });
                if (Has(text, "site")) Each(SccmSiteRx, text, delegate(Match m) { RegisterCustom(m.Groups["v"].Value, src); });
                if (text.IndexOf("311.21.8.", StringComparison.Ordinal) >= 0)
                    Each(ForestOidRx, text, delegate(Match m) { forestOids.GetOrAdd(m.Groups["v"].Value, m.Groups["v"].Value, src); });
            }
            if (ScrubAllGuids) Each(AnyGuidRx, text, delegate(Match m) { RegisterGuid(m.Groups["v"].Value, src); });

            if (ScrubEmails && text.IndexOf('@') >= 0)
                Each(EmailRx, text, delegate(Match m) { AddEmailObs(m.Value, m.Groups["local"].Value, m.Groups["domain"].Value, src); });

            // ---------- MAC ----------
            if (ScrubMac)
            {
                Each(MacRx, text, delegate(Match m)
                {
                    string raw = m.Groups["mac"].Value;
                    if (raw.IndexOf('.') >= 0 && !HasHexLetter(raw))
                    {
                        // 0050.5612.3456 is a MAC, 2019.1201.0001 is a version / date
                        if (raw.StartsWith("19", StringComparison.Ordinal) || raw.StartsWith("20", StringComparison.Ordinal)) return;
                        if (InVersionContext(text, m.Index)) return;
                    }
                    RegisterMac(raw, src);
                });
                Each(MacCtxRx, text, delegate(Match m) { RegisterMac(m.Groups["mac"].Value, src); });
                Each(MacSpaceRx, text, delegate(Match m)
                {
                    // only when the line talks about adapters / interfaces / MACs, to avoid random hex dumps
                    int ls = text.LastIndexOf('\n', m.Index) + 1;
                    int le = text.IndexOf('\n', m.Index); if (le < 0) le = text.Length;
                    string line = text.Substring(ls, le - ls);
                    if (Has(line, "adapter") || Has(line, "ethernet") || Has(line, "mac") || Has(line, "interface") || Has(line, "nic") || Has(line, "....") || Has(line, "physical"))
                        RegisterMac(m.Groups["mac"].Value, src);
                });
                if (text.IndexOf("00-0", StringComparison.Ordinal) >= 0) Each(DuidRx, text, delegate(Match m) { RegisterMac(m.Groups["mac"].Value, src); });
                if (Has(text, "cli ") || Has(text, "Calling-Station")) Each(RadiusCliRx, text, delegate(Match m) { RegisterMac(m.Groups["mac"].Value, src); });
                if (Has(text, "ll header") || Has(text, "MAC="))
                    Each(LinkHeaderRx, text, delegate(Match m) { RegisterMac(m.Groups["a"].Value, src); RegisterMac(m.Groups["b"].Value, src); });
            }

            // ---------- IP ----------
            if (ScrubIPv6 && text.IndexOf(':') >= 0) Each(IPv6Rx, text, delegate(Match m) { RegisterIPv6(m.Groups["v"].Value, src); });

            if (ScrubIPv4)
            {
                Each(IPv4Rx, text, delegate(Match m)
                {
                    if (InVersionContext(text, m.Index)) return;
                    if (m.Index > 1 && text[m.Index - 1] == '/' && char.IsLetter(text[m.Index - 2]) && m.Value.EndsWith(".0.0", StringComparison.Ordinal)) return; // Chrome/131.0.0.0
                    int end = m.Index + m.Length;
                    if (end + 8 <= text.Length && string.Compare(text, end, ".in-addr", 0, 8, StringComparison.OrdinalIgnoreCase) == 0) return;
                    RegisterIPv4(m.Value, src);
                });
                if (Has(text, "in-addr"))
                    Each(InAddrRx, text, delegate(Match m) { RegisterReverse(m.Groups["o"].Value, src); });
            }

            if ((ScrubHostnames || ScrubDomains || ScrubIPv4) && text.IndexOf("(0)", StringComparison.Ordinal) >= 0)
                Each(DnsWireRx, text, delegate(Match m)
                {
                    string name = DecodeDnsWire(m.Value);
                    if (name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase)) RegisterReverse(name.Substring(0, name.Length - 12), src);
                    else AddDottedObs(name, HintAuto, src);
                });

            if (text.IndexOf('=') >= 0) Each(DnRx, text, delegate(Match m) { RegisterDn(m.Value, src); });
            if (text.IndexOf("::", StringComparison.Ordinal) >= 0) Each(LdifB64Rx, text, delegate(Match m) { ScanLdifValue(m.Groups["k"].Value, m.Groups["v"].Value, src); });

            // ---------- host names ----------
            if (ScrubHostnames)
            {
                Each(HostCtxRx, text, delegate(Match m)
                {
                    if (!KeyPrefixOk(text, m.Groups["key"].Index, HostPrefixes)) return;
                    Group g = m.Groups["v"];
                    int after = g.Index + g.Length;
                    if (after < text.Length && text[after] == '/')
                    {
                        // "k8s-node-03/10.1.2.3" is a host; "Microsoft-IIS/10.0" or "krbtgt/REALM" is not
                        if (!HasDigit(g.Value) || (after + 1 < text.Length && char.IsLetter(text[after + 1]))) return;
                    }
                    if (after < text.Length && text[after] == '\\' && !HasDigit(g.Value) && g.Value.IndexOf('-') < 0 && g.Value.IndexOf('.') < 0)
                    {
                        // "Server: NWTRADERS\jsmith" style is a domain\user, not a host (but Data Source=SQL\INSTANCE is a host)
                        string head = text.Substring(m.Index, Math.Min(12, g.Index - m.Index)).ToLowerInvariant();
                        if (!head.StartsWith("data", StringComparison.Ordinal) && head.IndexOf("sql", StringComparison.Ordinal) < 0) return;
                    }
                    RegisterHostValue(g.Value, src);
                });
                if (text.IndexOf("DC:", StringComparison.Ordinal) >= 0) Each(NltestDcRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (hasBackslash) Each(UncRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                Each(SyslogRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (Has(text, "name") || Has(text, "host")) Each(CiscoHostnameRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (text.IndexOf('#') >= 0 || text.IndexOf('>') >= 0) Each(CiscoPromptRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (Has(text, "server")) Each(CiscoServerRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (text.IndexOf('$') >= 0)
                    Each(ComputerAcctRx, text, delegate(Match m)
                    {
                        string v = m.Groups["v"].Value;
                        if (v.Equals("ADMIN", StringComparison.OrdinalIgnoreCase) || v.Equals("IPC", StringComparison.OrdinalIgnoreCase) || v.Equals("PRINT", StringComparison.OrdinalIgnoreCase)) return;
                        RegisterHost(v, src);
                    });
                Each(HostIpRx, text, delegate(Match m)
                {
                    string v = TrimDots(m.Groups["v"].Value);
                    if (LooksLikeMachineName(v) || v.IndexOf('.') >= 0) RegisterHostValue(v, src);
                });
                Each(ResolveRx, text, delegate(Match m)
                {
                    string v = TrimDots(m.Groups["v"].Value);
                    if (LooksLikeIPv4(v)) return;
                    if (v.IndexOf('.') >= 0) { if (LooksLikeFqdn(v)) AddDottedObs(v, HintHost, src); }
                    else if (LooksLikeMachineName(v)) RegisterHost(v, src);
                });
                if (text.IndexOf('[') >= 0) Each(PostfixHostRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (text.IndexOf("] ", StringComparison.Ordinal) >= 0) Each(HaproxyRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (text.IndexOf('@') >= 0)
                    Each(ShellPromptRx, text, delegate(Match m) { RegisterUser(m.Groups["u"].Value, src); RegisterHostValue(m.Groups["h"].Value, src); });
                if (text.IndexOf('{') >= 0) Each(NestedHostRx, text, delegate(Match m) { RegisterHostValue(m.Groups["v"].Value, src); });
                if (hasColonSlash)
                    Each(UrlRx, text, delegate(Match m)
                    {
                        string scheme = m.Value.Substring(0, m.Value.IndexOf(':')).ToLowerInvariant();
                        if (!NetworkSchemes.ContainsKey(scheme)) return; // api://my-app, urn:..., app-specific URIs
                        string v = TrimDots(m.Groups["v"].Value);
                        if (v.IndexOf('.') < 0) RegisterHost(v, src); // dotted ones are handled by the FQDN detector
                    });
                if (text.IndexOf('/') >= 0)
                    Each(SpnRx, text, delegate(Match m)
                    {
                        if (m.Index > 0 && (IsAlnum(text[m.Index - 1]) || text[m.Index - 1] == '/')) return;
                        string svc = m.Groups["svc"].Value;
                        string v = TrimDots(m.Groups["v"].Value);
                        if (svc.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) || svc.Equals("kadmin", StringComparison.OrdinalIgnoreCase)) RegisterDomainValue(v, src);
                        else if (!LooksLikeIPv4(v)) RegisterHostValue(v, src);
                    });
                foreach (Regex rx in hostPatterns)
                    Each(rx, text, delegate(Match m)
                    {
                        Group g = m.Groups["host"];
                        string v = (g != null && g.Success) ? g.Value : m.Value;
                        v = TrimDots(v);
                        if (v.IndexOf('.') >= 0) AddDottedObs(v, HintHost, src);
                        else if (v.Length > 0 && !IsExcludedValue(v)) { weakHosts.Remove(v); hosts.GetOrAdd(v, v, src); }
                    });
            }

            if (text.IndexOf('@') >= 0)
                Each(KlistRx, text, delegate(Match m)
                {
                    string v = m.Groups["v"].Value;
                    int slash = v.IndexOf('/');
                    if (slash > 0)
                    {
                        string svc = v.Substring(0, slash), h = v.Substring(slash + 1);
                        if (svc.Equals("krbtgt", StringComparison.OrdinalIgnoreCase)) RegisterDomainValue(h, src);
                        else RegisterHostValue(h, src);
                    }
                    else RegisterUserValue(v, src);
                    RegisterDomainValue(m.Groups["r"].Value, src);
                });

            // ---------- users ----------
            if (ScrubUsers || ScrubDomains || ScrubHostnames)
            {
                Each(UserCtxRx, text, delegate(Match m)
                {
                    if (!KeyPrefixOk(text, m.Groups["key"].Index, UserPrefixes)) return;
                    int after = m.Groups["v"].Index + m.Groups["v"].Length;
                    if (after + 2 < text.Length && text[after] == '%' && IsHex(text[after + 1]) && IsHex(text[after + 2])) return; // NWTRADERS%5Cjsmith: the decoded variant handles it
                    RegisterUserMatch(m, src);
                });
                Each(ForUserRx, text, delegate(Match m) { RegisterUserMatch(m, src); });
                Each(SshUserRx, text, delegate(Match m) { RegisterUserMatch(m, src); });
                if (text.IndexOf('<') >= 0) Each(AngleUserRx, text, delegate(Match m) { RegisterUserValue(m.Groups["v"].Value, src); });
                if (hasBackslash)
                {
                    Each(DomainUserRx, text, delegate(Match m)
                    {
                        string d = m.Groups["d"].Value;
                        string v = m.Groups["v"].Value;
                        if (d.Equals("AzureAD", StringComparison.OrdinalIgnoreCase) || d.Equals("MicrosoftAccount", StringComparison.OrdinalIgnoreCase)) { RegisterUserValue(v, src); return; }
                        if (ignoreDomainPrefixes.ContainsKey(d) || FileExtRx.IsMatch(v)) return;
                        if (TrimDots(v).TrimEnd('$').Length < 2) return;
                        if (InPathContext(text, m.Index)) return; // ...\Microsoft SQL Server\Instance Names\SQL
                        RegisterUserMatch(m, src);
                    });
                    Each(LocalAcctRx, text, delegate(Match m) { RegisterUserValue(m.Groups["v"].Value, src); });
                    Each(UserPathRx, text, delegate(Match m) { RegisterProfileFolder(m.Groups["v"].Value, src); });
                }
                if (text.IndexOf("/home/", StringComparison.Ordinal) >= 0 || text.IndexOf("/Users/", StringComparison.Ordinal) >= 0)
                    Each(HomePathRx, text, delegate(Match m) { RegisterProfileFolder(m.Groups["v"].Value, src); });
                if (text.IndexOf('[') >= 0)
                    Each(ApacheRx, text, delegate(Match m)
                    {
                        string v = m.Groups["v"].Value;
                        if (v != "-") RegisterUserValue(SafeUnescape(v), src);
                        string h = m.Groups["h"].Value;
                        if (HasLetter(h) && h.IndexOf(':') < 0) RegisterHostValue(h, src);
                    });
                if (Has(text, "username")) Each(CiscoUserRx, text, delegate(Match m) { RegisterUser(m.Groups["v"].Value, src); });
                if (Has(text, "\"user\""))
                    Each(NestedUserRx, text, delegate(Match m)
                    {
                        string k = m.Groups["k"].Value.ToLowerInvariant();
                        string v = m.Groups["v"].Value;
                        if (k == "name") RegisterUserValue(v, src);
                        else if (k == "domain") RegisterDomainValue(v, src);
                        else if (k == "full_name") RegisterPersonCandidate(v, src);
                    });
            }

            // ---------- people / PII / organisation ----------
            if (ScrubPersons)
            {
                Each(OwnerUserRx, text, delegate(Match m) { RegisterUser(m.Groups["v"].Value, src); if (m.Groups["v2"].Success) RegisterUser(m.Groups["v2"].Value, src); });
                Each(PersonCtxRx, text, delegate(Match m) { if (KeyPrefixOk(text, m.Groups["key"].Index, PersonPrefixes)) RegisterPersonCandidate(m.Groups["v"].Value, src); });
                if (text.IndexOf('<') >= 0 && text.IndexOf('@') >= 0) Each(EmailNameRx, text, delegate(Match m) { RegisterPersonCandidate(m.Groups["v"].Value, src); });
                Each(NamePartCtxRx, text, delegate(Match m) { if (KeyPrefixOk(text, m.Groups["key"].Index, EmptyPrefixes)) RegisterNamePart(m.Groups["v"].Value, src); });
                Each(PiiCtxRx, text, delegate(Match m) { if (KeyPrefixOk(text, m.Groups["key"].Index, EmptyPrefixes)) RegisterPii(m.Groups["v"].Value, src); });
                if (text.IndexOf('(') >= 0 || text.IndexOf('+') >= 0) Each(PhoneRx, text, delegate(Match m) { RegisterPii(m.Value, src); });
                Each(PostalLineRx, text, delegate(Match m)
                {
                    int a = m.Index;
                    while (a > 0 && m.Index - a < 80 && "\r\n>\"|;\t".IndexOf(text[a - 1]) < 0) a--;
                    RegisterPii(text.Substring(a, m.Index + m.Length - a).Trim().TrimStart('>', ' ', '\t'), src);
                });
            }
            if (ScrubOrgUnits)
            {
                Each(OrgCtxRx, text, delegate(Match m) { if (KeyPrefixOk(text, m.Groups["key"].Index, OrgPrefixes)) RegisterOrg(m.Groups["v"].Value, src); });
                Each(CompanyAnyRx, text, delegate(Match m) { RegisterOrg(m.Groups["v"].Value, src); });
                Each(SiteCtxRx, text, delegate(Match m)
                {
                    Group k = m.Groups["key"];
                    if (!KeyPrefixOk(text, k.Index, k.Length == 1 ? EmptyPrefixes : SitePrefixes)) return;
                    if (k.Length == 1 && k.Index > 0 && text[k.Index - 1] != '\n' && text[k.Index - 1] != ' ' && text[k.Index - 1] != '\t' && text[k.Index - 1] != ',') return;
                    RegisterLocation(m.Groups["v"].Value, src);
                });
            }

            // ---------- domains ----------
            if (ScrubDomains || ScrubHostnames)
            {
                Each(DomainCtxRx, text, delegate(Match m) { if (KeyPrefixOk(text, m.Groups["key"].Index, DomainPrefixes)) RegisterDomainValue(m.Groups["v"].Value, src, true); });
                Each(FqdnRx, text, delegate(Match m)
                {
                    string v = m.Groups["v"].Value;
                    string[] labels = v.Split('.');
                    int tldIdx = labels.Length - 1;
                    if (!IsAutoTld(labels[tldIdx]))
                    {
                        // "web01.contoso.com.bak" -> "web01.contoso.com", but not "java.net.SocketException"
                        bool found = false;
                        int k = tldIdx;
                        while (k > 1 && IsExtLike(labels[k]))
                        {
                            k--;
                            if (IsAutoTld(labels[k])) { found = true; break; }
                        }
                        if (!found) return;
                        tldIdx = k;
                        v = string.Join(".", labels, 0, k + 1);
                    }
                    if (!CaseConsistent(labels, tldIdx)) return; // System.IO, System.Net ...
                    AddDottedObs(v, HintAuto, src);
                });
            }

            if (LearnNamingPatterns && ScrubHostnames && siblingCandidates.Count < MaxSiblingCandidates)
                Each(SiblingCandRx, text, delegate(Match m)
                {
                    string v = m.Value;
                    if (v.Length < 3 || v.Length > 48 || (!HasDigit(v) && v.IndexOf('-') < 0) || siblingCandidates.ContainsKey(v)) return;
                    if (siblingCandidates.Count < MaxSiblingCandidates) siblingCandidates[v] = src;
                });
        }

        private static string SafeUnescape(string s)
        {
            try { return Uri.UnescapeDataString(s); } catch (Exception) { return s; }
        }

        // ----- decoded variants -----

        private static bool IsHex(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
        }

        private static string UrlDecode(string s)
        {
            StringBuilder sb = null;
            int copied = 0;
            for (int i = 0; i + 2 < s.Length; i++)
            {
                if (s[i] != '%' || !IsHex(s[i + 1]) || !IsHex(s[i + 2])) continue;
                int v = Convert.ToInt32(s.Substring(i + 1, 2), 16);
                if (v < 0x20 || v > 0x7E) continue;
                if (sb == null) sb = new StringBuilder(s.Length);
                sb.Append(s, copied, i - copied);
                sb.Append((char)v);
                copied = i + 3;
                i += 2;
            }
            if (sb == null) return null;
            sb.Append(s, copied, s.Length - copied);
            return sb.ToString();
        }

        /// <summary>JSON-unescapes lines that look like JSON ({"key":...}) so "\njsmith" and "CORP\\jsmith" are seen correctly.</summary>
        private static string JsonUnescapeLines(string s)
        {
            if (s.IndexOf("\":", StringComparison.Ordinal) < 0 && s.IndexOf("\" :", StringComparison.Ordinal) < 0) return null;
            StringBuilder sb = new StringBuilder(s.Length);
            bool changed = false;
            int start = 0;
            while (start < s.Length)
            {
                int nl = s.IndexOf('\n', start);
                int end = nl < 0 ? s.Length : nl + 1;
                string line = s.Substring(start, end - start);
                string t = line.TrimStart();
                if ((t.StartsWith("{", StringComparison.Ordinal) || t.StartsWith("[", StringComparison.Ordinal) || t.StartsWith("\"", StringComparison.Ordinal)) && line.IndexOf('\\') >= 0)
                {
                    StringBuilder lb = new StringBuilder(line.Length);
                    for (int i = 0; i < line.Length; i++)
                    {
                        char c = line[i];
                        if (c == '\\' && i + 1 < line.Length)
                        {
                            char n = line[i + 1];
                            if (n == 'n' || n == 'r' || n == 't') { lb.Append(' '); i++; changed = true; continue; }
                            if (n == '\\' || n == '"' || n == '/') { lb.Append(n); i++; changed = true; continue; }
                            if (n == 'u' && i + 5 < line.Length && IsHex(line[i + 2]) && IsHex(line[i + 3]) && IsHex(line[i + 4]) && IsHex(line[i + 5]))
                            {
                                lb.Append((char)Convert.ToInt32(line.Substring(i + 2, 4), 16));
                                i += 5; changed = true; continue;
                            }
                        }
                        lb.Append(c);
                    }
                    sb.Append(lb.ToString());
                }
                else sb.Append(line);
                start = end;
            }
            return changed ? sb.ToString() : null;
        }

        /// <summary>Re-joins values that PowerShell Format-List wrapped onto indented continuation lines.</summary>
        private static string UnwrapFormatList(string s)
        {
            if (s.IndexOf(" : ", StringComparison.Ordinal) < 0) return null;
            string[] lines = s.Split('\n');
            StringBuilder sb = null;
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].TrimEnd('\r');
                Match m = FormatListLineRx.Match(line);
                if (!m.Success) continue;
                int col = m.Groups["v"].Index;
                if (col < 4) continue;
                StringBuilder joined = null;
                int j = i + 1;
                while (j < lines.Length)
                {
                    string nx = lines[j].TrimEnd('\r');
                    if (nx.Length <= col || !IsAllSpaces(nx, col) || nx[col] == ' ') break;
                    if (joined == null) joined = new StringBuilder(line);
                    joined.Append(nx.Substring(col));
                    j++;
                }
                if (joined != null)
                {
                    if (sb == null) sb = new StringBuilder();
                    sb.Append(joined.ToString()).Append('\n');
                    i = j - 1;
                }
            }
            return sb == null ? null : sb.ToString();
        }

        private static bool IsAllSpaces(string s, int count)
        {
            for (int i = 0; i < count; i++) if (s[i] != ' ') return false;
            return true;
        }

        // ----- column-aware discovery (CSV / TSV / W3C / Format-Table) -----

        private const int RoleNone = 0, RoleHost = 1, RoleUser = 2, RoleDomain = 3, RoleMac = 4, RolePerson = 5, RoleName = 6, RolePii = 7, RoleCustom = 8, RoleNamePart = 9, RoleLocation = 10;
        private static readonly Regex HostValueRx = new Regex(@"^\\{0,2}[A-Za-z0-9][A-Za-z0-9.-]{0,252}$", RegexOptions.CultureInvariant);
        private static readonly Dictionary<string, int> ColumnRoles = BuildColumnRoles();

        private static Dictionary<string, int> BuildColumnRoles()
        {
            Dictionary<string, int> d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (string s in ("computer computername machine machinename host hostname dnshostname server servername workstation workstationname "
                + "device devicename node nodename scomputername cshost srchost dsthost sourcehost sourcehostname destinationhost "
                + "destinationhostname clientname clienthostname serverhostname dvchost shost dhost fqdn netbiosname systemname sysname devname "
                + "srcname dstname endpoint endpointname asset assetname vmname vm guestname logonserver domaincontroller dc dcname "
                + "callingstationid calledstationid nasidentifier hostnames computers").Split(' ')) d[s] = RoleHost;
            foreach (string s in ("accountid owneraccount recipientaccountid").Split(' ')) d[s] = RoleCustom;
            foreach (string s in ("user username userid account accountname samaccountname upn userprincipalname csusername login loginname "
                + "logonname srcuser dstuser sourceuser destinationuser suser duser callerusername targetusername subjectusername "
                + "clientusername logonuser authuser remoteuser identity principal").Split(' ')) d[s] = RoleUser;
            foreach (string s in ("domain domainname accountdomain realm netbiosdomain dnsdomain targetdomainname subjectdomainname ntdomain "
                + "sntdom dntdom userdomain").Split(' ')) d[s] = RoleDomain;
            foreach (string s in ("mac macaddress physicaladdress hwaddr hwaddress clientmac smac dmac srcmac dstmac hardwareaddress macid "
                + "clientid").Split(' ')) d[s] = RoleMac;
            foreach (string s in ("displayname fullname manager owner ownername employeename contactname createdby modifiedby requestedby "
                + "assignedto").Split(' ')) d[s] = RolePerson;
            foreach (string s in ("office physicaldeliveryofficename officephone telephonenumber telephone phone phonenumber mobile mobilephone "
                + "homephone ipphone fax pager streetaddress street postalcode zip zipcode employeeid employeenumber badgeid homedirectory "
                + "profilepath scriptpath").Split(' ')) d[s] = RolePii;
            foreach (string s in ("serial serialnumber deviceserial assettag servicetag sitecode tenantname interfaceid vpcid subnetid instanceid").Split(' ')) d[s] = RoleCustom;
            foreach (string s in ("givenname firstname surname lastname sn middlename familyname").Split(' ')) d[s] = RoleNamePart;
            foreach (string s in ("city l site sitename location officelocation").Split(' ')) d[s] = RoleLocation;
            d["name"] = RoleName;
            d["cn"] = RoleName;
            return d;
        }

        private static int RoleOf(string header)
        {
            StringBuilder sb = new StringBuilder(header.Length);
            foreach (char c in header) if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
            int r;
            return ColumnRoles.TryGetValue(sb.ToString(), out r) ? r : RoleNone;
        }

        private void ScanColumns(string block, ColumnState st, string src)
        {
            int start = 0;
            while (start < block.Length)
            {
                int nl = block.IndexOf('\n', start);
                int end = nl < 0 ? block.Length : nl;
                string line = block.Substring(start, end - start).TrimEnd('\r');
                start = end + 1;
                ScanColumnLine(line, st, src);
            }
        }

        private void ScanColumnLine(string line, ColumnState st, string src)
        {
            string prev = st.PrevLine;
            st.PrevLine = line;
            if (line.StartsWith("#Fields:", StringComparison.Ordinal))
            {
                string[] f = line.Substring(8).Trim().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                st.Mode = 2; st.FieldCount = f.Length; st.Roles = new int[f.Length];
                for (int i = 0; i < f.Length; i++) st.Roles[i] = RoleOf(f[i]);
                return;
            }
            if (ParseFixedWidthTables && IsDashRule(line) && !string.IsNullOrEmpty(prev) && prev.Trim().Length > 0)
            {
                // PowerShell Format-Table: header line followed by "---- ----" rule
                List<int> starts = new List<int>();
                for (int i = 0; i < line.Length; i++) if (line[i] == '-' && (i == 0 || line[i - 1] == ' ')) starts.Add(i);
                st.Mode = 3; st.Starts = starts.ToArray(); st.Roles = new int[starts.Count];
                for (int i = 0; i < starts.Count; i++) st.Roles[i] = RoleOf(Field(prev, starts, i));
                return;
            }
            if (st.Mode == 3)
            {
                if (line.Trim().Length == 0) { st.Mode = 0; return; }
                bool aligned = true;
                foreach (int c in st.Starts) if (c > 0 && c < line.Length && line[c - 1] != ' ') { aligned = false; break; }
                if (!aligned) { st.Mode = 0; return; }
                List<int> starts = new List<int>(st.Starts);
                for (int i = 0; i < starts.Count; i++) if (st.Roles[i] != RoleNone) RegisterRole(st.Roles[i], Field(line, starts, i), src);
                return;
            }
            if (st.Mode == 2)
            {
                if (line.StartsWith("#", StringComparison.Ordinal)) return;
                string[] f = line.Split(' ');
                if (f.Length != st.FieldCount) return;
                for (int i = 0; i < f.Length; i++) if (st.Roles[i] != RoleNone) RegisterRole(st.Roles[i], SafeUnescape(f[i].Replace('+', ' ')), src);
                return;
            }
            if (line.Length == 0) return;

            // delimited text: try to recognise a header row
            char delim = PickDelimiter(line);
            if (delim != '\0')
            {
                List<string> f = SplitDelimited(line, delim);
                if (st.Mode == 1 && st.Delim == delim && f.Count > st.FieldCount && f.Count <= st.FieldCount + 4)
                {
                    for (int i = 0; i < st.FieldCount; i++)
                    {
                        int r = st.Roles[i];
                        if (r == RoleMac || r == RoleHost || r == RoleUser) RegisterRole(r, f[i], src);
                    }
                    return;
                }
                if (st.Mode == 1 && st.Delim == delim && f.Count == st.FieldCount)
                {
                    bool isHeaderAgain = true;
                    for (int i = 0; i < f.Count; i++) if (st.Roles[i] != RoleOf(f[i])) { isHeaderAgain = false; break; }
                    if (!isHeaderAgain)
                    {
                        for (int i = 0; i < f.Count; i++) if (st.Roles[i] != RoleNone) RegisterRole(st.Roles[i], f[i], src);
                        return;
                    }
                }
                // a header row: 3+ short, non-empty labels without ':' (so "\tAccount Name:\t\tjdoe" is not a header)
                int known = 0;
                bool plausible = f.Count >= 3;
                int[] roles = new int[f.Count];
                for (int i = 0; i < f.Count && plausible; i++)
                {
                    string h = f[i].Trim();
                    if (h.Length == 0 || h.Length > 48 || char.IsDigit(h[0]) || h.IndexOf(':') >= 0 || h.IndexOf('=') >= 0) { plausible = false; break; }
                    roles[i] = RoleOf(h);
                    if (roles[i] != RoleNone) known++;
                }
                if (plausible && known > 0)
                {
                    st.Mode = 1; st.Delim = delim; st.FieldCount = f.Count; st.Roles = roles;
                }
            }
        }

        private static bool IsDashRule(string line)
        {
            string t = line.Trim();
            if (t.Length < 3 || t[0] != '-') return false;
            foreach (char c in t) if (c != '-' && c != ' ') return false;
            return true;
        }

        private static string Field(string line, List<int> starts, int i)
        {
            int s = starts[i];
            if (s >= line.Length) return string.Empty;
            int e = i + 1 < starts.Count ? Math.Min(starts[i + 1], line.Length) : line.Length;
            return line.Substring(s, e - s).Trim();
        }

        private static char PickDelimiter(string line)
        {
            char best = '\0';
            int bestCount = 1;
            foreach (char d in new char[] { ',', '\t', ';', '|' })
            {
                int c = 0;
                foreach (char ch in line) if (ch == d) c++;
                if (c > bestCount) { best = d; bestCount = c; }
            }
            return best;
        }

        private static List<string> SplitDelimited(string line, char delim)
        {
            List<string> f = new List<string>();
            StringBuilder sb = new StringBuilder();
            bool q = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (q)
                {
                    if (c == '"') { if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } else q = false; }
                    else sb.Append(c);
                }
                else if (c == '"' && sb.ToString().Trim().Length == 0) { sb.Length = 0; q = true; }
                else if (c == delim) { f.Add(sb.ToString().Trim()); sb.Length = 0; }
                else sb.Append(c);
            }
            f.Add(sb.ToString().Trim());
            return f;
        }

        private void RegisterRole(int role, string value, string src)
        {
            string v = value.Trim().Trim('"', '\'');
            if (v.Length == 0 || v == "-" || v.EndsWith("...", StringComparison.Ordinal) || v.EndsWith("\u2026", StringComparison.Ordinal)) return;
            switch (role)
            {
                case RoleHost:
                    foreach (string part in v.Split(new char[] { ';', ' ', '|' }, StringSplitOptions.RemoveEmptyEntries))
                        if (ScrubHostnames && HasLetter(part) && !LooksLikeIPv4(part) && HostValueRx.IsMatch(part)) RegisterHostValue(part.TrimStart('\\'), src);
                    break;
                case RoleUser: RegisterUserValue(v, src); break;
                case RoleDomain: RegisterDomainValue(v, src); break;
                case RoleMac: if (ScrubMac) RegisterMac(v, src); break;
                case RolePii: RegisterPii(v, src); break;
                case RoleCustom: if (HasDigit(v) || v.Length >= 4) RegisterCustom(v, src); break;
                case RoleNamePart: RegisterNamePart(v, src); break;
                case RoleLocation: RegisterLocation(v, src); break;
                case RolePerson: RegisterPersonCandidate(v, src); break;
                case RoleName:
                    if (v.IndexOf(' ') >= 0 || v.IndexOf(',') >= 0) RegisterPersonCandidate(v, src);
                    else if (LooksLikeMachineName(v) && v.Length <= 63) RegisterHost(v, src);
                    break;
            }
        }

        // ----- registration helpers -----

        private void RegisterUserMatch(Match m, string source)
        {
            Group d = m.Groups["d"];
            if (d.Success && d.Value.Length > 0 && !ignoreDomainPrefixes.ContainsKey(d.Value)) RegisterDomainValue(d.Value, source, true);
            RegisterUserValue(m.Groups["v"].Value, source);
        }

        /// <summary>Accepts user, DOMAIN\user, user@domain, COMPUTER$.</summary>
        private void RegisterUserValue(string value, string source)
        {
            string v = TrimDots((value ?? string.Empty).Trim().Trim('"', '\'', '<', '>', '[', ']', '(', ')'));
            if (v.Length == 0) return;
            int bs = v.LastIndexOf('\\');
            if (bs > 0)
            {
                string d = v.Substring(0, bs).TrimEnd('\\');
                if (!ignoreDomainPrefixes.ContainsKey(d)) RegisterDomainValue(d, source, true);
                v = v.Substring(bs + 1);
            }
            int at = v.IndexOf('@');
            if (at > 0)
            {
                string dom = v.Substring(at + 1);
                v = v.Substring(0, at);
                if (dom.Length > 0 && HasLetter(dom)) RegisterDomainValue(dom, source);
            }
            if (v.EndsWith("$", StringComparison.Ordinal))
            {
                RegisterHost(v.TrimEnd('$'), source); // computer account, e.g. WEB01$
                return;
            }
            RegisterUser(v, source);
        }

        private void RegisterProfileFolder(string value, string source)
        {
            string v = value.Trim();
            if (v.Length == 0 || adBuiltins.ContainsKey(v)) return;
            string low = v.ToLowerInvariant();
            if (low == "public" || low == "default" || low == "all users" || low == "default user" || low.StartsWith("defaultuser", StringComparison.Ordinal)
                || low == "defaultapppool" || low.StartsWith(".net", StringComparison.Ordinal) || low.StartsWith("classic .net", StringComparison.Ordinal)
                || low.StartsWith("mssql", StringComparison.Ordinal) || low == "shared" || low == "guest") return;
            if (v.IndexOf(' ') >= 0) { RegisterPersonCandidate(v, source); return; }
            string[] parts = v.Split('.');
            RegisterUser(parts[0], source);
            for (int i = 1; i < parts.Length; i++)
                if (HasLetter(parts[i]) && !ignoreDomainPrefixes.ContainsKey(parts[i])) RegisterDomainValue(parts[i], source);
        }

        private bool IsCandidateName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 64) return false;
            if (!HasLetter(name) || name.IndexOf('@') >= 0) return false;
            if (ContainsToken(name) || GuidLike(name)) return false;
            if (ignoreNames.ContainsKey(name) || IsExcludedValue(name) || IsTokenValue(name)) return false;
            return true;
        }

        private void RegisterHost(string name, string source)
        {
            if (!ScrubHostnames) return;
            name = TrimDots(name);
            if (name.IndexOf('.') > 0) { if (LooksLikeFqdn(name)) AddDottedObs(name, HintHost, source); return; }
            if (hosts.Map.ContainsKey(name)) { weakHosts.Remove(name); return; }
            if (!IsCandidateName(name)) return;
            weakHosts.Remove(name);
            hosts.GetOrAdd(name, name, source);
        }

        private static string StripPortPath(string v)
        {
            int cut = v.IndexOfAny(new char[] { ':', '/', '\\', '[', '(', ' ' });
            return cut > 0 ? v.Substring(0, cut) : v;
        }

        private void RegisterHostValue(string v, string source)
        {
            v = TrimDots(StripPortPath(TrimDots(v ?? string.Empty).TrimStart('\\')));
            if (v.Length == 0 || LooksLikeIPv4(v)) return;
            if (v.IndexOf('.') >= 0) AddDottedObs(v, HintHost, source);
            else RegisterHost(v, source);
        }

        private void RegisterUser(string name, string source)
        {
            if (!ScrubUsers) return;
            name = TrimDots(name);
            if (users.Map.ContainsKey(name)) return;
            foreach (char c in name) if (char.IsWhiteSpace(c) || c == ':' || c == '/' || c == '"') return;
            if (!IsCandidateName(name) || IgnoredUserRx.IsMatch(name) || adBuiltins.ContainsKey(name)) return;
            users.GetOrAdd(name, name, source);
        }

        private void RegisterDomainValue(string v, string source)
        {
            v = TrimDots(StripPortPath(TrimDots(v ?? string.Empty)));
            if (v.Length == 0 || LooksLikeIPv4(v)) return;
            if (v.IndexOf('.') >= 0) AddDottedObs(v, HintDomain, source);
            else if (ScrubDomains && !IsKeepLabel(v) && HasLetter(v) && !IsTokenValue(v)) domains.GetOrAdd(v, v, source);
        }

        private void RegisterDomainValue(string v, string source, bool strong)
        {
            RegisterDomainValue(v, source);
            v = TrimDots(v);
            if (strong && v.Length > 0 && v.IndexOf('.') < 0 && domains.Map.ContainsKey(v)) strongDomains[v] = true;
        }

        private void RegisterSidKey(string key, string original, bool aad, string source)
        {
            if (IsExcludedValue(original) || sids.Find(key) != null) return;
            sids.Put(key, original, NextSid(aad), source);
        }

        private void RegisterReverse(string octets, string source)
        {
            if (!ScrubIPv4) return;
            string[] o = octets.TrimEnd('.').Split('.');
            Array.Reverse(o);
            if (o.Length == 4) RegisterIPv4(string.Join(".", o), source);
            else if (o.Length == 3 && CanonicalIPv4(string.Join(".", o) + ".1") != null) RegisterSubnet(o[0] + "." + o[1] + "." + o[2], source);
        }

        private void RegisterAzureResource(Group k, Group v, string source)
        {
            if (!k.Success || !v.Success) return;
            string kind = k.Value.ToLowerInvariant();
            if (kind == "virtualmachines" || kind == "servers" || kind == "flexibleservers" || kind == "managedclusters" || kind == "computers") RegisterHostValue(v.Value, source);
            else RegisterCustom(v.Value, source);
        }

        private void RegisterCookie(string pairs, string source)
        {
            foreach (string part in pairs.Split(';'))
            {
                int eq = part.IndexOf('=');
                if (eq <= 0) continue;
                string name = part.Substring(0, eq).Trim().ToLowerInvariant();
                string val = part.Substring(eq + 1).Trim();
                if (name == "path" || name == "domain" || name == "expires" || name == "max-age" || name == "samesite" || name == "version") continue;
                if (val.Length >= 8) RegisterSecret(val, source);
            }
        }

        private void RegisterPii(string v, string source)
        {
            if (!ScrubPersons) return;
            if (ContainsToken(v)) return;
            v = v.Trim().Trim('"', '\'', ',', ';');
            if (v.Length < 3 || v == "-" || secretNonValues.ContainsKey(v) || ignoreNames.ContainsKey(v) || IsTokenValue(v)) return;
            if (v.StartsWith("{", StringComparison.Ordinal) || v.StartsWith("%", StringComparison.Ordinal) || v.StartsWith("$", StringComparison.Ordinal)) return;
            pii.GetOrAdd(v, v, source);
            dirty = true;
        }

        private void RegisterNamePart(string v, string source)
        {
            if (!ScrubPersons) return;
            v = v.Trim();
            if (v.Length < 3 || personStopWords.ContainsKey(v) || CommonNameWords.ContainsKey(v) || ignoreNames.ContainsKey(v) || adBuiltins.ContainsKey(v)) return;
            foreach (char c in v) if (!(char.IsLetter(c) || c == '\'' || c == '-' || c == '\u2019')) return;
            nameParts.GetOrAdd(v, v, source);
            dirty = true;
        }

        // Given names / surnames that are also everyday words; never replaced on their own.
        private static readonly Dictionary<string, bool> CommonNameWords = Words(
              "Will May June April August Mark Grant Chase Bill Rich Young White Green Brown Black Long Rose Hope Faith Joy Summer "
            + "Art Penny Dawn Sky Rob Pat Sue Don Ray Jack Frank Max Earl King Price Little Hall Wood Hill Field Stone Banks Lane Street "
            + "Park Church Bell Page Case Cook Ward Hunter Fisher Baker Mason Carter Taylor Turner Walker Porter Hardy Moody Sharp Strong "
            + "Swift Best Love Read Day Knight Bishop Pope Major Rule Gray Grey North South East West Short Small Major Miles Mills "
            + "Jordan Austin Dallas Paris Lincoln Ford Chance Hunt Fox Wolf Lamb Bird Crow Drake Finch Nash Rice Salt Snow Frost Rain "
            + "Cash Gold Silver Shepherd Butler Cooper Clerk Gardner Glass Head Love Moon Star Storm Wells Booth Gates");

        private void ScanLdifValue(string attr, string b64, string source)
        {
            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); } catch (FormatException) { return; }
            string a = attr.ToLowerInvariant();
            if (a == "objectsid" && bytes.Length >= 8)
            {
                string sid = SidFromBytes(bytes);
                if (sid != null) ScanCore(sid, source);
                return;
            }
            string text = DecodeUtf8Text(bytes);
            if (text == null) return;
            if (a == "dn" || a == "distinguishedname") RegisterDn(text, source);
            else if (a == "cn" || a == "displayname" || a == "name") { RegisterPersonCandidate(CanonicalPerson(text), source); RegisterPersonCandidate(text, source); }
            else if (a == "givenname" || a == "sn") RegisterNamePart(text, source);
            ScanCore(a + ": " + text, source);
        }

        private static bool MostlyPrintable(string t)
        {
            if (t.Length < 6) return false;
            int good = 0;
            foreach (char c in t) if (!char.IsControl(c) || c == '\n' || c == '\r' || c == '\t') good++;
            if (good < t.Length * 0.95) return false;
            int letters = 0;
            foreach (char c in t) if (char.IsLetter(c)) letters++;
            return letters >= t.Length / 4;
        }

        /// <summary>base64 that decodes to readable text (UTF-8 or UTF-16LE, e.g. PowerShell -EncodedCommand), else null.</summary>
        private static string DecodeB64Text(string b64)
        {
            if (b64.Length % 4 != 0 || b64.Length > 65536) return null;
            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); } catch (FormatException) { return null; }
            if (bytes.Length >= 4 && bytes[1] == 0 && bytes[3] == 0)
            {
                string u = Encoding.Unicode.GetString(bytes);
                if (MostlyPrintable(u)) return u;
            }
            string t = DecodeUtf8Text(bytes);
            return (t != null && MostlyPrintable(t)) ? t : null;
        }

        private static string DecodeHexText(string hex)
        {
            if (hex.Length % 2 != 0) return null;
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
            for (int i = 0; i < b.Length; i++) if (b[i] == 0) b[i] = 0x20; // auditd proctitle separates arguments with NUL
            string t;
            try { t = new UTF8Encoding(false, true).GetString(b); } catch (DecoderFallbackException) { return null; }
            return MostlyPrintable(t) ? t : null;
        }

        private static string HexToIPv4(string hex8)
        {
            return Convert.ToInt32(hex8.Substring(0, 2), 16) + "." + Convert.ToInt32(hex8.Substring(2, 2), 16) + "." + Convert.ToInt32(hex8.Substring(4, 2), 16) + "." + Convert.ToInt32(hex8.Substring(6, 2), 16);
        }

        private static string DecodeUtf8Text(byte[] bytes)
        {
            try
            {
                string t = new UTF8Encoding(false, true).GetString(bytes);
                foreach (char c in t) if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t') return null;
                return t;
            }
            catch (DecoderFallbackException) { return null; }
        }

        private static string SidFromBytes(byte[] b)
        {
            if (b.Length < 8 || b[0] != 1 || b.Length != 8 + 4 * b[1]) return null;
            long auth = 0;
            for (int i = 2; i < 8; i++) auth = (auth << 8) | b[i];
            StringBuilder sb = new StringBuilder("S-1-" + auth.ToString(CultureInfo.InvariantCulture));
            for (int i = 0; i < b[1]; i++) sb.Append('-').Append(BitConverter.ToUInt32(b, 8 + 4 * i).ToString(CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private static byte[] SidToBytes(string sid)
        {
            string[] p = sid.Split('-');
            if (p.Length < 3) return null;
            byte[] b = new byte[8 + 4 * (p.Length - 3)];
            b[0] = 1; b[1] = (byte)(p.Length - 3);
            long auth = long.Parse(p[2], CultureInfo.InvariantCulture);
            for (int i = 7; i >= 2; i--) { b[i] = (byte)(auth & 0xFF); auth >>= 8; }
            for (int i = 3; i < p.Length; i++) Array.Copy(BitConverter.GetBytes(uint.Parse(p[i], CultureInfo.InvariantCulture)), 0, b, 8 + 4 * (i - 3), 4);
            return b;
        }

        private void RegisterCustom(string v, string source)
        {
            if (ContainsToken(v)) return;
            v = v.Trim();
            if (!HasLetter(v) && v.Length < 8) return; // a short number is not an identifier worth replacing everywhere
            if (v.Length < 3 || ignoreNames.ContainsKey(v) || IsExcludedValue(v) || IsTokenValue(v)) return;
            custom.GetOrAdd(v, v, source);
        }

        private void RegisterOrg(string v, string source)
        {
            if (ContainsToken(v)) return;
            v = v.Trim().TrimEnd('.', ',');
            if (v.Length < 3 || !HasLetter(v) || ignoreNames.ContainsKey(v) || IsExcludedValue(v) || IsTokenValue(v)) return;
            string low = v.ToLowerInvariant();
            if (low == "n/a" || low.StartsWith("unknown", StringComparison.Ordinal) || VendorOrgRx.IsMatch(v)) return;
            orgs.GetOrAdd(v, v, source);
        }

        private void RegisterLocation(string v, string source)
        {
            if (ContainsToken(v)) return;
            v = v.Trim();
            if (v.Length < 3 || !HasLetter(v) || ignoreNames.ContainsKey(v) || adBuiltins.ContainsKey(v) || IsExcludedValue(v) || IsTokenValue(v)) return;
            if (v.Equals("Default-First-Site-Name", StringComparison.OrdinalIgnoreCase)) return;
            locations.GetOrAdd(v, v, source);
        }

        private void RegisterGuid(string v, string source)
        {
            string g = v.ToLowerInvariant();
            if (g.StartsWith("00000000-0000-", StringComparison.Ordinal) || g.EndsWith("-c000-000000000000", StringComparison.Ordinal)) return;
            if (IsExcludedValue(g)) return;
            guids.GetOrAdd(g, g, source);
        }

        private string NextSid(bool aad)
        {
            string r;
            do
            {
                sids.Counter++;
                r = aad
                    ? "S-1-12-1-1111111111-2222222222-3333333333-" + (3000000000L + sids.Counter).ToString(CultureInfo.InvariantCulture)
                    : "S-1-5-21-1111111111-2222222222-" + (3000000000L + sids.Counter).ToString(CultureInfo.InvariantCulture);
            } while (sids.Used.ContainsKey(r));
            return r;
        }

        private void RegisterSecret(string value, string source)
        {
            string v = (value ?? string.Empty).Trim();
            if (ContainsToken(v)) return;
            if (v.Length >= 2 && ((v[0] == '"' && v[v.Length - 1] == '"') || (v[0] == '\'' && v[v.Length - 1] == '\''))) v = v.Substring(1, v.Length - 2);
            if (!IsPlausibleSecret(v)) return;
            string key = "sha256:" + Sha256Hex(v).Substring(0, 32);
            MapEntry e = secrets.GetOrAdd(key, key, source);
            secretRaw[v] = e;
        }

        private bool IsPlausibleSecret(string v)
        {
            if (v.Length < 3 || v.Length > 20000) return false;
            if (ignoreNames.ContainsKey(v) && IsAllLetters(v)) return false; // "--password via the CLI"
            if (secretNonValues.ContainsKey(v)) return false;
            char c0 = v[0];
            if (c0 == '/' || c0 == '~' || (v.Length > 2 && v[1] == ':' && v[2] == '\\')) return false; // PWD=/home/x, paths
            bool cryptHash = CryptHashRx.IsMatch(v); // $1$salt$hash, $6$..., $9$... (Cisco / Unix crypt)
            if (!cryptHash && (c0 == '$' || c0 == '%' || c0 == '<' || c0 == '{' || c0 == '[' || c0 == '(')) return false;
            bool same = true;
            foreach (char c in v) if (c != c0) { same = false; break; }
            if (same) return false;
            if (IsTokenValue(v)) return false;
            return true;
        }

        private static string Sha256Hex(string v)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(v));
                StringBuilder sb = new StringBuilder(64);
                foreach (byte b in h) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        // ----- people -----

        private bool IsPersonLike(string v)
        {
            string[] words = v.Replace(",", " ").Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length < 2 || words.Length > 4 || v.Length > 60) return false;
            int caps = 0;
            foreach (string w in words)
            {
                if (personStopWords.ContainsKey(w.TrimEnd('.'))) return false;
                if (w.Length == 2 && w[1] == '.') { caps++; continue; } // middle initial
                if (!char.IsUpper(w[0]))
                {
                    if (w == "van" || w == "de" || w == "del" || w == "da" || w == "von" || w == "le" || w == "la" || w == "di" || w == "du" || w == "dos" || w == "der") continue;
                    return false;
                }
                foreach (char c in w) if (!(char.IsLetter(c) || c == '\'' || c == '-' || c == '\u2019')) return false;
                bool allUpper = true;
                foreach (char c in w) if (char.IsLetter(c) && !char.IsUpper(c)) { allUpper = false; break; }
                if (allUpper && w.Length > 3) return false; // "SQL ADMINS", acronyms
                caps++;
            }
            return caps >= 2;
        }

        private void RegisterPersonCandidate(string value, string source)
        {
            if (!ScrubPersons || ContainsToken(value ?? string.Empty)) return;
            string v = Regex.Replace((value ?? string.Empty).Trim(), @"\s+", " ").Trim(',', ' ', '"', '\'');
            if (v.Length < 4 || adBuiltins.ContainsKey(v) || ignoreNames.ContainsKey(v) || IsExcludedValue(v)) return;
            if (CompanySuffixRx.IsMatch(v)) { if (ScrubOrgUnits) RegisterOrg(v, source); return; }
            if (!IsPersonLike(v)) return;
            RegisterPerson(v, source, false);
        }

        private MapEntry RegisterPerson(string v, string source, bool force)
        {
            string canonical = CanonicalPerson(v);
            MapEntry e;
            if (personAlias.TryGetValue(v, out e) || personAlias.TryGetValue(canonical, out e)) return e;
            e = persons.GetOrAdd(canonical, canonical, source);
            AddPersonAliases(canonical, e);
            AddPersonAliases(v, e);
            dirty = true;
            return e;
        }

        private static string CanonicalPerson(string v)
        {
            int comma = v.IndexOf(',');
            if (comma > 0)
            {
                string last = v.Substring(0, comma).Trim(), first = v.Substring(comma + 1).Trim();
                if (first.Length > 0 && last.Length > 0) return first + " " + last;
            }
            return v;
        }

        private static string FoldAccents(string s)
        {
            string d = s.Normalize(NormalizationForm.FormD);
            StringBuilder sb = new StringBuilder(d.Length);
            foreach (char c in d) if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) sb.Append(c);
            return sb.ToString().Normalize(NormalizationForm.FormC).Replace('\u00F8', 'o').Replace('\u00D8', 'O').Replace('\u00E6', 'a').Replace('\u0111', 'd').Replace('\u0110', 'D').Replace('\u00DF', 's');
        }

        private void AddPersonAliases(string name, MapEntry e)
        {
            string folded = FoldAccents(name);
            if (folded != name) AddPersonAliasesCore(folded, e);
            AddPersonAliasesCore(name, e);
        }

        private void AddPersonAliasesCore(string name, MapEntry e)
        {
            string canonical = CanonicalPerson(name);
            personAlias[name] = e;
            personAlias[canonical] = e;
            string[] w = canonical.Split(' ');
            if (w.Length >= 2)
            {
                string first = w[0], last = w[w.Length - 1];
                personAlias[last + ", " + first] = e;
                personAlias[last + "," + first] = e;
                personAlias[first + " " + last] = e;
                if (w.Length > 2)
                {
                    personAlias[last + ", " + string.Join(" ", w, 0, w.Length - 1)] = e;
                    string multiLast = string.Join(" ", w, 1, w.Length - 1);          // Aoife Ni Bhriain -> "Ni Bhriain, Aoife"
                    personAlias[multiLast + ", " + first] = e;
                    personAlias[multiLast + "," + first] = e;
                }
            }
        }

        // ----- LDAP DN -----

        private void RegisterDn(string dn, string source)
        {
            List<string> keys = new List<string>(), vals = new List<string>();
            foreach (Match c in DnCompRx.Matches(dn))
            {
                keys.Add(c.Groups["k"].Value.ToUpperInvariant());
                vals.Add(DnUnescape(c.Groups["v"].Value.Trim()));
            }
            if (keys.Count < 2) return;
            bool computerish = false;
            List<string> dcs = new List<string>();
            for (int i = 0; i < keys.Count; i++)
            {
                if (keys[i] == "DC") dcs.Add(vals[i]);
                string lv = vals[i].ToLowerInvariant();
                if ((keys[i] == "OU" || keys[i] == "CN") && i > 0 && (lv.IndexOf("computer", StringComparison.Ordinal) >= 0 || lv.IndexOf("server", StringComparison.Ordinal) >= 0
                    || lv.IndexOf("workstation", StringComparison.Ordinal) >= 0 || lv.IndexOf("laptop", StringComparison.Ordinal) >= 0 || lv.IndexOf("desktop", StringComparison.Ordinal) >= 0
                    || lv == "domain controllers")) computerish = true;
            }
            if (dcs.Count > 0 && ScrubDomains) AddDottedObs(string.Join(".", dcs.ToArray()), HintDomain, source);
            bool schema = false;
            for (int i = 0; i < keys.Count; i++) if (keys[i] == "CN" && vals[i].Equals("Schema", StringComparison.OrdinalIgnoreCase)) schema = true;
            for (int i = 0; i < keys.Count; i++)
            {
                string k = keys[i], v = vals[i].Trim().TrimEnd(',').Trim();
                if (v.Length == 0 || adBuiltins.ContainsKey(v) || IsTokenValue(v) || ContainsToken(v)) continue;
                if (ignoreNames.ContainsKey(v) && k != "OU") continue;
                if (schema && k == "CN") continue;
                if (k == "CN" && i + 1 < keys.Count && keys[i + 1] == "CN" && vals[i + 1].Equals("Sites", StringComparison.OrdinalIgnoreCase)) { if (ScrubOrgUnits) RegisterLocation(v, source); continue; }
                switch (k)
                {
                    case "CN":
                    case "UID":
                        if (v.IndexOf('.') > 0 && LooksLikeFqdn(v)) AddDottedObs(v, HintHost, source);
                        else if (VendorOrgRx.IsMatch(v)) { }
                        else if (v.IndexOf(' ') >= 0 || v.IndexOf(',') >= 0)
                        {
                            if (IsPersonLike(v)) { if (ScrubPersons) RegisterPerson(v, source, false); }
                            else if (ScrubOrgUnits && v.Length >= 3 && HasLetter(v)) RegisterCustom(v, source);
                        }
                        else if (GuidLike(v) || VendorOrgRx.IsMatch(v)) { }
                        else if (i == 0 && k == "CN" && (computerish || hosts.Map.ContainsKey(v))) RegisterHost(v, source);
                        else if (dcs.Count > 0 || k == "UID") RegisterUser(v, source);
                        else if (LooksLikeMachineName(v)) RegisterHost(v, source);
                        else if (ScrubOrgUnits) RegisterCustom(v, source);
                        break;
                    case "OU":
                        if (ScrubOrgUnits && HasLetter(v) && !v.Equals("Domain Controllers", StringComparison.OrdinalIgnoreCase)) ous.GetOrAdd(v, v, source);
                        break;
                    case "O": if (ScrubOrgUnits) RegisterOrg(v, source); break;
                    case "L":
                    case "ST":
                    case "S":
                    case "STREET": if (ScrubOrgUnits) RegisterLocation(v, source); break;
                    case "E": { int at = v.IndexOf('@'); if (at > 0 && ScrubEmails) AddEmailObs(v, v.Substring(0, at), v.Substring(at + 1), source); break; }
                }
            }
        }

        private static string DnUnescape(string v)
        {
            if (v.IndexOf('\\') < 0) return v;
            StringBuilder sb = new StringBuilder(v.Length);
            for (int i = 0; i < v.Length; i++)
            {
                if (v[i] == '\\' && i + 1 < v.Length) { sb.Append(v[i + 1]); i++; }
                else sb.Append(v[i]);
            }
            return sb.ToString();
        }

        private static bool GuidLike(string v)
        {
            return Regex.IsMatch(v, "^\\{?" + GuidPat + "\\}?$");
        }

        private static string DecodeDnsWire(string wire)
        {
            List<string> labels = new List<string>();
            foreach (Match m in DnsWireLabelRx.Matches(wire)) labels.Add(m.Groups[2].Value);
            return string.Join(".", labels.ToArray());
        }

        // ----- network values -----

        private void RegisterMac(string raw, string source)
        {
            string hex = MacHex(raw);
            if (hex == null) return;
            if (hex == "000000000000" || hex == "FFFFFFFFFFFF" || hex.StartsWith("020000", StringComparison.Ordinal)) return;
            if (hex.StartsWith("01005E", StringComparison.Ordinal) || hex.StartsWith("3333", StringComparison.Ordinal)) return; // multicast
            if (IsExcludedValue(raw) || IsExcludedValue(DisplayMac(hex))) return;
            MapEntry e = macs.Find(hex);
            if (e == null)
            {
                if (KeepMacVendor)
                {
                    string r;
                    do { macs.Counter++; r = DisplayMac(hex.Substring(0, 6) + macs.Counter.ToString("X6", CultureInfo.InvariantCulture)); } while (macs.Used.ContainsKey(r));
                    e = macs.Put(hex, DisplayMac(hex), r, source);
                }
                else e = macs.GetOrAdd(hex, DisplayMac(hex), source);
            }
            if (!macRaw.ContainsKey(raw)) macRaw[raw] = e;
        }

        private void RegisterIPv6(string v, string source)
        {
            if (v.Length < 3) return;
            int colons = 0, groups = 0;
            bool inGroup = false, hasV4 = v.IndexOf('.') >= 0;
            foreach (char c in v)
            {
                if (c == ':') { colons++; inGroup = false; }
                else if (!inGroup && c != '.') { inGroup = true; groups++; }
            }
            bool compressed = v.IndexOf("::", StringComparison.Ordinal) >= 0;
            if (!compressed && colons != 7 && !(hasV4 && colons == 6)) return; // 10:15:30 is a time, not an address
            if (groups < 2 && !hasV4) return;                                  // [Math]::Abs
            IPAddress a;
            if (!IPAddress.TryParse(v, out a) || a.AddressFamily != AddressFamily.InterNetworkV6) return;
            string canon = Canonical6(a);
            if (IsExcludedValue(v) || IsExcludedValue(canon)) return;
            byte[] b = a.GetAddressBytes();
            if (b[0] == 0xFF) return;                                          // multicast
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return; // documentation (already fake)
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
            {
                bool small = true;
                for (int i = 8; i < 15; i++) if (b[i] != 0) { small = false; break; }
                if (small) return; // fe80::1 style gateway addresses carry no identity
            }
            MapEntry e = MapIPv6(a, canon, source);
            if (e != null && !ipv6Raw.ContainsKey(v)) ipv6Raw[v] = e;
        }

        private MapEntry MapIPv6(IPAddress a, string canon, string source)
        {
            MapEntry e = ipv6.Find(canon);
            if (e != null) return e;
            byte[] b = a.GetAddressBytes();
            string repl;
            if (a.IsIPv4MappedToIPv6)
            {
                MapEntry e4 = RegisterIPv4(new IPAddress(new byte[] { b[12], b[13], b[14], b[15] }).ToString(), source);
                if (e4 == null) return null;
                repl = "::ffff:" + e4.Replacement;
            }
            else
            {
                bool linkLocal = b[0] == 0xFE && (b[1] & 0xC0) == 0x80;
                byte[] rb;
                string counterKey;
                if (linkLocal)
                {
                    rb = new byte[16]; rb[0] = 0xFE; rb[1] = 0x80;
                    counterKey = "fe80";
                }
                else
                {
                    StringBuilder pk = new StringBuilder(16);
                    for (int i = 0; i < 8; i++) pk.Append(b[i].ToString("x2", CultureInfo.InvariantCulture));
                    byte[] pb = new byte[16];
                    Array.Copy(b, pb, 8);
                    MapEntry pe = v6prefixes.GetOrAdd(pk.ToString(), new IPAddress(pb).ToString() + "/64", source);
                    rb = IPAddress.Parse(pe.Replacement.Substring(0, pe.Replacement.IndexOf('/'))).GetAddressBytes();
                    counterKey = pe.Replacement;
                }
                bool iidZero = true;
                for (int i = 8; i < 16; i++) if (b[i] != 0) { iidZero = false; break; }
                if (iidZero) repl = new IPAddress(rb).ToString();
                else
                {
                    long ctr;
                    v6IidCounters.TryGetValue(counterKey, out ctr);
                    do
                    {
                        ctr++;
                        for (int i = 0; i < 8; i++) rb[15 - i] = (byte)(ctr >> (8 * i));
                        repl = new IPAddress(rb).ToString();
                    } while (ipv6.Used.ContainsKey(repl));
                    v6IidCounters[counterKey] = ctr;
                }
            }
            return ipv6.Put(canon, canon, repl, source);
        }

        private MapEntry RegisterSubnet(string key, string source)
        {
            return subnets.GetOrAdd(key, key + ".0/24", source);
        }

        private MapEntry RegisterIPv4(string raw, string source)
        {
            string canon = CanonicalIPv4(raw);
            if (canon == null) return null;
            MapEntry e = ipv4.Find(canon);
            if (e != null) { if (raw != canon && !ipv4Raw.ContainsKey(raw)) ipv4Raw[raw] = e; return e; }
            string[] p = canon.Split('.');
            int a = int.Parse(p[0], CultureInfo.InvariantCulture), b = int.Parse(p[1], CultureInfo.InvariantCulture);
            // 0/8, loopback, multicast, reserved (240/4 - also the replacement pool), masks like 255.255.255.0
            if (a == 0 || a == 127 || a >= 224) return null;
            if (a == 198 && (b == 18 || b == 19)) return null; // replacement pool
            if (a == 2 && b == 5) return null;                 // X.500 OIDs 2.5.4.x / 2.5.29.x
            if (canon == "1.3.6.1") return null;
            if (IsExcludedValue(canon) || IsExcludedValue(raw)) return null;
            MapEntry sub = RegisterSubnet(p[0] + "." + p[1] + "." + p[2], source);
            string prefix = sub.Replacement.Substring(0, sub.Replacement.LastIndexOf('.')); // "198.18.0.0/24" -> "198.18.0"
            e = ipv4.Put(canon, canon, prefix + "." + p[3], source);
            if (raw != canon) ipv4Raw[raw] = e;
            return e;
        }

        private static string CanonicalIPv4(string raw)
        {
            string[] p = raw.Split('.');
            if (p.Length != 4) return null;
            int[] o = new int[4];
            for (int i = 0; i < 4; i++)
            {
                if (p[i].Length == 0 || p[i].Length > 3 || !int.TryParse(p[i], NumberStyles.None, CultureInfo.InvariantCulture, out o[i]) || o[i] > 255) return null;
            }
            return o[0].ToString(CultureInfo.InvariantCulture) + "." + o[1].ToString(CultureInfo.InvariantCulture) + "." + o[2].ToString(CultureInfo.InvariantCulture) + "." + o[3].ToString(CultureInfo.InvariantCulture);
        }

        private static bool InVersionContext(string text, int index)
        {
            int from = Math.Max(0, index - 20);
            return VersionCtxRx.IsMatch(text.Substring(from, index - from));
        }

        private DottedObs AddDottedObs(string raw, int hint, string source)
        {
            raw = TrimDots(raw);
            if (raw.Length == 0 || raw.Length > 253) return null;
            DottedObs known;
            if (dotted.TryGetValue(raw, out known))
            {
                if (known.Hint == HintAuto && hint != HintAuto) known.Hint = hint;
                return known;
            }
            string[] labels = raw.Split('.');
            foreach (string l in labels)
            {
                if (l.Length == 0 || l.Length > 63) return null;
                foreach (char c in l) if (!(IsAlnum(c) || c == '-' || c == '_')) return null;
            }
            if (IsExcludedDomain(raw) || IsExcludedValue(raw)) return null;
            bool allTokens = true;
            foreach (string l in labels) if (!IsTokenValue(l) && !IsKeepLabel(l) && !tlds.ContainsKey(l)) { allTokens = false; break; }
            if (allTokens) return null;
            if (hint == HintHost && !ScrubHostnames && !ScrubDomains) return null;
            if (hint == HintDomain && !ScrubDomains) return null;
            DottedObs o;
            if (dotted.TryGetValue(raw, out o))
            {
                if (o.Hint == HintAuto && hint != HintAuto) o.Hint = hint;
                return o;
            }
            o = new DottedObs();
            o.Raw = raw; o.Hint = hint; o.Source = source;
            dotted[raw] = o;
            dottedOrder.Add(o);
            dirty = true;
            return o;
        }

        private void AddEmailObs(string raw, string local, string domain, string source)
        {
            if (emails.ContainsKey(raw) || IsExcludedValue(raw)) return;
            if (IsTokenValue(local)) return;
            if (ScrubUsers) RegisterUser(local, source);
            if (ScrubDomains) AddDottedObs(domain, HintDomain, source);
            EmailObs o = new EmailObs();
            o.Raw = raw; o.Source = source;
            emails[raw] = o;
            emailOrder.Add(o);
            dirty = true;
        }

        // =========================================================================================
        // Index build (between passes)
        // =========================================================================================

        /// <summary>Number of trailing labels that belong to a cloud service suffix (blob.core.windows.net ...).</summary>
        private int PublicSuffixCount(string[] labels)
        {
            int best = 0;
            for (int k = labels.Length - 1; k >= 0; k--)
            {
                string suffix = string.Join(".", labels, k, labels.Length - k);
                if (publicSuffixes.ContainsKey(suffix)) best = labels.Length - k;
            }
            return best;
        }

        private bool KeepLabelAt(string[] labels, int i, int psl)
        {
            string l = labels[i];
            int last = labels.Length - 1;
            if (i == last && last > 0 && tlds.ContainsKey(l)) return true;
            if (psl > 0 && i >= labels.Length - psl) return true;
            if (psl > 0 && i == labels.Length - psl - 1 && i == 0 && (commonWords.ContainsKey(l) || ignoreNames.ContainsKey(l))) return true; // developer.okta.com
            if (AwsRegionRx.IsMatch(l)) return true;
            return IsKeepLabel(l);
        }

        private void RegisterLabels(DottedObs o, bool firstIsHost, bool skipFirst)
        {
            string[] labels = o.Raw.Split('.');
            int psl = PublicSuffixCount(labels);
            for (int i = skipFirst ? 1 : 0; i < labels.Length; i++)
            {
                string l = labels[i];
                if (KeepLabelAt(labels, i, psl) || IsTokenValue(l)) continue;
                if (i == 0 && firstIsHost) { if (ScrubHostnames) hosts.GetOrAdd(l, l, o.Source); }
                else if (ScrubDomains) domains.GetOrAdd(l, l, o.Source);
            }
        }

        private void BuildIndex()
        {
            // 1. classify dotted names. Forced hints first, then automatic ones: for "a.b.c.tld" the suffix is a
            //    domain; the first label is a host unless it is already known as a domain label.
            foreach (DottedObs o in dottedOrder)
                if (o.Hint == HintHost)
                {
                    o.FirstIsHost = true;
                    RegisterLabels(o, true, false);
                    if (!o.Loaded) weakHosts.Remove(o.Raw.Split('.')[0]);
                }
            foreach (DottedObs o in dottedOrder) if (o.Hint == HintDomain) { o.FirstIsHost = false; RegisterLabels(o, false, false); }
            foreach (DottedObs o in dottedOrder) if (o.Hint == HintAuto && o.Raw.Split('.').Length >= 3) RegisterLabels(o, false, true);
            foreach (DottedObs o in dottedOrder)
            {
                if (o.Hint != HintAuto) continue;
                string[] labels = o.Raw.Split('.');
                string first = labels[0];
                bool isHost;
                if (labels.Length == 2) isHost = hosts.Map.ContainsKey(first);
                else isHost = !(domains.Map.ContainsKey(first) && !hosts.Map.ContainsKey(first));
                o.FirstIsHost = isHost;
                bool existed = hosts.Map.ContainsKey(first);
                RegisterLabels(o, isHost, false);
                if (isHost && !existed && hosts.Map.ContainsKey(first) && commonWords.ContainsKey(first)) weakHosts[first] = true;
            }

            // 2. naming-convention siblings: WEB01 known -> WEB02 / web03 in free text are hosts too;
            //    hyphenated names that carry the organisation's host prefix (NWT-Server-Hardening) are redacted.
            if (LearnNamingPatterns && ScrubHostnames) { ResolveSiblings(); ResolveOrgTokens(); }

            // 2b. names registered as organisation are not people
            foreach (MapEntry o in orgs.Order)
            {
                MapEntry pe;
                if (personAlias.TryGetValue(o.Original, out pe))
                {
                    List<string> drop = new List<string>();
                    foreach (KeyValuePair<string, MapEntry> kv in personAlias) if (kv.Value == pe) drop.Add(kv.Key);
                    foreach (string d in drop) personAlias.Remove(d);
                    persons.Order.Remove(pe);
                    persons.Map.Remove(pe.Original);
                }
            }

            // 3. composite rows
            foreach (DottedObs o in dottedOrder)
            {
                if (o.Entry == null)
                {
                    o.Entry = new MapEntry();
                    o.Entry.Original = o.Raw;
                    o.Entry.FirstSeenIn = o.Source;
                }
                o.Entry.Type = o.FirstIsHost ? "FQDN" : "DomainName";
                o.Entry.Replacement = ComposeDotted(o.Raw, o.FirstIsHost);
            }
            foreach (EmailObs o in emailOrder)
            {
                if (o.Entry == null)
                {
                    o.Entry = new MapEntry();
                    o.Entry.Type = "Email";
                    o.Entry.Original = o.Raw;
                    o.Entry.FirstSeenIn = o.Source;
                }
                o.Entry.Replacement = ComposeEmail(o.Raw);
            }

            // 4. literal index (first registration of a key wins)
            literals = new Dictionary<string, Literal>(StringComparer.OrdinalIgnoreCase);
            phraseMap.Clear();
            List<string> phrases = new List<string>();
            foreach (MapEntry e in custom.Order) AddWordOrPhrase(e.Original, e, phrases);
            foreach (MapEntry e in orgs.Order)
            {
                AddWordOrPhrase(e.Original, e, phrases);
                string[] ow = e.Original.Split(' ');
                if (ow.Length >= 2 && ow[0].Length >= 5 && IsAllLetters(ow[0]) && !personStopWords.ContainsKey(ow[0]) && !ignoreNames.ContainsKey(ow[0])
                    && !commonWords.ContainsKey(ow[0]) && !CommonNameWords.ContainsKey(ow[0]))
                    AddLiteral(ow[0], Literal.Atomic, true, false, e, null, false);
            }
            foreach (KeyValuePair<string, MapEntry> kv in personAlias) { phraseMap[kv.Key] = kv.Value; phrases.Add(kv.Key); }
            foreach (MapEntry e in locations.Order) AddWordOrPhrase(e.Original, e, phrases);
            foreach (MapEntry e in pii.Order) AddWordOrPhrase(e.Original, e, phrases);
            // user names such as marie.dupont first, so they are not composed as host.domain
            foreach (MapEntry e in users.Order) if (e.Original.IndexOf('.') > 0) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
            foreach (DottedObs o in dottedOrder)
                if (!string.Equals(o.Entry.Replacement, o.Raw, StringComparison.OrdinalIgnoreCase))
                    AddLiteral(o.Raw, Literal.Dotted, true, false, o.Entry, null, o.FirstIsHost);
            foreach (EmailObs o in emailOrder)
                if (!string.Equals(o.Entry.Replacement, o.Raw, StringComparison.OrdinalIgnoreCase))
                    AddLiteral(o.Raw, Literal.Email, true, false, o.Entry, null, false);
            foreach (MapEntry e in ipv4.Order) AddLiteral(e.Original, Literal.Atomic, false, true, e, null, false);
            foreach (KeyValuePair<string, MapEntry> kv in ipv4Raw) AddLiteral(kv.Key, Literal.Atomic, false, true, kv.Value, null, false);
            foreach (KeyValuePair<string, MapEntry> kv in ipv6Raw) AddLiteral(kv.Key, Literal.Atomic, false, false, kv.Value, null, false);
            foreach (MapEntry e in ipv6.Order) AddLiteral(e.Original, Literal.Atomic, false, false, e, null, false);
            foreach (KeyValuePair<string, MapEntry> kv in macRaw) AddLiteral(kv.Key, Literal.Atomic, false, false, kv.Value, FormatMacLike(kv.Key, kv.Value.Replacement), false);
            foreach (MapEntry e in macs.Order)
            {
                string hex = MacHex(e.Original);
                if (hex == null) continue;
                AddLiteral(e.Original, Literal.Atomic, false, false, e, FormatMacLike(e.Original, e.Replacement), false);
                string dash = e.Original.Replace(':', '-'), dotted3 = hex.Substring(0, 4) + "." + hex.Substring(4, 4) + "." + hex.Substring(8, 4);
                AddLiteral(dash, Literal.Atomic, false, false, e, FormatMacLike(dash, e.Replacement), false);
                AddLiteral(dotted3, Literal.Atomic, false, false, e, FormatMacLike(dotted3, e.Replacement), false);
            }
            foreach (MapEntry e in guids.Order) AddLiteral(e.Original, Literal.Atomic, false, false, e, null, false);
            foreach (MapEntry e in accounts.Order) AddLiteral(e.Original, Literal.Atomic, false, false, e, null, false);
            foreach (MapEntry e in hosts.Order)
                if (e.Original.Length >= MinBareLength && !weakHosts.ContainsKey(e.Original))
                {
                    AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
                    if (e.Original.IndexOf('-') > 0) AddLiteral(e.Original.Replace('-', '_'), Literal.Atomic, true, false, e, e.Replacement.Replace('-', '_'), false);
                }
            foreach (MapEntry e in domains.Order)
                if (e.Original.Length >= MinBareLength && strongDomains.ContainsKey(e.Original)) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
            foreach (MapEntry e in users.Order) if (e.Original.Length >= MinBareLength) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
            foreach (MapEntry e in domains.Order)
                if (e.Original.Length >= MinBareLength && (strongDomains.ContainsKey(e.Original) || !commonWords.ContainsKey(e.Original)))
                    AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);

            // given names / surnames: case-sensitive, capitalised, never common words
            Dictionary<string, MapEntry> parts = new Dictionary<string, MapEntry>(StringComparer.Ordinal);
            foreach (MapEntry e in nameParts.Order) parts[e.Original] = e;
            foreach (MapEntry e in persons.Order)
                foreach (string w in e.Original.Split(' '))
                {
                    string t = w.Trim(',', '.');
                    if (t.Length >= 3 && char.IsUpper(t[0]) && !CommonNameWords.ContainsKey(t) && !personStopWords.ContainsKey(t) && !parts.ContainsKey(t) && !ignoreNames.ContainsKey(t))
                        parts[t] = nameParts.GetOrAdd(t, t, e.FirstSeenIn);
                }
            namePartMap = parts;
            namePartRx = null;
            if (parts.Count > 0)
            {
                List<string> names = new List<string>(parts.Keys);
                names.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
                StringBuilder nb = new StringBuilder(@"(?<![\p{L}0-9_\\-])(?:");
                for (int i = 0; i < names.Count; i++) { if (i > 0) nb.Append('|'); nb.Append(Regex.Escape(names[i])); }
                nb.Append(@")(?![\p{L}0-9_-])");
                namePartRx = R(nb.ToString(), RegexOptions.CultureInvariant);
            }

            maxLiteralLength = 0;
            foreach (string k in literals.Keys) if (k.Length > maxLiteralLength) maxLiteralLength = k.Length;
            literalLengths = new bool[maxLiteralLength + 1];
            foreach (string k in literals.Keys) literalLengths[k.Length] = true;

            // prefixes of names, for "WEB01.corp.con..." (Format-Table truncation) and wrapped Format-List values
            prefixIndex = new Dictionary<string, PrefixHit>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, Literal> kv in literals)
            {
                if (!kv.Value.NameLike || kv.Key.Length < 5) continue;
                for (int len = 3; len < kv.Key.Length; len++)
                {
                    string p = kv.Key.Substring(0, len);
                    if (prefixIndex.ContainsKey(p) || literals.ContainsKey(p)) continue;
                    PrefixHit h = new PrefixHit();
                    h.Lit = kv.Value; h.FullKey = kv.Key;
                    prefixIndex[p] = h;
                }
            }

            phraseRx = BuildAlternation(phrases, @"(?<![\p{L}0-9])", @"(?![\p{L}0-9])");
            phraseTruncMap.Clear();
            List<string> truncs = new List<string>();
            foreach (string p in phrases)
                for (int len = 4; len < p.Length; len++)
                {
                    string t = p.Substring(0, len).TrimEnd();
                    if (t.Length < 4 || phraseTruncMap.ContainsKey(t)) continue;
                    phraseTruncMap[t] = p;
                    truncs.Add(t);
                }
            phraseTruncRx = BuildAlternation(truncs, @"(?<![\p{L}0-9])", @"(?=\.\.\.|\u2026)");

            List<string> bare = new List<string>();
            foreach (string s in secretRaw.Keys) if (s.Length >= 6 && s.IndexOf('\n') < 0) bare.Add(s);
            secretBareRx = null;
            if (bare.Count > 0)
            {
                bare.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < bare.Count; i++)
                {
                    if (i > 0) sb.Append('|');
                    string s = bare[i];
                    sb.Append("(?:");
                    bool longSecret = s.Length >= 12;
                    if (IsAlnum(s[0]) && !longSecret) sb.Append(@"(?<![A-Za-z0-9])");
                    sb.Append(Regex.Escape(s));
                    if (IsAlnum(s[s.Length - 1]) && !longSecret) sb.Append(@"(?![A-Za-z0-9])");
                    sb.Append(')');
                }
                secretBareRx = R(sb.ToString(), RegexOptions.CultureInvariant);
            }
            dirty = false;
        }

        private void AddWordOrPhrase(string original, MapEntry e, List<string> phrases)
        {
            if (e.Type == "Organization" && !original.EndsWith(".", StringComparison.Ordinal) && Regex.IsMatch(original, @"\b(?:Inc|Ltd|Co|Corp|L\.L\.C|S\.A|B\.V)$"))
                AddWordOrPhrase(original + ".", e, phrases);
            if (IsWordLiteral(original)) AddLiteral(original, Literal.Atomic, true, false, e, null, false);
            else if (!phraseMap.ContainsKey(original)) { phraseMap[original] = e; phrases.Add(original); }
        }

        private static Regex BuildAlternation(List<string> items, string before, string after)
        {
            if (items.Count == 0) return null;
            List<string> sorted = new List<string>(items);
            sorted.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
            StringBuilder sb = new StringBuilder(before + "(?:");
            for (int i = 0; i < sorted.Count; i++)
            {
                if (i > 0) sb.Append('|');
                sb.Append(PhrasePattern(sorted[i]));
            }
            sb.Append(")" + after);
            return R(sb.ToString(), RxOptI);
        }

        /// <summary>Regex for a phrase that also matches "Jane+Smith", "Jane%20Smith", "Gonzalez%2C%20Ana", "O%27Connor".</summary>
        private static string PhrasePattern(string phrase)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in phrase)
            {
                if (c == ' ') sb.Append(@"(?:\s+|\+|%20)");
                else if (c == ',') sb.Append(@"(?:,|%2C)");
                else if (c == '\'') sb.Append(@"(?:'|%27)");
                else sb.Append(Regex.Escape(c.ToString()));
            }
            return sb.ToString();
        }

        private static string NormalizePhrase(string v)
        {
            string t = v.Replace("%20", " ").Replace("%2C", ",").Replace("%2c", ",").Replace("%27", "'");
            t = Regex.Replace(t, @"(?<=[\p{L},'])\+(?=[\p{L}])", " ");
            return Regex.Replace(t, @"\s+", " ");
        }

        private void ResolveSiblings()
        {
            Dictionary<string, string> shapes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (MapEntry e in hosts.Order)
            {
                if (weakHosts.ContainsKey(e.Original)) continue;
                string k = SiblingShape(e.Original);
                if (k != null && !shapes.ContainsKey(k)) shapes[k] = e.Original;
            }
            if (shapes.Count == 0) return;
            foreach (KeyValuePair<string, string> kv in siblingCandidates)
            {
                if (hosts.Map.ContainsKey(kv.Key) || users.Map.ContainsKey(kv.Key) || !IsCandidateName(kv.Key)) continue;
                string k = SiblingShape(kv.Key);
                string model;
                if (k != null && shapes.TryGetValue(k, out model)) hosts.GetOrAdd(kv.Key, kv.Key, kv.Value + " (naming pattern of " + model + ")");
            }
        }

        private void ResolveOrgTokens()
        {
            Dictionary<string, int> count = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (MapEntry e in hosts.Order)
            {
                if (weakHosts.ContainsKey(e.Original) || e.Original.IndexOf('-') < 0) continue;
                string first = e.Original.Split('-')[0];
                int c;
                count.TryGetValue(first, out c);
                count[first] = c + 1;
            }
            Dictionary<string, bool> tokens = NewSet();
            foreach (KeyValuePair<string, int> kv in count)
            {
                string t = kv.Key;
                if (kv.Value < 3 || t.Length < 2 || t.Length > 10 || !IsAllLetters(t)) continue;
                if (siblingDeny.ContainsKey(t) || commonWords.ContainsKey(t) || ignoreNames.ContainsKey(t)) continue;
                tokens[t] = true;
            }
            if (tokens.Count == 0) return;
            foreach (KeyValuePair<string, string> kv in siblingCandidates)
            {
                string c = kv.Key;
                if (c.IndexOf('-') < 0 || hosts.Map.ContainsKey(c) || custom.Map.ContainsKey(c) || users.Map.ContainsKey(c)) continue;
                foreach (string seg in c.Split('-'))
                    if (tokens.ContainsKey(seg))
                    {
                        if (!IsCandidateName(c)) break;
                        custom.GetOrAdd(c, c, kv.Value + " (organisation prefix " + seg + ")");
                        break;
                    }
            }
        }

        private static bool IsAllLetters(string s)
        {
            foreach (char c in s) if (!char.IsLetter(c)) return false;
            return true;
        }

        /// <summary>WEB01 -> "A|WEB|2"; NWT-SQL-P01 -> "B|3|NWT|A99". null when the name has no usable shape.</summary>
        private string SiblingShape(string name)
        {
            if (name.Length < 3 || name.Length > 40) return null;
            if (name.IndexOf('-') < 0)
            {
                int i = 0;
                while (i < name.Length && char.IsLetter(name[i])) i++;
                if (i < 2 || i == name.Length) return null;
                bool alldigits = true;
                for (int j = i; j < name.Length; j++) if (!char.IsDigit(name[j])) { alldigits = false; break; }
                if (!alldigits)
                {
                    // site+number+role+number (AUS1DCS001, lon1fs02): first letter run literal, then the run pattern
                    if (name.Length < 6 || i > 6 || siblingDeny.ContainsKey(name.Substring(0, i))) return null;
                    StringBuilder rs = new StringBuilder();
                    for (int j = i; j < name.Length; j++)
                    {
                        char t = char.IsDigit(name[j]) ? '9' : (char.IsLetter(name[j]) ? 'A' : '?');
                        if (t == '?') return null;
                        if (rs.Length == 0 || rs[rs.Length - 1] != t) rs.Append(t);
                    }
                    if (rs.ToString() != "9A9") return null;
                    return "C|" + name.Substring(0, i).ToUpperInvariant() + "|" + rs.ToString();
                }
                string prefix = name.Substring(0, i);
                if (siblingDeny.ContainsKey(prefix)) return null;
                return "A|" + prefix.ToUpperInvariant() + "|" + (name.Length - i).ToString(CultureInfo.InvariantCulture);
            }
            string[] seg = name.Split('-');
            foreach (string s in seg) if (s.Length == 0) return null;
            string lastSeg = seg[seg.Length - 1];
            if (!HasDigit(lastSeg) || seg[0].Length < 2 || !char.IsLetter(seg[0][0]) || siblingDeny.ContainsKey(seg[0])) return null;
            StringBuilder shape = new StringBuilder();
            for (int i = 0; i < lastSeg.Length; i++)
            {
                char c = lastSeg[i];
                if (char.IsDigit(c)) shape.Append('9');
                else if (shape.Length == 0 || shape[shape.Length - 1] != 'A') shape.Append('A');
            }
            return "B|" + seg.Length.ToString(CultureInfo.InvariantCulture) + "|" + seg[0].ToUpperInvariant() + "|" + shape.ToString();
        }

        private void AddLiteral(string key, int kind, bool nameLike, bool ipLike, MapEntry e, string fixedRepl, bool firstIsHost)
        {
            if (string.IsNullOrEmpty(key) || literals.ContainsKey(key)) return;
            Literal l = new Literal();
            l.Kind = kind; l.NameLike = nameLike; l.IpLike = ipLike; l.Entry = e; l.Fixed = fixedRepl; l.FirstIsHost = firstIsHost;
            literals[key] = l;
        }

        // =========================================================================================
        // Pass 2 - replacement
        // =========================================================================================

        public string ScrubText(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            if (dirty) BuildIndex();
            if (secrets.Map.Count > 0) text = ReplaceSecrets(text);
            if (sids.Map.Count > 0)
            {
                text = SidRx.Replace(text, delegate(Match m) { return MapWhole(sids.Find(SidKey(m)), m.Value); });
                text = AadSidRx.Replace(text, delegate(Match m) { return MapWhole(sids.Find(AadSidKey(m)), m.Value); });
            }
            if (macs.Map.Count > 0) text = ReplaceMacForms(text);
            if (forestOids.Map.Count > 0 && text.IndexOf("311.21.8.", StringComparison.Ordinal) >= 0)
                text = ReplaceGroup(ForestOidRx, text, "v", delegate(string v) { MapEntry e = forestOids.Find(v); if (e == null) return null; e.Matches++; return e.Replacement; });
            if (text.IndexOf("::", StringComparison.Ordinal) >= 0) text = LdifB64Rx.Replace(text, ReplaceLdif);
            text = B64Rx.Replace(text, delegate(Match m)
            {
                string v = m.Value;
                if (v.Length % 4 != 0 || v.Length > 65536) return v;
                byte[] bytes;
                try { bytes = Convert.FromBase64String(v); } catch (FormatException) { return v; }
                bool utf16 = bytes.Length >= 4 && bytes[1] == 0 && bytes[3] == 0;
                string t = DecodeB64Text(v);
                if (t == null) return v;
                string sc = ScrubText(t);
                if (sc == t) return v;
                return Convert.ToBase64String(utf16 ? Encoding.Unicode.GetBytes(sc) : Encoding.UTF8.GetBytes(sc));
            });
            if (text.IndexOf('=') >= 0)
            {
                text = ReplaceGroup(HexFieldRx, text, "v", delegate(string hex)
                {
                    string t = DecodeHexText(hex);
                    if (t == null) return null;
                    string sc = ScrubText(t);
                    if (sc == t) return null;
                    StringBuilder hb = new StringBuilder();
                    foreach (byte by in Encoding.UTF8.GetBytes(sc)) hb.Append(by.ToString("X2", CultureInfo.InvariantCulture));
                    return hb.ToString();
                });
                if (ipv4.Map.Count > 0)
                    text = ReplaceGroup(SockaddrRx, text, "ip", delegate(string hex)
                    {
                        MapEntry e = ipv4.Find(HexToIPv4(hex));
                        if (e == null) return null;
                        e.Matches++;
                        StringBuilder hb = new StringBuilder();
                        foreach (string o in e.Replacement.Split('.')) hb.Append(int.Parse(o, CultureInfo.InvariantCulture).ToString("X2", CultureInfo.InvariantCulture));
                        return hb.ToString();
                    });
            }
            if (text.IndexOf("(0)", StringComparison.Ordinal) >= 0) text = DnsWireRx.Replace(text, ReplaceDnsWire);
            if (ipv4.Map.Count > 0 && text.IndexOf("in-addr", StringComparison.OrdinalIgnoreCase) >= 0) text = InAddrRx.Replace(text, ReplaceInAddr);
            if (text.IndexOf('=') >= 0) text = DnRx.Replace(text, ReplaceDn);
            if (phraseRx != null) text = phraseRx.Replace(text, ReplacePhrase);
            if (phraseTruncRx != null) text = phraseTruncRx.Replace(text, ReplacePhraseTrunc);
            text = ReplaceLiterals(text);
            if (namePartRx != null) text = namePartRx.Replace(text, delegate(Match m) { MapEntry e; if (!namePartMap.TryGetValue(m.Value, out e)) return m.Value; e.Matches++; return e.Replacement; });
            return text;
        }

        private static string MapWhole(MapEntry e, string original)
        {
            if (e == null) return original;
            e.Matches++;
            return e.Replacement;
        }

        private string MapSecret(string value)
        {
            string v = value.Trim();
            if (v.Length >= 2 && ((v[0] == '"' && v[v.Length - 1] == '"') || (v[0] == '\'' && v[v.Length - 1] == '\''))) v = v.Substring(1, v.Length - 2);
            MapEntry e;
            if (!secretRaw.TryGetValue(v, out e)) return null;
            e.Matches++;
            return value.Replace(v, e.Replacement);
        }

        private static string ReplaceGroup(Regex rx, string text, string group, Func<string, string> map)
        {
            return rx.Replace(text, delegate(Match m)
            {
                Group g = m.Groups[group];
                if (!g.Success || g.Length == 0) return m.Value;
                string r = map(g.Value);
                if (r == null) return m.Value;
                int off = g.Index - m.Index;
                return m.Value.Substring(0, off) + r + m.Value.Substring(off + g.Length);
            });
        }

        private string ReplaceSecrets(string text)
        {
            if (text.IndexOf("-----BEGIN ", StringComparison.Ordinal) >= 0) text = PemRx.Replace(text, ReplacePem);
            foreach (Regex rx in SecretValueRxs) text = ReplaceGroup(rx, text, "v", MapSecret);
            text = ReplaceGroup(SshKeyRx, text, "key", MapSecret);
            text = JwtRx.Replace(text, delegate(Match m) { return MapSecret(m.Value) ?? m.Value; });
            text = AwsKeyRx.Replace(text, delegate(Match m) { return MapSecret(m.Value) ?? m.Value; });
            if (secretBareRx != null) text = secretBareRx.Replace(text, delegate(Match m) { return MapSecret(m.Value) ?? m.Value; });
            return text;
        }

        private string ReplacePem(Match m)
        {
            string body = m.Groups["body"].Value;
            MapEntry e;
            if (!secretRaw.TryGetValue(body.Trim(), out e)) return m.Value;
            e.Matches++;
            // keep the line count: first body line becomes the token, the other lines become empty
            StringBuilder sb = new StringBuilder();
            bool first = true;
            int i = 0;
            while (i < body.Length)
            {
                int nl = body.IndexOf('\n', i);
                int end = nl < 0 ? body.Length : nl;
                string line = body.Substring(i, end - i);
                bool cr = line.EndsWith("\r", StringComparison.Ordinal);
                string content = cr ? line.Substring(0, line.Length - 1) : line;
                if (content.Trim().Length > 0 && first) { sb.Append(e.Replacement); first = false; }
                if (cr) sb.Append('\r');
                if (nl >= 0) sb.Append('\n');
                i = end + 1;
            }
            if (first) sb.Append(e.Replacement);
            return "-----BEGIN " + m.Groups["t"].Value + "-----" + sb.ToString() + "-----END " + m.Groups["t"].Value + "-----";
        }

        private string ReplaceMacForms(string text)
        {
            // space separated ("00 50 56 a1 2b 77") and MACs embedded in longer byte runs (DUIDs, relay-agent hex, link headers)
            text = MacSpaceRx.Replace(text, delegate(Match m)
            {
                MapEntry e = macs.Find(MacHex(m.Value) ?? "");
                if (e == null) return m.Value;
                e.Matches++;
                return ApplyCase(m.Value, DisplayMac(MacHex(e.Replacement)).Replace(':', ' '));
            });
            if (macs.Map.Count > 20000) return text;
            return ByteRunRx.Replace(text, delegate(Match m)
            {
                string run = m.Value;
                int start = run.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0;
                StringBuilder hex = new StringBuilder();
                List<int> pos = new List<int>();
                for (int i = start; i < run.Length; i++) if (IsHex(run[i])) { hex.Append(char.ToUpperInvariant(run[i])); pos.Add(i); }
                if (hex.Length % 2 != 0 || hex.Length < 12) return run;
                string h = hex.ToString();
                char[] outc = run.ToCharArray();
                bool changed = false;
                for (int b = 0; b + 12 <= h.Length; b += 2)
                {
                    MapEntry e = macs.Find(h.Substring(b, 12));
                    if (e == null) continue;
                    string r = MacHex(e.Replacement);
                    for (int j = 0; j < 12; j++)
                    {
                        char rc = r[j];
                        outc[pos[b + j]] = char.IsLower(run[pos[b + j]]) ? char.ToLowerInvariant(rc) : rc;
                    }
                    e.Matches++;
                    changed = true;
                    b += 10;
                }
                return changed ? new string(outc) : run;
            });
        }

        private string ReplaceLdif(Match m)
        {
            string attr = m.Groups["k"].Value, b64 = m.Groups["v"].Value;
            byte[] bytes;
            try { bytes = Convert.FromBase64String(b64); } catch (FormatException) { return m.Value; }
            string repl = null;
            if (attr.Equals("objectSid", StringComparison.OrdinalIgnoreCase))
            {
                string sid = SidFromBytes(bytes);
                if (sid == null) return m.Value;
                string scrubbed = ScrubText(sid);
                if (scrubbed != sid) { byte[] nb = SidToBytes(scrubbed); if (nb != null) repl = Convert.ToBase64String(nb); }
            }
            else
            {
                string t = DecodeUtf8Text(bytes);
                if (t == null) return m.Value;
                string scrubbed = ScrubText(t);
                if (scrubbed != t) repl = Convert.ToBase64String(Encoding.UTF8.GetBytes(scrubbed));
            }
            if (repl == null) return m.Value;
            Group g = m.Groups["v"];
            return m.Value.Substring(0, g.Index - m.Index) + repl + m.Value.Substring(g.Index - m.Index + g.Length);
        }

        private string ReplaceDnsWire(Match m)
        {
            string name = DecodeDnsWire(m.Value);
            if (name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
            {
                string mapped = InAddrRx.Replace(name, ReplaceInAddr);
                if (mapped == name) return m.Value;
                return EncodeDnsWire(mapped);
            }
            DottedObs o;
            bool fih = dotted.TryGetValue(name, out o) ? o.FirstIsHost : hosts.Find(name.Split('.')[0]) != null;
            string composed = ComposeDotted(name, fih);
            if (string.Equals(composed, name, StringComparison.Ordinal)) return m.Value;
            if (o != null && o.Entry != null) o.Entry.Matches++;
            return EncodeDnsWire(composed);
        }

        private static string EncodeDnsWire(string name)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string l in name.Split('.')) sb.Append('(').Append(l.Length.ToString(CultureInfo.InvariantCulture)).Append(')').Append(l);
            sb.Append("(0)");
            return sb.ToString();
        }

        private string ReplaceInAddr(Match m)
        {
            string[] o = m.Groups["o"].Value.TrimEnd('.').Split('.');
            Array.Reverse(o);
            string mapped = null;
            if (o.Length == 4)
            {
                MapEntry e = ipv4.Find(CanonicalIPv4(string.Join(".", o)) ?? "");
                if (e != null) { e.Matches++; mapped = e.Replacement; }
            }
            else if (o.Length == 3)
            {
                MapEntry e = subnets.Find(o[0] + "." + o[1] + "." + o[2]);
                if (e != null) { e.Matches++; mapped = e.Replacement.Substring(0, e.Replacement.IndexOf(".0/", StringComparison.Ordinal)); }
            }
            if (mapped == null) return m.Value;
            string[] r = mapped.Split('.');
            Array.Reverse(r);
            return string.Join(".", r) + "." + m.Value.Substring(m.Groups["o"].Length);
        }

        private string ReplaceDn(Match m)
        {
            string dn = m.Value;
            MatchCollection comps = DnCompRx.Matches(dn);
            int lastDc = -1;
            for (int i = 0; i < comps.Count; i++) if (comps[i].Groups["k"].Value.Equals("DC", StringComparison.OrdinalIgnoreCase)) lastDc = i;
            StringBuilder sb = new StringBuilder(dn.Length);
            int copied = 0;
            bool changed = false;
            for (int i = 0; i < comps.Count; i++)
            {
                Match c = comps[i];
                Group vg = c.Groups["v"];
                string k = c.Groups["k"].Value.ToUpperInvariant();
                string trimmed = vg.Value.TrimEnd();
                string val = DnUnescape(trimmed);
                string repl = null;
                MapEntry e = null;
                switch (k)
                {
                    case "DC":
                        if (!(i == lastDc && tlds.ContainsKey(val)) && !IsKeepLabel(val)) e = domains.Find(val);
                        break;
                    case "OU": e = ous.Find(val); break;
                    case "O": e = orgs.Find(val) ?? orgs.Find(val.TrimEnd('.')); break;
                    case "L":
                    case "ST":
                    case "S":
                    case "STREET": e = locations.Find(val); break;
                    case "E":
                        {
                            Literal lit;
                            if (literals.TryGetValue(val, out lit) && lit.Kind == Literal.Email) { lit.Entry.Matches++; repl = ComposeEmail(val); }
                            break;
                        }
                    case "CN":
                    case "UID":
                        {
                            MapEntry pe;
                            if (personAlias.TryGetValue(val, out pe)) e = pe;
                            else
                            {
                                Literal lit;
                                if (literals.TryGetValue(val, out lit)) { lit.Entry.Matches++; repl = Render(lit, val); }
                                else if (phraseMap.TryGetValue(val, out pe)) e = pe;
                            }
                            break;
                        }
                }
                if (e != null) { e.Matches++; repl = ApplyCase(val, e.Replacement); }
                if (repl == null) continue;
                sb.Append(dn, copied, vg.Index - copied);
                sb.Append(repl);
                copied = vg.Index + trimmed.Length;
                changed = true;
            }
            if (!changed) return dn;
            sb.Append(dn, copied, dn.Length - copied);
            return sb.ToString();
        }

        private string ReplacePhrase(Match m)
        {
            string key = NormalizePhrase(m.Value);
            MapEntry e;
            if (!phraseMap.TryGetValue(key, out e)) return m.Value;
            e.Matches++;
            return ApplyCase(m.Value, e.Replacement);
        }

        private string ReplacePhraseTrunc(Match m)
        {
            string full;
            MapEntry e;
            if (!phraseTruncMap.TryGetValue(NormalizePhrase(m.Value), out full) || !phraseMap.TryGetValue(full, out e)) return m.Value;
            e.Matches++;
            return ApplyCase(m.Value, e.Replacement);
        }

        private static bool IsEncodedBoundary(string s, int i)
        {
            // %5Cjsmith (URL-encoded) or \njsmith (JSON escape) count as a word boundary
            if (i >= 3 && s[i - 3] == '%' && IsHex(s[i - 2]) && IsHex(s[i - 1])) return true;
            if (i >= 2 && s[i - 2] == '\\' && (s[i - 1] == 'n' || s[i - 1] == 'r' || s[i - 1] == 't')) return true;
            return false;
        }

        private string ReplaceLiterals(string s)
        {
            if (literals.Count == 0) return s;
            int n = s.Length;
            StringBuilder sb = null;
            int copied = 0;
            int[] ends = new int[Math.Max(1, maxLiteralLength + 1)];
            int i = 0;
            while (i < n)
            {
                char c = s[i];
                if (!(IsAlnum(c) || c == ':' || c == '_')) { i++; continue; }
                bool encoded = false;
                if (i > 0 && IsAlnum(s[i - 1]))
                {
                    if (!IsEncodedBoundary(s, i)) { i++; continue; }
                    encoded = true;
                }

                // candidate end positions: inside the current "word", right before a non-alphanumeric char
                int endCount = 0;
                int limit = Math.Min(n, i + maxLiteralLength);
                int j = i;
                while (j < limit && IsWordChar(s[j]))
                {
                    j++;
                    if ((j == n || !IsAlnum(s[j])) && literalLengths[j - i]) ends[endCount++] = j;
                }

                bool matched = false;
                for (int k = endCount - 1; k >= 0; k--)
                {
                    int end = ends[k];
                    Literal lit;
                    if (!literals.TryGetValue(s.Substring(i, end - i), out lit)) continue;
                    char prev = (i > 0 && !encoded) ? s[i - 1] : ' ';
                    char next = end < n ? s[end] : ' ';
                    // WEB01 must not match inside OLD-WEB01-X for short plain words, but distinctive names (digits / 6+ chars) do
                    if (lit.NameLike && (prev == '-' || next == '-') && !HyphenOk(lit, s, i, end)) continue;
                    if (lit.IpLike && (prev == '.' || (next == '.' && end + 1 < n && char.IsDigit(s[end + 1])))) continue;
                    if (lit.IpLike && end + 8 <= n && string.Compare(s, end, ".in-addr", 0, 8, StringComparison.OrdinalIgnoreCase) == 0) continue;

                    string matchText = s.Substring(i, end - i);
                    string repl = Render(lit, matchText);
                    lit.Entry.Matches++;
                    if (sb == null) sb = new StringBuilder(n + 64);
                    sb.Append(s, copied, i - copied);
                    sb.Append(repl);
                    copied = end;
                    i = end;
                    matched = true;
                    break;
                }
                if (!matched && prefixIndex.Count > 0 && (i == 0 || s[i - 1] != '-'))
                {
                    int newPos = TryPrefix(s, i, ref sb, ref copied);
                    if (newPos > i) { i = newPos; matched = true; }
                }
                if (!matched) i++;
            }
            if (sb == null) return s;
            sb.Append(s, copied, n - copied);
            return sb.ToString();
        }

        /// <summary>Truncated ("WEB01.corp.con...") or wrapped (Format-List continuation line) value.</summary>
        private int TryPrefix(string s, int i, ref StringBuilder sb, ref int copied)
        {
            int n = s.Length;
            int wEnd = i;
            while (wEnd < n && IsWordChar(s[wEnd])) wEnd++;
            int k = wEnd;
            while (k > i && s[k - 1] == '.') k--;
            int dots = wEnd - k;
            bool truncated = dots >= 3 || (wEnd < n && s[wEnd] == '\u2026');
            if (k - i < 3) return i;
            string w = s.Substring(i, k - i);
            PrefixHit hit;
            if (!prefixIndex.TryGetValue(w, out hit)) return i;

            if (truncated)
            {
                if (sb == null) sb = new StringBuilder(n + 64);
                sb.Append(s, copied, i - copied);
                sb.Append(Render(hit.Lit, hit.FullKey));
                hit.Lit.Entry.Matches++;
                copied = k;
                return k;
            }
            if (dots > 0 || w.Length < 4) return i;
            // wrapped: "...DC=nwtrad" + newline + spaces + "ers,DC=local"
            int p = k;
            if (p < n && s[p] == '\r') p++;
            if (p >= n || s[p] != '\n') return i;
            p++;
            int spaces = 0;
            while (p < n && s[p] == ' ') { p++; spaces++; }
            if (spaces < 8) return i;
            string rem = hit.FullKey.Substring(w.Length);
            if (p + rem.Length > n || string.Compare(s, p, rem, 0, rem.Length, StringComparison.OrdinalIgnoreCase) != 0) return i;
            if (p + rem.Length < n && IsAlnum(s[p + rem.Length]) && IsAlnum(rem[rem.Length - 1])) return i;
            if (sb == null) sb = new StringBuilder(n + 64);
            sb.Append(s, copied, i - copied);
            sb.Append(Render(hit.Lit, hit.FullKey));
            sb.Append(s, k, (p - k));
            hit.Lit.Entry.Matches++;
            copied = p + rem.Length;
            return copied;
        }

        private string Render(Literal lit, string matchText)
        {
            switch (lit.Kind)
            {
                case Literal.Dotted: return ComposeDotted(matchText, lit.FirstIsHost);
                case Literal.Email: return ComposeEmail(matchText);
                default: return ApplyCase(matchText, lit.Fixed ?? lit.Entry.Replacement);
            }
        }

        private string ComposeDotted(string raw, bool firstIsHost)
        {
            string[] labels = raw.Split('.');
            int psl = PublicSuffixCount(labels);
            for (int i = 0; i < labels.Length; i++)
            {
                string l = labels[i];
                if (KeepLabelAt(labels, i, psl)) continue;
                MapEntry e = (i == 0 && firstIsHost) ? hosts.Find(l) : domains.Find(l);
                if (e == null) e = (i == 0 && firstIsHost) ? domains.Find(l) : hosts.Find(l);
                if (e != null) labels[i] = ApplyCase(l, e.Replacement);
            }
            return string.Join(".", labels);
        }

        private string ComposeEmail(string raw)
        {
            int at = raw.IndexOf('@');
            if (at <= 0) return raw;
            string local = raw.Substring(0, at);
            string domain = raw.Substring(at + 1);
            MapEntry u = users.Find(local);
            string l2 = u != null ? ApplyCase(local, u.Replacement) : local;
            string d2 = IsExcludedDomain(domain) ? domain : ComposeDotted(domain, false);
            return l2 + "@" + d2;
        }

        // =========================================================================================
        // Audit
        // =========================================================================================

        /// <summary>
        /// Prepares a post-scrub audit: an Aho-Corasick search for every original name (relaxed boundaries) plus a fresh
        /// detector run whose findings are compared with the replacement ranges.
        /// </summary>
        public AuditSession CreateAudit()
        {
            if (dirty) BuildIndex();
            AuditSession a = new AuditSession(this);
            Dictionary<string, string> needles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            AddNeedles(needles, hosts, "Hostname", true);
            AddNeedles(needles, users, "User", false);
            AddNeedles(needles, domains, "DomainLabel", false);
            AddNeedles(needles, custom, "Custom", false);
            AddNeedles(needles, orgs, "Organization", false);
            AddNeedles(needles, locations, "Location", false);
            AddNeedles(needles, pii, "PII", false);
            foreach (string p in personAlias.Keys) if (!needles.ContainsKey(p)) needles[p] = "Person";
            foreach (string s in secretRaw.Keys) if (s.Length >= 4 && !needles.ContainsKey(s)) needles[s] = "Secret";
            foreach (DottedObs o in dottedOrder) if (!needles.ContainsKey(o.Raw) && !string.Equals(o.Entry.Replacement, o.Raw, StringComparison.OrdinalIgnoreCase)) needles[o.Raw] = o.FirstIsHost ? "FQDN" : "DomainName";
            foreach (EmailObs o in emailOrder) if (!needles.ContainsKey(o.Raw) && !string.Equals(o.Entry.Replacement, o.Raw, StringComparison.OrdinalIgnoreCase)) needles[o.Raw] = "Email";
            foreach (KeyValuePair<string, string> kv in needles) a.AddNeedle(kv.Key, kv.Value);
            return a;
        }

        private void AddNeedles(Dictionary<string, string> needles, Table t, string kind, bool skipWeak)
        {
            foreach (MapEntry e in t.Order)
            {
                if (e.Original.Length < Math.Max(4, MinBareLength)) continue;
                if (skipWeak && weakHosts.ContainsKey(e.Original)) continue;
                if (t == domains && commonWords.ContainsKey(e.Original) && !strongDomains.ContainsKey(e.Original)) continue;
                if (!needles.ContainsKey(e.Original)) needles[e.Original] = kind;
            }
        }

        /// <summary>True when a value found in scrubbed output is one of our replacement values (or deliberately kept).</summary>
        internal bool IsReplacementValue(MapEntry e)
        {
            string v = e.Original;
            switch (e.Type)
            {
                case "IPv4":
                    {
                        string[] p = v.Split('.');
                        int a, b;
                        if (p.Length != 4) return false;
                        if (int.TryParse(p[0], out a) && int.TryParse(p[1], out b) && ((a == 198 && (b == 18 || b == 19)) || a >= 240)) return true;
                        // reversed (in-addr.arpa) form of a replacement address
                        return int.TryParse(p[3], out a) && int.TryParse(p[2], out b) && ((a == 198 && (b == 18 || b == 19)) || a >= 240);
                    }
                case "IPv4Subnet": return true;
                case "IPv6": return v.StartsWith("2001:db8:", StringComparison.OrdinalIgnoreCase) || v.StartsWith("::ffff:198.1", StringComparison.OrdinalIgnoreCase) || (v.StartsWith("fe80::", StringComparison.OrdinalIgnoreCase) && v.Length <= 16);
                case "IPv6Prefix": return v.StartsWith("2001:db8:", StringComparison.OrdinalIgnoreCase);
                case "MAC": return v.StartsWith("02:00:00", StringComparison.OrdinalIgnoreCase) || KeepMacVendor;
                case "SID": return v.IndexOf("1111111111-2222222222", StringComparison.Ordinal) >= 0;
                case "Guid": return v.StartsWith("00000000-0000-4000-8000-", StringComparison.OrdinalIgnoreCase);
                case "CloudAccount": return v.StartsWith("1000000", StringComparison.Ordinal);
                case "ForestOid": return v.StartsWith("1000000.", StringComparison.Ordinal);
                case "Secret": return false;
                case "HostLabel": return true;
                case "FQDN":
                case "DomainName":
                    {
                        string[] labels = v.Split('.');
                        int psl = PublicSuffixCount(labels);
                        for (int i = 0; i < labels.Length; i++) if (!IsTokenValue(labels[i]) && !KeepLabelAt(labels, i, psl)) return false;
                        return true;
                    }
                case "Email":
                    {
                        int at = v.IndexOf('@');
                        string local = at > 0 ? v.Substring(0, at) : v;
                        if (!IsTokenValue(local) && !ignoreNames.ContainsKey(local) && HasLetter(local)) return false;
                        string dom = v.Substring(at + 1);
                        if (IsExcludedDomain(dom)) return true;
                        foreach (string l in dom.Split('.')) if (!IsTokenValue(l) && !IsKeepLabel(l) && !tlds.ContainsKey(l)) return false;
                        return true;
                    }
                default:
                    foreach (string part in v.Split(new char[] { '@', '\\', '$', '_', '.' }, StringSplitOptions.RemoveEmptyEntries))
                        if (!IsTokenValue(part) && !IsKeepLabel(part) && !tlds.ContainsKey(part) && !IsExcludedDomain(part) && !IgnoredUserRx.IsMatch(part)) return false;
                    return true;
            }
        }

        // =========================================================================================
        // Results
        // =========================================================================================

        public List<MapEntry> GetEntries()
        {
            if (dirty) BuildIndex();
            List<MapEntry> all = new List<MapEntry>();
            foreach (MapEntry e in hosts.Order) e.Type = weakHosts.ContainsKey(e.Original) ? "HostLabel" : "Hostname";
            foreach (MapEntry e in domains.Order)
                e.Type = strongDomains.ContainsKey(e.Original) ? "DomainLabel" : (commonWords.ContainsKey(e.Original) ? "DomainWord" : "DomainPart");
            all.AddRange(hosts.Order);
            foreach (DottedObs o in dottedOrder) if (o.Entry != null && o.Entry.Type == "FQDN") all.Add(o.Entry);
            all.AddRange(domains.Order);
            foreach (DottedObs o in dottedOrder) if (o.Entry != null && o.Entry.Type == "DomainName") all.Add(o.Entry);
            all.AddRange(users.Order);
            all.AddRange(persons.Order);
            all.AddRange(nameParts.Order);
            all.AddRange(pii.Order);
            foreach (EmailObs o in emailOrder) if (o.Entry != null) all.Add(o.Entry);
            all.AddRange(orgs.Order);
            all.AddRange(ous.Order);
            all.AddRange(locations.Order);
            all.AddRange(ipv4.Order);
            all.AddRange(subnets.Order);
            all.AddRange(ipv6.Order);
            all.AddRange(v6prefixes.Order);
            all.AddRange(macs.Order);
            all.AddRange(sids.Order);
            all.AddRange(guids.Order);
            all.AddRange(accounts.Order);
            all.AddRange(forestOids.Order);
            all.AddRange(secrets.Order);
            all.AddRange(custom.Order);
            return all;
        }

        /// <summary>Writes the correlation sheet (UTF-8 with BOM so Excel shows non-ASCII text correctly).</summary>
        public int WriteCorrelationCsv(string path)
        {
            List<MapEntry> all = GetEntries();
            using (StreamWriter sw = new StreamWriter(path, false, new UTF8Encoding(true)))
            {
                sw.NewLine = "\r\n";
                sw.WriteLine("\"Type\",\"Original\",\"Replacement\",\"MatchesThisRun\",\"FirstSeenIn\"");
                foreach (MapEntry e in all)
                {
                    sw.Write(CsvField(e.Type)); sw.Write(',');
                    sw.Write(CsvField(e.Original)); sw.Write(',');
                    sw.Write(CsvField(e.Replacement)); sw.Write(',');
                    sw.Write(CsvField(e.Matches.ToString(CultureInfo.InvariantCulture))); sw.Write(',');
                    sw.WriteLine(CsvField(e.FirstSeenIn));
                }
            }
            return all.Count;
        }

        /// <summary>Loads an existing correlation sheet. Returns the number of rows loaded.</summary>
        public int LoadCorrelationCsv(string path)
        {
            int loaded = 0;
            using (StreamReader sr = new StreamReader(path, Encoding.UTF8, true))
            {
                List<string> header = ReadCsvRecord(sr);
                if (header == null) return 0;
                int iType = header.IndexOf("Type"), iOrig = header.IndexOf("Original"), iRepl = header.IndexOf("Replacement"), iSeen = header.IndexOf("FirstSeenIn");
                if (iType < 0 || iOrig < 0 || iRepl < 0)
                    throw new InvalidDataException(path + " is not a correlation sheet (needs Type, Original, Replacement columns).");
                List<string> rec;
                while ((rec = ReadCsvRecord(sr)) != null)
                {
                    if (rec.Count <= Math.Max(iType, Math.Max(iOrig, iRepl))) continue;
                    LoadEntry(rec[iType], rec[iOrig], rec[iRepl], (iSeen >= 0 && iSeen < rec.Count) ? rec[iSeen] : null);
                    loaded++;
                }
            }
            return loaded;
        }

        private static List<string> ReadCsvRecord(TextReader r)
        {
            int c = r.Peek();
            if (c < 0) return null;
            List<string> fields = new List<string>();
            StringBuilder sb = new StringBuilder();
            bool quoted = false, any = false;
            while ((c = r.Read()) >= 0)
            {
                any = true;
                char ch = (char)c;
                if (quoted)
                {
                    if (ch == '"')
                    {
                        if (r.Peek() == '"') { r.Read(); sb.Append('"'); }
                        else quoted = false;
                    }
                    else sb.Append(ch);
                }
                else if (ch == '"') quoted = true;
                else if (ch == ',') { fields.Add(sb.ToString()); sb.Length = 0; }
                else if (ch == '\r') { if (r.Peek() == '\n') r.Read(); break; }
                else if (ch == '\n') break;
                else sb.Append(ch);
            }
            if (!any) return null;
            fields.Add(sb.ToString());
            return fields;
        }

        /// <summary>Number of correlation entries per type, in sheet order.</summary>
        public List<KeyValuePair<string, int>> GetTypeCounts()
        {
            List<KeyValuePair<string, int>> result = new List<KeyValuePair<string, int>>();
            Dictionary<string, int> index = new Dictionary<string, int>();
            foreach (MapEntry e in GetEntries())
            {
                int i;
                if (index.TryGetValue(e.Type, out i)) result[i] = new KeyValuePair<string, int>(e.Type, result[i].Value + 1);
                else { index[e.Type] = result.Count; result.Add(new KeyValuePair<string, int>(e.Type, 1)); }
            }
            return result;
        }

        private static string CsvField(string s)
        {
            string v = s ?? string.Empty;
            // neutralise spreadsheet formulas (CSV injection) in values that came from logs
            if (v.Length > 0 && (v[0] == '=' || v[0] == '+' || v[0] == '@' || (v[0] == '-' && v.Length > 1 && !char.IsDigit(v[1])))) v = "'" + v;
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        }

        // =========================================================================================
        // Helpers
        // =========================================================================================

        private static readonly Dictionary<string, bool> TokenPrefixes = Words("HOST DOMAIN USER PERSON NAME PII REDACTED ORG OU LOCATION SECRET");

        /// <summary>True for replacement tokens such as HOST-0001 / user-0042 (case-insensitive).</summary>
        private static readonly Regex ContainsTokenRx = new Regex(@"(?<![A-Za-z0-9])(?:HOST|DOMAIN|USER|PERSON|NAME|PII|REDACTED|ORG|OU|LOCATION|SECRET)-\d{4,}(?![0-9])|00000000-0000-4000-8000-[0-9a-f]{12}|1111111111-2222222222", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>True when the value already contains one of our replacement tokens (scrubbed text being re-scanned).</summary>
        private static bool ContainsToken(string v)
        {
            return v.IndexOf('-') > 0 && ContainsTokenRx.IsMatch(v);
        }

        private static bool IsTokenValue(string v)
        {
            int dash = v.IndexOf('-');
            if (dash < 2 || v.Length - dash - 1 < 4) return false;
            for (int i = dash + 1; i < v.Length; i++) if (v[i] < '0' || v[i] > '9') return false;
            return TokenPrefixes.ContainsKey(v.Substring(0, dash));
        }

        internal static bool IsAlnum(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        }

        private static bool IsWordChar(char c)
        {
            return IsAlnum(c) || c == '.' || c == '-' || c == ':' || c == '@' || c == '_';
        }

        private static bool IsWordLiteral(string s)
        {
            if (s.Length == 0 || !IsAlnum(s[0]) || !IsAlnum(s[s.Length - 1])) return false;
            foreach (char c in s) if (!IsWordChar(c)) return false;
            return true;
        }

        private static bool HasLetter(string s)
        {
            foreach (char c in s) if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return true;
            return false;
        }

        private static bool HasDigit(string s)
        {
            foreach (char c in s) if (c >= '0' && c <= '9') return true;
            return false;
        }

        /// <summary>
        /// May a literal touch a '-' (tailspin-toys, WEB01-old, svc-jenkins-github)? Yes for organisation, domain and
        /// custom names and for names that contain a digit, '-', '.' or '_'; no for plain host / user words ("catalog").
        /// </summary>
        private bool HyphenOk(Literal lit, string s, int from, int to)
        {
            for (int i = from; i < to; i++) { char c = s[i]; if ((c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') return true; }
            string t = lit.Entry.Type;
            if (t == "Organization" || t == "Custom" || t == "NamePart") return true;
            if (t == "DomainLabel" && !commonWords.ContainsKey(lit.Entry.Original)) return true;
            return false;
        }

        private static bool HasDigitIn(string s, int from, int to)
        {
            for (int i = from; i < to; i++) if (s[i] >= '0' && s[i] <= '9') return true;
            return false;
        }

        private static bool HasHexLetter(string s)
        {
            foreach (char c in s) if ((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) return true;
            return false;
        }

        private static string TrimDots(string s)
        {
            return s == null ? string.Empty : s.Trim().Trim('.');
        }

        private static bool LooksLikeMachineName(string s)
        {
            return HasLetter(s) && (HasDigit(s) || s.IndexOf('-') > 0);
        }

        private bool LooksLikeFqdn(string s)
        {
            string[] labels = s.Split('.');
            return labels.Length >= 2 && tlds.ContainsKey(labels[labels.Length - 1]) && HasLetter(labels[0]);
        }

        private static bool LooksLikeIPv4(string s)
        {
            foreach (char c in s) if (!(char.IsDigit(c) || c == '.')) return false;
            return true;
        }

        /// <summary>Keep the case style of the original: all-lower stays lower, all-upper stays upper.</summary>
        private static string ApplyCase(string original, string replacement)
        {
            bool lower = false, upper = false;
            foreach (char c in original)
            {
                if (char.IsLower(c)) lower = true;
                else if (char.IsUpper(c)) upper = true;
            }
            if (lower && !upper) return replacement.ToLowerInvariant();
            if (upper && !lower) return replacement.ToUpperInvariant();
            return replacement;
        }

        private bool IsKeepLabel(string l)
        {
            if (l.Length == 0 || l[0] == '_' || !HasLetter(l) || publicTlds.ContainsKey(l)) return true;
            return ignoreNames.ContainsKey(l) || excludeValues.ContainsKey(l);
        }

        private bool IsExcludedValue(string v)
        {
            return excludeValues.ContainsKey(v);
        }

        private bool IsExcludedDomain(string fqdn)
        {
            string f = fqdn.ToLowerInvariant().TrimEnd('.');
            string[] labels = f.Split('.');
            int psl = PublicSuffixCount(labels);
            if (psl > 0 && labels.Length > psl && !commonWords.ContainsKey(labels[labels.Length - psl - 1]) && !ignoreNames.ContainsKey(labels[labels.Length - psl - 1])) return false;
            foreach (string d in excludeDomains)
                if (f == d || f.EndsWith("." + d, StringComparison.Ordinal)) return true;
            return false;
        }

        private bool IsAutoTld(string label)
        {
            if (!tlds.ContainsKey(label)) return false;
            return label == label.ToLowerInvariant() || label == label.ToUpperInvariant();
        }

        private static bool IsExtLike(string label)
        {
            if (label.Length < 1 || label.Length > 4) return false;
            foreach (char c in label) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
            return true;
        }

        private static bool CaseConsistent(string[] labels, int tldIdx)
        {
            string tld = labels[tldIdx];
            if (tld == tld.ToLowerInvariant()) return true;
            for (int i = 0; i <= tldIdx; i++)
                foreach (char c in labels[i]) if (c >= 'a' && c <= 'z') return false;
            return true;
        }

        private static string SidKey(Match m)
        {
            return m.Groups[1].Value + "-" + m.Groups[2].Value + "-" + m.Groups[3].Value;
        }

        private static string AadSidKey(Match m)
        {
            return "aad:" + m.Groups[1].Value + "-" + m.Groups[2].Value + "-" + m.Groups[3].Value + "-" + m.Groups[4].Value;
        }

        private static string SubnetKeyFromDisplay(string display)
        {
            // "10.20.30.0/24" -> "10.20.30"
            string s = display;
            int slash = s.IndexOf('/');
            if (slash >= 0) s = s.Substring(0, slash);
            string[] p = s.Split('.');
            if (p.Length < 3) return null;
            return p[0] + "." + p[1] + "." + p[2];
        }

        private static string V6PrefixKeyFromDisplay(string display)
        {
            int slash = display.IndexOf('/');
            IPAddress a;
            if (!IPAddress.TryParse(slash >= 0 ? display.Substring(0, slash) : display, out a)) return null;
            byte[] b = a.GetAddressBytes();
            StringBuilder pk = new StringBuilder(16);
            for (int i = 0; i < 8; i++) pk.Append(b[i].ToString("x2", CultureInfo.InvariantCulture));
            return pk.ToString();
        }

        private static string PoolSubnet(int idx)
        {
            // 198.18.0.0/15 (RFC 2544 benchmarking, never routed) then 240.0.0.0/4 (reserved).
            if (idx < 512) return "198." + (18 + idx / 256).ToString(CultureInfo.InvariantCulture) + "." + (idx % 256).ToString(CultureInfo.InvariantCulture);
            int k = idx - 512;
            return (240 + k / 65536).ToString(CultureInfo.InvariantCulture) + "." + ((k / 256) % 256).ToString(CultureInfo.InvariantCulture) + "." + (k % 256).ToString(CultureInfo.InvariantCulture);
        }

        private static string Canonical6(IPAddress a)
        {
            string s = a.ToString().ToLowerInvariant();
            int pct = s.IndexOf('%');
            return pct >= 0 ? s.Substring(0, pct) : s;
        }

        private static string MacFromIndex(int n)
        {
            // 02:xx:xx:xx:xx:xx = locally administered, never assigned to real hardware.
            return DisplayMac("0200" + n.ToString("X8", CultureInfo.InvariantCulture));
        }

        private static string MacHex(string raw)
        {
            StringBuilder sb = new StringBuilder(12);
            foreach (char c in raw)
            {
                if (IsHex(c)) sb.Append(char.ToUpperInvariant(c));
                else if (c != ':' && c != '-' && c != '.' && c != ' ') return null;
            }
            return sb.Length == 12 ? sb.ToString() : null;
        }

        private static string DisplayMac(string hex)
        {
            StringBuilder sb = new StringBuilder(17);
            for (int i = 0; i < 12; i += 2)
            {
                if (i > 0) sb.Append(':');
                sb.Append(hex, i, 2);
            }
            return sb.ToString();
        }

        private static string FormatMacLike(string raw, string replacementDisplay)
        {
            string hex = MacHex(replacementDisplay);
            if (hex == null) return replacementDisplay;
            if (raw.IndexOf('.') >= 0) return hex.Substring(0, 4) + "." + hex.Substring(4, 4) + "." + hex.Substring(8, 4);
            if (raw.IndexOf('-') >= 0) return DisplayMac(hex).Replace(':', '-');
            if (raw.IndexOf(':') >= 0) return DisplayMac(hex);
            return hex;
        }
    }

    /// <summary>Post-scrub verification of output files.</summary>
    public sealed class AuditSession
    {
        private readonly ScrubEngine owner;
        private readonly ScrubEngine fresh;
        private readonly AhoCorasick ac = new AhoCorasick();
        private readonly List<string> kinds = new List<string>();
        private readonly List<AuditFinding> findings = new List<AuditFinding>();
        public int MaxFindingsPerFile = 200;

        internal AuditSession(ScrubEngine owner)
        {
            this.owner = owner;
            fresh = owner.CloneConfiguration();
        }

        internal void AddNeedle(string value, string kind)
        {
            ac.Add(value);
            kinds.Add(kind);
        }

        public int NeedleCount { get { return ac.Count; } }

        public void AuditFile(string path, TextFileInfo info, string label)
        {
            long lineBase = 0;
            int count = 0;
            ColumnState cs = new ColumnState();
            ReadAll(path, info, delegate(string block)
            {
                fresh.ScanBlock(block, label, cs);
                if (ac.Count > 0 && count < MaxFindingsPerFile)
                {
                    string lower = block.ToLowerInvariant();
                    long lb = lineBase;
                    ac.Search(lower, delegate(int p, int end)
                    {
                        if (count >= MaxFindingsPerFile) return;
                        string pat = ac.Pattern(p);
                        int start = end - pat.Length;
                        bool plain = !HasDigitOrDash(pat) && pat.IndexOf('.') < 0 && pat.IndexOf('_') < 0;
                        bool leftOk = start == 0 || (!ScrubEngine.IsAlnum(block[start - 1]) && !(plain && block[start - 1] == '-'));
                        bool rightOk = end >= block.Length || (!ScrubEngine.IsAlnum(block[end]) && !(plain && block[end] == '-'));
                        string kind;
                        if (leftOk && rightOk) kind = "Leak:" + kinds[p];
                        else if (pat.Length >= 8 || (pat.Length >= 6 && (HasDigitOrDash(pat)))) kind = "Embedded:" + kinds[p];
                        else return;
                        AuditFinding f = new AuditFinding();
                        f.File = label;
                        f.Line = lb + 1 + CountNl(block, start);
                        f.Kind = kind;
                        f.Value = block.Substring(start, pat.Length);
                        f.Context = Snip(block, start, pat.Length);
                        findings.Add(f);
                        count++;
                    });
                }
                lineBase += CountNl(block, block.Length);
            });
        }

        private static void ReadAll(string path, TextFileInfo info, Action<string> onBlock)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (Stream st = info.IsGzip ? (Stream)new GZipStream(fs, CompressionMode.Decompress) : fs)
            using (StreamReader sr = new StreamReader(st, info.WriteEncoding, true, 1 << 16))
            {
                char[] buf = new char[1 << 20];
                StringBuilder pending = new StringBuilder();
                int n;
                while ((n = sr.Read(buf, 0, buf.Length)) > 0)
                {
                    int lastNl = -1;
                    for (int k = n - 1; k >= 0; k--) { if (buf[k] == '\n') { lastNl = k; break; } }
                    if (lastNl < 0) { pending.Append(buf, 0, n); continue; }
                    pending.Append(buf, 0, lastNl + 1);
                    onBlock(pending.ToString());
                    pending.Length = 0;
                    pending.Append(buf, lastNl + 1, n - lastNl - 1);
                }
                if (pending.Length > 0) onBlock(pending.ToString());
            }
        }

        private static bool HasDigitOrDash(string s)
        {
            foreach (char c in s) if (char.IsDigit(c) || c == '-') return true;
            return false;
        }

        private static long CountNl(string s, int upTo)
        {
            long n = 0;
            for (int i = 0; i < upTo && i < s.Length; i++) if (s[i] == '\n') n++;
            return n;
        }

        private static string Snip(string s, int start, int len)
        {
            int a = Math.Max(0, start - 40), b = Math.Min(s.Length, start + len + 40);
            return s.Substring(a, b - a).Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
        }

        /// <summary>All findings: original values still present plus unexpected values detected in the output.</summary>
        public List<AuditFinding> Finish()
        {
            List<AuditFinding> all = new List<AuditFinding>(findings);
            foreach (MapEntry e in fresh.GetEntries())
            {
                if (owner.IsReplacementValue(e)) continue;
                AuditFinding f = new AuditFinding();
                f.File = e.FirstSeenIn;
                f.Line = 0;
                f.Kind = "Detected:" + e.Type;
                f.Value = e.Type == "Secret" ? "(secret-like value, see file)" : e.Original;
                f.Context = string.Empty;
                all.Add(f);
            }
            return all;
        }
    }
}
