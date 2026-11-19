// ---------------------------------------------------------------------------------------------
// LogScrubEngine.cs - core engine used by Invoke-LogScrub.ps1
//
// Compiled at runtime with Add-Type. Written to C# 5 / .NET Framework 4.5 level so it compiles
// under Windows PowerShell 5.1 as well as PowerShell 7+ (.NET 6/8). Avoid newer language features
// (string interpolation, ?. , out var, expression bodies, etc.) and System.Core-only types
// (HashSet, LINQ) when editing this file.
//
// How it works
//   Pass 1 (ScanFile / ScanText): regex detectors discover sensitive values (IPs, MACs, FQDNs,
//          host/user/domain names from key=value context, UNC paths, DOMAIN\user, e-mail, SIDs)
//          and assign each a stable replacement token.
//   Pass 2 (ScrubFile / ScrubText): every discovered value is replaced everywhere it occurs,
//          including bare mentions (e.g. "WEB01" on its own after "web01.corp.contoso.com" was
//          seen), using a fast literal lookup so tokens are consistent across all files.
// ---------------------------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
        public bool CanFallBack;
        public string EncodingName;
        public Encoding ReadEncoding;
        public Encoding WriteEncoding;
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

    internal sealed class DottedObs
    {
        public string Raw;
        public int Hint;
        public bool FirstIsHost;
        public string Source;
        public MapEntry Entry;
    }

    internal sealed class EmailObs
    {
        public string Raw;
        public string Local;
        public string Domain;
        public string Source;
        public MapEntry Entry;
    }

    public sealed class ScrubEngine
    {
        public const string EngineVersion = "1.0.0";

        // ----- options (set from PowerShell) -----
        public bool ScrubIPv4 = true;
        public bool ScrubIPv6 = true;
        public bool ScrubMac = true;
        public bool ScrubHostnames = true;
        public bool ScrubDomains = true;
        public bool ScrubUsers = true;
        public bool ScrubEmails = true;
        public bool ScrubSids = true;
        /// <summary>Names shorter than this are mapped (for FQDN composition) but not replaced on their own.</summary>
        public int MinBareLength = 3;

        private const int HintAuto = 0, HintHost = 1, HintDomain = 2;
        private const RegexOptions RxOpt = RegexOptions.Compiled | RegexOptions.CultureInvariant;
        private const RegexOptions RxOptI = RxOpt | RegexOptions.IgnoreCase;

        // ----- detectors -----
        // Key/value separator: optional closing quote, ipconfig-style dot leaders, then : = or > (XML), optional opening quote.
        private const string Sep = @"[""']?[ \t.]*[:=>][ \t]*[""'\[(]?";

        private static readonly Regex SidRx = new Regex(
            @"(?<![A-Za-z0-9-])S-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})(?![0-9])", RxOptI);

        private static readonly Regex EmailRx = new Regex(
            @"(?<![A-Za-z0-9._-])(?<local>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9_])?)@(?<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-]|\.[A-Za-z0-9])", RxOpt);

        private static readonly Regex MacRx = new Regex(
            @"(?<![A-Za-z0-9:.-])(?<mac>[0-9A-Fa-f]{2}(?<sep>[:-])[0-9A-Fa-f]{2}(?:\k<sep>[0-9A-Fa-f]{2}){4}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![A-Za-z0-9:-]|\.[0-9A-Za-z])", RxOpt);

        private static readonly Regex MacCtxRx = new Regex(
            @"(?<![A-Za-z0-9])(?:mac|mac[ _-]?addr(?:ess)?|physical[ _-]?address|hw[ _-]?addr(?:ess)?|hardware[ _-]?address|chaddr|client[ _-]?mac)" + Sep + @"(?<mac>[0-9A-Fa-f]{12})(?![A-Za-z0-9])", RxOptI);

        private static readonly Regex IPv4Rx = new Regex(
            @"(?<![A-Za-z0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![A-Za-z0-9]|\.[0-9])", RxOpt);

        private static readonly Regex VersionCtxRx = new Regex(
            @"(?:version|ver|build|release|v)[ \t]*[=:]?[ \t]*[""']?$", RxOptI);

        private static readonly Regex IPv6Rx = new Regex(
            @"(?<![A-Za-z0-9:.])(?<v>(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?)(?:%[A-Za-z0-9_.-]+)?(?![A-Za-z0-9:]|\.[0-9])", RxOpt);

        private static readonly Regex HostCtxRx = new Regex(
            @"(?<![A-Za-z0-9])(?:computer|computer[ _-]?name|machine[ _-]?name|host|host[ _-]?name|server|server[ _-]?name|workstation|workstation[ _-]?name|source[ _-]?workstation|client[ _-]?name|device[ _-]?name|dns[ _-]?host[ _-]?name|domain[ _-]?controller|dc[ _-]?name|logon[ _-]?server|node[ _-]?name|target[ _-]?server[ _-]?name|caller[ _-]?computer[ _-]?name|src[ _-]?host|dst[ _-]?host|dest[ _-]?host|data[ _-]?source|sql[ _-]?server|fqdn)"
            + Sep + @"(?:\\\\)?(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?![/\\_@])", RxOptI);

        private static readonly Regex UserCtxRx = new Regex(
            @"(?<![A-Za-z0-9])(?:user|user[ _-]?name|user[ _-]?id|account|account[ _-]?name|logon[ _-]?account|target[ _-]?user[ _-]?name|subject[ _-]?user[ _-]?name|sam[ _-]?account[ _-]?name|upn|user[ _-]?principal[ _-]?name|login|logon[ _-]?name|login[ _-]?name|run[ _-]?as)"
            + Sep + @"(?:(?<d>[A-Za-z0-9][A-Za-z0-9.-]{0,62})\\{1,2})?(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))(?![/\\])", RxOptI);

        private static readonly Regex ForUserRx = new Regex(
            @"(?<![A-Za-z0-9])(?:for|by)[ \t]+user[ \t]+[""'\[]?(?:(?<d>[A-Za-z0-9][A-Za-z0-9.-]{0,62})\\{1,2})?(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))(?![/\\])", RxOptI);

        private static readonly Regex DomainUserRx = new Regex(
            @"(?<![A-Za-z0-9\\/.:$%-])(?<d>[A-Za-z][A-Za-z0-9-]{1,14})\\{1,2}(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))(?![\\/A-Za-z0-9])", RxOpt);

        private static readonly Regex DomainCtxRx = new Regex(
            @"(?<![A-Za-z0-9])(?:domain|domain[ _-]?name|account[ _-]?domain|logon[ _-]?domain|target[ _-]?domain[ _-]?name|subject[ _-]?domain[ _-]?name|user[ _-]?domain|user[ _-]?dns[ _-]?domain|dns[ _-]?domain|dns[ _-]?domain[ _-]?name|dns[ _-]?suffix|primary[ _-]?dns[ _-]?suffix|connection[ _-]?specific[ _-]?dns[ _-]?suffix|dns[ _-]?suffix[ _-]?search[ _-]?list|realm|workgroup|forest|forest[ _-]?name|netbios[ _-]?domain[ _-]?name|ad[ _-]?domain)"
            + Sep + @"(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?![/\\@])", RxOptI);

        private static readonly Regex UncRx = new Regex(
            @"(?<![\\A-Za-z0-9$%._:/-])\\{2,4}(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?=[\\""'\s,;:)\]]|$)", RxOpt);

        private static readonly Regex UrlRx = new Regex(
            @"(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9+.-]{1,15}://(?:[^@/\s""']+@)?(?<v>(?>[A-Za-z0-9][A-Za-z0-9.-]{0,253}))(?=[:/\s""'?#)\]]|$)", RxOpt);

        // RFC 3164 "Nov 18 14:10:01 host prog[pid]:" / ISO-timestamp variants, and RFC 5424 "<34>1 2026-... host app ..."
        private static readonly Regex SyslogRx = new Regex(
            @"^(?:(?:<\d{1,3}>)?(?:[A-Z][a-z]{2} +\d{1,2}|\d{4}-\d\d-\d\d)[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)? (?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,253}) (?=[A-Za-z0-9_./()-]+(?:\[\d+\])?:)|<\d{1,3}>1 \S+ (?<v>[A-Za-z0-9][A-Za-z0-9.-]{0,253}) )",
            RxOpt | RegexOptions.Multiline);

        private static readonly Regex SshUserRx = new Regex(
            @"(?<![A-Za-z0-9])(?:(?:Accepted|Failed) [a-z-]+ for (?:invalid user )?|Invalid user |session (?:opened|closed) for user )(?<v>(?>[A-Za-z0-9][A-Za-z0-9._$-]{0,63}))",
            RxOpt);

        private static readonly Regex FqdnRx = new Regex(
            @"(?<![A-Za-z0-9._-])(?<v>(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.){1,20}[A-Za-z]{2,24})(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", RxOpt);

        private static readonly Regex IgnoredUserRx = new Regex(
            @"^(?:DWM-\d+|UMFD-\d+|S-1-[0-9-]+|IUSR_.*|\d+)$", RxOptI);

        private static readonly Regex FileExtRx = new Regex(
            @"\.(?:log|txt|exe|dll|sys|ps1|psm1|psd1|bat|cmd|vbs|js|xml|json|csv|ini|cfg|conf|config|evtx|etl|dmp|zip|msi|msu|cab|inf|cat|mui|htm|html|tmp|bak|old|dat|db|mdf|ldf|pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|reg|pol|lnk|ocx|drv|cpl|scr)$", RxOptI);

        // ----- configuration sets -----
        private readonly Dictionary<string, bool> tlds = NewSet();
        private readonly Dictionary<string, bool> ignoreNames = NewSet();
        private readonly Dictionary<string, bool> ignoreDomainPrefixes = NewSet();
        private readonly Dictionary<string, bool> excludeValues = NewSet();
        private readonly List<string> excludeDomains = new List<string>();
        private readonly List<Regex> hostPatterns = new List<Regex>();

        // ----- mapping tables -----
        private readonly Table hosts;
        private readonly Table domains;
        private readonly Table users;
        private readonly Table custom;
        private readonly Table ipv4;
        private readonly Table subnets;
        private readonly Table ipv6;
        private readonly Table macs;
        private readonly Table sids;
        private readonly Dictionary<string, MapEntry> ipv6Raw = new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, MapEntry> macRaw = new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DottedObs> dotted = new Dictionary<string, DottedObs>(StringComparer.OrdinalIgnoreCase);
        private readonly List<DottedObs> dottedOrder = new List<DottedObs>();
        private readonly Dictionary<string, EmailObs> emails = new Dictionary<string, EmailObs>(StringComparer.OrdinalIgnoreCase);
        private readonly List<EmailObs> emailOrder = new List<EmailObs>();
        // Host labels seen only as the first label of an automatically detected FQDN ("time" in time.contoso.com) and
        // without a digit or '-'. They are replaced inside FQDNs but not as bare words (avoids scrubbing "time", "files").
        private readonly Dictionary<string, bool> weakHosts = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        // ----- pass-2 index -----
        private Dictionary<string, Literal> literals = new Dictionary<string, Literal>(StringComparer.OrdinalIgnoreCase);
        private bool[] literalLengths = new bool[1];
        private int maxLiteralLength;
        private Regex phraseRx;
        private readonly Dictionary<string, MapEntry> phraseMap = new Dictionary<string, MapEntry>(StringComparer.OrdinalIgnoreCase);
        private bool dirty = true;

        public ScrubEngine()
        {
            hosts = new Table("Hostname", delegate(int n) { return "HOST-" + n.ToString("D4", CultureInfo.InvariantCulture); });
            domains = new Table("DomainLabel", delegate(int n) { return "DOMAIN-" + n.ToString("D4", CultureInfo.InvariantCulture); });
            users = new Table("User", delegate(int n) { return "USER-" + n.ToString("D4", CultureInfo.InvariantCulture); });
            custom = new Table("Custom", delegate(int n) { return "REDACTED-" + n.ToString("D4", CultureInfo.InvariantCulture); });
            ipv4 = new Table("IPv4", null);
            subnets = new Table("IPv4Subnet", delegate(int n) { return PoolSubnet(n - 1) + ".0/24"; });
            ipv6 = new Table("IPv6", Ipv6FromIndex);
            macs = new Table("MAC", MacFromIndex);
            sids = new Table("SID", delegate(int n) { return "S-1-5-21-1111111111-2222222222-" + (3000000000L + n).ToString(CultureInfo.InvariantCulture); });
            LoadDefaults();
        }

        // =========================================================================================
        // Configuration
        // =========================================================================================

        private static Dictionary<string, bool> NewSet()
        {
            return new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        }

        private static void AddAll(Dictionary<string, bool> set, string spaceSeparated)
        {
            foreach (string s in spaceSeparated.Split(new char[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                set[s] = true;
        }

        private void LoadDefaults()
        {
            // TLDs recognised for automatic FQDN detection. Deliberately conservative: TLDs that are also common
            // words or code identifiers (info, name, app, int, in, it, is, to, me ...) are left out to avoid
            // false positives such as "logging.info". Add more with AddTld / -ExtraTld.
            AddAll(tlds, "com net org edu gov mil biz io co us uk ca de fr nl au jp cn eu ch se dk fi es nz br mx za sg hk kr tw ru pl cz il ie "
                       + "local lan corp internal intranet intra home private localdomain ad priv");

            // Names that are never treated as sensitive on their own (well-known accounts, generic DNS labels, common words).
            AddAll(ignoreNames,
                  "localhost localdomain local www www2 mail smtp imap pop pop3 ftp sftp api web app apps vpn dns ns mx autodiscover "
                + "login portal owa sts adfs cdn static wpad isatap prod dev test stage staging qa uat internal intranet lan "
                + "dc gc pdc _msdcs _tcp _udp _ldap _kerberos _gc _sites domaindnszones forestdnszones "
                + "workgroup builtin nt authority system administrator administrators admin guest guests users everyone "
                + "localsystem localservice networkservice root krbtgt defaultaccount wdagutilityaccount anonymous nobody daemon "
                + "www-data sshd null none unknown n/a na true false yes no on off enabled disabled failed failure success successful "
                + "server host client computer machine user account domain default service services network sa dbo public "
                + "noreply no-reply postmaster support info webmaster help abuse security hostmaster "
                + "microsoft windows nginx apache iis kestrel tomcat");

            // Things that look like DOMAIN\user but are not.
            AddAll(ignoreDomainPrefixes,
                  "HKLM HKCU HKCR HKU HKCC HKEY APPPOOL SERVICE MACHINE MANAGER HOST AUTHORITY BUILTIN WINDOWS SYSTEM SYSTEM32 SYSWOW64 "
                + "PROGRAM USERS TEMP TMP LOGS LOG DATA APPDATA LOCAL LOCALLOW ROAMING SOFTWARE MICROSOFT DRIVERS ETC SYSTEMROOT "
                + "CURRENTCONTROLSET CONTROLSET001 CONTROLSET002 SERVICES POLICIES CLASSES DEVICE GLOBALROOT HARDDISKVOLUME "
                + "SHARE SHARES INETPUB WWWROOT DOCUMENTS DESKTOP DOWNLOADS BIN OBJ DEBUG RELEASE SRC LIB INCLUDE CONFIG");

            // Public / vendor domains that are not sensitive and keep logs readable.
            foreach (string d in new string[] {
                "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "msftconnecttest.com", "live.com", "office.com",
                "office365.com", "microsoftonline.com", "msedge.net", "akamai.net", "akamaiedge.net", "digicert.com",
                "verisign.com", "globalsign.com", "entrust.net", "letsencrypt.org", "google.com", "googleapis.com",
                "gstatic.com", "apple.com", "mozilla.org", "ubuntu.com", "debian.org", "redhat.com", "w3.org",
                "xmlsoap.org", "openxmlformats.org", "example.com", "example.net", "example.org", "asp.net", "ado.net", "vb.net" })
                excludeDomains.Add(d);

            // Values that are never scrubbed.
            AddAll(excludeValues, "0.0.0.0 127.0.0.1 255.255.255.255 :: ::1 localhost");
        }

        /// <summary>Removes the built-in ignore / exclusion lists (TLD list is kept).</summary>
        public void ClearDefaultExclusions()
        {
            ignoreNames.Clear();
            excludeDomains.Clear();
            excludeValues.Clear();
        }

        public void AddTld(string tld) { if (!string.IsNullOrEmpty(tld)) tlds[tld.Trim().TrimStart('.')] = true; }
        public void AddIgnoreName(string name) { if (!string.IsNullOrEmpty(name)) ignoreNames[name.Trim()] = true; }
        public void AddExcludeValue(string value) { if (!string.IsNullOrEmpty(value)) excludeValues[value.Trim()] = true; }
        public void AddExcludeDomain(string domain) { if (!string.IsNullOrEmpty(domain)) excludeDomains.Add(domain.Trim().Trim('.').ToLowerInvariant()); }

        public void AddHostnamePattern(string pattern)
        {
            hostPatterns.Add(new Regex(pattern, RxOptI));
        }

        /// <summary>
        /// Registers a value the user knows is sensitive. type = Hostname | Domain | User | Custom.
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
                if (v.IndexOf('.') >= 0) { PutCustom(v, replacement, src); return; }
                ignoreNames.Remove(v);
                weakHosts.Remove(v);
                if (replacement != null) hosts.Put(v, v, replacement, src); else hosts.GetOrAdd(v, v, src);
            }
            else if (t == "domain" || t == "domainlabel")
            {
                string v = TrimDots(value);
                if (v.IndexOf('.') >= 0 && replacement == null)
                {
                    foreach (string l in v.Split('.')) if (!tlds.ContainsKey(l)) ignoreNames.Remove(l);
                    AddDottedObs(v, HintDomain, src);
                    return;
                }
                if (v.IndexOf('.') >= 0) { PutCustom(v, replacement, src); return; }
                ignoreNames.Remove(v);
                if (replacement != null) domains.Put(v, v, replacement, src); else domains.GetOrAdd(v, v, src);
            }
            else if (t == "user" || t == "username")
            {
                ignoreNames.Remove(value);
                if (replacement != null) users.Put(value, value, replacement, src); else users.GetOrAdd(value, value, src);
            }
            else
            {
                PutCustom(value, replacement, src);
            }
        }

        private void PutCustom(string value, string replacement, string src)
        {
            if (replacement != null) custom.Put(value, value, replacement, src); else custom.GetOrAdd(value, value, src);
        }

        /// <summary>Restores one row of an existing correlation sheet so replacements stay stable between runs.</summary>
        public void LoadEntry(string type, string original, string replacement, string firstSeenIn)
        {
            if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(original) || string.IsNullOrEmpty(replacement)) return;
            string src = string.IsNullOrEmpty(firstSeenIn) ? "(correlation file)" : firstSeenIn;
            dirty = true;
            switch (type.Trim())
            {
                case "Hostname": hosts.Put(original, original, replacement, src); break;
                case "HostLabel":
                    if (hosts.Find(original) == null)
                    {
                        hosts.Put(original, original, replacement, src);
                        if (!LooksLikeMachineName(original)) weakHosts[original] = true;
                    }
                    break;
                case "DomainLabel": domains.Put(original, original, replacement, src); break;
                case "User": users.Put(original, original, replacement, src); break;
                case "Custom": custom.Put(original, original, replacement, src); break;
                case "IPv4": ipv4.Put(original, original, replacement, src); break;
                case "IPv4Subnet":
                    {
                        string key = SubnetKeyFromDisplay(original);
                        if (key != null) subnets.Put(key, original, replacement, src);
                        break;
                    }
                case "IPv6":
                    {
                        IPAddress a;
                        if (IPAddress.TryParse(original, out a)) { ipv6.Put(Canonical6(a), original, replacement, src); }
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
                        if (m.Success) sids.Put(SidKey(m), original, replacement, src);
                        break;
                    }
                case "FQDN":
                case "DomainName":
                    {
                        DottedObs o = AddDottedObs(original, type == "FQDN" ? HintHost : HintDomain, src);
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

        // =========================================================================================
        // File handling
        // =========================================================================================

        public static TextFileInfo Inspect(string path)
        {
            byte[] buf = new byte[65536];
            int read = 0;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                int n;
                while (read < buf.Length && (n = fs.Read(buf, read, buf.Length - read)) > 0) read += n;
            }

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

            int zeroOdd = 0, zeroEven = 0;
            for (int i = 0; i < read; i++)
            {
                if (buf[i] == 0) { if ((i & 1) == 1) zeroOdd++; else zeroEven++; }
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
            info.EncodingName = "ANSI/Latin-1 (not valid UTF-8)";
        }

        private static void ReadBlocks(string path, Encoding enc, Action<string> onBlock)
        {
            const int MaxPending = 8 * 1024 * 1024;
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            using (StreamReader sr = new StreamReader(fs, enc, false, 1 << 16))
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
                        if (pending.Length > MaxPending) { onBlock(pending.ToString()); pending.Length = 0; }
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
                ReadBlocks(path, info.ReadEncoding, delegate(string b) { ScanText(b, src); });
            }
            catch (DecoderFallbackException)
            {
                if (!info.CanFallBack) throw;
                FallBackToLatin1(info);
                ReadBlocks(path, info.ReadEncoding, delegate(string b) { ScanText(b, src); });
            }
        }

        /// <summary>Pass 2 for one file.</summary>
        public void ScrubFile(string inPath, string outPath, TextFileInfo info)
        {
            string dir = Path.GetDirectoryName(outPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            using (StreamWriter sw = new StreamWriter(outPath, false, info.WriteEncoding, 1 << 16))
            {
                ReadBlocks(inPath, info.ReadEncoding, delegate(string b) { sw.Write(ScrubText(b)); });
            }
        }

        // =========================================================================================
        // Pass 1 - discovery
        // =========================================================================================

        public void ScanText(string text, string source)
        {
            if (string.IsNullOrEmpty(text)) return;
            dirty = true;
            Match m;

            if (ScrubSids)
                for (m = SidRx.Match(text); m.Success; m = m.NextMatch())
                    if (!IsExcludedValue(m.Value)) sids.GetOrAdd(SidKey(m), "S-1-5-21-" + SidKey(m), source);

            if (ScrubEmails)
                for (m = EmailRx.Match(text); m.Success; m = m.NextMatch())
                    AddEmailObs(m.Value, m.Groups["local"].Value, m.Groups["domain"].Value, source);

            if (ScrubMac)
            {
                for (m = MacRx.Match(text); m.Success; m = m.NextMatch())
                {
                    string raw = m.Groups["mac"].Value;
                    if (raw.IndexOf('.') >= 0 && !HasHexLetter(raw)) continue; // 2019.1201.0001 is a version, not a MAC
                    RegisterMac(raw, source);
                }
                for (m = MacCtxRx.Match(text); m.Success; m = m.NextMatch())
                    RegisterMac(m.Groups["mac"].Value, source);
            }

            if (ScrubIPv6)
                for (m = IPv6Rx.Match(text); m.Success; m = m.NextMatch())
                    RegisterIPv6(m.Groups["v"].Value, source);

            if (ScrubIPv4)
                for (m = IPv4Rx.Match(text); m.Success; m = m.NextMatch())
                {
                    int from = Math.Max(0, m.Index - 12);
                    if (VersionCtxRx.IsMatch(text.Substring(from, m.Index - from))) continue; // "Version=4.0.0.0"
                    RegisterIPv4(m.Value, source);
                }

            if (ScrubHostnames)
            {
                for (m = HostCtxRx.Match(text); m.Success; m = m.NextMatch()) RegisterHostValue(m.Groups["v"].Value, source);
                for (m = UncRx.Match(text); m.Success; m = m.NextMatch()) RegisterHostValue(m.Groups["v"].Value, source);
                for (m = SyslogRx.Match(text); m.Success; m = m.NextMatch()) RegisterHostValue(m.Groups["v"].Value, source);
                for (m = UrlRx.Match(text); m.Success; m = m.NextMatch())
                {
                    string v = TrimDots(m.Groups["v"].Value);
                    if (v.IndexOf('.') < 0) RegisterHost(v, source); // dotted ones are handled by the FQDN detector
                }
                foreach (Regex rx in hostPatterns)
                    for (m = rx.Match(text); m.Success; m = m.NextMatch())
                    {
                        Group g = m.Groups["host"];
                        string v = (g != null && g.Success) ? g.Value : m.Value;
                        if (v.IndexOf('.') >= 0) AddDottedObs(TrimDots(v), HintHost, source);
                        else if (v.Length > 0 && !IsExcludedValue(v)) { weakHosts.Remove(v); hosts.GetOrAdd(v, v, source); }
                    }
            }

            if (ScrubUsers || ScrubDomains || ScrubHostnames)
            {
                for (m = UserCtxRx.Match(text); m.Success; m = m.NextMatch()) RegisterUserMatch(m, source);
                for (m = ForUserRx.Match(text); m.Success; m = m.NextMatch()) RegisterUserMatch(m, source);
                for (m = SshUserRx.Match(text); m.Success; m = m.NextMatch()) RegisterUserMatch(m, source);
                for (m = DomainUserRx.Match(text); m.Success; m = m.NextMatch())
                {
                    string d = m.Groups["d"].Value;
                    string v = m.Groups["v"].Value;
                    if (ignoreDomainPrefixes.ContainsKey(d) || FileExtRx.IsMatch(v)) continue;
                    if (TrimDots(v).TrimEnd('$').Length < 2) continue;
                    RegisterUserMatch(m, source);
                }
            }

            if (ScrubDomains || ScrubHostnames)
            {
                for (m = DomainCtxRx.Match(text); m.Success; m = m.NextMatch()) RegisterDomainValue(m.Groups["v"].Value, source);

                for (m = FqdnRx.Match(text); m.Success; m = m.NextMatch())
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
                        if (!found) continue;
                        tldIdx = k;
                        v = string.Join(".", labels, 0, k + 1);
                    }
                    if (!CaseConsistent(labels, tldIdx)) continue; // System.IO, System.Net ...
                    AddDottedObs(v, HintAuto, source);
                }
            }
        }

        private void RegisterUserMatch(Match m, string source)
        {
            Group d = m.Groups["d"];
            if (d.Success && d.Value.Length > 0 && !ignoreDomainPrefixes.ContainsKey(d.Value)) RegisterDomainValue(d.Value, source);
            string v = TrimDots(m.Groups["v"].Value);
            if (v.EndsWith("$", StringComparison.Ordinal))
            {
                RegisterHost(v.TrimEnd('$'), source); // computer account, e.g. WEB01$
                return;
            }
            RegisterUser(v, source);
        }

        private bool IsCandidateName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 64) return false;
            if (!HasLetter(name)) return false;
            if (ignoreNames.ContainsKey(name) || IsExcludedValue(name)) return false;
            return true;
        }

        private void RegisterHost(string name, string source)
        {
            if (!ScrubHostnames) return;
            name = TrimDots(name);
            if (!IsCandidateName(name)) return;
            weakHosts.Remove(name);
            hosts.GetOrAdd(name, name, source);
        }

        private void RegisterHostValue(string v, string source)
        {
            v = TrimDots(v);
            if (v.Length == 0 || LooksLikeIPv4(v)) return;
            if (v.IndexOf('.') >= 0) AddDottedObs(v, HintHost, source);
            else RegisterHost(v, source);
        }

        private void RegisterUser(string name, string source)
        {
            if (!ScrubUsers) return;
            if (!IsCandidateName(name) || IgnoredUserRx.IsMatch(name)) return;
            users.GetOrAdd(name, name, source);
        }

        private void RegisterDomainValue(string v, string source)
        {
            v = TrimDots(v);
            if (v.Length == 0 || LooksLikeIPv4(v)) return;
            if (v.IndexOf('.') >= 0) AddDottedObs(v, HintDomain, source);
            else if (ScrubDomains && !IsKeepLabel(v) && HasLetter(v)) domains.GetOrAdd(v, v, source);
        }

        private void RegisterMac(string raw, string source)
        {
            string hex = MacHex(raw);
            if (hex == null) return;
            if (hex == "000000000000" || hex == "FFFFFFFFFFFF") return;
            if (IsExcludedValue(raw) || IsExcludedValue(DisplayMac(hex))) return;
            MapEntry e = macs.GetOrAdd(hex, DisplayMac(hex), source);
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
            MapEntry e = ipv6.GetOrAdd(canon, canon, source);
            if (!ipv6Raw.ContainsKey(v)) ipv6Raw[v] = e;
        }

        private void RegisterIPv4(string v, string source)
        {
            if (ipv4.Map.ContainsKey(v)) return;
            string[] p = v.Split('.');
            int a = int.Parse(p[0], CultureInfo.InvariantCulture);
            // 0/8, loopback, multicast, reserved (240/4 - also the replacement pool), masks like 255.255.255.0
            if (a == 0 || a == 127 || a >= 224) return;
            if (IsExcludedValue(v)) return;
            string key = p[0] + "." + p[1] + "." + p[2];
            MapEntry sub = subnets.GetOrAdd(key, key + ".0/24", source);
            string prefix = sub.Replacement.Substring(0, sub.Replacement.LastIndexOf('.'));
            ipv4.Put(v, v, prefix + "." + p[3], source);
        }

        private DottedObs AddDottedObs(string raw, int hint, string source)
        {
            raw = TrimDots(raw);
            if (raw.Length == 0 || raw.Length > 253) return null;
            string[] labels = raw.Split('.');
            foreach (string l in labels) if (l.Length == 0) return null;
            if (IsExcludedDomain(raw) || IsExcludedValue(raw)) return null;
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
            if (ScrubUsers) RegisterUser(local, source);
            if (ScrubDomains) AddDottedObs(domain, HintDomain, source);
            EmailObs o = new EmailObs();
            o.Raw = raw; o.Local = local; o.Domain = TrimDots(domain); o.Source = source;
            emails[raw] = o;
            emailOrder.Add(o);
            dirty = true;
        }

        // =========================================================================================
        // Index build (between passes)
        // =========================================================================================

        private void RegisterLabels(DottedObs o, bool firstIsHost, bool skipFirst)
        {
            string[] labels = o.Raw.Split('.');
            int last = labels.Length - 1;
            for (int i = skipFirst ? 1 : 0; i < labels.Length; i++)
            {
                string l = labels[i];
                if (i == last && last > 0 && tlds.ContainsKey(l)) continue;
                if (IsKeepLabel(l)) continue;
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
                    weakHosts.Remove(o.Raw.Split('.')[0]);
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
                if (isHost && !existed && hosts.Map.ContainsKey(first) && !LooksLikeMachineName(first)) weakHosts[first] = true;
            }

            // 2. composite rows
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

            // 3. literal index (first registration of a key wins)
            literals = new Dictionary<string, Literal>(StringComparer.OrdinalIgnoreCase);
            phraseMap.Clear();
            List<string> phrases = new List<string>();
            foreach (MapEntry e in custom.Order)
            {
                if (IsWordLiteral(e.Original)) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
                else { phraseMap[e.Original] = e; phrases.Add(e.Original); }
            }
            foreach (DottedObs o in dottedOrder)
                if (!string.Equals(o.Entry.Replacement, o.Raw, StringComparison.OrdinalIgnoreCase))
                    AddLiteral(o.Raw, Literal.Dotted, true, false, o.Entry, null, o.FirstIsHost);
            foreach (EmailObs o in emailOrder)
                if (!string.Equals(o.Entry.Replacement, o.Raw, StringComparison.OrdinalIgnoreCase))
                    AddLiteral(o.Raw, Literal.Email, true, false, o.Entry, null, false);
            foreach (MapEntry e in ipv4.Order) AddLiteral(e.Original, Literal.Atomic, false, true, e, null, false);
            foreach (KeyValuePair<string, MapEntry> kv in ipv6Raw) AddLiteral(kv.Key, Literal.Atomic, false, true, kv.Value, null, false);
            foreach (MapEntry e in ipv6.Order) AddLiteral(e.Original, Literal.Atomic, false, true, e, null, false);
            foreach (KeyValuePair<string, MapEntry> kv in macRaw) AddLiteral(kv.Key, Literal.Atomic, false, false, kv.Value, FormatMacLike(kv.Key, kv.Value.Replacement), false);
            foreach (MapEntry e in macs.Order) AddLiteral(e.Original, Literal.Atomic, false, false, e, FormatMacLike(e.Original, e.Replacement), false);
            foreach (MapEntry e in hosts.Order) if (e.Original.Length >= MinBareLength && !weakHosts.ContainsKey(e.Original)) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
            foreach (MapEntry e in users.Order) if (e.Original.Length >= MinBareLength) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);
            foreach (MapEntry e in domains.Order) if (e.Original.Length >= MinBareLength) AddLiteral(e.Original, Literal.Atomic, true, false, e, null, false);

            maxLiteralLength = 0;
            foreach (string k in literals.Keys) if (k.Length > maxLiteralLength) maxLiteralLength = k.Length;
            literalLengths = new bool[maxLiteralLength + 1];
            foreach (string k in literals.Keys) literalLengths[k.Length] = true;

            phraseRx = null;
            if (phrases.Count > 0)
            {
                phrases.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
                StringBuilder sb = new StringBuilder(@"(?<![A-Za-z0-9])(?:");
                for (int i = 0; i < phrases.Count; i++)
                {
                    if (i > 0) sb.Append('|');
                    sb.Append(Regex.Escape(phrases[i]));
                }
                sb.Append(@")(?![A-Za-z0-9])");
                phraseRx = new Regex(sb.ToString(), RxOptI);
            }
            dirty = false;
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
            if (ScrubSids && sids.Map.Count > 0) text = SidRx.Replace(text, ReplaceSid);
            if (phraseRx != null) text = phraseRx.Replace(text, ReplacePhrase);
            return ReplaceLiterals(text);
        }

        private string ReplaceSid(Match m)
        {
            MapEntry e = sids.Find(SidKey(m));
            if (e == null) return m.Value;
            e.Matches++;
            return e.Replacement;
        }

        private string ReplacePhrase(Match m)
        {
            MapEntry e;
            if (!phraseMap.TryGetValue(m.Value, out e)) return m.Value;
            e.Matches++;
            return ApplyCase(m.Value, e.Replacement);
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
                if (!(IsAlnum(c) || c == ':' || c == '_') || (i > 0 && IsAlnum(s[i - 1]))) { i++; continue; }

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
                    char prev = i > 0 ? s[i - 1] : ' ';
                    char next = end < n ? s[end] : ' ';
                    if (lit.NameLike && (prev == '-' || next == '-')) continue;
                    if (lit.IpLike && (prev == '.' || (next == '.' && end + 1 < n && char.IsDigit(s[end + 1])))) continue;

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
                if (!matched) i++;
            }
            if (sb == null) return s;
            sb.Append(s, copied, n - copied);
            return sb.ToString();
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
            int last = labels.Length - 1;
            for (int i = 0; i < labels.Length; i++)
            {
                string l = labels[i];
                if (i == last && last > 0 && tlds.ContainsKey(l)) continue;
                if (IsKeepLabel(l)) continue;
                MapEntry e = (i == 0 && firstIsHost) ? hosts.Find(l) : domains.Find(l);
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
        // Results
        // =========================================================================================

        public List<MapEntry> GetEntries()
        {
            if (dirty) BuildIndex();
            List<MapEntry> all = new List<MapEntry>();
            foreach (MapEntry e in hosts.Order) e.Type = weakHosts.ContainsKey(e.Original) ? "HostLabel" : "Hostname";
            all.AddRange(hosts.Order);
            foreach (DottedObs o in dottedOrder) if (o.Entry != null && o.Entry.Type == "FQDN") all.Add(o.Entry);
            all.AddRange(domains.Order);
            foreach (DottedObs o in dottedOrder) if (o.Entry != null && o.Entry.Type == "DomainName") all.Add(o.Entry);
            all.AddRange(users.Order);
            foreach (EmailObs o in emailOrder) if (o.Entry != null) all.Add(o.Entry);
            all.AddRange(ipv4.Order);
            all.AddRange(subnets.Order);
            all.AddRange(ipv6.Order);
            all.AddRange(macs.Order);
            all.AddRange(sids.Order);
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
            return "\"" + (s ?? string.Empty).Replace("\"", "\"\"") + "\"";
        }

        // =========================================================================================
        // Helpers
        // =========================================================================================

        private static bool IsAlnum(char c)
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
            foreach (char c in s) if (char.IsDigit(c) || c == '-') return true;
            return false;
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
                if (c >= 'a' && c <= 'z') lower = true;
                else if (c >= 'A' && c <= 'Z') upper = true;
            }
            if (lower && !upper) return replacement.ToLowerInvariant();
            if (upper && !lower) return replacement.ToUpperInvariant();
            return replacement;
        }

        private bool IsKeepLabel(string l)
        {
            if (l.Length == 0 || l[0] == '_' || !HasLetter(l)) return true;
            return ignoreNames.ContainsKey(l) || excludeValues.ContainsKey(l);
        }

        private bool IsExcludedValue(string v)
        {
            return excludeValues.ContainsKey(v);
        }

        private bool IsExcludedDomain(string fqdn)
        {
            string f = fqdn.ToLowerInvariant();
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

        private static string PoolSubnet(int idx)
        {
            // 198.18.0.0/15 (RFC 2544 benchmarking, never routed) then 240.0.0.0/4 (reserved).
            if (idx < 512) return "198." + (18 + idx / 256).ToString(CultureInfo.InvariantCulture) + "." + (idx % 256).ToString(CultureInfo.InvariantCulture);
            int k = idx - 512;
            return (240 + k / 65536).ToString(CultureInfo.InvariantCulture) + "." + ((k / 256) % 256).ToString(CultureInfo.InvariantCulture) + "." + (k % 256).ToString(CultureInfo.InvariantCulture);
        }

        private static string Ipv6FromIndex(int n)
        {
            // 2001:db8::/32 is reserved for documentation.
            byte[] b = new byte[16];
            b[0] = 0x20; b[1] = 0x01; b[2] = 0x0d; b[3] = 0xb8;
            b[12] = (byte)(n >> 24); b[13] = (byte)(n >> 16); b[14] = (byte)(n >> 8); b[15] = (byte)n;
            return new IPAddress(b).ToString();
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
            string hex = "0200" + n.ToString("X8", CultureInfo.InvariantCulture);
            return DisplayMac(hex);
        }

        private static string MacHex(string raw)
        {
            StringBuilder sb = new StringBuilder(12);
            foreach (char c in raw)
            {
                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) sb.Append(char.ToUpperInvariant(c));
                else if (c != ':' && c != '-' && c != '.') return null;
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
}
