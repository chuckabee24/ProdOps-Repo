<#
.SYNOPSIS
    Focused edge-case tests for LogScrubEngine.cs. Each case scans + scrubs a snippet and checks that the
    sensitive values are gone and that look-alike text is untouched.

.EXAMPLE
    pwsh -File .\tests\Test-EngineCases.ps1
#>
[CmdletBinding()]
param([string]$Filter = '*')

$ErrorActionPreference = 'Stop'
$engineFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'LogScrubEngine.cs'
if (-not ('LogScrub.ScrubEngine' -as [type])) { Add-Type -Path $engineFile }

$cases = @(
    @{ Name = 'Windows event text'; Text = "Computer:      NWT-FS01.nwtraders.local`nSubject:`n`tAccount Name:`t`tjsmith`n`tAccount Domain:`t`tNWTRADERS`n`tSecurity ID:`t`tS-1-5-21-1004336348-1177238915-682003330-1105`nNetwork Information:`n`tWorkstation Name:`tLT-JSMITH-01`n`tSource Network Address:`t10.1.20.55"
       Gone = 'NWT-FS01', 'nwtraders', 'jsmith', 'NWTRADERS', '1004336348', 'LT-JSMITH-01', '10.1.20.55'; Kept = 'Account Name:', 'Security ID:' }
    @{ Name = 'URL-encoded IIS query'; Text = "Account Name: jsmith`n2026-11-18 10:00:00 GET /app/search user=NWTRADERS%5Cjsmith&email=jsmith%40northwindtraders.com&q=report 443"
       Gone = 'jsmith', 'NWTRADERS', 'northwindtraders'; Kept = 'GET /app/search', '&q=report' }
    @{ Name = 'URL-encoded only'; Text = "GET /login?username=a.gonzalez%40northwindtraders.com&next=%2Fhome 200"
       Gone = 'a.gonzalez', 'northwindtraders'; Kept = 'next=%2Fhome' }
    @{ Name = 'JSON escapes'; Text = '{"ts":"x","user":"NWTRADERS\\pkumar","msg":"retry\nfor pkumar on \\\\NWT-SQL-P01\\backups"}'
       Gone = 'pkumar', 'NWT-SQL-P01', 'NWTRADERS'; Kept = '"ts":"x"' }
    @{ Name = 'DNS debug wire format'; Text = "Rcv 10.1.20.55 0001 Q [0001 D NOERROR] A (9)nwt-fs01b(9)nwtraders(5)local(0)`nComputer: NWT-FS01B"
       Gone = 'nwt-fs01b', 'nwtraders', '10.1.20.55'; Kept = '(5)local(0)', 'Q [0001 D NOERROR] A' }
    @{ Name = 'LDAP DN with escaped comma'; Text = "Object DN: CN=Smith\, Jane,OU=Finance,OU=Corp Users,DC=nwtraders,DC=local`nManager: Jane Smith"
       Gone = 'Smith\, Jane', 'Jane Smith', 'Finance', 'Corp Users', 'nwtraders'; Kept = 'DC=local', 'Object DN: CN=' }
    @{ Name = 'Certificate subject'; Text = "Subject: CN=portal.northwindtraders.com, OU=IT Operations, O=Northwind Traders, L=Seattle, S=WA, C=US`nIssuer: CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US"
       Gone = 'northwindtraders', 'Northwind Traders', 'Seattle', 'IT Operations'; Kept = 'C=US', 'Issuer: CN=' }
    @{ Name = 'Person contexts'; Text = "From: Ana Gonzalez <a.gonzalez@northwindtraders.com>`nDisplayName : Gonzalez, Ana`nRegistered Owner: Priya Kumar`nThe Windows Update service started."
       Gone = 'Ana Gonzalez', 'Gonzalez, Ana', 'Priya Kumar', 'a.gonzalez'; Kept = 'The Windows Update service started.' }
    @{ Name = 'Format-Table truncation'; Text = "Name         DNSHostName                IPv4Address`n----         -----------                -----------`nNWT-WEB01    nwt-web01.nwtraders.local  10.1.10.21`nNWT-WEB02    nwt-web02.nwtraders.lo...  10.1.10.22"
       Gone = 'NWT-WEB01', 'NWT-WEB02', 'nwt-web02.nwtraders.lo', 'nwtraders', '10.1.10.22'; Kept = 'DNSHostName' }
    @{ Name = 'Format-List wrap'; Text = "DistinguishedName : CN=NWT-APP07,OU=Servers,DC=nwtraders,DC=lo`n                    cal`nDNSHostName       : nwt-app07.nwtraders.local"
       Gone = 'NWT-APP07', 'nwtraders'; Kept = 'DistinguishedName :' }
    @{ Name = 'Secrets'; Text = "Server=tcp:nwt-sql-p01,1433;Database=Orders;User ID=svc_orders;Password=Spr1ng!2026;Encrypt=True`nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqc21pdGgifQ.c2lnbmF0dXJlLXZhbHVl`naws_access_key_id = AKIAIOSFODNN7EXAMPLE`nhttps://svc_deploy:Hunter2-pass@repo.northwindtraders.com/x`nnet use Z: \\nwt-fs01\finance /user:NWTRADERS\jsmith Winter2026!`n`$pw = ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force"
       Gone = 'Spr1ng!2026', 'eyJhbGciOiJIUzI1NiJ9', 'AKIAIOSFODNN7EXAMPLE', 'Hunter2-pass', 'Winter2026!', 'P@ssw0rd123', 'nwt-sql-p01', 'svc_orders', 'svc_deploy', 'jsmith'; Kept = 'Database=Orders', '-AsPlainText -Force' }
    @{ Name = 'PEM block keeps line count'; Text = "key:`n-----BEGIN RSA PRIVATE KEY-----`nMIIEpAIBAAKCAQEA1x2y3z`nQWERTYUIOPASDFGHJKL123`n-----END RSA PRIVATE KEY-----`nend"
       Gone = 'MIIEpAIBAAKCAQEA1x2y3z', 'QWERTYUIOPASDFGHJKL123'; Kept = '-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'; Lines = $true }
    @{ Name = 'Cisco config'; Text = "hostname CORE-SW01`n!`nenable secret 5 `$1`$mERr`$hx5rVt7rPNoS4wqbXKX7m0`nusername netops privilege 15 secret 9 `$9`$abcDEF`nsnmp-server community N0rthw1nd-RO RO`ninterface GigabitEthernet1/0/1`n description Uplink to DIST-SW02`nCORE-SW01#show cdp neighbors"
       Gone = 'CORE-SW01', 'hx5rVt7rPNoS4wqbXKX7m0', 'netops', 'N0rthw1nd-RO'; Kept = 'interface GigabitEthernet1/0/1', 'show cdp neighbors' }
    @{ Name = 'Naming-convention siblings'; Text = "Computer: NWT-WEB01`nLoad balancer pool: NWT-WEB02 NWT-WEB03 healthy; nwt-web04 drained`nKB5027702 RTM-CU22 Win64 x64 HTTP/1.1"
       Gone = 'NWT-WEB02', 'NWT-WEB03', 'nwt-web04'; Kept = 'KB5027702', 'RTM-CU22', 'Win64', 'x64', 'HTTP/1.1' }
    @{ Name = 'IPv6 /64 kept, EUI-64 removed'; Text = "addr 2001:470:1f0b:7a9::25 and 2001:470:1f0b:7a9:250:56ff:fea1:b2c3 prefix 2001:470:1f0b:7a9::/64 ll fe80::250:56ff:fea1:b2c3%12 [2001:470:1f0b:7a9::25]:443"
       Gone = '2001:470', '250:56ff:fea1:b2c3'; Kept = '%12', ']:443' }
    @{ Name = 'Kerberos klist + SPN'; Text = "#0>  Client: jsmith @ NWTRADERS.LOCAL`n     Server: krbtgt/NWTRADERS.LOCAL @ NWTRADERS.LOCAL`n     Server: MSSQLSvc/nwt-sql-p01.nwtraders.local:1433 @ NWTRADERS.LOCAL`nSPN HOST/NWT-FS01 registered"
       Gone = 'jsmith', 'NWTRADERS', 'nwt-sql-p01', 'NWT-FS01'; Kept = 'krbtgt/', 'MSSQLSvc/', 'HOST/' }
    @{ Name = 'Profile paths'; Text = "Loaded C:\Users\pkumar.NWTRADERS\AppData\Local\Temp\x.log and /home/jsmith/.bashrc and C:\Users\Public\Desktop and C:\Users\Default"
       Gone = 'pkumar', 'NWTRADERS', 'jsmith'; Kept = 'C:\Users\Public\Desktop', 'C:\Users\Default', '\AppData\Local\Temp\x.log', '/.bashrc' }
    @{ Name = 'IPv4 forms'; Text = "ip 010.001.020.055 rev 55.20.1.10.in-addr.arpa zone 20.1.10.in-addr.arpa range 10.1.20.55-10.1.20.60 cidr 10.1.20.0/24 mask 255.255.255.0 dns 8.8.8.8 oid 2.5.4.3 ver Version=4.0.0.0"
       Gone = '010.001.020.055', '55.20.1.10.in-addr', '20.1.10.in-addr', '10.1.20.55', '10.1.20.60', '10.1.20.0'; Kept = '255.255.255.0', '8.8.8.8', '2.5.4.3', 'Version=4.0.0.0' }
    @{ Name = 'Apache / sshd / sudo'; Text = "10.1.30.5 - jsmith [18/Nov/2026:14:00:01 +0000] `"GET / HTTP/1.1`" 200 512`nNov 18 14:00:02 nwt-jump01 sshd[811]: Accepted publickey for a.gonzalez from 10.1.30.6 port 50122 ssh2`nNov 18 14:00:03 nwt-jump01 sudo:   pkumar : TTY=pts/0 ; PWD=/home/pkumar ; USER=root ; COMMAND=/bin/ls"
       Gone = 'jsmith', 'a.gonzalez', 'pkumar', 'nwt-jump01', '10.1.30.5'; Kept = 'GET / HTTP/1.1', 'USER=root', 'COMMAND=/bin/ls' }
    @{ Name = 'DHCP audit CSV with bare MACs'; Text = "ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name,TransactionID`n10,11/18/26,14:10:01,Assign,10.1.40.77,LT-AGONZALEZ-02.nwtraders.local,3C52821A2B3C,,12345`n11,11/18/26,14:11:01,Renew,10.1.40.78,kiosk7.nwtraders.local,005056A1B2C4,,12346"
       Gone = 'LT-AGONZALEZ-02', '3C52821A2B3C', '005056A1B2C4', 'kiosk7', 'nwtraders'; Kept = 'ID,Date,Time,Description', 'Assign', 'Renew' }
    @{ Name = 'Cloud identifiers'; Text = '{"tenantId":"72f988bf-86f1-41af-91ab-2d7cd011db47","resourceId":"/subscriptions/9b1c3f4e-1111-4222-8333-444455556666/resourceGroups/rg-nwt-finance/providers/Microsoft.Compute/virtualMachines/NWT-VM-FIN01","arn":"arn:aws:iam::123456789012:user/jsmith","correlationId":"0f8fad5b-d9cb-469f-a165-70867728950e"}'
       Gone = '72f988bf-86f1-41af-91ab-2d7cd011db47', '9b1c3f4e-1111-4222-8333-444455556666', 'rg-nwt-finance', 'NWT-VM-FIN01', '123456789012', 'jsmith'; Kept = '0f8fad5b-d9cb-469f-a165-70867728950e', 'Microsoft.Compute' }
    @{ Name = 'ECS nested JSON'; Text = '{"host":{"name":"k8s-node-03","ip":["10.1.50.13"],"mac":["00-50-56-AA-BB-CC"]},"user":{"name":"svc_k8s","domain":"NWTRADERS"},"event":{"action":"x"}}'
       Gone = 'k8s-node-03', '10.1.50.13', '00-50-56-AA-BB-CC', 'svc_k8s', 'NWTRADERS'; Kept = '"event":{"action":"x"}' }
    @{ Name = 'Java / .NET host mentions'; Text = "java.net.UnknownHostException: nwt-cache-01`nConnection refused: nwt-app02/10.1.10.32:8080`ncurl: (6) Could not resolve host: nwt-api-03.nwtraders.local`n   at System.Net.Sockets.Socket.Connect(EndPoint remoteEP)"
       Gone = 'nwt-cache-01', 'nwt-app02', '10.1.10.32', 'nwt-api-03', 'nwtraders'; Kept = 'System.Net.Sockets.Socket.Connect(EndPoint remoteEP)', 'java.net.UnknownHostException' }
    @{ Name = 'CEF / FortiGate keys'; Text = 'CEF:0|Fortinet|FortiGate|7.2|0001|traffic|3|src=10.1.20.55 shost=LT-JSMITH-01 suser=jsmith smac=00:50:56:aa:bb:01 dvchost=fw-edge-01' + "`n" + 'devname="FGT-HQ-01" srcname="nas01" user="a.gonzalez" srcmac="00:50:56:aa:bb:02"'
       Gone = 'LT-JSMITH-01', 'jsmith', '00:50:56:aa:bb:01', 'fw-edge-01', 'FGT-HQ-01', 'nas01', 'a.gonzalez'; Kept = 'CEF:0|Fortinet|FortiGate|7.2|0001|traffic|3|' }
    @{ Name = 'PII fields + phone numbers'; Text = "StreetAddress     : 500 Harbor Blvd, Suite 12`nPostalCode        : 98101`nOfficePhone       : +1 (425) 555-0199`nEmployeeID        : 204871`nCall me on +44 20 7946 0958 today"
       Gone = '500 Harbor Blvd', '98101', '555-0199', '204871', '7946 0958'; Kept = 'StreetAddress     :', 'Call me on' }
    @{ Name = 'Given name / surname fields'; Text = "GivenName : Thandiwe`nSurname   : Okonkwo`nDisplayName : Thandiwe Okonkwo`nHi Thandiwe, the will be ready in May."
       Gone = 'Thandiwe', 'Okonkwo'; Kept = 'the will be ready in May.' }
    @{ Name = 'LDIF base64 values'; Text = "dn:: Q049U21pdGhcLCBKYW5lLE9VPUZpbmFuY2UsREM9bnd0cmFkZXJzLERDPWxvY2Fs`ndisplayName:: SmFuZSBTbWl0aA==`nobjectSid:: AQUAAAAAAAUVAAAAL9XsbdwFntSl6rSPUwQAAA==`nsAMAccountName: jsmith"
       Gone = 'Q049U21pdGhcLCBKYW5lLE9VPUZpbmFuY2UsREM9bnd0cmFkZXJzLERDPWxvY2Fs', 'SmFuZSBTbWl0aA==', 'AQUAAAAAAAUVAAAAL9XsbdwFntSl6rSPUwQAAA==', 'jsmith'; Kept = 'dn:: ', 'objectSid:: ' }
    @{ Name = 'MAC address forms'; Text = "Interface List`n  6...00 50 56 a1 2b 77 ......vmxnet3 Ethernet Adapter`nDHCPv6 Client DUID. . . . : 00-01-00-01-2C-1A-3B-4D-00-50-56-A1-2B-77`nkernel: ll header: 00000000: 52 54 00 8e 21 4f 52 54 00 1c 7a 3e 08 00`nUFW BLOCK MAC=52:54:00:8e:21:4f:52:54:00:1c:7a:3e:08:00 SRC=10.9.9.9"
       Gone = '00 50 56 a1 2b 77', '00-50-56-A1-2B-77', '52 54 00 8e 21 4f', '52:54:00:1c:7a:3e', '52:54:00:8e:21:4f'; Kept = 'vmxnet3 Ethernet Adapter', '08 00', '00-01-00-01-' }
    @{ Name = 'Secrets in XML, cookies, mysql'; Text = '<add key="ida:ClientSecret" value="Qx8~bN3.vR7_kL2-mP9sT4wY6zA1cE5gH0jK" />' + "`n" + '< Set-Cookie: session=Hz7Lq2Wv9Xb4Nc1Mk8Rt3; path=/; HttpOnly' + "`n" + 'sudo: x : COMMAND=/usr/bin/mysql -u root -pS3rv1ce#Db -h db1' + "`n" + '{"sid":"Hz7Lq2Wv9Xb4Nc1Mk8Rt3"}'
       Gone = 'Qx8~bN3.vR7_kL2-mP9sT4wY6zA1cE5gH0jK', 'Hz7Lq2Wv9Xb4Nc1Mk8Rt3', 'S3rv1ce#Db'; Kept = 'ida:ClientSecret', 'path=/; HttpOnly' }
    @{ Name = 'Organisation prefix learning'; Text = "Computer: NWT-DC01`nComputer: NWT-FS01`nComputer: NWT-APP02`nApplied GPOs: NWT-Workstation-Baseline, NWT-BitLocker-Laptops`nVPN group GP-NWT-VPN, role arn:aws:iam::123456789012:role/nwt-sftp-ec2-role`nNon-Interactive x-forwarded-for"
       Gone = 'NWT-Workstation-Baseline', 'NWT-BitLocker-Laptops', 'GP-NWT-VPN', 'nwt-sftp-ec2-role'; Kept = 'Non-Interactive x-forwarded-for', 'Applied GPOs:' }
    @{ Name = 'Cloud service suffixes'; Text = "Host: nwtfinance01.blob.core.windows.net`nEndpointSuffix=core.windows.net`neventSource: s3.amazonaws.com region us-west-2 type AWS::S3::Object`nec2-54-213-77-140.us-west-2.compute.amazonaws.com`nhttps://management.core.windows.net/"
       Gone = 'nwtfinance01', 'ec2-54-213-77-140'; Kept = '.blob.core.windows.net', 'EndpointSuffix=core.windows.net', 's3.amazonaws.com', 'us-west-2', 'AWS::S3::Object', 'https://management.core.windows.net/' }
    @{ Name = 'Host variants'; Text = "Computer: NWT-SQL-P02`nLinked server 'NWT_SQL_P02' failed; disk nwt-sql-p02-data01.vhdx; nwt-sql-p02's agent"
       Gone = 'NWT_SQL_P02', 'nwt-sql-p02'; Kept = 'Linked server', '.vhdx' }
    @{ Name = 'Correlation GUIDs stay, tenant GUIDs go'; Text = '{"eventID":"c3e5a7f9-1b2d-4e6f-8a0b-2c4d6e8f0a1b","correlationId":"0f8fad5b-d9cb-469f-a165-70867728950e","tenantId":"72f988bf-86f1-41af-91ab-2d7cd011db47","appid":"04b07795-8ddb-461a-bbee-02f9e1bf7b46"}'
       Gone = '72f988bf-86f1-41af-91ab-2d7cd011db47'; Kept = 'c3e5a7f9-1b2d-4e6f-8a0b-2c4d6e8f0a1b', '0f8fad5b-d9cb-469f-a165-70867728950e', '04b07795-8ddb-461a-bbee-02f9e1bf7b46' }
    @{ Name = 'Generic words never become names'; Text = "<Data Name='ObjectClass'>user</Data> Mandatory Label\High Mandatory Level`nHKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`npam_unix(cron:session): session opened for user root(uid=0) by (uid=0)`nlogname= uid=0 euid=0 tty=ssh ruser= rhost=10.1.1.1`nInvalid user oracle from 10.1.1.2`nCN=Person,CN=Schema,CN=Configuration,DC=nwtraders,DC=local"
       Gone = @(); Kept = "<Data Name='ObjectClass'>user</Data>", 'Mandatory Label\High Mandatory Level', 'Instance Names\SQL', 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)', 'logname= uid=0 euid=0 tty=ssh ruser=', 'Invalid user oracle', 'CN=Person,CN=Schema,CN=Configuration' }
    @{ Name = 'Encoded content (base64, auditd hex, PowerShell -EncodedCommand)'; Text = "Account Name: priya.raman`nrejected x-auth-context=eyJzdWIiOiJwcml5YS5yYW1hbiIsInNyYyI6IjE3Mi4yOS4xNC45MCJ9 reason=expired`ntype=PROCTITLE proctitle=73736800726A6F68616E73736F6E407661756C742D322E74746C6162732E696E7465726E616C`npowershell.exe -EncodedCommand bgBlAHQAIAB1AHMAZQAgAFwAXABsAG8AbgAxAGYAcwAwADIAXABmAGkAbgBhAG4AYwBlACQA"
       Gone = 'eyJzdWIiOiJwcml5YS5yYW1hbiIsInNyYyI6IjE3Mi4yOS4xNC45MCJ9', '73736800726A6F68616E73736F6E407661756C742D322E74746C6162732E696E7465726E616C', 'bgBlAHQAIAB1AHMAZQAgAFwAXABsAG8AbgAxAGYAcwAwADIAXABmAGkAbgBhAG4AYwBlACQA'; Kept = 'reason=expired', 'type=PROCTITLE proctitle=', '-EncodedCommand ' }
    @{ Name = 'Command-line secrets'; Text = "sqlcmd -S kronos-db -U sa -P Kr0n0s!SqlSa2026 -Q `"select 1`"`n+ docker login reg.ttlabs.internal -u svc-ci -p J3nkins!Build2026`n+ aws configure set aws_secret_access_key wJ8kq/Zr3Xn7Pd2Lm5Tb9Vc4Hy6Gf1Ks0Ea8Wu+Q --profile legacy`nPassword: 412335-073183-551441-208208-692087-034661-145167-320221`nWARNING! Using --password via the CLI is insecure."
       Gone = 'Kr0n0s!SqlSa2026', 'J3nkins!Build2026', 'wJ8kq/Zr3Xn7Pd2Lm5Tb9Vc4Hy6Gf1Ks0Ea8Wu+Q', '412335-073183-551441-208208-692087-034661-145167-320221'; Kept = 'Using --password via the CLI is insecure.', '--profile legacy' }
    @{ Name = 'Cloud resource ids'; Text = "2 739102846351 eni-07b2e1d4c9a3f5086 10.1.2.3 10.1.2.4 443 49152 6 20 4249 1794994200 1794994260 ACCEPT OK`n+ vpc_id = `"vpc-0c81d2e4f7a9b3615`"`n{`"actor`":{`"id`":`"00u1tt2wr3RoSe4x7d7`",`"type`":`"User`"},`"profileId`":`"104523987612345678901`"}`nimage ami-0c55b159cbfafe1f0"
       Gone = '739102846351', 'eni-07b2e1d4c9a3f5086', 'vpc-0c81d2e4f7a9b3615', '00u1tt2wr3RoSe4x7d7', '104523987612345678901'; Kept = 'ACCEPT OK', 'ami-0c55b159cbfafe1f0' }
    @{ Name = 'More host / user contexts'; Text = "Computer: AUS1DCS001`nlog: AUS1GPG001 and SYD2WEB011 seen; syd2ap1403 associated`n<14>Nov 18 09:33:12 AUS1FWL002 1,2026/11/18 09:33:12,013201004567,GLOBALPROTECT,0`nhaproxy[811]: 10.9.8.7:50311 [18/Nov/2026:09:31:29.440] fe_https~ be_sso/artemis 0/0/0/22/22 200 2210`n[tkowalski@build-agent-7 ~]$ ls`nFreeRADIUS: Login OK: [bob] (from client nas01 port 0 cli 3c22fb4e81d0)`nUser: AzureAD\WillRose"
       Gone = 'AUS1GPG001', 'AUS1FWL002', 'artemis', 'tkowalski', 'build-agent-7', '3c22fb4e81d0', 'WillRose', '013201004567'; Kept = 'GLOBALPROTECT', 'fe_https~', 'AzureAD\' }
    @{ Name = 'People, organisations, addresses'; Text = "DisplayName : Nguy" + [char]0x1EC5 + "n Th" + [char]0x1ECB + " Lan`nnew starter Nguyen Thi Lan joins`n> Head of Integrations, Fabrikam Logistics Ltd`n> Unit 4, Brindley Park, Coventry CV3 4FJ`n> T: +44 7700 900461`nowner = `"zhang_wei`" -> `"priya_raman`""
       Gone = 'Nguyen Thi Lan', 'Fabrikam Logistics Ltd', 'Brindley Park, Coventry CV3 4FJ', '7700 900461', 'zhang_wei', 'priya_raman'; Kept = 'Head of Integrations', 'new starter' }
    @{ Name = 'Ordinary words never become names'; Text = "at TCPConnectWrap.afterConnect (node:net:1611:16)`nfor user session 1 UPN will.rose@tailspintoys.com`nServer version name:   Apache Tomcat/10.1.34`nissuer: CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US`n[junos@2636.1.1.1.2.129 source-address=`"1.2.3.4`"]`nAudience: api://toy-catalog`nThe network path was not found. A new process has been created. Terraform will perform the following actions"
       Gone = 'will.rose'; Kept = '(node:net:1611:16)', 'for user session 1', 'Apache Tomcat/10.1.34', 'CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US', '[junos@2636.1.1.1.2.129', 'api://toy-catalog', 'The network path was not found. A new process has been created. Terraform will perform the following actions' }
    @{ Name = 'Organisation name in slugs and packages'; Text = "Subject: CN=www.tailspintoys.com, O=Tailspin Toys Inc., L=Austin, C=US`nCloning https://github.com/tailspin-toys/toy-catalog.git; at com.tailspin.catalog.Sync`nSSID Tailspin-Corp"
       Gone = 'Tailspin Toys Inc.', 'tailspin-toys', 'com.tailspin', 'Tailspin-Corp', 'Austin'; Kept = 'github.com/', 'C=US' }
    @{ Name = 'Look-alikes stay'; Text = "Loaded System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089`n`"token_type`": `"Bearer`"`nLogin failed: Password did not match`nPasswordLastSet : 1/1/2026`nNT AUTHORITY\SYSTEM Domain Admins S-1-5-18 Chrome/119.0.6045.105 OID 1.3.6.1.4.1.311.21.8 svchost.exe 0xC000006D"
       Gone = @(); Kept = 'PublicKeyToken=b77a5c561934e089', '"token_type": "Bearer"', 'Password did not match', 'PasswordLastSet : 1/1/2026', 'NT AUTHORITY\SYSTEM', 'Domain Admins', 'S-1-5-18', 'Chrome/119.0.6045.105', '1.3.6.1.4.1.311.21.8', 'svchost.exe', '0xC000006D' }
)

$fail = 0; $pass = 0
foreach ($c in $cases) {
    if ($c.Name -notlike $Filter) { continue }
    $e = New-Object LogScrub.ScrubEngine
    $e.ScanText($c.Text, 'case')
    $out = $e.ScrubText($c.Text)
    $problems = @()
    foreach ($g in $c.Gone) { if ($out.IndexOf($g, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $problems += "still contains '$g'" } }
    foreach ($k in $c.Kept) { if ($out.IndexOf($k, [StringComparison]::Ordinal) -lt 0) { $problems += "lost '$k'" } }
    if ($c.ContainsKey('Lines') -and (($c.Text -split "`n").Count -ne ($out -split "`n").Count)) { $problems += 'line count changed' }
    if ($problems.Count -eq 0) { $pass++; Write-Host "  PASS  $($c.Name)" -ForegroundColor Green }
    else {
        $fail++
        Write-Host "  FAIL  $($c.Name): $($problems -join '; ')" -ForegroundColor Red
        Write-Host ("        output: " + ($out -replace "`n", "`n                ")) -ForegroundColor DarkGray
    }
}
# ---- performance guard: no detector may be pathologically slow (catches catastrophic regex backtracking) ----
if ('Detector performance' -like $Filter) {
    $sb = New-Object Text.StringBuilder
    $rnd = New-Object Random 7
    for ($i = 0; $i -lt 6000; $i++) {
        [void]$sb.AppendFormat("2026-11-18 14:00:{0:00}.{1:000} INFO Computer=SRV{2:000}.corp.contoso.com client 10.{3}.{4}.{5} User: CORP\user{6} request /api/v1/items/{1} done in {0} ms status=200 trace={1:x8} Name : Value {7}`n", ($i % 60), $i, $rnd.Next(1, 400), $rnd.Next(0, 40), $rnd.Next(0, 255), $rnd.Next(1, 254), $rnd.Next(1, 2000), $i)
    }
    $text = $sb.ToString()
    $slow = @()
    foreach ($fld in [LogScrub.ScrubEngine].GetFields([Reflection.BindingFlags]'NonPublic,Static')) {
        if ($fld.FieldType -ne [regex]) { continue }
        $rx = $fld.GetValue($null)
        $sw = [Diagnostics.Stopwatch]::StartNew(); [void]$rx.Matches($text).Count; $sw.Stop()
        if ($sw.ElapsedMilliseconds -gt 1500) { $slow += "$($fld.Name) $($sw.ElapsedMilliseconds) ms" }
    }
    if ($slow.Count -eq 0) { $pass++; Write-Host ("  PASS  Detector performance ({0:n1} MB, every detector < 1.5 s)" -f ($text.Length / 1MB)) -ForegroundColor Green }
    else { $fail++; Write-Host "  FAIL  Detector performance: $($slow -join ', ')" -ForegroundColor Red }
}

Write-Host ("`n{0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit [int]($fail -gt 0)
