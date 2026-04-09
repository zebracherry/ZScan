# ⚡ ZScan — Air-gap Safe Network Scanner v2.1.0

> **Full NSE-suite network scanner — 95+ embedded scripts, zero installs, works completely offline**

---

## Changelog

### v2.1.0
| Area | Improvement |
|---|---|
| **HTTP** | `http-methods` — OPTIONS-based risky method detection (PUT/DELETE/PATCH etc.) |
| **HTTP** | `http-webdav-scan` — PROPFIND/MKCOL/LOCK/UNLOCK exposure with server date |
| **HTTP** | `http-open-proxy` — CONNECT method detection |
| **HTTP** | `http-trace` — TRACE XST vulnerability check |
| **HTTP** | Non-standard ports now get full HTTP script suite (e.g. 33033, 45332, 45443) |
| **SSL** | Cert check now uses raw `SslStream` — works on **any** port (e.g. 44330) |
| **SSL** | Protocol version reported — TLS 1.0 / SSL3 flagged as weak |
| **Service** | Banner-based name upgrade — `unknown` ports now show `http`/`ftp`/`ssh` etc. |
| **Banner** | TLS handshake fallback probe for non-standard SSL ports |
| **Banner** | HTTP `GET` probe sent on all non-raw-service ports |
| **FTP** | Directory listing grouped into a single result (cleaner nmap-style output) |

### v2.0.0
| Area | Improvement |
|---|---|
| **FTP** | Full anonymous login + PASV directory listing (mirrors `nmap ftp-anon`) |
| **FTP** | `SYST` command, bounce check, vsftpd 2.3.4 backdoor (CVE-2011-2523) |
| **FTP** | Non-standard port detection via banner (`30021`, `2121`, etc.) |
| **SSH** | Hostkey + SSHv1 weak version detection |
| **SMB** | Improved EternalBlue / DoublePulsar detection |
| **DNS** | Recursion check + zone transfer (AXFR) probe |
| **SNMP** | Community string brute (public / private / community / manager / admin) |
| **NTP** | Server info + monlist DDoS amplification check (CVE-2013-5211) |
| **Rsync** | Unauthenticated module listing |
| **Docker** | Unauthenticated remote API exposure check |
| **Kubernetes** | API server + Kubelet unauthenticated access check |
| **Modbus** | ICS/SCADA device exposure (port 502) |
| **Output** | Vuln summary count in terminal output |

---

## Two versions, one tool

|  | `zscan.py` | `zscan.ps1` |
|---|---|---|
| **Platform** | Linux + Windows | Windows only |
| **Requires** | Python 3.6+ (stdlib only) | PowerShell 5.1+ (built-in on Win10+) |
| **Install** | Nothing | Nothing |
| **SYN/FIN/NULL/XMAS scan** | ✅ root | ❌ no raw sockets in PS |
| **TCP Connect scan** | ✅ | ✅ |
| **UDP scan** | ✅ root | ✅ limited |
| **Version detection** | ✅ | ✅ |
| **OS detection (TTL)** | ✅ | ✅ |
| **Embedded scripts** | ✅ **95+ scripts** | ✅ **60+ scripts** |
| **Output formats** | Terminal / JSON / XML / Grepable | Terminal / JSON / HTML / CSV |
| **Air-gap safe** | ✅ stdlib only | ✅ .NET built-in only |

---

## Quick Start

### Python — Linux / Windows

```bash
# Basic top-1000 scan
python3 zscan.py 192.168.1.1

# Ping sweep
python3 zscan.py 192.168.1.0/24 -sn -T4

# Version + default scripts
python3 zscan.py 192.168.1.1 -sT -sV --script default

# Non-standard ports — full service detection + all scripts
python3 zscan.py 192.168.1.1 -p 30021,33033,44330,45332 --script all -sV

# Full SYN + OS detection + all scripts
sudo python3 zscan.py 10.0.0.1 -sS -p 1-1024 -O --script all

# All 65535 ports + JSON output
sudo python3 zscan.py 10.0.0.1 -sS -p - --script all -oJ results.json
```

### PowerShell — Windows

```powershell
# Basic scan
.\zscan.ps1 -Target 192.168.1.1

# Ping sweep
.\zscan.ps1 -Target 192.168.1.0/24 -ScanType Ping

# Non-standard ports — full scripts
.\zscan.ps1 -Target 192.168.1.1 -Ports "30021,33033,44330" -ServiceDetection -Scripts all

# Full scan with HTML report
.\zscan.ps1 -Target 10.0.0.1 -Ports "1-1024" -ServiceDetection -OSDetect -Scripts all -OutputHTML report.html

# All ports + JSON + CSV
.\zscan.ps1 -Target 10.0.0.0/24 -T 4 -Scripts vuln -OutputJSON scan.json -OutputCSV scan.csv
```

---

## Scan Types

### Python

| Flag | Type | Root? |
|---|---|---|
| `-sS` | TCP SYN (fast, stealthy) | ✅ |
| `-sT` | TCP Connect (default) | ❌ |
| `-sU` | UDP scan | ✅ |
| `-sF` | FIN scan | ✅ |
| `-sN` | NULL scan | ✅ |
| `-sX` | XMAS scan | ✅ |
| `-sn` | Ping sweep only | ❌ |

### PowerShell

`-ScanType TCP` (default) · `-ScanType UDP` · `-ScanType Ping`

---

## Timing Templates

| Level | Workers | Timeout | Use case |
|---|---|---|---|
| `-T0` paranoid | 10 | 5s | Maximum stealth |
| `-T1` sneaky | 50 | 3s | IDS evasion |
| `-T2` polite | 100 | 2s | Low bandwidth |
| `-T3` normal | 300 | 1.5s | Default |
| `-T4` aggressive | 500 | 0.75s | Fast LAN |
| `-T5` insane | 1000 | 0.3s | Maximum speed |

---

## Embedded Scripts

### FTP
| Script | Notes |
|---|---|
| `ftp-anon` | Anonymous login + full PASV directory listing — works on any port via banner |
| `ftp-syst` | OS fingerprint via SYST command |
| `ftp-bounce` | PORT-command bounce test |
| `ftp-vsftpd-backdoor` | vsftpd 2.3.4 backdoor — CVE-2011-2523 |

### HTTP / HTTPS
| Script | Notes |
|---|---|
| `http-title` | Page title |
| `http-server-header` | Server header fingerprint |
| `http-methods` | OPTIONS-based method detection — flags PUT/DELETE/PATCH/TRACE/WebDAV as risky |
| `http-webdav-scan` | WebDAV exposure — PROPFIND/MKCOL/LOCK/UNLOCK with server date |
| `http-open-proxy` | CONNECT method → open proxy |
| `http-trace` | TRACE method → XST vulnerability |
| `http-security-headers` | Missing CSP / HSTS / X-Frame-Options etc. |
| `http-cors` | Wildcard CORS misconfiguration |
| `http-waf-detect` | Cloudflare / AWS WAF / ModSecurity / F5 detection |
| `http-auth` | 401 auth type fingerprint |
| `http-robots.txt` | Disallowed paths |
| `http-git` | Exposed `.git/HEAD` |
| `http-passwd` | Directory traversal → `/etc/passwd` |
| `http-shellshock` | CVE-2014-6271 |
| `http-internal-ip-disclosure` | Private IP leaked in HTTP response |
| `http-php-version` | PHP version from `X-Powered-By` |
| `http-generator` | Framework / version info headers |
| `http-spring-boot-actuator` | Spring Boot `/actuator` exposure |
| `http-wordpress-users` | WordPress user enumeration via REST API |
| `http-enum` | Common sensitive path brute (admin / phpmyadmin / .env etc.) |
| `http-open-redirect` | Redirect parameter injection |
| `http-vuln-cve2017-5638` | Apache Struts RCE |
| `http-vuln-cve2012-1823` | PHP-CGI argument injection |

### SMB / NetBIOS
| Script | Notes |
|---|---|
| `smb-protocols` | SMBv1 detection |
| `smb-vuln-ms17-010` | EternalBlue / WannaCry — CVE-2017-0144 |
| `smb-double-pulsar-backdoor` | DoublePulsar implant check |

### SSH / SMTP
| Script | Notes |
|---|---|
| `ssh-hostkey` | Banner + key fingerprint |
| `ssh-auth-methods` | Accepted authentication methods |
| `ssh-weak-version` | SSHv1 detection — CVE-2001-0553 |
| `smtp-commands` | EHLO capability list |
| `smtp-open-relay` | Unauthenticated relay test |
| `smtp-enum-users` | VRFY user enumeration |

### Database Services
| Script | Notes |
|---|---|
| `mysql-info` | Version fingerprint from handshake |
| `pgsql-empty-password` | Passwordless auth check |
| `redis-info` | Unauthenticated access + version |
| `mongodb-info` | Unauthenticated isMaster probe |
| `elasticsearch-info` | Unauthenticated access + version |
| `memcached-info` | Unauthenticated stats + version |

### Network Services
| Script | Notes |
|---|---|
| `dns-recursion` | Open resolver check |
| `dns-zone-transfer` | AXFR probe via TCP |
| `ntp-info` | Version + stratum + timestamp |
| `ntp-monlist` | DDoS amplification — CVE-2013-5211 |
| `snmp-info` | Community string brute (5 common strings) |
| `ldap-rootdse` | Anonymous bind check |
| `rsync-list-modules` | Unauthenticated module listing |
| `telnet-ntlm-info` | Cleartext protocol banner |
| `imap-capabilities` | CAPABILITY response |
| `pop3-capabilities` | CAPA response |

### SSL / TLS
| Script | Notes |
|---|---|
| `ssl-cert` | Subject / org / expiry / days remaining — works on **any** port |
| `ssl-enum-ciphers` | Protocol version — TLS 1.0 / SSL3 flagged as weak |

### Remote Access
| Script | Notes |
|---|---|
| `rdp-enum-encryption` | NLA / CredSSP enforcement check |
| `vnc-info` | Protocol version banner |
| `realvnc-auth-bypass` | Old RFB protocol auth bypass — CVE-2006-2369 |

### ICS / SCADA
| Script | Notes |
|---|---|
| `modbus-discover` | Port 502 Modbus device response — ICS/SCADA exposure |

### Infrastructure / DevOps
| Script | Notes |
|---|---|
| `docker-version` | Unauthenticated Docker API (port 2375/2376) |
| `kubernetes-api` | Unauthenticated K8s API server |
| `kubernetes-kubelet` | Unauthenticated Kubelet (port 10250) |

---

## Output Formats

### Python
```
-oJ output.json      JSON
-oX output.xml       XML (nmap-compatible style)
-oG output.gnmap     Grepable
```

### PowerShell
```
-OutputJSON r.json
-OutputHTML r.html   Dark themed dashboard
-OutputCSV  r.csv
```

---

## Air-Gap Guarantee

| Check | Python | PowerShell |
|---|---|---|
| External imports | ✅ stdlib only | ✅ System.Net only |
| Package manager calls | ✅ None | ✅ None |
| Auto-downloads | ✅ None | ✅ None |
| Outbound connections | ✅ Only to your targets | ✅ Only to your targets |

Copy a single file to the target. Run. Done.

---

## Install

```bash
# Linux — run from anywhere
sudo cp zscan.py /usr/local/bin/zscan
sudo chmod +x /usr/local/bin/zscan
zscan 192.168.1.1 --script all
```

```powershell
# Windows — allow local scripts then run
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\zscan.ps1 -Target 192.168.1.1 -Scripts all
```

---

**For authorised security testing only. Only scan systems you own or have explicit written permission to test.**

MIT License
