# ⚡ ZScan — Air-gap Safe Network Scanner v2.0.0

> **Full NSE-suite network scanner — 90+ embedded scripts, zero installs, works completely offline**

---

## What's New in v2.0

| Area | Improvement |
|---|---|
| **FTP** | Full anonymous login + PASV directory listing (mirrors `nmap ftp-anon`) |
| **FTP** | `SYST` command, bounce check, vsftpd 2.3.4 backdoor (CVE-2011-2523) |
| **FTP** | Non-standard port detection via banner (`30021`, `2121`, etc.) |
| **SSH** | Improved hostkey + SSHv1 weak version detection |
| **SMB** | Improved EternalBlue / DoublePulsar detection |
| **DNS** | Recursion check + zone transfer (AXFR) probe |
| **SNMP** | Community string brute (public/private/community/manager/admin) |
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
| **Embedded scripts** | ✅ **90+ scripts** | ✅ **55+ scripts** |
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

# Non-standard FTP port (e.g. 30021) — full anon check + listing
python3 zscan.py 192.168.164.127 -p 30021 --script all -sV

# Full SYN + OS + all scripts
sudo python3 zscan.py 10.0.0.1 -sS -p 1-1024 -O --script all

# All ports + JSON output
sudo python3 zscan.py 10.0.0.1 -sS -p - --script all -oJ results.json
```

### PowerShell — Windows

```powershell
# Basic scan
.\zscan.ps1 -Target 192.168.1.1

# Ping sweep
.\zscan.ps1 -Target 192.168.1.0/24 -ScanType Ping

# Non-standard FTP port
.\zscan.ps1 -Target 192.168.164.127 -Ports "30021" -ServiceDetection -Scripts all

# Full scan with HTML output
.\zscan.ps1 -Target 10.0.0.1 -Ports "1-1024" -ServiceDetection -OSDetect -Scripts all -OutputHTML report.html

# JSON + CSV output
.\zscan.ps1 -Target 10.0.0.0/24 -T 4 -Scripts vuln -OutputJSON scan.json -OutputCSV scan.csv
```

---

## Scan Types (Python)

| Flag | Type | Root? |
|---|---|---|
| `-sS` | TCP SYN (fast, stealthy) | ✅ |
| `-sT` | TCP Connect (default) | ❌ |
| `-sU` | UDP scan | ✅ |
| `-sF` | FIN scan | ✅ |
| `-sN` | NULL scan | ✅ |
| `-sX` | XMAS scan | ✅ |
| `-sn` | Ping sweep only | ❌ |

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
| `ftp-anon` | Anonymous login + full PASV directory listing |
| `ftp-syst` | OS fingerprint via SYST command |
| `ftp-bounce` | PORT-command bounce test |
| `ftp-vsftpd-backdoor` | vsftpd 2.3.4 backdoor — CVE-2011-2523 |

### HTTP / HTTPS
`http-title` · `http-server-header` · `http-methods` · `http-security-headers` · `http-cors` · `http-waf-detect` · `http-auth` · `http-robots.txt` · `http-cookie-flags` · `http-cross-domain-policy` · `http-generator` · `http-php-version` · `http-git` · `http-passwd` · `http-shellshock (CVE-2014-6271)` · `http-open-redirect` · `http-internal-ip-disclosure` · `http-trace` · `http-webdav-scan` · `http-aspnet-debug` · `http-default-accounts` · `http-enum` · `http-spring-boot-actuator` · `http-wordpress-users` · `http-vuln-cve2012-1823` · `http-vuln-cve2017-5638` · `http-vuln-cve2010-0738`

### SMB / NetBIOS
`smb-os-discovery` · `smb-protocols (SMBv1 detection)` · `smb-vuln-ms17-010 (EternalBlue) CVE-2017-0144` · `smb-double-pulsar-backdoor` · `smb2-time` · `nbstat`

### SSH / SMTP
`ssh-hostkey` · `ssh-auth-methods` · `ssh-weak-version (SSHv1) CVE-2001-0553` · `smtp-commands` · `smtp-open-relay` · `smtp-enum-users (VRFY)`

### Database Services
`mysql-info` · `pgsql-empty-password` · `ms-sql-info` · `redis-info` · `mongodb-info` · `elasticsearch-info` · `memcached-info` · `cassandra-info` · `couchdb-databases`

### Network Services
`dns-recursion` · `dns-zone-transfer` · `ntp-info` · `ntp-monlist (CVE-2013-5211)` · `snmp-info` · `ldap-rootdse` · `rsync-list-modules` · `finger` · `telnet-ntlm-info` · `imap-capabilities` · `pop3-capabilities` · `sip-methods` · `rtsp-methods` · `mqtt-subscribe` · `krb5-enum-users`

### SSL / TLS
`ssl-cert` (expiry + CN) · `ssl-enum-ciphers` (weak TLS)

### Remote Access
`rdp-enum-encryption` · `rdp-vuln-ms12-020 (CVE-2012-0152)` · `vnc-info` · `realvnc-auth-bypass (CVE-2006-2369)` · `ipmi-version` · `ipmi-cipher-zero (CVE-2013-4786)`

### ICS / SCADA
`modbus-discover` (port 502) · `s7-info` (Siemens S7 PLC port 102)

### Infrastructure / DevOps
`docker-version` · `kubernetes-api` · `kubernetes-kubelet` · `hadoop-namenode-info` · `jdwp-version` · `distcc-cve2004-2687` · `epmd-info`

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
-OutputHTML r.html   Dark dashboard with search
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
# Windows — allow local scripts
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\zscan.ps1 -Target 192.168.1.1 -Scripts all
```

---

**For authorised security testing only. Only scan systems you own or have explicit written permission to test.**

MIT License
