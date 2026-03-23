# ⚡ ZScan — Air-gap Safe Network Scanner v1.0.0

> **Full NSE-suite network scanner — 86 embedded scripts, zero installs, works completely offline**

---

## Two versions, one tool

| | `zscan.py` | `zscan.ps1` |
|---|---|---|
| **Platform** | Linux + Windows | Windows only |
| **Requires** | Python 3.6+ (stdlib only) | PowerShell 5.1+ (built-in on Win10+) |
| **Install** | Nothing | Nothing |
| **SYN/FIN/NULL/XMAS scan** | ✅ root | ❌ no raw sockets in PS |
| **TCP Connect scan** | ✅ | ✅ |
| **UDP scan** | ✅ root | ✅ limited |
| **Version detection** | ✅ | ✅ |
| **OS detection (TTL)** | ✅ | ✅ |
| **Embedded NSE scripts** | ✅ **86 scripts** | ✅ **52 scripts** |
| **Output formats** | Terminal / JSON / XML / Grepable | Terminal / JSON / HTML / CSV |
| **Speed at -T4** | ~10k ports/sec | ~3k ports/sec |
| **Air-gap safe** | ✅ stdlib only | ✅ .NET built-in only |

---

## Quick Start

### Python — Linux / Windows
```bash
python3 zscan.py 192.168.1.1                                    # default top-1000 scan
python3 zscan.py 192.168.1.0/24 -sn -T4                         # ping sweep
python3 zscan.py 192.168.1.1 -sT -sV --script default           # version + basic scripts
sudo python3 zscan.py 10.0.0.1 -sS -p 1-1024 -O --script all   # full SYN + OS + all scripts
sudo python3 zscan.py 10.0.0.1 -sS -p - --script all -oJ r.json # all ports + JSON output
```

### PowerShell — Windows (no Python needed)
```powershell
.\zscan.ps1 -Target 192.168.1.1                                          # default scan
.\zscan.ps1 -Target 192.168.1.0/24 -ScanType Ping                        # ping sweep
.\zscan.ps1 -Target 10.0.0.1 -Ports "1-1024" -ServiceDetection -Scripts vuln -OutputHTML r.html
.\zscan.ps1 -Target 10.0.0.1 -ServiceDetection -OSDetect -Scripts all -OutputJSON r.json -OutputCSV r.csv
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
| | Workers | Timeout | Use case |
|---|---|---|---|
| `-T0` paranoid | 10 | 5s | Maximum stealth |
| `-T1` sneaky | 50 | 3s | IDS evasion |
| `-T2` polite | 100 | 2s | Low bandwidth |
| `-T3` normal | 300 | 1.5s | Default |
| `-T4` aggressive | 500 | 0.75s | Fast LAN |
| `-T5` insane | 1000 | 0.3s | Maximum speed |

---

## Embedded Scripts — Full NSE Suite (86 Python / 52 PowerShell)

### HTTP / HTTPS
| Script | Category | CVE |
|---|---|---|
| http-title | default | |
| http-server-header | default | |
| http-methods | safe | |
| http-security-headers | safe | |
| http-cors | safe | |
| http-waf-detect | safe | |
| http-auth | default | |
| http-robots.txt | safe | |
| http-cookie-flags | safe | |
| http-cross-domain-policy | safe | |
| http-generator | safe | |
| http-php-version | safe | |
| http-apache-server-status | discovery | |
| http-git | vuln | |
| http-passwd | vuln | |
| http-shellshock | vuln | CVE-2014-6271 |
| http-open-redirect | vuln | |
| http-internal-ip-disclosure | vuln | |
| http-trace | vuln | |
| http-webdav-scan | vuln | |
| http-aspnet-debug | vuln | |
| http-default-accounts | auth | |
| http-enum | discovery | |
| http-spring-boot-actuator | vuln | |
| http-wordpress-users | discovery | |
| http-drupal-enum | vuln | CVE-2014-3704 |
| http-vuln-cve2012-1823 | vuln | CVE-2012-1823 |
| http-vuln-cve2017-5638 | vuln | CVE-2017-5638 |
| http-vuln-cve2010-0738 | vuln | CVE-2010-0738 |
| http-iis-short-name-brute | vuln | |

### SMB / NetBIOS
| Script | CVE |
|---|---|
| smb-os-discovery | |
| smb-protocols (SMBv1 detection) | |
| smb-vuln-ms17-010 (EternalBlue) | CVE-2017-0144 |
| smb-double-pulsar-backdoor | |
| smb2-time | |
| nbstat | |

### SSH / FTP / SMTP
| Script | CVE |
|---|---|
| ssh-hostkey | |
| ssh-auth-methods | |
| ssh-weak-version (SSHv1) | CVE-2001-0553 |
| ftp-anon | |
| ftp-syst | |
| ftp-vsftpd-backdoor | CVE-2011-2523 |
| smtp-commands | |
| smtp-open-relay | |
| smtp-enum-users (VRFY) | |

### Database Services
| Script | Notes |
|---|---|
| mysql-info | Version fingerprint |
| pgsql-empty-password | Auth bypass check |
| ms-sql-info | TDS probe |
| redis-info | Unauthenticated access |
| mongodb-info | Unauthenticated access |
| elasticsearch-info | Unauthenticated access |
| memcached-info | Unauthenticated access |
| cassandra-info | CQL auth check |
| couchdb-databases | Unauthenticated + list DBs |

### Network Services
| Script | Notes |
|---|---|
| dns-recursion | Open resolver |
| dns-zone-transfer | AXFR check |
| ntp-info | Version + time |
| ntp-monlist | CVE-2013-5211 DDoS amplification |
| snmp-info | Community string brute (public/private) |
| ldap-rootdse | Anonymous bind |
| rsync-list-modules | Unauthenticated module listing |
| finger | User enumeration |
| telnet-ntlm-info | Cleartext protocol banner |
| imap-capabilities | IMAP feature list |
| pop3-capabilities | POP3 feature list |
| sip-methods | VoIP OPTIONS probe |
| rtsp-methods | Streaming server OPTIONS |
| mqtt-subscribe | Broker anonymous access |
| krb5-enum-users | Kerberos AS-REQ probe |

### SSL/TLS
| Script | Notes |
|---|---|
| ssl-cert | Expiry + CN |
| ssl-enum-ciphers | Weak TLS version |

### Remote Access
| Script | Notes |
|---|---|
| rdp-enum-encryption | NLA vs classic |
| rdp-vuln-ms12-020 | CVE-2012-0152 |
| vnc-info | Version |
| realvnc-auth-bypass | CVE-2006-2369 |
| ipmi-version | RMCP probe |
| ipmi-cipher-zero | CVE-2013-4786 |

### ICS / SCADA
| Script | Notes |
|---|---|
| modbus-discover | Port 502 — ICS/SCADA exposure |
| s7-info | Siemens S7 PLC port 102 |

### Infrastructure / DevOps
| Script | Notes |
|---|---|
| docker-version | Unauthenticated Docker API (port 2375/2376) |
| kubernetes-api | Unauthenticated K8s API |
| kubernetes-kubelet | Unauthenticated Kubelet |
| hadoop-namenode-info | Hadoop web UI |
| jdwp-version | Java debug port RCE |
| distcc-cve2004-2687 | Remote compile daemon |
| epmd-info | Erlang node listing |

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
| External imports | ✅ stdlib only | ✅ System.Net.Sockets only |
| Package manager calls | ✅ None | ✅ None |
| Auto-downloads | ✅ None | ✅ None |
| Outbound connections | ✅ Only to your targets | ✅ Only to your targets |

Copy a single file to the target. Run. Done.

---

## Push to GitHub

```bash
cd ZScan
git init && git add .
git commit -m "feat: ZScan v1.0.0 — 86-script air-gap network scanner"
git branch -M main
git remote add origin https://github.com/YOUR_USER/ZScan.git
git push -u origin main
```

---

**For authorised security testing only. Only scan systems you own or have explicit written permission to test.**

MIT License
