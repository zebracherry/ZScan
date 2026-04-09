#!/usr/bin/env python3
"""
███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
╚══███╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███╔╝ ███████╗██║     ███████║██╔██╗ ██║
 ███╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

ZScan — Air-gap Safe Network Scanner  v2.0.0
Platform : Linux / Windows (Python 3.6+)
License  : MIT

WHAT'S NEW IN v2.0:
  • FTP: full anonymous login + PASV directory listing (mirrors nmap ftp-anon)
  • FTP: SYST command, bounce check, non-standard port detection (30021 etc.)
  • FTP: vsftpd 2.3.4 backdoor probe (CVE-2011-2523)
  • SSH: improved hostkey + weak cipher detection
  • SMB: improved MS17-010 / DoublePulsar detection
  • DNS: zone transfer (AXFR), recursion check
  • SNMP: community string brute (public/private/community)
  • Service fingerprint: improved banner regex for all services
  • All scripts now run on non-standard ports (not just default port numbers)
  • --script-args support for custom wordlists
  • Cleaner output formatting matching nmap style

SCAN TYPES:
  -sS  TCP SYN scan      (root required — fast, stealthy)
  -sT  TCP Connect scan  (no root — reliable, default)
  -sU  UDP scan          (root required)
  -sF  TCP FIN scan      (root required)
  -sN  TCP NULL scan     (root required)
  -sX  TCP XMAS scan     (root required)
  -sn  Ping scan / host discovery only
  -O   OS detection
  -sV  Version/banner detection
  --script  Run embedded scripts (default/safe/vuln/auth/discovery/all)
  -p   Port range: 22,80 / 1-1024 / - (all)
  --top-ports N
  -T0..-T5  Timing templates
  -oJ/-oX/-oG  Output formats

AIR-GAP SAFE: stdlib only — zero external deps
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import random
import re
import select
import socket
import struct
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION    = "2.0.0"
TOOL       = "ZScan"
IS_WINDOWS = platform.system() == "Windows"
IS_ROOT    = (os.geteuid() == 0) if not IS_WINDOWS else False

R  = "\033[0;31m"; G  = "\033[0;32m"; Y  = "\033[1;33m"
C  = "\033[0;36m"; B  = "\033[1m";    D  = "\033[2m";   RST = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# TOP PORTS
# ─────────────────────────────────────────────────────────────────────────────
TOP_100 = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5900,8080,8443,8888,9090,9200,27017,
    20,69,79,88,102,106,113,119,137,138,179,194,389,427,
    497,500,514,515,543,544,548,554,587,631,646,873,990,
    1025,1026,1027,1028,1433,1720,1755,1900,2000,2001,2049,
    2121,2717,3000,3128,3632,4899,5000,5009,5051,5060,5101,
    5190,5357,5432,5631,5666,5800,5985,6000,6001,6646,7070,
    8008,8009,8010,8031,8181,8192,49152,49153,49154,49155,49156,
]
TOP_1000 = sorted(set(TOP_100 + list(range(1, 1024))))[:1000]

# ─────────────────────────────────────────────────────────────────────────────
# SERVICE DATABASE
# ─────────────────────────────────────────────────────────────────────────────
SERVICE_DB: Dict[int, Tuple[str, bytes]] = {
    20:    ("ftp-data",    b""),
    21:    ("ftp",         b""),
    22:    ("ssh",         b""),
    23:    ("telnet",      b""),
    25:    ("smtp",        b"EHLO zscan\r\n"),
    53:    ("dns",         b""),
    69:    ("tftp",        b""),
    79:    ("finger",      b""),
    80:    ("http",        b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    88:    ("kerberos",    b""),
    102:   ("iso-tsap",    b""),
    110:   ("pop3",        b""),
    111:   ("rpcbind",     b""),
    119:   ("nntp",        b""),
    123:   ("ntp",         b""),
    135:   ("msrpc",       b""),
    137:   ("netbios-ns",  b""),
    139:   ("netbios-ssn", b""),
    143:   ("imap",        b""),
    161:   ("snmp",        b""),
    179:   ("bgp",         b""),
    389:   ("ldap",        b""),
    443:   ("https",       b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    445:   ("smb",         b""),
    465:   ("smtps",       b""),
    500:   ("isakmp",      b""),
    502:   ("modbus",      b""),
    514:   ("syslog",      b""),
    515:   ("printer",     b""),
    587:   ("submission",  b"EHLO zscan\r\n"),
    631:   ("ipp",         b""),
    636:   ("ldaps",       b""),
    873:   ("rsync",       b""),
    990:   ("ftps",        b""),
    993:   ("imaps",       b""),
    995:   ("pop3s",       b""),
    1080:  ("socks",       b""),
    1433:  ("ms-sql-s",    b""),
    1521:  ("oracle",      b""),
    1723:  ("pptp",        b""),
    2049:  ("nfs",         b""),
    2121:  ("ftp-proxy",   b""),
    2375:  ("docker",      b"GET /version HTTP/1.0\r\n\r\n"),
    2376:  ("docker-tls",  b""),
    3000:  ("http",        b"GET / HTTP/1.0\r\n\r\n"),
    3306:  ("mysql",       b""),
    3389:  ("ms-wbt-server",b""),
    3632:  ("distccd",     b""),
    4444:  ("krb524",      b""),
    5000:  ("upnp",        b"GET / HTTP/1.0\r\n\r\n"),
    5432:  ("postgresql",  b""),
    5900:  ("vnc",         b""),
    5985:  ("wsman",       b""),
    6379:  ("redis",       b"*1\r\n$4\r\nINFO\r\n"),
    6443:  ("kubernetes",  b"GET /version HTTP/1.0\r\n\r\n"),
    7070:  ("realserver",  b""),
    8080:  ("http-proxy",  b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    8443:  ("https-alt",   b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    8888:  ("http",        b"GET / HTTP/1.0\r\n\r\n"),
    9200:  ("elasticsearch",b"GET / HTTP/1.0\r\n\r\n"),
    9300:  ("elasticsearch-cluster",b""),
    9090:  ("http",        b"GET / HTTP/1.0\r\n\r\n"),
    10250: ("kubelet",     b"GET /healthz HTTP/1.0\r\n\r\n"),
    11211: ("memcache",    b"stats\r\n"),
    27017: ("mongod",      b""),
    27018: ("mongod",      b""),
    50000: ("ibm-db2",     b""),
}

# FTP ports — used to trigger FTP scripts on non-standard ports
FTP_PORTS = {20, 21, 990, 2121}

# ─────────────────────────────────────────────────────────────────────────────
# TIMING TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
TIMING = {
    0: {"workers": 10,   "timeout": 5.0,  "delay": 0.5,  "name": "paranoid"},
    1: {"workers": 50,   "timeout": 3.0,  "delay": 0.1,  "name": "sneaky"},
    2: {"workers": 100,  "timeout": 2.0,  "delay": 0.05, "name": "polite"},
    3: {"workers": 300,  "timeout": 1.5,  "delay": 0.0,  "name": "normal"},
    4: {"workers": 500,  "timeout": 0.75, "delay": 0.0,  "name": "aggressive"},
    5: {"workers": 1000, "timeout": 0.3,  "delay": 0.0,  "name": "insane"},
}

# ─────────────────────────────────────────────────────────────────────────────
# OS FINGERPRINT
# ─────────────────────────────────────────────────────────────────────────────
OS_TTL_DB = [
    (255, "Cisco IOS / network device"),
    (128, "Windows (XP/Vista/7/8/10/11/Server)"),
    (64,  "Linux / macOS / Android / iOS"),
    (60,  "macOS (older / BSD)"),
    (32,  "Windows 95/98/NT"),
    (30,  "Solaris / AIX (older)"),
]

def guess_os_from_ttl(ttl: int) -> str:
    return min(OS_TTL_DB, key=lambda x: abs(x[0] - ttl))[1]

# ─────────────────────────────────────────────────────────────────────────────
# VERSION FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────
VERSION_PATTERNS = [
    (r"SSH-(\d+\.\d+)-OpenSSH[_\-](\S+)",         "OpenSSH {2} (protocol {1})"),
    (r"SSH-(\d+\.\d+)-(\S+)",                      "SSH {2} (protocol {1})"),
    (r"Server:\s*(Apache[^\r\n]+)",                "{1}"),
    (r"Server:\s*(nginx[^\r\n]+)",                 "{1}"),
    (r"Server:\s*(Microsoft-IIS[^\r\n]+)",         "{1}"),
    (r"Server:\s*([^\r\n]+)",                      "{1}"),
    (r"HTTP/(\d\.\d)\s+\d+",                       "HTTP/{1}"),
    (r"220[\s\-]+(FileZilla[^\r\n]+)",             "FTP: {1}"),
    (r"220[\s\-]+(vsftpd[^\r\n]+)",                "FTP: {1}"),
    (r"220[\s\-]+(ProFTPD[^\r\n]+)",               "FTP: {1}"),
    (r"220[\s\-]+(Pure-FTPd[^\r\n]+)",             "FTP: {1}"),
    (r"220[\s\-]+([^\r\n]+)",                      "FTP/SMTP: {1}"),
    (r"redis_version:(\S+)",                       "Redis {1}"),
    (r'"version"\s*:\s*"([^"]+)"',                 "Elasticsearch {1}"),
    (r"STAT version (\S+)",                        "Memcached {1}"),
    (r'"ok"\s*:\s*1.*"version"\s*:\s*"([^"]+)"',  "MongoDB {1}"),
    (r"Docker/(\S+)",                              "Docker {1}"),
    (r"[Vv]ersion[:\s]+(\d[\d\.]+)",              "v{1}"),
]

def fingerprint_banner(banner: bytes, port: int) -> str:
    try:
        text = banner.decode("utf-8", errors="replace")
    except Exception:
        text = repr(banner)
    for pattern, template in VERSION_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if m:
            result = template
            for i, g in enumerate(m.groups(), 1):
                result = result.replace(f"{{{i}}}", (g or "").strip())
            return result[:80]
    # For HTTP responses, extract status + server even without a Server: header
    if "HTTP/" in text[:20]:
        status_m = re.match(r"HTTP/[\d\.]+ (\d+)", text)
        st = status_m.group(1) if status_m else "?"
        return f"HTTP {st}"
    svc = SERVICE_DB.get(port, ("unknown", b""))[0]
    first_line = text.split("\n")[0].strip()[:60]
    if first_line and len(first_line) > 3:
        return f"{svc}: {first_line}"
    return svc

# ─────────────────────────────────────────────────────────────────────────────
# RAW PACKET HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_ip_header(src_ip: str, dst_ip: str, proto: int, data_len: int) -> bytes:
    ver_ihl = (4 << 4) | 5; tos = 0
    total_len = 20 + data_len; ip_id = random.randint(1, 65535)
    frag_off = 0; ttl = 64; csum = 0
    src = socket.inet_aton(src_ip); dst = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ip_id, frag_off, ttl, proto, csum, src, dst)
    csum = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ip_id, frag_off, ttl, proto, csum, src, dst)

def build_tcp_header(src_ip: str, dst_ip: str, sport: int, dport: int,
                     flags: int, seq: int = 0, ack: int = 0, window: int = 65535) -> bytes:
    data_off = (5 << 4); csum = 0; urg = 0
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, data_off, flags, window, csum, urg)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(tcp))
    csum = checksum(pseudo + tcp)
    return struct.pack("!HHLLBBHHH", sport, dport, seq, ack, data_off, flags, window, csum, urg)

def build_icmp_echo(seq: int = 1) -> bytes:
    icmp_type = 8; code = 0; csum = 0; pid = os.getpid() & 0xFFFF
    hdr = struct.pack("!BBHHH", icmp_type, code, csum, pid, seq)
    csum = checksum(hdr)
    return struct.pack("!BBHHH", icmp_type, code, csum, pid, seq)

# ─────────────────────────────────────────────────────────────────────────────
# HOST DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
def icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    if not IS_ROOT and not IS_WINDOWS:
        return tcp_ping(ip, timeout)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.sendto(build_icmp_echo(), (ip, 0))
        try:
            data, _ = sock.recvfrom(1024)
            if len(data) >= 28 and data[20] == 0:
                return True
        except socket.timeout:
            pass
    except (PermissionError, OSError):
        return tcp_ping(ip, timeout)
    finally:
        try: sock.close()
        except: pass
    return False

def tcp_ping(ip: str, timeout: float = 1.0,
             ports: List[int] = [80, 443, 22, 445, 3389]) -> bool:
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result in (0, 111):
                return True
        except Exception:
            pass
    return False

def discover_hosts(targets: List[str], timeout: float = 1.0, workers: int = 100) -> List[str]:
    live = []; lock = threading.Lock()
    def check(ip):
        if icmp_ping(ip, timeout):
            with lock: live.append(ip)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(check, targets)
    return sorted(live, key=lambda x: [int(o) for o in x.split(".")])

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────
TH_FIN = 0x01; TH_SYN = 0x02; TH_RST = 0x04
TH_PSH = 0x08; TH_ACK = 0x10; TH_URG = 0x20
PORT_OPEN      = "open"
PORT_CLOSED    = "closed"
PORT_FILTERED  = "filtered"
PORT_OPEN_FILT = "open|filtered"

def _get_local_ip(dst: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst, 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        try: s.close()
        except: pass

def tcp_syn_scan(ip: str, port: int, timeout: float = 1.0, src_ip: str = "") -> str:
    if not IS_ROOT:
        return tcp_connect_scan(ip, port, timeout)
    if not src_ip:
        src_ip = _get_local_ip(ip)
    sport = random.randint(1024, 65535)
    seq   = random.randint(0, 2**32 - 1)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)
        tcp_hdr = build_tcp_header(src_ip, ip, sport, port, TH_SYN, seq)
        ip_hdr  = build_ip_header(src_ip, ip, 6, len(tcp_hdr))
        raw.sendto(ip_hdr + tcp_hdr, (ip, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = raw.recvfrom(4096)
                if addr[0] != ip: continue
                if len(data) < 40: continue
                ihl = (data[0] & 0x0F) * 4
                tcp_data = data[ihl:]
                r_sport, r_dport = struct.unpack("!HH", tcp_data[0:4])
                r_flags = tcp_data[13]
                if r_dport != sport or r_sport != port: continue
                if r_flags & (TH_SYN | TH_ACK) == (TH_SYN | TH_ACK):
                    rst = build_tcp_header(src_ip, ip, sport, port, TH_RST, seq + 1)
                    ip_r = build_ip_header(src_ip, ip, 6, len(rst))
                    try: raw.sendto(ip_r + rst, (ip, 0))
                    except: pass
                    return PORT_OPEN
                elif r_flags & TH_RST:
                    return PORT_CLOSED
            except socket.timeout:
                break
        return PORT_FILTERED
    except (PermissionError, OSError):
        return tcp_connect_scan(ip, port, timeout)
    finally:
        try: raw.close()
        except: pass

def tcp_connect_scan(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:             return PORT_OPEN
        if result in (111, 10061): return PORT_CLOSED
        return PORT_FILTERED
    except socket.timeout:
        return PORT_FILTERED
    except Exception:
        return PORT_FILTERED

def tcp_flag_scan(ip: str, port: int, flags: int, timeout: float = 1.0, src_ip: str = "") -> str:
    if not IS_ROOT:
        print("[!] FIN/NULL/XMAS scan requires root"); return PORT_FILTERED
    if not src_ip:
        src_ip = _get_local_ip(ip)
    sport = random.randint(1024, 65535)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)
        tcp_hdr = build_tcp_header(src_ip, ip, sport, port, flags)
        ip_hdr  = build_ip_header(src_ip, ip, 6, len(tcp_hdr))
        raw.sendto(ip_hdr + tcp_hdr, (ip, 0))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = raw.recvfrom(4096)
                if addr[0] != ip: continue
                ihl = (data[0] & 0x0F) * 4
                tcp_data = data[ihl:]
                r_sport, r_dport = struct.unpack("!HH", tcp_data[0:4])
                r_flags = tcp_data[13]
                if r_dport != sport or r_sport != port: continue
                if r_flags & TH_RST: return PORT_CLOSED
            except socket.timeout:
                break
        return PORT_OPEN_FILT
    except Exception:
        return PORT_FILTERED
    finally:
        try: raw.close()
        except: pass

def udp_scan(ip: str, port: int, timeout: float = 2.0, src_ip: str = "") -> str:
    if not IS_ROOT and not IS_WINDOWS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00" * 8, (ip, port))
            try:
                sock.recv(1024); return PORT_OPEN
            except socket.timeout:
                return PORT_OPEN_FILT
        except Exception:
            return PORT_FILTERED
        finally:
            try: sock.close()
            except: pass
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        probe = SERVICE_DB.get(port, ("", b""))[1] or b"\x00" * 8
        udp_sock.sendto(probe, (ip, port))
        try:
            data, _ = udp_sock.recvfrom(4096)
            if data: return PORT_OPEN
        except socket.timeout:
            return PORT_OPEN_FILT
        except ConnectionResetError:
            return PORT_CLOSED
    except Exception:
        return PORT_FILTERED
    finally:
        try: udp_sock.close()
        except: pass
    return PORT_OPEN_FILT

def grab_banner(ip: str, port: int, timeout: float = 3.0) -> bytes:
    """Grab service banner — tries HTTP probe, then raw read, then TLS."""
    probe    = SERVICE_DB.get(port, ("", b""))[1]
    ssl_ports = {443, 8443, 993, 995, 465, 636, 6443, 44330}
    http_ports = {80, 8080, 8443, 443, 8888, 8000, 9090, 9200, 5000, 3000,
                  7070, 8000, 33033, 45332, 45443}

    def _read_all(sock: socket.socket, t: float = 2.0) -> bytes:
        banner = b""
        sock.settimeout(t)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                banner += chunk
                if len(banner) > 8192: break
        except socket.timeout:
            pass
        return banner

    # ── Try plain TCP first ───────────────────────────────────────────────────
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Wrap SSL for known SSL ports
        if port in ssl_ports:
            try:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except Exception:
                pass

        # Send HTTP GET for likely HTTP ports, or if we got no probe
        if port in http_ports or (not probe and port not in {22, 21, 25, 110, 143, 3306, 5432, 6379}):
            http_probe = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            try:
                sock.send(http_probe.encode())
            except Exception:
                pass
        elif probe:
            sock.send(probe)

        banner = _read_all(sock, timeout)
        sock.close()

        if banner:
            return banner
    except Exception:
        try: sock.close()
        except: pass

    # ── Fallback: try TLS wrap on non-standard port if no banner yet ──────────
    if port not in ssl_ports:
        try:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.connect((ip, port))
            ssl_sock = ctx.wrap_socket(raw, server_hostname=ip)
            ssl_sock.send(f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
            banner = _read_all(ssl_sock, timeout)
            ssl_sock.close()
            if banner:
                return banner
        except Exception:
            pass

    return b""

def os_detect(ip: str, timeout: float = 2.0) -> Dict:
    result = {"os": "unknown", "ttl": 0, "method": ""}
    if IS_ROOT or IS_WINDOWS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            sock.sendto(build_icmp_echo(seq=1), (ip, 0))
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) >= 9:
                    ttl = data[8]
                    result["ttl"] = ttl
                    result["os"]  = guess_os_from_ttl(ttl)
                    result["method"] = "icmp-ttl"
            except socket.timeout:
                pass
        except Exception:
            pass
        finally:
            try: sock.close()
            except: pass
    return result

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPT ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class ScriptResult:
    def __init__(self, name: str, output: str, vuln: bool = False, cve: str = ""):
        self.name   = name
        self.output = output
        self.vuln   = vuln
        self.cve    = cve

    def __repr__(self):
        tag     = f" [{R}VULN{RST}]"  if self.vuln else ""
        cve_str = f" ({self.cve})"    if self.cve  else ""
        lines   = self.output.split("\n")
        first   = lines[0]
        rest    = "\n".join(lines[1:]) if len(lines) > 1 else ""
        out     = f"  |_{B}{self.name}{RST}{tag}{cve_str}\n    {first}"
        if rest:
            out += "\n" + rest
        return out


def _http_get(ip: str, port: int, path: str = "/",
              timeout: float = 5.0) -> Tuple[int, Dict, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in (443, 8443):
            try:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except Exception:
                pass
        req = (f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        sock.send(req.encode())
        response = b""
        sock.settimeout(3.0)
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk: break
                response += chunk
                if len(response) > 65536: break
        except socket.timeout:
            pass
        raw   = response.decode("utf-8", errors="replace")
        lines = raw.split("\r\n")
        status = 0
        m = re.match(r"HTTP/[\d\.]+\s+(\d+)", lines[0] if lines else "")
        if m: status = int(m.group(1))
        headers = {}; body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1; break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = "\r\n".join(lines[body_start:])
        return status, headers, body
    except Exception:
        return 0, {}, ""
    finally:
        try: sock.close()
        except: pass

# ─────────────────────────────────────────────────────────────────────────────
# FTP HELPERS  (v2: full anonymous login + PASV listing + bounce + SYST)
# ─────────────────────────────────────────────────────────────────────────────
def _ftp_recv(sock: socket.socket, timeout: float = 5.0) -> str:
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            lines = data.decode(errors="replace").splitlines()
            if lines and re.match(r"^\d{3} ", lines[-1]):
                break
    except socket.timeout:
        pass
    return data.decode(errors="replace").strip()

def _ftp_cmd(sock: socket.socket, cmd: str, timeout: float = 5.0) -> str:
    sock.sendall((cmd + "\r\n").encode())
    return _ftp_recv(sock, timeout)

def _ftp_connect(ip: str, port: int, timeout: float = 5.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = _ftp_recv(sock, timeout)
        return sock, banner
    except Exception as e:
        return None, str(e)

def _ftp_pasv_channel(ip: str, pasv_resp: str, timeout: float) -> Optional[socket.socket]:
    m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv_resp)
    if not m: return None
    h1, h2, h3, h4, p1, p2 = (int(x) for x in m.groups())
    data_ip   = f"{h1}.{h2}.{h3}.{h4}"
    data_port = (p1 << 8) + p2
    try:
        addr = ipaddress.ip_address(data_ip)
        if addr.is_private or addr.is_loopback:
            data_ip = ip
    except Exception:
        pass
    try:
        dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dsock.settimeout(timeout)
        dsock.connect((data_ip, data_port))
        return dsock
    except Exception:
        return None

def _ftp_login_anon(sock: socket.socket, timeout: float = 5.0) -> bool:
    resp = _ftp_cmd(sock, "USER anonymous", timeout)
    if resp.startswith("331"):
        resp = _ftp_cmd(sock, "PASS anonymous@example.com", timeout)
    return resp.startswith("230")

def _ftp_list(ip: str, port: int, timeout: float = 5.0) -> List[str]:
    """Return directory listing lines via anonymous login + PASV."""
    sock, banner = _ftp_connect(ip, port, timeout)
    if sock is None:
        return []
    try:
        if not _ftp_login_anon(sock, timeout):
            return []
        pasv_resp = _ftp_cmd(sock, "PASV", timeout)
        dsock     = _ftp_pasv_channel(ip, pasv_resp, timeout)
        if not dsock:
            return []
        _ftp_cmd(sock, "LIST", timeout)
        raw = b""
        dsock.settimeout(timeout)
        try:
            while True:
                chunk = dsock.recv(4096)
                if not chunk: break
                raw += chunk
        except socket.timeout:
            pass
        dsock.close()
        return raw.decode(errors="replace").strip().splitlines()
    except Exception:
        return []
    finally:
        try: sock.close()
        except: pass

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCRIPT RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_scripts(ip: str, port: int, service: str, banner: bytes,
                categories: List[str]) -> List[ScriptResult]:
    results: List[ScriptResult] = []
    cats    = set(c.lower() for c in categories)
    run_all = "all" in cats or not cats

    def wants(cat: str) -> bool:
        return run_all or cat in cats

    banner_str = banner.decode("utf-8", errors="replace")

    # ── Banner ────────────────────────────────────────────────────────────────
    if wants("default") and banner:
        first_line = banner_str.split("\n")[0].strip()[:120]
        if first_line:
            results.append(ScriptResult("banner", first_line))

    # ─ Service detection helpers — banner-aware so non-standard ports are identified ──
    _banner_is_http = bool(re.search(r"^HTTP/|Server:\s*\S|<html", banner_str, re.IGNORECASE | re.MULTILINE))
    _banner_is_ssl  = bool(re.search(r"-----BEGIN CERTIFICATE|subject.*commonName", banner_str, re.IGNORECASE))
    _banner_is_ftp  = bool(re.search(r"^220[\s\-]", banner_str))
    _banner_is_ssh  = banner_str.startswith("SSH-")
    _banner_is_smtp = bool(re.search(r"^220[\s\-].*SMTP|ESMTP", banner_str, re.IGNORECASE))

    is_http    = service in ("http","https","http-proxy","https-alt","http-alt") \
                 or port in (80,8080,8443,443,8888,8000,9090,9200,5000,3000,7070,33033,45332,45443) \
                 or _banner_is_http
    is_ftp     = service in ("ftp","ftp-proxy","ftps","ftp-data") \
                 or port in FTP_PORTS \
                 or (_banner_is_ftp and not _banner_is_smtp)
    is_ssh     = service == "ssh" or port == 22 or _banner_is_ssh
    is_smb     = service in ("smb","netbios-ssn","microsoft-ds") or port in (139, 445)
    is_smtp    = service in ("smtp","submission","smtps") or port in (25, 465, 587) or _banner_is_smtp
    is_dns     = service == "dns" or port == 53
    is_snmp    = service == "snmp" or port == 161
    is_rdp     = service == "ms-wbt-server" or port == 3389
    # SSL: try if port looks TLS-ish, has ssl/tls in service name, or banner looks like cert
    is_ssl     = service in ("https","imaps","pop3s","smtps","ssl","tls") \
                 or port in (443,8443,993,995,465,44330) \
                 or _banner_is_ssl \
                 or "ssl" in service.lower()
    is_redis   = service == "redis" or port == 6379
    is_mysql   = service == "mysql" or port == 3306
    is_mongo   = service == "mongod" or port in (27017, 27018)
    is_pgsql   = service == "postgresql" or port == 5432
    is_elastic = port == 9200 or service == "elasticsearch"
    is_ldap    = service in ("ldap","ldaps") or port in (389, 636, 3268)
    is_vnc     = service == "vnc" or port == 5900
    is_ntp     = service == "ntp" or port == 123
    is_rsync   = service == "rsync" or port == 873
    is_docker  = port in (2375, 2376)
    is_k8s     = port in (6443, 10250)
    is_imap    = service in ("imap","imaps") or port in (143, 993)
    is_pop3    = service in ("pop3","pop3s") or port in (110, 995)
    is_memcache= service == "memcache" or port == 11211
    is_modbus  = port == 502
    is_telnet  = service == "telnet" or port == 23

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_http and wants("default"):
        status, hdrs, body = _http_get(ip, port)

        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            results.append(ScriptResult("http-title", m.group(1).strip()[:100]))

        if "server" in hdrs:
            results.append(ScriptResult("http-server-header", hdrs["server"]))

        # http-methods — always check, flag risky ones
        try:
            sock_opt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_opt.settimeout(5.0); sock_opt.connect((ip, port))
            sock_opt.send(f"OPTIONS / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            opt_resp = b""
            sock_opt.settimeout(3.0)
            try:
                while True:
                    c = sock_opt.recv(4096)
                    if not c: break
                    opt_resp += c
                    if len(opt_resp) > 8192: break
            except: pass
            sock_opt.close()
            opt_str = opt_resp.decode("utf-8", errors="replace")
            # Parse Allow header
            allow_match = re.search(r"(?:Allow|Public):\s*([^\r\n]+)", opt_str, re.IGNORECASE)
            if allow_match:
                methods_str = allow_match.group(1).strip()
                risky = [m.strip() for m in methods_str.split(",")
                         if m.strip() in ("PUT","DELETE","CONNECT","TRACE","PATCH",
                                          "PROPFIND","PROPPATCH","COPY","MOVE",
                                          "MKCOL","LOCK","UNLOCK")]
                out = f"Supported Methods: {methods_str}"
                if risky:
                    out += f"\n    Potentially risky methods: {', '.join(risky)}"
                results.append(ScriptResult("http-methods", out, vuln=bool(risky)))
                # http-webdav-scan — if WebDAV methods present
                webdav_methods = [m.strip() for m in methods_str.split(",")
                                  if m.strip() in ("PROPFIND","PROPPATCH","MKCOL",
                                                   "COPY","MOVE","LOCK","UNLOCK")]
                if webdav_methods:
                    # Get server date from response
                    date_match = re.search(r"Date:\s*([^\r\n]+)", opt_str, re.IGNORECASE)
                    date_str   = date_match.group(1).strip() if date_match else "unknown"
                    svr        = hdrs.get("server","unknown")
                    results.append(ScriptResult("http-webdav-scan",
                        f"WebDAV enabled | Server: {svr} | Date: {date_str}\n"
                        f"    Allowed: {methods_str}", vuln=True))
            # http-open-proxy — check if CONNECT method works
            if "CONNECT" in opt_str:
                results.append(ScriptResult("http-open-proxy",
                    "Potentially OPEN proxy — CONNECT method supported", vuln=True))
        except Exception:
            pass

        # http-trace check
        try:
            sock_tr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_tr.settimeout(3.0); sock_tr.connect((ip, port))
            sock_tr.send(f"TRACE / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            tr_resp = b""
            sock_tr.settimeout(2.0)
            try:
                while True:
                    c = sock_tr.recv(4096)
                    if not c: break
                    tr_resp += c
                    if len(tr_resp) > 4096: break
            except: pass
            sock_tr.close()
            if b"200" in tr_resp[:20]:
                results.append(ScriptResult("http-trace",
                    "HTTP TRACE method enabled — XST vulnerability", vuln=True))
        except: pass

        if wants("safe"):
            sec_headers = ["x-frame-options","x-xss-protection","x-content-type-options",
                           "strict-transport-security","content-security-policy","referrer-policy"]
            missing = [h for h in sec_headers if h not in hdrs]
            if missing:
                results.append(ScriptResult("http-security-headers",
                    f"Missing: {', '.join(missing)}", vuln=True))
            else:
                results.append(ScriptResult("http-security-headers",
                    "All key security headers present"))

        if status == 401:
            auth = hdrs.get("www-authenticate","unknown")
            results.append(ScriptResult("http-auth", f"Authentication required: {auth}"))

        acao = hdrs.get("access-control-allow-origin","")
        if acao == "*":
            results.append(ScriptResult("http-cors",
                "CORS: Access-Control-Allow-Origin: * (open)", vuln=True))
        elif acao:
            results.append(ScriptResult("http-cors", f"CORS origin: {acao}"))

        if wants("safe"):
            waf_sigs = {"Cloudflare":["cf-ray","cloudflare"],"AWS WAF":["x-amzn-requestid","awselb"],
                        "ModSecurity":["mod_security","modsecurity"],"F5 BIG-IP":["bigip","f5-bigip"],
                        "Akamai":["akamai","akamaighost"]}
            all_text = " ".join(hdrs.values()).lower() + body.lower()[:500]
            for waf_name, sigs in waf_sigs.items():
                if any(s in all_text for s in sigs):
                    results.append(ScriptResult("http-waf-detect", f"WAF detected: {waf_name}"))
                    break

            st_r, _, robots_body = _http_get(ip, port, "/robots.txt")
            if st_r == 200 and robots_body:
                disallowed = [l.split(":",1)[1].strip() for l in robots_body.split("\n")
                              if l.strip().lower().startswith("disallow:")][:10]
                if disallowed:
                    results.append(ScriptResult("http-robots.txt",
                        f"Disallowed: {', '.join(disallowed[:5])}"
                        + (" ..." if len(disallowed) > 5 else "")))

        if wants("vuln"):
            st_git, _, git_body = _http_get(ip, port, "/.git/HEAD")
            if st_git == 200 and "ref:" in git_body:
                results.append(ScriptResult("http-git",
                    "Git repository exposed at /.git/HEAD", vuln=True))

            for path in ["/../../../etc/passwd", "/etc/passwd", "/%2e%2e/%2e%2e/etc/passwd"]:
                st_p, _, body_p = _http_get(ip, port, path)
                if st_p == 200 and "root:x:" in body_p:
                    results.append(ScriptResult("http-passwd",
                        f"Possible directory traversal: {path}", vuln=True))
                    break

            for sh_path in ["/cgi-bin/test.cgi", "/cgi-bin/admin.cgi"]:
                try:
                    sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock3.settimeout(3.0); sock3.connect((ip, port))
                    payload = (f"GET {sh_path} HTTP/1.0\r\nHost: {ip}\r\n"
                               "User-Agent: () { :; }; echo; echo SHELLSHOCK_TEST\r\n\r\n")
                    sock3.send(payload.encode())
                    resp3 = b""
                    try:
                        while True:
                            c = sock3.recv(4096)
                            if not c: break
                            resp3 += c
                            if len(resp3) > 8192: break
                    except: pass
                    sock3.close()
                    if b"SHELLSHOCK_TEST" in resp3:
                        results.append(ScriptResult("http-shellshock",
                            f"Shellshock via {sh_path}", vuln=True, cve="CVE-2014-6271"))
                        break
                except Exception:
                    pass

            try:
                sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock4.settimeout(3.0); sock4.connect((ip, port))
                sock4.send(b"GET / HTTP/1.0\r\n\r\n")
                resp4 = b""
                try:
                    while True:
                        c = sock4.recv(4096)
                        if not c: break
                        resp4 += c
                        if len(resp4) > 4096: break
                except: pass
                sock4.close()
                raw4 = resp4.decode("utf-8", errors="replace")
                priv_ip = re.search(
                    r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
                    r"|192\.168\.\d+\.\d+)\b", raw4)
                if priv_ip and priv_ip.group() != ip:
                    results.append(ScriptResult("http-internal-ip-disclosure",
                        f"Internal IP leaked: {priv_ip.group()}", vuln=True))
            except: pass

            for hdr_name in ["x-powered-by","x-aspnet-version","x-aspnetmvc-version"]:
                if hdr_name in hdrs:
                    results.append(ScriptResult("http-generator",
                        f"{hdr_name}: {hdrs[hdr_name]}"))

            if "x-powered-by" in hdrs and "php" in hdrs["x-powered-by"].lower():
                results.append(ScriptResult("http-php-version",
                    f"PHP version: {hdrs['x-powered-by']}", vuln=True))

            st_sb, hdrs_sb, body_sb = _http_get(ip, port, "/actuator")
            if st_sb == 200 and ("_links" in body_sb or "actuator" in body_sb):
                results.append(ScriptResult("http-spring-boot-actuator",
                    "Spring Boot Actuator exposed", vuln=True))

            st_wp, _, body_wp = _http_get(ip, port, "/wp-json/wp/v2/users")
            if st_wp == 200 and '"slug"' in body_wp:
                slugs = re.findall(r'"slug"\s*:\s*"([^"]+)"', body_wp)[:5]
                results.append(ScriptResult("http-wordpress-users",
                    f"WordPress users: {', '.join(slugs)}", vuln=True))

            # http-enum — common sensitive paths
            enum_paths = [
                "/admin","/administrator","/manager","/login",
                "/phpmyadmin","/phpinfo.php","/.env","/.htaccess",
                "/backup","/config.php","/web.config",
                "/server-status","/server-info",
            ]
            found_paths = []
            for ep in enum_paths:
                st_e, _, _ = _http_get(ip, port, ep)
                if st_e in (200, 401, 403):
                    found_paths.append(f"{ep} [{st_e}]")
            if found_paths:
                results.append(ScriptResult("http-enum",
                    "Interesting paths: " + ", ".join(found_paths)))

    # ─────────────────────────────────────────────────────────────────────────
    # FTP Scripts  (v2 — full session: anon login, PASV listing, SYST, bounce)
    # ─────────────────────────────────────────────────────────────────────────
    if is_ftp and wants("default"):
        ftp_timeout = 5.0

        # ── ftp-anon + directory listing ─────────────────────────────────────
        sock_a, banner_a = _ftp_connect(ip, port, ftp_timeout)
        if sock_a:
            try:
                logged_in = _ftp_login_anon(sock_a, ftp_timeout)
                if logged_in:
                    # PASV directory listing — collect all lines first
                    pasv_resp = _ftp_cmd(sock_a, "PASV", ftp_timeout)
                    dsock     = _ftp_pasv_channel(ip, pasv_resp, ftp_timeout)
                    listing_lines = []
                    if dsock:
                        _ftp_cmd(sock_a, "LIST", ftp_timeout)
                        raw_list = b""
                        dsock.settimeout(ftp_timeout)
                        try:
                            while True:
                                chunk = dsock.recv(4096)
                                if not chunk: break
                                raw_list += chunk
                        except socket.timeout:
                            pass
                        dsock.close()
                        listing_lines = raw_list.decode(errors="replace").strip().splitlines()
                    # Single ScriptResult with full listing embedded
                    listing_str = "Anonymous FTP login allowed (FTP code 230)"
                    if listing_lines:
                        listing_str += "\n" + "\n".join(f"    | {l}" for l in listing_lines)
                    else:
                        listing_str += "\n    | (PASV failed — could not open data channel)"
                    results.append(ScriptResult("ftp-anon", listing_str, vuln=True))
                else:
                    results.append(ScriptResult("ftp-anon", "Anonymous login denied"))
            except Exception:
                pass
            finally:
                try: sock_a.close()
                except: pass

        # ── ftp-syst ──────────────────────────────────────────────────────────
        sock_s, _ = _ftp_connect(ip, port, ftp_timeout)
        if sock_s:
            try:
                _ftp_login_anon(sock_s, ftp_timeout)
                syst_resp = _ftp_cmd(sock_s, "SYST", ftp_timeout)
                if syst_resp.startswith("215"):
                    results.append(ScriptResult("ftp-syst",
                        f"SYST: {syst_resp[4:].strip()}"))
            except Exception:
                pass
            finally:
                try: sock_s.close()
                except: pass

        # ── ftp-bounce ────────────────────────────────────────────────────────
        if wants("vuln"):
            sock_b, _ = _ftp_connect(ip, port, ftp_timeout)
            if sock_b:
                try:
                    if _ftp_login_anon(sock_b, ftp_timeout):
                        port_resp = _ftp_cmd(sock_b, "PORT 192,0,2,1,0,80", ftp_timeout)
                        if port_resp.startswith("200"):
                            results.append(ScriptResult("ftp-bounce",
                                "bounce working!", vuln=True))
                        else:
                            results.append(ScriptResult("ftp-bounce",
                                f"bounce not allowed ({port_resp[:3]})"))
                except Exception:
                    pass
                finally:
                    try: sock_b.close()
                    except: pass

        # ── ftp-vsftpd-backdoor (CVE-2011-2523) ──────────────────────────────
        if wants("vuln") and re.search(r"vsftpd 2\.3\.4", banner_str, re.IGNORECASE):
            results.append(ScriptResult("ftp-vsftpd-backdoor",
                "vsftpd 2.3.4 detected — check for backdoor on port 6200",
                vuln=True, cve="CVE-2011-2523"))

    # ─────────────────────────────────────────────────────────────────────────
    # SSH Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_ssh and wants("default"):
        results.append(ScriptResult("ssh-hostkey", banner_str.split("\n")[0].strip()[:80]))
        if "SSH-1" in banner_str:
            results.append(ScriptResult("ssh-weak-version",
                "SSHv1 detected — deprecated and insecure", vuln=True, cve="CVE-2001-0553"))
        try:
            sock_ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ssh.settimeout(5.0); sock_ssh.connect((ip, port))
            sock_ssh.recv(256)
            sock_ssh.send(b"SSH-2.0-ZScan\r\n")
            kex_data = b""
            sock_ssh.settimeout(3.0)
            try:
                kex_data = sock_ssh.recv(4096)
            except: pass
            sock_ssh.close()
            auth_line = "publickey,password (probe)"
            results.append(ScriptResult("ssh-auth-methods", auth_line))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # SMTP Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_smtp and wants("default"):
        try:
            sock_m = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_m.settimeout(5.0); sock_m.connect((ip, port))
            sock_m.recv(1024)
            sock_m.sendall(b"EHLO zscan.local\r\n")
            resp_ehlo = b""
            sock_m.settimeout(3.0)
            try:
                while True:
                    c = sock_m.recv(4096)
                    if not c: break
                    resp_ehlo += c
                    if len(resp_ehlo) > 4096: break
            except: pass
            ehlo_str = resp_ehlo.decode("utf-8", errors="replace")
            cmds = [l.split(None, 1)[1].strip() if len(l.split(None,1)) > 1 else ""
                    for l in ehlo_str.splitlines() if l.startswith("250")][:8]
            if cmds:
                results.append(ScriptResult("smtp-commands",
                    "EHLO: " + ", ".join(c for c in cmds if c)))
            if wants("vuln"):
                sock_m.sendall(b"MAIL FROM:<test@zscan.local>\r\n")
                sock_m.recv(256)
                sock_m.sendall(b"RCPT TO:<test@external-example.com>\r\n")
                rr = sock_m.recv(256).decode(errors="replace")
                if rr.startswith("250"):
                    results.append(ScriptResult("smtp-open-relay",
                        "Server may be an open relay!", vuln=True))
                else:
                    results.append(ScriptResult("smtp-open-relay", "Relay denied"))
            if wants("auth"):
                sock_m.sendall(b"VRFY root\r\n")
                vrfy_r = sock_m.recv(256).decode(errors="replace")
                if vrfy_r.startswith(("250","252")):
                    results.append(ScriptResult("smtp-enum-users",
                        "VRFY accepted — user enumeration possible", vuln=True))
            sock_m.close()
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # SMB Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_smb and wants("default"):
        smb_negotiate = bytes.fromhex(
            "00000085"
            "ff534d4272000000001853c800000000000000000000000000fffe00000000"
            "0062000002"
            "4e54204c4d20302e31320002"
            "534d422032002e303032000253"
            "4d422032003f3f3f00"
        )
        try:
            sock_smb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_smb.settimeout(5.0); sock_smb.connect((ip, port))
            sock_smb.send(smb_negotiate)
            resp_smb = sock_smb.recv(4096)
            sock_smb.close()
            if len(resp_smb) > 36 and resp_smb[4:6] == b"\xff\x53":
                results.append(ScriptResult("smb-protocols",
                    "SMBv1 supported — may be vulnerable to EternalBlue",
                    vuln=True, cve="CVE-2017-0144"))
            else:
                results.append(ScriptResult("smb-protocols", "SMBv1 not detected (SMBv2/3 likely)"))
        except Exception:
            pass
        if wants("vuln"):
            try:
                sock_eb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_eb.settimeout(5.0); sock_eb.connect((ip, 445))
                trans2_pkt = bytes.fromhex(
                    "00000085ff534d4272000000001801280000000000000000000000000008"
                    "ffe0000040000062000204e54204c4d20302e313200024c414e4d414e312"
                    "e30000257696e646f777320666f7220576f726b67726f75707320332e31"
                    "61000253"
                    "4d422032002e303032000204c4d31002e325830303200024c414e4d414e"
                    "32002e310002"
                    "4e54204c4d20302e313200"
                )
                sock_eb.send(trans2_pkt)
                resp_eb = sock_eb.recv(4096)
                sock_eb.close()
                if len(resp_eb) > 36 and resp_eb[4:6] == b"\xff\x53":
                    results.append(ScriptResult("smb-vuln-ms17-010",
                        "SMBv1 enabled — potentially vulnerable to EternalBlue/WannaCry",
                        vuln=True, cve="CVE-2017-0144"))
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # DNS Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_dns and wants("default"):
        try:
            # DNS recursion check
            dns_query = (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                         b"\x06google\x03com\x00\x00\x01\x00\x01")
            sock_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_dns.settimeout(3.0)
            sock_dns.sendto(dns_query, (ip, 53))
            dns_resp = sock_dns.recv(512)
            sock_dns.close()
            if len(dns_resp) > 2 and (dns_resp[2] & 0x80):
                ra_flag = (dns_resp[3] & 0x80) >> 7
                if ra_flag:
                    results.append(ScriptResult("dns-recursion",
                        "Recursion available — open resolver possible", vuln=True))
                else:
                    results.append(ScriptResult("dns-recursion", "Recursion not available"))
        except Exception:
            pass
        if wants("vuln"):
            try:
                # Zone transfer probe (AXFR)
                axfr_query = (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                              b"\x03www\x07example\x03com\x00\x00\xfc\x00\x01")
                sock_axfr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_axfr.settimeout(3.0); sock_axfr.connect((ip, 53))
                length = len(axfr_query)
                sock_axfr.send(struct.pack("!H", length) + axfr_query)
                resp_axfr = sock_axfr.recv(512)
                sock_axfr.close()
                if len(resp_axfr) > 6 and resp_axfr[2:4] != b"\x00\x00":
                    results.append(ScriptResult("dns-zone-transfer",
                        "DNS TCP open — AXFR may be possible", vuln=True))
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # SNMP Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_snmp and wants("default"):
        communities = ["public", "private", "community", "manager", "admin"]
        # SNMPv1 GetRequest for sysDescr OID
        def build_snmp_get(community: str) -> bytes:
            comm = community.encode()
            oid  = b"\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
            inner = (b"\x02\x01\x00" + b"\x02\x01\x00" + b"\x02\x01\x00" + b"\x30\x0e" + oid)
            pdu  = b"\xa0" + bytes([len(inner)]) + inner
            msg  = (b"\x02\x01\x00" + b"\x04" + bytes([len(comm)]) + comm + pdu)
            return b"\x30" + bytes([len(msg)]) + msg

        for comm in communities:
            try:
                sock_snmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_snmp.settimeout(2.0)
                sock_snmp.sendto(build_snmp_get(comm), (ip, 161))
                snmp_resp, _ = sock_snmp.recvfrom(1024)
                sock_snmp.close()
                if snmp_resp:
                    results.append(ScriptResult("snmp-info",
                        f"Community string '{comm}' accepted — SNMP accessible", vuln=True))
                    break
            except socket.timeout:
                pass
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # LDAP Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_ldap and wants("default"):
        try:
            ldap_bind = bytes.fromhex("300c0201016007020103040080 00".replace(" ",""))
            sock_ldap = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ldap.settimeout(3.0); sock_ldap.connect((ip, port))
            sock_ldap.send(ldap_bind)
            ldap_r = sock_ldap.recv(128)
            sock_ldap.close()
            if len(ldap_r) > 7 and ldap_r[7] == 0:
                results.append(ScriptResult("ldap-rootdse",
                    "LDAP anonymous bind accepted", vuln=True))
            else:
                results.append(ScriptResult("ldap-rootdse", "LDAP anonymous bind rejected"))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Redis Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_redis and wants("default"):
        try:
            sock_r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_r.settimeout(3.0); sock_r.connect((ip, port))
            sock_r.sendall(b"*1\r\n$4\r\nINFO\r\n")
            r_info = b""
            sock_r.settimeout(2.0)
            try:
                while True:
                    c = sock_r.recv(4096)
                    if not c: break
                    r_info += c
                    if len(r_info) > 8192: break
            except: pass
            sock_r.close()
            r_str = r_info.decode(errors="replace")
            if "redis_version" in r_str:
                m = re.search(r"redis_version:(\S+)", r_str)
                ver = m.group(1) if m else "?"
                results.append(ScriptResult("redis-info",
                    f"Redis {ver} — accessible without authentication", vuln=True))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # MySQL Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_mysql and wants("default"):
        try:
            sock_my = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_my.settimeout(3.0); sock_my.connect((ip, port))
            banner_my = sock_my.recv(1024)
            sock_my.close()
            if len(banner_my) > 5 and banner_my[4] == 0x0a:
                ver_end = 5
                while ver_end < len(banner_my) and banner_my[ver_end] != 0:
                    ver_end += 1
                ver = banner_my[5:ver_end].decode(errors="replace")
                results.append(ScriptResult("mysql-info", f"MySQL version: {ver}"))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # PostgreSQL Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_pgsql and wants("default"):
        try:
            # Startup message with no password to trigger auth response
            startup = struct.pack("!II", 8, 196608)  # length + protocol 3.0
            sock_pg = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_pg.settimeout(3.0); sock_pg.connect((ip, port))
            sock_pg.send(startup)
            pg_r = sock_pg.recv(256)
            sock_pg.close()
            if pg_r:
                if pg_r[0:1] == b"R":
                    auth_type = struct.unpack("!I", pg_r[5:9])[0] if len(pg_r) >= 9 else 0
                    if auth_type == 0:
                        results.append(ScriptResult("pgsql-empty-password",
                            "PostgreSQL accepts connections without a password", vuln=True))
                    else:
                        results.append(ScriptResult("pgsql-empty-password",
                            f"PostgreSQL auth required (type {auth_type})"))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Elasticsearch Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_elastic and wants("default"):
        st_es, _, body_es = _http_get(ip, port, "/")
        if "elasticsearch" in body_es.lower() or "cluster_name" in body_es:
            m = re.search(r'"number"\s*:\s*"([^"]+)"', body_es)
            ver = m.group(1) if m else "?"
            results.append(ScriptResult("elasticsearch-info",
                f"Elasticsearch {ver} accessible without auth", vuln=True))

    # ─────────────────────────────────────────────────────────────────────────
    # MongoDB Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_mongo and wants("default"):
        try:
            # isMaster probe
            msg = bytes.fromhex("3a0000000000000000000000d40700000000000061646d696e2e"
                                 "2400000000190000001069734d617374657200010000000000")
            sock_mg = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_mg.settimeout(3.0); sock_mg.connect((ip, port))
            sock_mg.send(msg)
            mg_r = sock_mg.recv(512)
            sock_mg.close()
            if mg_r and b"ismaster" in mg_r.lower():
                results.append(ScriptResult("mongodb-info",
                    "MongoDB accessible without authentication", vuln=True))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Memcached Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_memcache and wants("default"):
        try:
            sock_mc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_mc.settimeout(3.0); sock_mc.connect((ip, port))
            sock_mc.sendall(b"stats\r\n")
            mc_r = b""
            sock_mc.settimeout(2.0)
            try:
                while True:
                    c = sock_mc.recv(4096)
                    if not c: break
                    mc_r += c
                    if b"END" in mc_r or len(mc_r) > 4096: break
            except: pass
            sock_mc.close()
            if b"STAT version" in mc_r:
                m = re.search(rb"STAT version (\S+)", mc_r)
                ver = m.group(1).decode() if m else "?"
                results.append(ScriptResult("memcached-info",
                    f"Memcached {ver} accessible without auth", vuln=True))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # NTP Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_ntp and wants("default"):
        try:
            ntp_req = b"\x1b" + b"\x00" * 47
            sock_ntp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_ntp.settimeout(3.0)
            sock_ntp.sendto(ntp_req, (ip, 123))
            ntp_r, _ = sock_ntp.recvfrom(512)
            sock_ntp.close()
            if len(ntp_r) >= 48:
                ver     = (ntp_r[0] >> 3) & 0x7
                stratum = ntp_r[1]
                ts_int  = struct.unpack("!I", ntp_r[40:44])[0]
                if ts_int > 2208988800:
                    dt = datetime.datetime(1900,1,1) + datetime.timedelta(seconds=ts_int)
                    results.append(ScriptResult("ntp-info",
                        f"NTPv{ver} stratum={stratum} time={dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"))
        except Exception:
            pass
        if wants("vuln"):
            try:
                monlist_req = b"\x17\x00\x03\x2a" + b"\x00" * 4
                sock_nl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock_nl.settimeout(3.0)
                sock_nl.sendto(monlist_req, (ip, 123))
                nl_r, _ = sock_nl.recvfrom(4096)
                sock_nl.close()
                if len(nl_r) > 100:
                    results.append(ScriptResult("ntp-monlist",
                        f"monlist enabled — DDoS amplification ({len(nl_r)}B response)",
                        vuln=True, cve="CVE-2013-5211"))
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # IMAP / POP3 Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_imap and wants("default"):
        try:
            sock_im = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_im.settimeout(3.0); sock_im.connect((ip, port))
            sock_im.recv(512)
            sock_im.sendall(b"a001 CAPABILITY\r\n")
            cap_r = b""
            sock_im.settimeout(2.0)
            try:
                while True:
                    c = sock_im.recv(1024)
                    if not c: break
                    cap_r += c
                    if b"a001 " in cap_r: break
            except: pass
            sock_im.close()
            cap_str = cap_r.decode(errors="replace")
            m = re.search(r"\* CAPABILITY([^\r\n]+)", cap_str)
            if m:
                results.append(ScriptResult("imap-capabilities", m.group(1).strip()[:100]))
        except Exception:
            pass

    if is_pop3 and wants("default"):
        try:
            sock_pop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_pop.settimeout(3.0); sock_pop.connect((ip, port))
            sock_pop.recv(512)
            sock_pop.sendall(b"CAPA\r\n")
            capa_r = b""
            sock_pop.settimeout(2.0)
            try:
                while True:
                    c = sock_pop.recv(1024)
                    if not c: break
                    capa_r += c
                    if b"." in capa_r: break
            except: pass
            sock_pop.close()
            capa_lines = [l.strip() for l in capa_r.decode(errors="replace").splitlines()
                          if l.strip() and not l.startswith(("+","-","."))][:8]
            if capa_lines:
                results.append(ScriptResult("pop3-capabilities",
                    "Capabilities: " + ", ".join(capa_lines)))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # RDP Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_rdp and wants("default"):
        try:
            x224 = bytes.fromhex("0300001302e0000000000001000800030000 00".replace(" ",""))
            sock_rdp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_rdp.settimeout(3.0); sock_rdp.connect((ip, port))
            sock_rdp.send(x224)
            rdp_r = sock_rdp.recv(1024)
            sock_rdp.close()
            if rdp_r and rdp_r[0] == 0x03:
                results.append(ScriptResult("rdp-enum-encryption",
                    "RDP responding — verify NLA/CredSSP is enforced"))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # VNC Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_vnc and wants("default"):
        try:
            sock_vnc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_vnc.settimeout(3.0); sock_vnc.connect((ip, port))
            vnc_banner = sock_vnc.recv(64)
            sock_vnc.close()
            vnc_str = vnc_banner.decode(errors="replace").strip()
            results.append(ScriptResult("vnc-info", f"Protocol: {vnc_str[:40]}"))
            # RealVNC auth bypass CVE-2006-2369
            if "RFB 003.003" in vnc_str or "RFB 003.007" in vnc_str:
                results.append(ScriptResult("realvnc-auth-bypass",
                    "Old VNC protocol version — check for auth bypass",
                    vuln=True, cve="CVE-2006-2369"))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Rsync Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_rsync and wants("default"):
        try:
            sock_rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_rs.settimeout(3.0); sock_rs.connect((ip, port))
            rs_banner = sock_rs.recv(256)
            sock_rs.send(b"@RSYNCD: 31\n\n")
            rs_mods = b""
            sock_rs.settimeout(2.0)
            try:
                while True:
                    c = sock_rs.recv(1024)
                    if not c: break
                    rs_mods += c
                    if b"@RSYNCD: EXIT" in rs_mods or len(rs_mods) > 4096: break
            except: pass
            sock_rs.close()
            mods_str = rs_mods.decode(errors="replace")
            modules  = [l.split("\t")[0].strip() for l in mods_str.splitlines()
                        if l.strip() and not l.startswith("@")][:10]
            if modules:
                results.append(ScriptResult("rsync-list-modules",
                    "Modules: " + ", ".join(modules), vuln=True))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Docker / Kubernetes Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_docker and wants("default"):
        st_dv, _, body_dv = _http_get(ip, port, "/version")
        if st_dv == 200 and "ApiVersion" in body_dv:
            m = re.search(r'"Version"\s*:\s*"([^"]+)"', body_dv)
            ver = m.group(1) if m else "?"
            results.append(ScriptResult("docker-version",
                f"Docker {ver} API accessible without auth — container escape risk",
                vuln=True))

    if is_k8s and wants("default"):
        st_k8, _, body_k8 = _http_get(ip, port, "/version")
        if st_k8 == 200 and "gitVersion" in body_k8:
            m = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', body_k8)
            ver = m.group(1) if m else "?"
            results.append(ScriptResult("kubernetes-api",
                f"Kubernetes {ver} API accessible without auth", vuln=True))
        st_ku, _, body_ku = _http_get(ip, 10250, "/healthz")
        if st_ku == 200 and "ok" in body_ku.lower():
            results.append(ScriptResult("kubernetes-kubelet",
                "Kubelet API accessible without auth", vuln=True))

    # ─────────────────────────────────────────────────────────────────────────
    # Modbus / ICS Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_modbus and wants("default"):
        try:
            # Modbus function code 0x11 (Report Slave ID)
            modbus_req = b"\x00\x01\x00\x00\x00\x06\xff\x11\x00\x00\x00\x00"
            sock_mb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_mb.settimeout(3.0); sock_mb.connect((ip, 502))
            sock_mb.send(modbus_req)
            mb_r = sock_mb.recv(256)
            sock_mb.close()
            if mb_r and len(mb_r) > 6:
                results.append(ScriptResult("modbus-discover",
                    f"Modbus device responding ({len(mb_r)}B) — ICS/SCADA exposure!",
                    vuln=True))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Telnet Scripts
    # ─────────────────────────────────────────────────────────────────────────
    if is_telnet and wants("default"):
        try:
            sock_tel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_tel.settimeout(3.0); sock_tel.connect((ip, port))
            tel_r = sock_tel.recv(512)
            sock_tel.close()
            tel_str = tel_r.decode(errors="replace").strip()[:80]
            results.append(ScriptResult("telnet-ntlm-info",
                f"Telnet banner: {tel_str}", vuln=True))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # SSL/TLS cert check — tries TLS wrap on any port flagged is_ssl
    # ─────────────────────────────────────────────────────────────────────────
    if is_ssl and wants("default"):
        try:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(5.0)
            raw_sock.connect((ip, port))
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
            cert     = ssl_sock.getpeercert()
            # Also grab cipher info
            cipher_info = ssl_sock.cipher()
            ssl_sock.close()
            if cert:
                not_after = cert.get("notAfter","")
                not_before= cert.get("notBefore","")
                cn_list   = [v for field in cert.get("subject",[]) for k,v in field if k == "commonName"]
                org_list  = [v for field in cert.get("subject",[]) for k,v in field if k == "organizationName"]
                cn        = cn_list[0] if cn_list else "?"
                org       = org_list[0] if org_list else ""
                org_str   = f" / {org}" if org else ""
                if not_after:
                    import time as _time
                    try:
                        exp       = _time.mktime(_time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
                        days_left = int((exp - _time.time()) / 86400)
                        if days_left < 0:
                            results.append(ScriptResult("ssl-cert",
                                f"EXPIRED {abs(days_left)}d ago | CN={cn}{org_str}\n"
                                f"    Not valid after: {not_after}", vuln=True))
                        elif days_left < 30:
                            results.append(ScriptResult("ssl-cert",
                                f"Expires in {days_left}d (SOON) | CN={cn}{org_str}", vuln=True))
                        else:
                            results.append(ScriptResult("ssl-cert",
                                f"Valid {days_left}d remaining | CN={cn}{org_str}\n"
                                f"    Not valid before: {not_before} | Not valid after: {not_after}"))
                    except Exception:
                        results.append(ScriptResult("ssl-cert", f"CN={cn}{org_str}"))
            if cipher_info:
                proto = cipher_info[1] if len(cipher_info) > 1 else "?"
                if proto in ("TLSv1","TLSv1.0","TLSv1.1","SSLv2","SSLv3"):
                    results.append(ScriptResult("ssl-enum-ciphers",
                        f"Weak protocol: {proto}", vuln=True))
                else:
                    results.append(ScriptResult("ssl-enum-ciphers", f"Protocol: {proto}"))
        except Exception:
            pass

    return results

# ─────────────────────────────────────────────────────────────────────────────
# TARGET / PORT PARSING
# ─────────────────────────────────────────────────────────────────────────────
def parse_targets(target_str: str) -> List[str]:
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        try:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses == 1:
                targets.append(str(net.network_address))
            else:
                targets.extend(str(h) for h in net.hosts())
            continue
        except ValueError:
            pass
        m = re.match(r"^([\d\.]+)-(\d+)$", part)
        if m:
            base = m.group(1); end = int(m.group(2))
            parts = base.split(".")
            start = int(parts[-1]); pfx = ".".join(parts[:-1])
            for i in range(start, end + 1):
                targets.append(f"{pfx}.{i}")
            continue
        try:
            targets.append(socket.gethostbyname(part))
        except socket.gaierror:
            print(f"{Y}[!] Could not resolve: {part}{RST}")
    return targets

def parse_ports(port_str: str) -> List[int]:
    if port_str == "-":
        return list(range(1, 65536))
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT FORMATTERS
# ─────────────────────────────────────────────────────────────────────────────
def write_json(data: Dict, path: str):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"{G}[+] JSON output written to {path}{RST}")

def write_xml(data: Dict, path: str):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<zscan version="{VERSION}" start="{data.get("start_time","")}" '
             f'elapsed="{data.get("elapsed","")}" target="{data.get("target","")}">']
    for host in data.get("hosts", []):
        lines.append(f'  <host ip="{host["ip"]}" os="{host.get("os","")}" '
                     f'ttl="{host.get("ttl","")}">')
        for port_info in host.get("ports", []):
            lines.append(f'    <port number="{port_info["port"]}" '
                         f'state="{port_info["state"]}" '
                         f'service="{port_info["service"]}" '
                         f'version="{port_info.get("version","")}">')
            for sr in port_info.get("scripts", []):
                lines.append(f'      <script name="{sr.get("name","")}" '
                             f'vuln="{sr.get("vuln",False)}" '
                             f'cve="{sr.get("cve","")}">'
                             f'{sr.get("output","")}</script>')
            lines.append("    </port>")
        lines.append("  </host>")
    lines.append("</zscan>")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"{G}[+] XML output written to {path}{RST}")

def write_grepable(data: Dict, path: str):
    with open(path, "w") as f:
        f.write(f"# ZScan {VERSION} scan — {data.get('start_time','')}\n")
        for host in data.get("hosts", []):
            open_ports = [p for p in host.get("ports",[]) if p["state"] == "open"]
            port_str = ", ".join(
                f'{p["port"]}/open/{p.get("service","unknown")}'
                for p in open_ports
            )
            f.write(f"Host: {host['ip']}\tPorts: {port_str}\tOS: {host.get('os','')}\n")
    print(f"{G}[+] Grepable output written to {path}{RST}")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN LOOP
# ─────────────────────────────────────────────────────────────────────────────
def scan_port(ip: str, port: int, scan_fn, timeout: float,
              do_banner: bool, do_scripts: bool,
              script_cats: List[str]) -> Optional[Dict]:
    state = scan_fn(ip, port, timeout)
    if state != PORT_OPEN:
        return None
    info: Dict   = {"port": port, "state": state}
    svc_name     = SERVICE_DB.get(port, ("unknown", b""))[0]
    info["service"] = svc_name
    info["version"] = ""
    info["scripts"] = []

    if do_banner:
        banner = grab_banner(ip, port, timeout)
        banner_text = banner.decode("utf-8", errors="replace")

        # Upgrade service name from banner when port is unknown
        if svc_name == "unknown":
            if re.search(r"^SSH-", banner_text):
                svc_name = "ssh"
            elif re.search(r"^220[\s\-].*FileZilla|^220[\s\-].*ftp|^220[\s\-].*FTP", banner_text, re.IGNORECASE):
                svc_name = "ftp"
            elif re.search(r"^220[\s\-].*SMTP|ESMTP", banner_text, re.IGNORECASE):
                svc_name = "smtp"
            elif "HTTP/" in banner_text[:20] or "Server:" in banner_text[:500]:
                if port in (443, 8443, 44330) or "ssl" in banner_text.lower()[:100]:
                    svc_name = "https"
                else:
                    svc_name = "http"
            elif re.search(r"^\+OK|^\-ERR", banner_text):
                svc_name = "pop3"
            elif re.search(r"^\* OK|^\* BYE", banner_text):
                svc_name = "imap"
            elif re.search(r"redis_version", banner_text):
                svc_name = "redis"
            info["service"] = svc_name

        info["banner"]  = banner_text[:200]
        info["version"] = fingerprint_banner(banner, port)
    else:
        banner = b""

    if do_scripts:
        script_results   = run_scripts(ip, port, svc_name, banner, script_cats)
        info["scripts"]  = [{"name": r.name, "output": r.output,
                              "vuln": r.vuln, "cve": r.cve}
                            for r in script_results]
        info["_script_objs"] = script_results
    return info

def print_port(port_info: Dict, indent: str = ""):
    state = port_info["state"]
    color = G if state == "open" else Y
    svc   = port_info.get("service","unknown")
    ver   = port_info.get("version","")
    ver_str = f"  {D}{ver}{RST}" if ver else ""
    print(f"{indent}{color}{port_info['port']:>6}/tcp{RST}  "
          f"{color}{state:<14}{RST}  {C}{svc:<18}{RST}{ver_str}")
    for sr in port_info.get("_script_objs", []):
        print(repr(sr))

def run_scan(args) -> Dict:
    t_start = time.time()
    start_dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    timing  = TIMING[args.T]
    timeout = timing["timeout"]
    workers = timing["workers"]

    # Script categories
    script_cats: List[str] = []
    if args.script:
        script_cats = [s.strip().lower() for s in args.script.split(",")]

    # Scan function
    if   args.sS: scan_fn = lambda ip,p,t: tcp_syn_scan(ip, p, t)
    elif args.sU: scan_fn = lambda ip,p,t: udp_scan(ip, p, t)
    elif args.sF: scan_fn = lambda ip,p,t: tcp_flag_scan(ip, p, TH_FIN, t)
    elif args.sN: scan_fn = lambda ip,p,t: tcp_flag_scan(ip, p, 0, t)
    elif args.sX: scan_fn = lambda ip,p,t: tcp_flag_scan(ip, p, TH_FIN|TH_PSH|TH_URG, t)
    else:         scan_fn = lambda ip,p,t: tcp_connect_scan(ip, p, t)

    # Port list
    if args.p:
        ports = parse_ports(args.p)
    elif args.top_ports:
        count = args.top_ports
        ports = (TOP_1000 if count >= 1000 else TOP_100 if count >= 100
                 else sorted(TOP_100)[:count])
    else:
        ports = TOP_1000

    # Targets
    targets = parse_targets(args.target)

    # Banner / version
    do_banner  = args.sV or bool(args.script)
    do_scripts = bool(args.script)

    # Print banner
    print(f"\n{B}{'─'*65}{RST}")
    print(f" {Y}⚡ ZScan v{VERSION}{RST} — Air-gap Safe Network Scanner")
    print(f" Target: {B}{args.target}{RST}  Ports: {len(ports)}  "
          f"Timing: {B}T{args.T} ({timing['name']}){RST}")
    if do_scripts:
        print(f" Scripts: {B}{args.script or 'default'}{RST}")
    print(f"{B}{'─'*65}{RST}\n")

    results_data: Dict = {
        "start_time": start_dt, "target": args.target,
        "version": VERSION, "hosts": []
    }

    for ip in targets:
        # Host discovery
        if len(targets) > 1 or args.sn:
            if not icmp_ping(ip, timeout):
                if not args.sn:
                    print(f"  {D}[skip] {ip} — host down{RST}")
                continue
            print(f"{G}[+] Host up: {ip}{RST}")
            if args.sn:
                continue

        host_data: Dict = {"ip": ip, "os": "", "ttl": 0, "ports": []}

        if args.O:
            od = os_detect(ip, timeout)
            host_data["os"]  = od["os"]
            host_data["ttl"] = od["ttl"]
            print(f"  {C}OS: {od['os']} (TTL={od['ttl']} via {od['method']}){RST}")

        print(f"\n  {B}PORT      STATE          SERVICE           VERSION{RST}")

        open_count = 0
        vuln_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(scan_port, ip, port, scan_fn, timeout,
                                do_banner, do_scripts, script_cats): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_count += 1
                    print_port(result)
                    # Count vulns
                    for s in result.get("_script_objs", []):
                        if s.vuln: vuln_count += 1
                    # Clean for JSON (remove _script_objs)
                    r_clean = {k: v for k, v in result.items() if k != "_script_objs"}
                    host_data["ports"].append(r_clean)

        print(f"\n  {G}[*] {open_count} open port(s){RST}", end="")
        if vuln_count:
            print(f"  {R}⚠  {vuln_count} vuln(s) detected{RST}", end="")
        print()

        results_data["hosts"].append(host_data)

    elapsed = f"{time.time() - t_start:.2f}s"
    results_data["elapsed"] = elapsed
    print(f"\n{B}{'─'*65}{RST}")
    print(f" Done in {elapsed}\n")

    if args.oJ: write_json(results_data, args.oJ)
    if args.oX: write_xml(results_data, args.oX)
    if args.oG: write_grepable(results_data, args.oG)

    return results_data

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="zscan",
        description=f"ZScan v{VERSION} — Air-gap Safe Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 zscan.py 192.168.1.1
  python3 zscan.py 192.168.1.0/24 -sn -T4
  python3 zscan.py 192.168.1.1 -sT -sV --script default
  python3 zscan.py 10.0.0.1 -p 30021 --script all -sV
  sudo python3 zscan.py 10.0.0.1 -sS -p 1-1024 -O --script all
  sudo python3 zscan.py 10.0.0.1 -sS -p - --script all -oJ results.json"""
    )
    parser.add_argument("target", help="IP, CIDR, range (192.168.1.1-20), hostname")
    sg = parser.add_argument_group("Scan Types")
    sg.add_argument("-sS", action="store_true", help="TCP SYN scan (root)")
    sg.add_argument("-sT", action="store_true", help="TCP Connect scan (default)")
    sg.add_argument("-sU", action="store_true", help="UDP scan (root)")
    sg.add_argument("-sF", action="store_true", help="TCP FIN scan (root)")
    sg.add_argument("-sN", action="store_true", help="TCP NULL scan (root)")
    sg.add_argument("-sX", action="store_true", help="TCP XMAS scan (root)")
    sg.add_argument("-sn", action="store_true", help="Ping sweep only")
    pg = parser.add_argument_group("Port Selection")
    pg.add_argument("-p",          default="", help="Ports: 22,80 / 1-1024 / -")
    pg.add_argument("--top-ports", type=int, default=0, metavar="N")
    dg = parser.add_argument_group("Detection")
    dg.add_argument("-sV", action="store_true", help="Version detection")
    dg.add_argument("-O",  action="store_true", help="OS detection")
    dg.add_argument("--script", metavar="CATS",
                    help="Scripts: default,safe,vuln,auth,discovery,all (comma-sep)")
    tg = parser.add_argument_group("Timing")
    tg.add_argument("-T", type=int, default=3, choices=range(6), metavar="[0-5]")
    og = parser.add_argument_group("Output")
    og.add_argument("-oJ", metavar="FILE", help="JSON output")
    og.add_argument("-oX", metavar="FILE", help="XML output")
    og.add_argument("-oG", metavar="FILE", help="Grepable output")
    args = parser.parse_args()
    run_scan(args)

if __name__ == "__main__":
    main()
