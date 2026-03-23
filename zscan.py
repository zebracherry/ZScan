#!/usr/bin/env python3
"""
███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
╚══███╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███╔╝ ███████╗██║     ███████║██╔██╗ ██║
 ███╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

ZScan — Air-gap Safe Network Scanner
Version  : 1.0.0
Platform : Linux / Windows (Python 3.6+)
Author   : ZScan Project
License  : MIT

Features:
  -sS  TCP SYN scan      (root/admin required — fast, stealthy)
  -sT  TCP Connect scan  (no root — reliable)
  -sU  UDP scan          (root required)
  -sF  TCP FIN scan      (root required)
  -sN  TCP NULL scan     (root required)
  -sX  TCP XMAS scan     (root required)
  -sn  Ping scan / host discovery only
  -O   OS detection (TTL + window heuristics)
  -sV  Version/banner detection
  --script  Run embedded NSE-equivalent scripts
  -p   Port range: 22,80 / 1-1024 / - (all)
  --top-ports N  Scan top N common ports
  -T0..-T5  Timing templates (like nmap)
  -oJ  JSON output  -oX  XML output  -oG  Grepable output
  --min-rate  Minimum packets per second

AIR-GAP SAFE: stdlib only — socket, struct, threading, concurrent.futures
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import queue
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
VERSION = "1.0.0"
TOOL    = "ZScan"
IS_WINDOWS = platform.system() == "Windows"
IS_ROOT    = (os.geteuid() == 0) if not IS_WINDOWS else False

# Terminal colours
R="\033[0;31m"; G="\033[0;32m"; Y="\033[1;33m"
C="\033[0;36m"; B="\033[1m"; D="\033[2m"; RST="\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# TOP PORTS (mirrors nmap's --top-ports list)
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
TOP_1000 = TOP_100 + list(range(1, 1024))
TOP_1000 = sorted(set(TOP_1000))[:1000]

# ─────────────────────────────────────────────────────────────────────────────
# SERVICE / PORT DATABASE  (port → (service_name, default_banner_probe))
# ─────────────────────────────────────────────────────────────────────────────
SERVICE_DB: Dict[int, Tuple[str, bytes]] = {
    21:    ("ftp",        b""),
    22:    ("ssh",        b""),
    23:    ("telnet",     b""),
    25:    ("smtp",       b"EHLO zscan\r\n"),
    53:    ("dns",        b""),
    69:    ("tftp",       b""),
    79:    ("finger",     b""),
    80:    ("http",       b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    88:    ("kerberos",   b""),
    110:   ("pop3",       b""),
    111:   ("rpcbind",    b""),
    119:   ("nntp",       b""),
    135:   ("msrpc",      b""),
    137:   ("netbios-ns", b""),
    139:   ("netbios-ssn",b""),
    143:   ("imap",       b""),
    161:   ("snmp",       b""),
    179:   ("bgp",        b""),
    389:   ("ldap",       b""),
    443:   ("https",      b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    445:   ("smb",        b""),
    465:   ("smtps",      b""),
    500:   ("isakmp",     b""),
    514:   ("syslog",     b""),
    515:   ("printer",    b""),
    587:   ("submission", b"EHLO zscan\r\n"),
    631:   ("ipp",        b""),
    636:   ("ldaps",      b""),
    873:   ("rsync",      b""),
    993:   ("imaps",      b""),
    995:   ("pop3s",      b""),
    1080:  ("socks",      b""),
    1433:  ("ms-sql-s",   b""),
    1521:  ("oracle",     b""),
    1723:  ("pptp",       b""),
    2049:  ("nfs",        b""),
    2121:  ("ftp-proxy",  b""),
    3000:  ("ppp",        b"GET / HTTP/1.0\r\n\r\n"),
    3306:  ("mysql",      b""),
    3389:  ("ms-wbt-server", b""),
    3632:  ("distccd",    b""),
    4444:  ("krb524",     b""),
    5000:  ("upnp",       b"GET / HTTP/1.0\r\n\r\n"),
    5432:  ("postgresql", b""),
    5900:  ("vnc",        b""),
    5985:  ("wsman",      b""),
    6379:  ("redis",      b"*1\r\n$4\r\nINFO\r\n"),
    6443:  ("sun-sr-https", b""),
    7070:  ("realserver", b""),
    8080:  ("http-proxy", b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    8443:  ("https-alt",  b"GET / HTTP/1.0\r\nHost: target\r\n\r\n"),
    8888:  ("sun-answerbook", b"GET / HTTP/1.0\r\n\r\n"),
    9200:  ("elasticsearch", b"GET / HTTP/1.0\r\n\r\n"),
    9300:  ("vrace",      b""),
    9090:  ("zeus-admin", b"GET / HTTP/1.0\r\n\r\n"),
    11211: ("memcache",   b"stats\r\n"),
    27017: ("mongod",     b""),
    27018: ("mongod",     b""),
    50000: ("ibm-db2",    b""),
}

# ─────────────────────────────────────────────────────────────────────────────
# TIMING TEMPLATES  (like nmap -T0 to -T5)
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
# OS FINGERPRINT DATABASE  (TTL → OS guess)
# ─────────────────────────────────────────────────────────────────────────────
OS_TTL_DB = [
    (255, "Cisco IOS / network device"),
    (128, "Windows (XP/7/8/10/11/Server)"),
    (64,  "Linux / macOS / Android / iOS"),
    (60,  "macOS (older)"),
    (32,  "Windows 95/98/NT"),
    (30,  "Solaris / AIX (older)"),
]

def guess_os_from_ttl(ttl: int) -> str:
    closest = min(OS_TTL_DB, key=lambda x: abs(x[0] - ttl))
    return closest[1]

# ─────────────────────────────────────────────────────────────────────────────
# VERSION FINGERPRINTING  (banner regex → service version)
# ─────────────────────────────────────────────────────────────────────────────
VERSION_PATTERNS = [
    # SSH
    (r"SSH-(\d+\.\d+)-OpenSSH[_\-](\S+)",     "OpenSSH {2}"),
    (r"SSH-(\d+\.\d+)-(\S+)",                  "SSH {2}"),
    # HTTP
    (r"Server:\s*(Apache[^\r\n]+)",            "{1}"),
    (r"Server:\s*(nginx[^\r\n]+)",             "{1}"),
    (r"Server:\s*(Microsoft-IIS[^\r\n]+)",     "{1}"),
    (r"Server:\s*([^\r\n]+)",                  "{1}"),
    (r"HTTP/(\d\.\d)\s+\d+",                   "HTTP/{1}"),
    # FTP
    (r"220[\s-]+(.*?)\r?\n",                   "FTP: {1}"),
    # SMTP
    (r"220[\s-]+(.*?)\r?\n",                   "SMTP: {1}"),
    # MySQL
    (r"\x00\x00\x00\x0a([\d\.]+)",            "MySQL {1}"),
    # Redis
    (r"redis_version:(\S+)",                   "Redis {1}"),
    # MongoDB
    (r"\"version\"\s*:\s*\"([^\"]+)\"",        "MongoDB {1}"),
    # Elasticsearch
    (r"\"number\"\s*:\s*\"([^\"]+)\"",         "Elasticsearch {1}"),
    # Memcached
    (r"STAT version (\S+)",                     "Memcached {1}"),
    # RDP/Windows
    (r"Windows (\S+ \S+)",                      "Windows {1}"),
    # Generic version
    (r"[Vv]ersion[:\s]+(\d[\d\.]+)",           "v{1}"),
]

def fingerprint_banner(banner: bytes, port: int) -> str:
    """Extract version from banner bytes."""
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

    svc = SERVICE_DB.get(port, ("unknown", b""))[0]
    # Return first readable line of banner as fallback
    first_line = text.split("\n")[0].strip()[:60]
    if first_line and len(first_line) > 3:
        return f"{svc}: {first_line}"
    return svc

# ─────────────────────────────────────────────────────────────────────────────
# CHECKSUM HELPERS  (for raw packet construction)
# ─────────────────────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    if len(data) % 2:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_ip_header(src_ip: str, dst_ip: str, proto: int, data_len: int) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + data_len
    ip_id = random.randint(1, 65535)
    frag_off = 0
    ttl = 64
    csum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ip_id, frag_off, ttl, proto, csum, src, dst)
    csum = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ip_id, frag_off, ttl, proto, csum, src, dst)

def build_tcp_header(src_ip: str, dst_ip: str, sport: int, dport: int,
                     flags: int, seq: int = 0, ack: int = 0,
                     window: int = 65535) -> bytes:
    data_off = (5 << 4)
    csum = 0
    urg = 0
    tcp = struct.pack("!HHLLBBHHH",
        sport, dport, seq, ack, data_off, flags, window, csum, urg)
    # Pseudo header for checksum
    pseudo = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(tcp))
    csum = checksum(pseudo + tcp)
    return struct.pack("!HHLLBBHHH",
        sport, dport, seq, ack, data_off, flags, window, csum, urg)

def build_icmp_echo(seq: int = 1) -> bytes:
    icmp_type = 8; code = 0; csum = 0; pid = os.getpid() & 0xFFFF
    hdr = struct.pack("!BBHHH", icmp_type, code, csum, pid, seq)
    csum = checksum(hdr)
    return struct.pack("!BBHHH", icmp_type, code, csum, pid, seq)

def build_udp_header(sport: int, dport: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    csum = 0
    return struct.pack("!HHHH", sport, dport, length, csum)

# ─────────────────────────────────────────────────────────────────────────────
# HOST DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def icmp_ping(ip: str, timeout: float = 1.0) -> bool:
    """ICMP echo — requires root."""
    if not IS_ROOT and not IS_WINDOWS:
        return tcp_ping(ip, timeout)
    try:
        if IS_WINDOWS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        pkt = build_icmp_echo()
        sock.sendto(pkt, (ip, 0))
        try:
            data, _ = sock.recvfrom(1024)
            # ICMP reply is type 0
            if len(data) >= 28 and data[20] == 0:
                return True
        except socket.timeout:
            pass
    except (PermissionError, OSError):
        return tcp_ping(ip, timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return False


def tcp_ping(ip: str, timeout: float = 1.0,
             ports: List[int] = [80, 443, 22, 445, 3389]) -> bool:
    """TCP ping — works without root."""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result in (0, 111):   # connected or refused = host is up
                return True
        except Exception:
            pass
    return False


def discover_hosts(targets: List[str], timeout: float = 1.0,
                   workers: int = 100) -> List[str]:
    """Ping sweep a list of IPs, return live ones."""
    live = []
    lock = threading.Lock()

    def check(ip):
        if icmp_ping(ip, timeout):
            with lock:
                live.append(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(check, targets)

    return sorted(live, key=lambda x: [int(o) for o in x.split(".")])

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────

# TCP flag constants
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
        try:
            s.close()
        except Exception:
            pass


def tcp_syn_scan(ip: str, port: int, timeout: float = 1.0,
                 src_ip: str = "") -> str:
    """SYN scan — requires root. Fast, half-open, stealthy."""
    if not IS_ROOT:
        return tcp_connect_scan(ip, port, timeout)
    if not src_ip:
        src_ip = _get_local_ip(ip)
    sport = random.randint(1024, 65535)
    seq   = random.randint(0, 2**32 - 1)
    try:
        if IS_WINDOWS:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                socket.IPPROTO_TCP)
        else:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                socket.IPPROTO_TCP)
            raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)
        tcp_hdr = build_tcp_header(src_ip, ip, sport, port, TH_SYN, seq)
        ip_hdr  = build_ip_header(src_ip, ip, 6, len(tcp_hdr))
        raw.sendto(ip_hdr + tcp_hdr, (ip, 0))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = raw.recvfrom(4096)
                if addr[0] != ip:
                    continue
                # Parse IP header (20 bytes) then TCP
                if len(data) < 40:
                    continue
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 14:
                    continue
                tcp_data = data[ihl:]
                r_sport, r_dport = struct.unpack("!HH", tcp_data[0:4])
                r_flags = tcp_data[13]
                if r_dport != sport or r_sport != port:
                    continue
                if r_flags & (TH_SYN | TH_ACK) == (TH_SYN | TH_ACK):
                    # Send RST to close gracefully
                    rst = build_tcp_header(src_ip, ip, sport, port, TH_RST,
                                           seq + 1)
                    ip_r = build_ip_header(src_ip, ip, 6, len(rst))
                    try:
                        raw.sendto(ip_r + rst, (ip, 0))
                    except Exception:
                        pass
                    return PORT_OPEN
                elif r_flags & TH_RST:
                    return PORT_CLOSED
            except socket.timeout:
                break
            except Exception:
                break
        return PORT_FILTERED
    except (PermissionError, OSError):
        return tcp_connect_scan(ip, port, timeout)
    finally:
        try:
            raw.close()
        except Exception:
            pass


def tcp_connect_scan(ip: str, port: int, timeout: float = 1.0) -> str:
    """TCP Connect scan — no root needed. Reliable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return PORT_OPEN
        elif result in (111, 10061):   # ECONNREFUSED
            return PORT_CLOSED
        else:
            return PORT_FILTERED
    except socket.timeout:
        return PORT_FILTERED
    except Exception:
        return PORT_FILTERED


def tcp_flag_scan(ip: str, port: int, flags: int, timeout: float = 1.0,
                  src_ip: str = "") -> str:
    """FIN / NULL / XMAS scan — requires root."""
    if not IS_ROOT:
        print(f"[!] FIN/NULL/XMAS scan requires root")
        return PORT_FILTERED
    if not src_ip:
        src_ip = _get_local_ip(ip)
    sport = random.randint(1024, 65535)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                            socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)
        tcp_hdr = build_tcp_header(src_ip, ip, sport, port, flags)
        ip_hdr  = build_ip_header(src_ip, ip, 6, len(tcp_hdr))
        raw.sendto(ip_hdr + tcp_hdr, (ip, 0))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = raw.recvfrom(4096)
                if addr[0] != ip:
                    continue
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 14:
                    continue
                tcp_data = data[ihl:]
                r_sport, r_dport = struct.unpack("!HH", tcp_data[0:4])
                r_flags = tcp_data[13]
                if r_dport != sport or r_sport != port:
                    continue
                if r_flags & TH_RST:
                    return PORT_CLOSED
            except socket.timeout:
                break
        # No response = open|filtered (expected for FIN/NULL/XMAS on open ports)
        return PORT_OPEN_FILT
    except Exception:
        return PORT_FILTERED
    finally:
        try:
            raw.close()
        except Exception:
            pass


def udp_scan(ip: str, port: int, timeout: float = 2.0,
             src_ip: str = "") -> str:
    """UDP scan — requires root for ICMP unreachable detection."""
    if not IS_ROOT and not IS_WINDOWS:
        # Fallback: just try to send a UDP packet
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00" * 8, (ip, port))
            try:
                sock.recv(1024)
                return PORT_OPEN
            except socket.timeout:
                return PORT_OPEN_FILT
            except Exception:
                return PORT_FILTERED
        except Exception:
            return PORT_FILTERED
        finally:
            try:
                sock.close()
            except Exception:
                pass

    try:
        # Send UDP probe
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)

        # Use known probe if available
        probe = SERVICE_DB.get(port, ("", b""))[1] or b"\x00" * 8
        udp_sock.sendto(probe, (ip, port))

        try:
            data, _ = udp_sock.recvfrom(4096)
            if data:
                return PORT_OPEN
        except socket.timeout:
            # No response — could be open|filtered
            return PORT_OPEN_FILT
        except ConnectionResetError:
            # Windows: ICMP port unreachable
            return PORT_CLOSED
        except Exception:
            pass

        return PORT_OPEN_FILT
    except Exception:
        return PORT_FILTERED
    finally:
        try:
            udp_sock.close()
        except Exception:
            pass


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> bytes:
    """Grab service banner via TCP."""
    probe = SERVICE_DB.get(port, ("", b""))[1]
    # For SSL/TLS ports, skip (would need ssl module wrap)
    ssl_ports = {443, 8443, 993, 995, 465, 636, 6443}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in ssl_ports:
            try:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except Exception:
                pass

        # Send probe if we have one
        if probe:
            sock.send(probe)

        banner = b""
        sock.settimeout(2.0)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 8192:
                    break
        except socket.timeout:
            pass
        return banner
    except Exception:
        return b""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def os_detect(ip: str, timeout: float = 2.0) -> Dict:
    """OS detection via ICMP TTL + TCP window size heuristics."""
    result = {"os": "unknown", "ttl": 0, "method": ""}

    # Method 1: ICMP TTL
    if IS_ROOT or IS_WINDOWS:
        try:
            if IS_WINDOWS:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_ICMP)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
            pkt = build_icmp_echo(seq=1)
            sock.sendto(pkt, (ip, 0))
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) >= 9:
                    ttl = data[8]
                    result["ttl"] = ttl
                    result["os"] = guess_os_from_ttl(ttl)
                    result["method"] = "icmp-ttl"
            except socket.timeout:
                pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # Method 2: TCP window size
    if result["os"] == "unknown":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            for port in [80, 443, 22, 445]:
                try:
                    sock.connect((ip, port))
                    # If connected, check local TCP info isn't possible in stdlib
                    # but we can infer from behavior
                    result["os"] = "unknown (connected)"
                    result["method"] = "tcp-connect"
                    break
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return result

# ─────────────────────────────────────────────────────────────────────────────
# EMBEDDED NSE-EQUIVALENT SCRIPTS
# All checks are pure Python — no external tools, no internet, air-gap safe
# ─────────────────────────────────────────────────────────────────────────────

class ScriptResult:
    def __init__(self, name: str, output: str, vuln: bool = False,
                 cve: str = ""):
        self.name   = name
        self.output = output
        self.vuln   = vuln
        self.cve    = cve

    def __repr__(self):
        tag = f" [{R}VULN{RST}]" if self.vuln else ""
        cve_str = f" ({self.cve})" if self.cve else ""
        return f"  |_{B}{self.name}{RST}{tag}{cve_str}\n    {self.output}"


def _http_get(ip: str, port: int, path: str = "/",
              timeout: float = 5.0, https: bool = False) -> Tuple[int, Dict, str]:
    """Minimal HTTP GET returning (status, headers, body)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if https or port in (443, 8443):
            try:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            except Exception:
                pass

        req = (f"GET {path} HTTP/1.0\r\n"
               f"Host: {ip}\r\n"
               f"User-Agent: Mozilla/5.0\r\n"
               f"Connection: close\r\n\r\n")
        sock.send(req.encode())

        response = b""
        sock.settimeout(3.0)
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
        except socket.timeout:
            pass

        raw = response.decode("utf-8", errors="replace")
        lines = raw.split("\r\n")
        if not lines:
            return 0, {}, ""

        # Status line
        status = 0
        m = re.match(r"HTTP/[\d\.]+\s+(\d+)", lines[0])
        if m:
            status = int(m.group(1))

        # Headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if not line:
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body = "\r\n".join(lines[body_start:])
        return status, headers, body
    except Exception:
        return 0, {}, ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run_scripts(ip: str, port: int, service: str, banner: bytes,
                categories: List[str]) -> List[ScriptResult]:
    """Run all relevant embedded scripts for this port/service."""
    results = []
    cats = set(c.lower() for c in categories)
    run_all = "all" in cats or not cats

    def wants(cat: str) -> bool:
        return run_all or cat in cats

    banner_str = banner.decode("utf-8", errors="replace")

    # ── BANNER GRAB ──────────────────────────────────────────────────────────
    if wants("default") and banner:
        first_line = banner_str.split("\n")[0].strip()[:120]
        if first_line:
            results.append(ScriptResult("banner", first_line))

    # ── HTTP SCRIPTS ─────────────────────────────────────────────────────────
    is_http = service in ("http", "https", "http-proxy", "https-alt",
                          "http-alt") or port in (80, 8080, 8443, 443, 8888,
                                                   8000, 9090, 9200, 5000,
                                                   3000, 7070)
    if is_http and wants("default"):
        status, hdrs, body = _http_get(ip, port)

        # http-title
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:100]
            results.append(ScriptResult("http-title", title))

        # http-server-header
        if "server" in hdrs:
            results.append(ScriptResult("http-server-header", hdrs["server"]))

        # http-methods
        if wants("safe"):
            # Send OPTIONS request
            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(3.0)
                sock2.connect((ip, port))
                req = f"OPTIONS / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                sock2.send(req.encode())
                resp = b""
                try:
                    while True:
                        c = sock2.recv(4096)
                        if not c:
                            break
                        resp += c
                        if len(resp) > 8192:
                            break
                except Exception:
                    pass
                sock2.close()
                raw2 = resp.decode("utf-8", errors="replace")
                for line in raw2.split("\r\n"):
                    if line.lower().startswith("allow:"):
                        methods = line.split(":", 1)[1].strip()
                        risky = [m.strip() for m in methods.split(",")
                                 if m.strip() in ("PUT", "DELETE", "CONNECT",
                                                   "TRACE", "PATCH")]
                        out = f"Supported: {methods}"
                        if risky:
                            out += f"  [Potentially risky: {', '.join(risky)}]"
                        results.append(ScriptResult("http-methods", out))
                        break
            except Exception:
                pass

        # http-robots.txt
        if wants("safe"):
            st, _, robots_body = _http_get(ip, port, "/robots.txt")
            if st == 200 and robots_body:
                disallowed = [l.split(":", 1)[1].strip()
                              for l in robots_body.split("\n")
                              if l.strip().lower().startswith("disallow:")][:10]
                if disallowed:
                    results.append(ScriptResult(
                        "http-robots.txt",
                        f"Disallowed entries: {', '.join(disallowed[:5])}"
                        + (" ..." if len(disallowed) > 5 else "")))

        # http-security-headers
        if wants("safe") or wants("vuln"):
            missing = []
            security_headers = [
                "x-frame-options", "x-xss-protection",
                "x-content-type-options", "strict-transport-security",
                "content-security-policy", "referrer-policy",
            ]
            for h in security_headers:
                if h not in hdrs:
                    missing.append(h)
            if missing:
                results.append(ScriptResult(
                    "http-security-headers",
                    f"Missing security headers: {', '.join(missing)}",
                    vuln=True))
            else:
                results.append(ScriptResult(
                    "http-security-headers",
                    "All key security headers present"))

        # http-auth (check for 401)
        if status == 401:
            auth = hdrs.get("www-authenticate", "unknown")
            results.append(ScriptResult("http-auth",
                f"Authentication required: {auth}"))

        # http-git (exposed .git)
        if wants("vuln"):
            st_git, _, git_body = _http_get(ip, port, "/.git/HEAD")
            if st_git == 200 and "ref:" in git_body:
                results.append(ScriptResult(
                    "http-git",
                    "Git repository exposed at /.git/HEAD",
                    vuln=True))

        # http-passwd (directory traversal)
        if wants("vuln"):
            for path in ["/../../../etc/passwd", "/etc/passwd",
                          "/%2e%2e/%2e%2e/etc/passwd"]:
                st_p, _, body_p = _http_get(ip, port, path)
                if st_p == 200 and "root:x:" in body_p:
                    results.append(ScriptResult(
                        "http-passwd",
                        f"Possible directory traversal: {path}",
                        vuln=True))
                    break

        # http-shellshock (CVE-2014-6271)
        if wants("vuln"):
            try:
                sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock3.settimeout(3.0)
                sock3.connect((ip, port))
                payload = ("GET /cgi-bin/test.cgi HTTP/1.0\r\n"
                           "Host: {ip}\r\n"
                           "User-Agent: () { :; }; echo; echo SHELLSHOCK_TEST\r\n\r\n")
                sock3.send(payload.encode())
                resp3 = b""
                try:
                    while True:
                        c = sock3.recv(4096)
                        if not c:
                            break
                        resp3 += c
                        if len(resp3) > 8192:
                            break
                except Exception:
                    pass
                sock3.close()
                if b"SHELLSHOCK_TEST" in resp3:
                    results.append(ScriptResult(
                        "http-shellshock",
                        "Server appears vulnerable to Shellshock",
                        vuln=True, cve="CVE-2014-6271"))
            except Exception:
                pass

        # http-cors
        if wants("safe"):
            status_c, hdrs_c, _ = _http_get(ip, port)
            acao = hdrs_c.get("access-control-allow-origin", "")
            if acao == "*":
                results.append(ScriptResult(
                    "http-cors",
                    "CORS: Access-Control-Allow-Origin: * (open)",
                    vuln=True))
            elif acao:
                results.append(ScriptResult(
                    "http-cors", f"CORS origin: {acao}"))

        # http-waf-detect (basic)
        if wants("safe"):
            waf_sigs = {
                "Cloudflare": ["cf-ray", "cloudflare"],
                "AWS WAF":    ["x-amzn-requestid", "awselb"],
                "ModSecurity":["mod_security", "modsecurity"],
                "F5 BIG-IP":  ["bigip", "f5-bigip"],
                "Akamai":     ["akamai", "akamaighost"],
            }
            detected_waf = None
            all_headers = " ".join(hdrs.values()).lower() + body.lower()[:500]
            for waf_name, sigs in waf_sigs.items():
                if any(s in all_headers for s in sigs):
                    detected_waf = waf_name
                    break
            if detected_waf:
                results.append(ScriptResult(
                    "http-waf-detect", f"WAF detected: {detected_waf}"))

        # http-open-redirect (basic check)
        if wants("vuln"):
            test_urls = [
                "/?redirect=http://evil.com",
                "/?url=http://evil.com",
                "/?next=http://evil.com",
            ]
            for url in test_urls:
                st_r, hdrs_r, _ = _http_get(ip, port, url)
                loc = hdrs_r.get("location", "")
                if st_r in (301, 302, 303, 307, 308) and "evil.com" in loc:
                    results.append(ScriptResult(
                        "http-open-redirect",
                        f"Open redirect via: {url}",
                        vuln=True))
                    break

        # http-internal-ip-disclosure
        if wants("vuln"):
            try:
                sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock4.settimeout(3.0)
                sock4.connect((ip, port))
                req4 = f"GET / HTTP/1.0\r\n\r\n"   # no Host header
                sock4.send(req4.encode())
                resp4 = b""
                try:
                    while True:
                        c = sock4.recv(4096)
                        if not c:
                            break
                        resp4 += c
                        if len(resp4) > 4096:
                            break
                except Exception:
                    pass
                sock4.close()
                raw4 = resp4.decode("utf-8", errors="replace")
                priv_ip = re.search(
                    r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
                    r"|192\.168\.\d+\.\d+)\b", raw4)
                if priv_ip and priv_ip.group() != ip:
                    results.append(ScriptResult(
                        "http-internal-ip-disclosure",
                        f"Internal IP leaked: {priv_ip.group()}",
                        vuln=True))
            except Exception:
                pass

    # ── SSH SCRIPTS ──────────────────────────────────────────────────────────
    is_ssh = service == "ssh" or port == 22
    if is_ssh and wants("default"):
        # ssh-hostkey (parse from banner)
        if b"SSH-" in banner:
            ssh_banner = banner_str.split("\n")[0].strip()
            results.append(ScriptResult("ssh-hostkey", ssh_banner))

        # ssh-auth-methods
        if wants("safe"):
            try:
                sock_ssh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_ssh.settimeout(5.0)
                sock_ssh.connect((ip, port))
                banner_b = sock_ssh.recv(256)
                # Send our banner
                sock_ssh.send(b"SSH-2.0-ZScan_1.0\r\n")
                # Send a SERVICE_REQUEST for ssh-userauth — simplified probe
                # Just check banner for useful info
                results.append(ScriptResult(
                    "ssh-auth-methods",
                    "Use ssh -o PreferredAuthentications=none to enumerate"))
                sock_ssh.close()
            except Exception:
                pass

        # Weak SSH version check
        if wants("vuln") and "SSH-1." in banner_str:
            results.append(ScriptResult(
                "ssh-weak-version",
                f"SSH v1 detected — insecure protocol version",
                vuln=True, cve="CVE-2001-0553"))

    # ── SMB SCRIPTS ──────────────────────────────────────────────────────────
    is_smb = service in ("smb", "netbios-ssn", "microsoft-ds") or port in (139, 445)
    if is_smb and wants("default"):
        # smb-os-discovery (negotiate protocol)
        try:
            sock_smb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_smb.settimeout(5.0)
            sock_smb.connect((ip, port))

            # NetBIOS Session Request (for port 139)
            if port == 139:
                nb_req = b"\x81\x00\x00\x44" + b"\x20" + b"CACACACACACACACACACACACACACACAAA\x00"
                nb_req += b"\x20" + b"CACACACACACACACACACACACACACACAAA\x00"
                sock_smb.send(nb_req)
                sock_smb.recv(4)

            # SMB Negotiate Protocol Request
            smb_hdr = b"\xff\x53\x4d\x42"  # \xffSMB
            smb_hdr += b"\x72"              # Negotiate Protocol
            smb_hdr += b"\x00" * 19         # Status, flags, etc.
            smb_hdr += b"\x00" * 12         # Reserved
            smb_hdr += b"\xff\xff"          # TID
            smb_hdr += b"\xff\xff"          # PID
            smb_hdr += b"\xff\xff"          # UID
            smb_hdr += b"\xff\xff"          # MID
            # Dialect strings
            dialects = (b"\x02NT LM 0.12\x00"
                        b"\x02SMB 2.002\x00"
                        b"\x02SMB 2.???\x00")
            word_count = b"\x00"
            byte_count = struct.pack("<H", len(dialects))
            smb_body = word_count + byte_count + dialects
            # NetBIOS length prefix
            nb_len = struct.pack(">I", len(smb_hdr) + len(smb_body))
            packet = b"\x00" + nb_len[1:] + smb_hdr + smb_body
            sock_smb.send(packet)

            resp = sock_smb.recv(4096)
            if resp and len(resp) > 36:
                # Try to extract OS string from response
                try:
                    resp_str = resp.decode("utf-16-le", errors="replace")
                    os_match = re.search(r"Windows[^\x00]+", resp_str)
                    if os_match:
                        results.append(ScriptResult(
                            "smb-os-discovery",
                            f"OS: {os_match.group().strip()}"))
                except Exception:
                    results.append(ScriptResult(
                        "smb-os-discovery",
                        "SMB service detected"))
            sock_smb.close()
        except Exception:
            if port in (139, 445):
                results.append(ScriptResult(
                    "smb-os-discovery", "SMB port open — could not negotiate"))

        # smb-vuln-ms17-010 (EternalBlue detection)
        if wants("vuln"):
            try:
                sock_eb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_eb.settimeout(5.0)
                sock_eb.connect((ip, 445))

                # SMBv1 negotiate
                payload = (
                    b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                    b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50"
                    b"\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f"
                    b"\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e"
                    b"\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f"
                    b"\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72"
                    b"\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d"
                    b"\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d"
                    b"\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20"
                    b"\x30\x2e\x31\x32\x00"
                )
                sock_eb.send(payload)
                resp_eb = sock_eb.recv(1024)
                sock_eb.close()

                # Check if SMBv1 is supported (EternalBlue requires SMBv1)
                if resp_eb and b"\xff\x53\x4d\x42\x72" in resp_eb:
                    # Check for VULNERABLE status — simplified check
                    # A full check requires session setup, this is detection only
                    results.append(ScriptResult(
                        "smb-vuln-ms17-010",
                        "SMBv1 is enabled — system may be vulnerable to EternalBlue. "
                        "Verify patch status.",
                        vuln=True,
                        cve="CVE-2017-0144"))
            except Exception:
                pass

        # smb-double-pulsar-backdoor check
        if wants("vuln"):
            try:
                sock_dp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_dp.settimeout(5.0)
                sock_dp.connect((ip, 445))
                # DoublePulsar ping packet
                dp_payload = (
                    b"\x00\x00\x00\x3f\xff\x53\x4d\x42\x25\x00\x00\x00\x00"
                    b"\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x08\xff\xfe\x00\x00\x40\x00\x00\x0c\x00"
                    b"\x04\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                )
                sock_dp.send(dp_payload)
                resp_dp = sock_dp.recv(1024)
                sock_dp.close()
                # DoublePulsar responses with a specific multiplex_id
                if resp_dp and len(resp_dp) > 34:
                    mult_id = struct.unpack_from("<H", resp_dp, 30)[0]
                    if mult_id == 65:  # 0x41 — DoublePulsar signature
                        results.append(ScriptResult(
                            "smb-double-pulsar-backdoor",
                            "DoublePulsar backdoor DETECTED!",
                            vuln=True, cve="MS17-010"))
            except Exception:
                pass

    # ── FTP SCRIPTS ──────────────────────────────────────────────────────────
    is_ftp = service == "ftp" or port == 21
    if is_ftp and wants("default"):
        # ftp-anon
        try:
            sock_ftp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ftp.settimeout(5.0)
            sock_ftp.connect((ip, port))
            sock_ftp.recv(1024)  # banner
            sock_ftp.send(b"USER anonymous\r\n")
            r1 = sock_ftp.recv(1024).decode("utf-8", errors="replace")
            sock_ftp.send(b"PASS anonymous@\r\n")
            r2 = sock_ftp.recv(1024).decode("utf-8", errors="replace")
            sock_ftp.close()
            if r2.startswith("230"):
                results.append(ScriptResult(
                    "ftp-anon",
                    "Anonymous FTP login allowed",
                    vuln=True))
            else:
                results.append(ScriptResult(
                    "ftp-anon", "Anonymous login denied"))
        except Exception:
            pass

        # ftp-syst
        if wants("safe"):
            try:
                sock_fs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_fs.settimeout(5.0)
                sock_fs.connect((ip, port))
                sock_fs.recv(1024)
                sock_fs.send(b"SYST\r\n")
                syst = sock_fs.recv(1024).decode("utf-8", errors="replace").strip()
                sock_fs.close()
                results.append(ScriptResult("ftp-syst", syst))
            except Exception:
                pass

        # ftp-vsftpd-backdoor (CVE-2011-2523)
        if wants("vuln"):
            try:
                sock_vb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_vb.settimeout(5.0)
                sock_vb.connect((ip, port))
                ban = sock_vb.recv(1024).decode("utf-8", errors="replace")
                if "vsFTPd 2.3.4" in ban:
                    sock_vb.send(b"USER test:)\r\n")
                    sock_vb.recv(1024)
                    sock_vb.send(b"PASS x\r\n")
                    time.sleep(0.5)
                    # Try connecting to backdoor port 6200
                    sock_bd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock_bd.settimeout(2.0)
                    try:
                        sock_bd.connect((ip, 6200))
                        results.append(ScriptResult(
                            "ftp-vsftpd-backdoor",
                            "vsFTPd 2.3.4 backdoor shell found on port 6200!",
                            vuln=True, cve="CVE-2011-2523"))
                        sock_bd.close()
                    except Exception:
                        results.append(ScriptResult(
                            "ftp-vsftpd-backdoor",
                            "vsFTPd 2.3.4 detected — check for backdoor"))
                sock_vb.close()
            except Exception:
                pass

    # ── SMTP SCRIPTS ─────────────────────────────────────────────────────────
    is_smtp = service in ("smtp", "submission", "smtps") or port in (25, 465, 587)
    if is_smtp and wants("default"):
        try:
            sock_smtp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_smtp.settimeout(5.0)
            sock_smtp.connect((ip, port))
            sock_smtp.recv(1024)
            sock_smtp.send(b"EHLO zscan.local\r\n")
            ehlo_resp = sock_smtp.recv(4096).decode("utf-8", errors="replace")
            cmds = [l.lstrip("250-250 ").strip()
                    for l in ehlo_resp.split("\n") if l.startswith("250")]
            results.append(ScriptResult(
                "smtp-commands",
                f"EHLO commands: {', '.join(cmds[:10])}"))

            # smtp-open-relay check
            if wants("vuln"):
                sock_smtp.send(b"MAIL FROM:<test@zscan.local>\r\n")
                r1 = sock_smtp.recv(1024).decode("utf-8", errors="replace")
                sock_smtp.send(b"RCPT TO:<test@example.com>\r\n")
                r2 = sock_smtp.recv(1024).decode("utf-8", errors="replace")
                if r2.startswith("250"):
                    results.append(ScriptResult(
                        "smtp-open-relay",
                        "Server may be an open mail relay",
                        vuln=True))
                else:
                    results.append(ScriptResult(
                        "smtp-open-relay", "Relay denied"))
            sock_smtp.close()
        except Exception:
            pass

        # smtp-enum-users (VRFY)
        if wants("auth"):
            try:
                sock_eu = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_eu.settimeout(5.0)
                sock_eu.connect((ip, port))
                sock_eu.recv(1024)
                sock_eu.send(b"VRFY root\r\n")
                vrfy = sock_eu.recv(1024).decode("utf-8", errors="replace")
                sock_eu.close()
                if vrfy.startswith("252") or vrfy.startswith("250"):
                    results.append(ScriptResult(
                        "smtp-enum-users",
                        "VRFY command accepted — user enumeration possible",
                        vuln=True))
                else:
                    results.append(ScriptResult(
                        "smtp-enum-users",
                        "VRFY command rejected"))
            except Exception:
                pass

    # ── DNS SCRIPTS ──────────────────────────────────────────────────────────
    is_dns = service == "dns" or port == 53
    if is_dns and wants("default"):
        # dns-recursion check (UDP)
        try:
            dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_sock.settimeout(3.0)
            # Minimal DNS query for google.com A record with recursion desired
            dns_query = (
                b"\x00\x01"   # Transaction ID
                b"\x01\x00"   # Flags: recursion desired
                b"\x00\x01"   # Questions: 1
                b"\x00\x00\x00\x00\x00\x00"  # Answers/Auth/Add: 0
                b"\x06google\x03com\x00"
                b"\x00\x01"   # Type A
                b"\x00\x01"   # Class IN
            )
            dns_sock.sendto(dns_query, (ip, 53))
            resp_dns, _ = dns_sock.recvfrom(4096)
            dns_sock.close()
            if resp_dns and len(resp_dns) > 12:
                flags = struct.unpack("!H", resp_dns[2:4])[0]
                ra_bit = (flags >> 7) & 1
                if ra_bit:
                    results.append(ScriptResult(
                        "dns-recursion",
                        "Recursion allowed — DNS server accepts recursive queries",
                        vuln=(not (ip.startswith("10.") or
                                   ip.startswith("192.168.") or
                                   ip.startswith("172."))
                             )))
                else:
                    results.append(ScriptResult(
                        "dns-recursion", "Recursion not available"))
        except Exception:
            pass

        # dns-zone-transfer check
        if wants("vuln"):
            try:
                dns_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dns_tcp.settimeout(5.0)
                dns_tcp.connect((ip, 53))
                # AXFR for example.com (harmless probe)
                axfr = (
                    b"\x00\x1d"    # Length prefix
                    b"\xde\xad"    # Transaction ID
                    b"\x00\x00"    # Flags
                    b"\x00\x01"    # Questions
                    b"\x00\x00\x00\x00\x00\x00"
                    b"\x07example\x03com\x00"
                    b"\x00\xfc"    # Type AXFR
                    b"\x00\x01"    # Class IN
                )
                dns_tcp.send(struct.pack("!H", len(axfr) - 2) + axfr[2:])
                resp_ax = dns_tcp.recv(4096)
                dns_tcp.close()
                if resp_ax and len(resp_ax) > 6:
                    rcode = resp_ax[5] & 0x0F if len(resp_ax) > 5 else 5
                    if rcode == 0:
                        results.append(ScriptResult(
                            "dns-zone-transfer",
                            "Zone transfer may be allowed!",
                            vuln=True))
                    else:
                        results.append(ScriptResult(
                            "dns-zone-transfer",
                            "Zone transfer denied (RCODE != 0)"))
            except Exception:
                pass

    # ── SNMP SCRIPTS ─────────────────────────────────────────────────────────
    is_snmp = service == "snmp" or port == 161
    if is_snmp and wants("default"):
        # Try common community strings
        for community in [b"public", b"private", b"community"]:
            try:
                snmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                snmp_sock.settimeout(2.0)
                # SNMPv1 GetRequest for sysDescr OID
                oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
                varbind = (b"\x30" + bytes([2 + len(oid)]) +
                           b"\x06" + bytes([len(oid)]) + oid +
                           b"\x05\x00")
                varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
                pdu = (b"\xa0" + bytes([10 + len(community) + len(varbind_list)]) +
                       b"\x02\x01\x00"  # request-id
                       b"\x02\x01\x00"  # error-status
                       b"\x02\x01\x00"  # error-index
                       + varbind_list)
                msg = (b"\x30" + bytes([6 + len(community) + len(pdu)]) +
                       b"\x02\x01\x00"  # version SNMPv1
                       b"\x04" + bytes([len(community)]) + community +
                       pdu)
                snmp_sock.sendto(msg, (ip, 161))
                resp_snmp, _ = snmp_sock.recvfrom(4096)
                snmp_sock.close()
                if resp_snmp:
                    # Extract string value from response
                    snmp_str = resp_snmp.decode("latin-1", errors="replace")
                    # Find printable segments
                    printable = re.findall(r"[\x20-\x7e]{4,}", snmp_str)
                    sys_desc = " ".join(printable[:3])[:100]
                    results.append(ScriptResult(
                        "snmp-info",
                        f"Community '{community.decode()}' accepted. "
                        f"SysDescr: {sys_desc}",
                        vuln=(community == b"public")))
                    break
            except Exception:
                pass

    # ── SSL/TLS SCRIPTS ──────────────────────────────────────────────────────
    is_ssl = service in ("https", "https-alt", "imaps", "pop3s", "smtps") or \
             port in (443, 8443, 993, 995, 465)
    if is_ssl and wants("default"):
        try:
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(5.0)
            raw_sock.connect((ip, port))
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)

            # ssl-cert
            cert = ssl_sock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter", "unknown")
                cn = subject.get("commonName", "unknown")
                results.append(ScriptResult(
                    "ssl-cert",
                    f"Subject: {cn} | Issuer: {issuer.get('organizationName','?')} "
                    f"| Expires: {not_after}"))

                # Check expiry
                try:
                    exp = datetime.datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        results.append(ScriptResult(
                            "ssl-cert",
                            f"CERTIFICATE EXPIRED {abs(days_left)} days ago!",
                            vuln=True))
                    elif days_left < 30:
                        results.append(ScriptResult(
                            "ssl-cert",
                            f"Certificate expires in {days_left} days",
                            vuln=True))
                except Exception:
                    pass

            # ssl-enum-ciphers (check TLS version)
            tls_ver = ssl_sock.version()
            if tls_ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                results.append(ScriptResult(
                    "ssl-enum-ciphers",
                    f"Weak TLS version in use: {tls_ver}",
                    vuln=True))
            else:
                results.append(ScriptResult(
                    "ssl-enum-ciphers",
                    f"TLS version: {tls_ver}"))

            ssl_sock.close()
        except ImportError:
            results.append(ScriptResult("ssl-cert", "ssl module not available"))
        except Exception:
            pass

    # ── REDIS SCRIPTS ────────────────────────────────────────────────────────
    is_redis = service == "redis" or port == 6379
    if is_redis and wants("default"):
        try:
            sock_r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_r.settimeout(3.0)
            sock_r.connect((ip, port))
            sock_r.send(b"*1\r\n$4\r\nINFO\r\n")
            resp_r = sock_r.recv(4096).decode("utf-8", errors="replace")
            sock_r.close()

            if "redis_version" in resp_r:
                ver_m = re.search(r"redis_version:(\S+)", resp_r)
                role_m = re.search(r"role:(\S+)", resp_r)
                results.append(ScriptResult(
                    "redis-info",
                    f"Version: {ver_m.group(1) if ver_m else '?'} "
                    f"Role: {role_m.group(1) if role_m else '?'}",
                    vuln=True))

            # Check for no-auth
            sock_r2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_r2.settimeout(3.0)
            sock_r2.connect((ip, port))
            sock_r2.send(b"*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n")
            resp_r2 = sock_r2.recv(256).decode("utf-8", errors="replace")
            sock_r2.close()
            if "+OK" in resp_r2 or "*" in resp_r2:
                results.append(ScriptResult(
                    "redis-info",
                    "Redis accessible without authentication!",
                    vuln=True))
        except Exception:
            pass

    # ── MONGODB SCRIPTS ──────────────────────────────────────────────────────
    is_mongo = service in ("mongod",) or port in (27017, 27018)
    if is_mongo and wants("default"):
        try:
            sock_m = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_m.settimeout(3.0)
            sock_m.connect((ip, port))
            # MongoDB OP_QUERY for isMaster
            msg = (b"\x41\x00\x00\x00"  # message length
                   b"\x01\x00\x00\x00"  # request id
                   b"\x00\x00\x00\x00"  # response to
                   b"\xd4\x07\x00\x00"  # OP_QUERY
                   b"\x00\x00\x00\x00"  # flags
                   b"admin.$cmd\x00"    # collection
                   b"\x00\x00\x00\x00"  # skip
                   b"\x01\x00\x00\x00"  # return 1
                   b"\x13\x00\x00\x00"  # doc len
                   b"\x10isMaster\x00\x01\x00\x00\x00\x00")
            sock_m.send(msg)
            resp_m = sock_m.recv(4096)
            sock_m.close()
            if resp_m:
                results.append(ScriptResult(
                    "mongodb-info",
                    "MongoDB accessible — no authentication required",
                    vuln=True))
        except Exception:
            pass

    # ── RDP SCRIPTS ──────────────────────────────────────────────────────────
    is_rdp = service == "ms-wbt-server" or port == 3389
    if is_rdp and wants("default"):
        try:
            sock_rdp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_rdp.settimeout(5.0)
            sock_rdp.connect((ip, port))
            # X.224 Connection Request
            x224 = (b"\x03\x00\x00\x13\x0e\xe0\x00\x00"
                     b"\x00\x00\x00\x01\x00\x08\x00\x03"
                     b"\x00\x00\x00")
            sock_rdp.send(x224)
            resp_rdp = sock_rdp.recv(1024)
            sock_rdp.close()
            if resp_rdp and b"\x03\x00" in resp_rdp:
                # Check NLA (CredSSP) vs classic
                if b"\x02\x01\x00" in resp_rdp:
                    results.append(ScriptResult(
                        "rdp-enum-encryption",
                        "RDP: Classic RDP security (no NLA) — credentials sent in weaker encryption",
                        vuln=True))
                else:
                    results.append(ScriptResult(
                        "rdp-enum-encryption",
                        "RDP: NLA/CredSSP authentication"))
        except Exception:
            pass

        # rdp-vuln-ms12-020
        if wants("vuln"):
            try:
                sock_ms = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_ms.settimeout(3.0)
                sock_ms.connect((ip, 3389))
                pkt = (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"
                        b"\x01\x00\x08\x00\x0b\x00\x00\x00")
                sock_ms.send(pkt)
                resp_ms = sock_ms.recv(1024)
                sock_ms.close()
                # Simplified: if RDP responds, flag for manual check
                results.append(ScriptResult(
                    "rdp-vuln-ms12-020",
                    "RDP responding — manually verify MS12-020 patch status",
                    vuln=False, cve="CVE-2012-0152"))
            except Exception:
                pass

    # ── VNC SCRIPTS ──────────────────────────────────────────────────────────
    is_vnc = service == "vnc" or port == 5900
    if is_vnc and wants("default"):
        try:
            sock_vnc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_vnc.settimeout(5.0)
            sock_vnc.connect((ip, port))
            banner_vnc = sock_vnc.recv(12).decode("utf-8", errors="replace")
            if "RFB" in banner_vnc:
                ver = banner_vnc.strip()
                results.append(ScriptResult("vnc-info", f"Protocol: {ver}"))
                # Check for no-auth (security type 1)
                sock_vnc.send(banner_vnc.encode())
                sec_types = sock_vnc.recv(256)
                if sec_types and 1 in sec_types:
                    results.append(ScriptResult(
                        "realvnc-auth-bypass",
                        "VNC security type 1 (None) offered — no auth required",
                        vuln=True, cve="CVE-2006-2369"))
            sock_vnc.close()
        except Exception:
            pass

    # ── MYSQL SCRIPTS ────────────────────────────────────────────────────────
    is_mysql = service in ("mysql",) or port == 3306
    if is_mysql and wants("default"):
        try:
            sock_my = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_my.settimeout(3.0)
            sock_my.connect((ip, port))
            resp_my = sock_my.recv(1024)
            sock_my.close()
            if resp_my and len(resp_my) > 5:
                # MySQL handshake: payload starts at byte 4
                payload = resp_my[4:]
                if payload[0] == 10:  # Protocol v10
                    null_pos = payload.find(b"\x00", 1)
                    version = payload[1:null_pos].decode("utf-8", errors="replace")
                    results.append(ScriptResult(
                        "mysql-info", f"MySQL version: {version}"))
        except Exception:
            pass

    # ── NFS SCRIPTS ──────────────────────────────────────────────────────────
    is_nfs = service == "nfs" or port == 2049
    if is_nfs and wants("default"):
        results.append(ScriptResult(
            "nfs-showmount",
            "NFS port open — run: showmount -e {ip} to list exports"))

    # ── MEMCACHED ────────────────────────────────────────────────────────────
    is_memcache = service == "memcache" or port == 11211
    if is_memcache and wants("default"):
        try:
            sock_mc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_mc.settimeout(3.0)
            sock_mc.connect((ip, port))
            sock_mc.send(b"stats\r\n")
            resp_mc = sock_mc.recv(4096).decode("utf-8", errors="replace")
            sock_mc.close()
            if "STAT" in resp_mc:
                ver_m = re.search(r"STAT version (\S+)", resp_mc)
                results.append(ScriptResult(
                    "memcached-info",
                    f"Version: {ver_m.group(1) if ver_m else '?'} "
                    f"— Accessible without auth",
                    vuln=True))
        except Exception:
            pass

    # ── ELASTICSEARCH ────────────────────────────────────────────────────────
    is_es = port == 9200
    if is_es and wants("default"):
        st_es, _, body_es = _http_get(ip, port, "/")
        if "elasticsearch" in body_es.lower() or "cluster_name" in body_es:
            results.append(ScriptResult(
                "elasticsearch-info",
                "Elasticsearch accessible without authentication",
                vuln=True))

    # ── NBSTAT (NetBIOS names + MAC) ─────────────────────────────────────────
    is_netbios = service in ("netbios-ns", "netbios-ssn") or port in (137, 139)
    if is_netbios and wants("default"):
        try:
            nb_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            nb_sock.settimeout(2.0)
            # NetBIOS Node Status Request
            nb_query = (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
                        b"\x00\x21\x00\x01")
            nb_sock.sendto(nb_query, (ip, 137))
            try:
                resp_nb, _ = nb_sock.recvfrom(1024)
                nb_sock.close()
                if len(resp_nb) > 57:
                    num_names = resp_nb[56]
                    names = []
                    for i in range(min(num_names, 10)):
                        offset = 57 + (i * 18)
                        if offset + 15 > len(resp_nb):
                            break
                        nm = resp_nb[offset:offset+15].decode("ascii", "replace").strip()
                        if nm:
                            names.append(nm)
                    mac_off = 57 + num_names * 18
                    mac = ""
                    if len(resp_nb) >= mac_off + 6:
                        mac = ":".join(f"{b:02x}" for b in resp_nb[mac_off:mac_off+6])
                    results.append(ScriptResult(
                        "nbstat",
                        f"Names: {', '.join(names[:5])} | MAC: {mac}"))
            except socket.timeout:
                nb_sock.close()
        except Exception:
            pass

    # ── NTP INFO ──────────────────────────────────────────────────────────────
    is_ntp = service == "ntp" or port == 123
    if is_ntp and wants("default"):
        try:
            ntp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ntp_sock.settimeout(3.0)
            ntp_req = b"\x1b" + b"\x00" * 47
            ntp_sock.sendto(ntp_req, (ip, 123))
            resp_ntp, _ = ntp_sock.recvfrom(1024)
            ntp_sock.close()
            if len(resp_ntp) >= 48:
                ver = (resp_ntp[0] >> 3) & 0x7
                stratum = resp_ntp[1]
                ts_int = struct.unpack("!I", resp_ntp[40:44])[0]
                if ts_int > 2208988800:
                    dt = datetime.datetime.utcfromtimestamp(ts_int - 2208988800)
                    results.append(ScriptResult(
                        "ntp-info",
                        f"NTPv{ver} stratum={stratum} time={dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"))
        except Exception:
            pass
        # ntp-monlist CVE-2013-5211
        if wants("vuln"):
            try:
                ntp_s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ntp_s2.settimeout(3.0)
                ntp_s2.sendto(b"\x17\x00\x03\x2a" + b"\x00" * 4, (ip, 123))
                try:
                    resp_ml, _ = ntp_s2.recvfrom(4096)
                    if len(resp_ml) > 100:
                        results.append(ScriptResult(
                            "ntp-monlist",
                            f"monlist enabled — DDoS amplification! ({len(resp_ml)}B response)",
                            vuln=True, cve="CVE-2013-5211"))
                except socket.timeout:
                    pass
                ntp_s2.close()
            except Exception:
                pass

    # ── IMAP CAPABILITIES ─────────────────────────────────────────────────────
    is_imap = service in ("imap", "imaps") or port in (143, 993)
    if is_imap and wants("default"):
        try:
            sock_im = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_im.settimeout(5.0)
            sock_im.connect((ip, port))
            sock_im.recv(1024)
            sock_im.send(b"a001 CAPABILITY\r\n")
            caps = sock_im.recv(1024).decode("utf-8", errors="replace")
            sock_im.close()
            cap_line = next((l for l in caps.split("\n") if "CAPABILITY" in l.upper()), "")
            cap_line = re.sub(r"\*\s*CAPABILITY\s*", "", cap_line).strip()[:100]
            results.append(ScriptResult("imap-capabilities", cap_line or "IMAP responding"))
        except Exception:
            pass

    # ── POP3 CAPABILITIES ─────────────────────────────────────────────────────
    is_pop3 = service in ("pop3", "pop3s") or port in (110, 995)
    if is_pop3 and wants("default"):
        try:
            sock_pp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_pp.settimeout(5.0)
            sock_pp.connect((ip, port))
            sock_pp.recv(256)
            sock_pp.send(b"CAPA\r\n")
            resp_pp = sock_pp.recv(1024).decode("utf-8", errors="replace")
            sock_pp.close()
            caps = [l.strip() for l in resp_pp.split("\n")
                    if l.strip() and not l.startswith("+") and
                    not l.startswith("-") and l.strip() != "."][:8]
            results.append(ScriptResult("pop3-capabilities",
                                        f"Capabilities: {', '.join(caps)}"))
        except Exception:
            pass

    # ── FINGER ────────────────────────────────────────────────────────────────
    is_finger = service == "finger" or port == 79
    if is_finger and wants("default"):
        try:
            sock_fi = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_fi.settimeout(5.0)
            sock_fi.connect((ip, port))
            sock_fi.send(b"root\r\n")
            resp_fi = sock_fi.recv(2048).decode("utf-8", errors="replace").strip()
            sock_fi.close()
            if resp_fi:
                results.append(ScriptResult(
                    "finger",
                    f"Finger responding: {resp_fi[:80]}",
                    vuln=True))
        except Exception:
            pass

    # ── LDAP ──────────────────────────────────────────────────────────────────
    is_ldap = service in ("ldap", "ldaps") or port in (389, 636, 3268, 3269)
    if is_ldap and wants("default"):
        try:
            sock_ld = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ld.settimeout(5.0)
            sock_ld.connect((ip, port))
            # LDAP v3 anonymous bind
            ldap_bind = (b"\x30\x0c\x02\x01\x01\x60\x07"
                         b"\x02\x01\x03\x04\x00\x80\x00")
            sock_ld.send(ldap_bind)
            resp_ld = sock_ld.recv(128)
            sock_ld.close()
            if resp_ld and len(resp_ld) > 7:
                rc = resp_ld[7] if len(resp_ld) > 7 else 255
                if rc == 0:
                    results.append(ScriptResult(
                        "ldap-rootdse",
                        "Anonymous LDAP bind accepted — directory accessible unauthenticated",
                        vuln=True))
                else:
                    results.append(ScriptResult(
                        "ldap-rootdse", "LDAP anonymous bind rejected"))
        except Exception:
            pass

    # ── RSYNC LIST MODULES ────────────────────────────────────────────────────
    is_rsync = service == "rsync" or port == 873
    if is_rsync and wants("default"):
        try:
            sock_rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_rs.settimeout(5.0)
            sock_rs.connect((ip, port))
            banner_rs = sock_rs.recv(256).decode("utf-8", errors="replace")
            sock_rs.send(b"\n")
            modules_raw = sock_rs.recv(4096).decode("utf-8", errors="replace")
            sock_rs.close()
            mods = [l.strip() for l in modules_raw.split("\n")
                    if l.strip() and not l.startswith("@") and "\t" in l][:10]
            if mods:
                results.append(ScriptResult(
                    "rsync-list-modules",
                    f"Modules: {', '.join(m.split()[0] for m in mods[:5])}",
                    vuln=True))
            else:
                results.append(ScriptResult(
                    "rsync-list-modules",
                    f"rsync: {banner_rs.strip()[:60]}"))
        except Exception:
            pass

    # ── DOCKER REMOTE API ─────────────────────────────────────────────────────
    if port in (2375, 2376) and wants("default"):
        st_d, _, body_d = _http_get(ip, port, "/version")
        if '"Version"' in body_d or "docker" in body_d.lower():
            m_ver = re.search(r'"Version":"([^"]+)"', body_d)
            m_api = re.search(r'"ApiVersion":"([^"]+)"', body_d)
            results.append(ScriptResult(
                "docker-version",
                (f"Docker {m_ver.group(1) if m_ver else '?'} "
                 f"API {m_api.group(1) if m_api else '?'} "
                 f"— unauthenticated daemon!"),
                vuln=(port == 2375)))

    # ── SIP METHODS ───────────────────────────────────────────────────────────
    is_sip = service == "sip" or port in (5060, 5061)
    if is_sip and wants("default"):
        try:
            sip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sip_sock.settimeout(3.0)
            opts = (f"OPTIONS sip:{ip} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {ip}:5060;branch=z9hG4bK-zscan\r\n"
                    f"From: <sip:zscan@{ip}>;tag=zs1\r\n"
                    f"To: <sip:{ip}>\r\n"
                    f"Call-ID: zscan@{ip}\r\nCSeq: 1 OPTIONS\r\n"
                    f"Content-Length: 0\r\n\r\n").encode()
            sip_sock.sendto(opts, (ip, port))
            try:
                resp_sip, _ = sip_sock.recvfrom(4096)
                r = resp_sip.decode("utf-8", errors="replace")
                status = r.split("\r\n")[0]
                allow = next((l.split(":", 1)[1].strip()
                              for l in r.split("\r\n")
                              if l.lower().startswith("allow:")), "")
                srv = next((l.split(":", 1)[1].strip()
                            for l in r.split("\r\n")
                            if l.lower().startswith("server:")), "")
                results.append(ScriptResult(
                    "sip-methods",
                    f"{status} | Methods: {allow[:60]} | Server: {srv[:40]}"))
            except socket.timeout:
                pass
            sip_sock.close()
        except Exception:
            pass

    # ── RTSP METHODS ──────────────────────────────────────────────────────────
    is_rtsp = service == "rtsp" or port in (554, 8554)
    if is_rtsp and wants("default"):
        try:
            sock_rt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_rt.settimeout(5.0)
            sock_rt.connect((ip, port))
            sock_rt.send(
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            resp_rt = sock_rt.recv(2048).decode("utf-8", errors="replace")
            sock_rt.close()
            if "RTSP" in resp_rt:
                pub = next((l.split(":", 1)[1].strip()
                            for l in resp_rt.split("\r\n")
                            if l.lower().startswith("public:")), "")
                srv = next((l.split(":", 1)[1].strip()
                            for l in resp_rt.split("\r\n")
                            if l.lower().startswith("server:")), "")
                results.append(ScriptResult(
                    "rtsp-methods",
                    f"Server: {srv} | Methods: {pub[:80]}"))
        except Exception:
            pass

    # ── EPMD (Erlang Port Mapper) ─────────────────────────────────────────────
    if port == 4369 and wants("default"):
        try:
            sock_ep = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ep.settimeout(3.0)
            sock_ep.connect((ip, port))
            sock_ep.send(b"\x00\x01n")  # NAMES_REQ
            resp_ep = sock_ep.recv(4096).decode("utf-8", errors="replace")
            sock_ep.close()
            nodes = re.findall(r"name (\S+) at port (\d+)", resp_ep)
            if nodes:
                nd = ", ".join(f"{n}:{p}" for n, p in nodes[:5])
                results.append(ScriptResult(
                    "epmd-info",
                    f"Erlang nodes: {nd}",
                    vuln=True))
        except Exception:
            pass

    # ── MQTT ──────────────────────────────────────────────────────────────────
    is_mqtt = service == "mqtt" or port in (1883, 8883)
    if is_mqtt and wants("default"):
        try:
            sock_mq = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_mq.settimeout(5.0)
            sock_mq.connect((ip, port))
            cid = b"zscan"
            conn_pkt = (b"\x10"
                        + bytes([10 + 2 + len(cid)])
                        + b"\x00\x04MQTT\x04\x00\x00\x3c"
                        + bytes([0, len(cid)]) + cid)
            sock_mq.send(conn_pkt)
            resp_mq = sock_mq.recv(10)
            sock_mq.close()
            if resp_mq and len(resp_mq) >= 4 and resp_mq[0] == 0x20:
                rc = resp_mq[3]
                if rc == 0:
                    results.append(ScriptResult(
                        "mqtt-subscribe",
                        "MQTT broker accepts anonymous connections",
                        vuln=True))
                else:
                    results.append(ScriptResult(
                        "mqtt-subscribe",
                        f"MQTT broker requires auth (rc={rc})"))
        except Exception:
            pass

    # ── CASSANDRA ─────────────────────────────────────────────────────────────
    if port in (9042, 9160) and wants("default"):
        try:
            sock_ca = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ca.settimeout(5.0)
            sock_ca.connect((ip, port))
            startup = (b"\x04\x00\x00\x01\x01"
                       b"\x00\x00\x00\x16\x00\x01"
                       b"\x00\x0bCQL_VERSION\x00\x053.0.0")
            sock_ca.send(startup)
            resp_ca = sock_ca.recv(64)
            sock_ca.close()
            if resp_ca and len(resp_ca) > 4:
                if resp_ca[4] == 2:  # READY
                    results.append(ScriptResult(
                        "cassandra-info",
                        "Cassandra CQL accessible without authentication",
                        vuln=True))
                elif resp_ca[4] == 0x0a:  # AUTHENTICATE
                    results.append(ScriptResult(
                        "cassandra-info", "Cassandra CQL requires authentication"))
        except Exception:
            pass

    # ── COUCHDB ───────────────────────────────────────────────────────────────
    if port == 5984 and wants("default"):
        st_c, _, body_c = _http_get(ip, port, "/")
        if "couchdb" in body_c.lower():
            m = re.search(r'"version"\s*:\s*"([^"]+)"', body_c)
            results.append(ScriptResult(
                "couchdb-databases",
                f"CouchDB {m.group(1) if m else '?'} — unauthenticated access",
                vuln=True))
            st_db, _, body_db = _http_get(ip, port, "/_all_dbs")
            if st_db == 200 and "[" in body_db:
                dbs = re.findall(r'"([^"]+)"', body_db)[:5]
                results.append(ScriptResult(
                    "couchdb-databases",
                    f"Databases: {', '.join(dbs)}"))

    # ── DISTCC (CVE-2004-2687) ────────────────────────────────────────────────
    if port == 3632 and wants("vuln"):
        try:
            sock_dc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_dc.settimeout(5.0)
            sock_dc.connect((ip, port))
            ban_dc = sock_dc.recv(256)
            sock_dc.close()
            if ban_dc:
                results.append(ScriptResult(
                    "distcc-cve2004-2687",
                    "distccd detected — may allow unauthenticated RCE",
                    vuln=True, cve="CVE-2004-2687"))
        except Exception:
            pass

    # ── JDWP (Java Debug Wire Protocol) ──────────────────────────────────────
    if port in (5005, 8000, 9009, 4000) and wants("vuln"):
        try:
            sock_jd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_jd.settimeout(5.0)
            sock_jd.connect((ip, port))
            hs = b"JDWP-Handshake"
            sock_jd.send(hs)
            resp_jd = sock_jd.recv(len(hs))
            sock_jd.close()
            if resp_jd == hs:
                results.append(ScriptResult(
                    "jdwp-version",
                    "JDWP open — Java debug port allows remote code execution!",
                    vuln=True))
        except Exception:
            pass

    # ── MODBUS (ICS/SCADA) ────────────────────────────────────────────────────
    if port == 502 and wants("default"):
        try:
            sock_mb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_mb.settimeout(5.0)
            sock_mb.connect((ip, port))
            # Read Device Identification (FC43 MEI14)
            sock_mb.send(b"\x00\x01\x00\x00\x00\x05\x00\x2b\x0e\x01\x00")
            resp_mb = sock_mb.recv(256)
            sock_mb.close()
            if resp_mb and len(resp_mb) > 8:
                results.append(ScriptResult(
                    "modbus-discover",
                    "Modbus/TCP ICS device — exposed SCADA protocol!",
                    vuln=True))
        except Exception:
            pass

    # ── SIEMENS S7 (ICS, port 102) ───────────────────────────────────────────
    if port == 102 and wants("default"):
        try:
            sock_s7 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_s7.settimeout(5.0)
            sock_s7.connect((ip, port))
            cotp = (b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00"
                    b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02")
            sock_s7.send(cotp)
            resp_s7 = sock_s7.recv(256)
            sock_s7.close()
            if resp_s7 and len(resp_s7) > 5 and resp_s7[5] == 0xd0:
                results.append(ScriptResult(
                    "s7-info",
                    "Siemens S7 PLC on ISO-TSAP — ICS device exposed!",
                    vuln=True))
        except Exception:
            pass

    # ── HADOOP WEB UIs ────────────────────────────────────────────────────────
    hadoop_ports = {50070: "namenode", 50075: "datanode",
                    8088: "resource-manager", 19888: "history-server"}
    if port in hadoop_ports and wants("default"):
        comp = hadoop_ports[port]
        st_h, _, body_h = _http_get(ip, port, "/")
        if st_h in (200, 301, 302) or "hadoop" in body_h.lower():
            results.append(ScriptResult(
                f"hadoop-{comp}-info",
                f"Hadoop {comp} web UI — unauthenticated access",
                vuln=True))

    # ── KUBERNETES API / KUBELET ──────────────────────────────────────────────
    if port in (6443, 8001, 10250) and wants("default"):
        if port == 10250:
            st_k, _, body_k = _http_get(ip, port, "/pods")
            if "pods" in body_k.lower() or "containers" in body_k.lower():
                results.append(ScriptResult(
                    "kubernetes-kubelet",
                    "Kubelet API accessible unauthenticated — pod enumeration possible",
                    vuln=True))
        else:
            st_k, _, body_k = _http_get(ip, port, "/api/v1/namespaces")
            if "items" in body_k or "namespaces" in body_k.lower():
                results.append(ScriptResult(
                    "kubernetes-api",
                    "Kubernetes API unauthenticated — full cluster access!",
                    vuln=True))

    # ── POSTGRESQL EMPTY PASSWORD ─────────────────────────────────────────────
    is_pg = service == "postgresql" or port == 5432
    if is_pg and wants("auth"):
        try:
            sock_pg = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_pg.settimeout(5.0)
            sock_pg.connect((ip, port))
            user = b"postgres"
            body_pg = (b"\x00\x00\x03\x00"
                       b"user\x00" + user + b"\x00"
                       b"database\x00" + user + b"\x00\x00")
            body_len = struct.pack("!I", 4 + len(body_pg))
            sock_pg.send(body_len + body_pg)
            resp_pg = sock_pg.recv(64)
            sock_pg.close()
            if resp_pg and resp_pg[0:1] == b"R":
                method = struct.unpack("!I", resp_pg[5:9])[0] if len(resp_pg) >= 9 else -1
                if method == 0:
                    results.append(ScriptResult(
                        "pgsql-empty-password",
                        "PostgreSQL accepts connection without password (user=postgres)!",
                        vuln=True))
                else:
                    results.append(ScriptResult(
                        "pgsql-empty-password",
                        f"PostgreSQL auth required (method={method})"))
        except Exception:
            pass

    # ── MSSQL INFO ────────────────────────────────────────────────────────────
    is_mssql = service == "ms-sql-s" or port == 1433
    if is_mssql and wants("default"):
        try:
            sock_sq = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_sq.settimeout(5.0)
            sock_sq.connect((ip, port))
            # TDS pre-login probe
            prelogin = (b"\x12\x01\x00\x2f\x00\x00\x01\x00"
                        b"\x00\x00\x1a\x00\x06\x01\x00\x20"
                        b"\x00\x01\x02\x00\x21\x00\x01\x03"
                        b"\x00\x22\x00\x04\x04\x00\x26\x00"
                        b"\x01\xff\x08\x00\x01\x55\x00\x00"
                        b"\x00\x4d\x53\x53\x51\x4c\x53\x65"
                        b"\x72\x76\x65\x72")
            sock_sq.send(prelogin)
            resp_sq = sock_sq.recv(256)
            sock_sq.close()
            if resp_sq and len(resp_sq) > 8:
                results.append(ScriptResult(
                    "ms-sql-info",
                    "MS-SQL TDS responding — check ms-sql-empty-password for sa account"))
        except Exception:
            pass

    # ── TELNET ────────────────────────────────────────────────────────────────
    is_telnet = service == "telnet" or port == 23
    if is_telnet and wants("default"):
        try:
            sock_tel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_tel.settimeout(5.0)
            sock_tel.connect((ip, port))
            resp_tel = sock_tel.recv(512)
            sock_tel.close()
            clean = re.sub(rb"\xff[\xfb-\xfe].", b"", resp_tel)
            ban_tel = clean.decode("utf-8", errors="replace").strip()[:80]
            results.append(ScriptResult(
                "telnet-ntlm-info",
                f"Telnet open (cleartext): {ban_tel}",
                vuln=True))
        except Exception:
            pass

    # ── KERBEROS ──────────────────────────────────────────────────────────────
    if port in (88, 749) and wants("discovery"):
        try:
            krb_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            krb_sock.settimeout(3.0)
            # Minimal KRB5 AS-REQ
            krb_req = (b"\x6a\x81\x87\x30\x81\x84\xa1\x03\x02\x01\x05"
                       b"\xa2\x03\x02\x01\x0a\xa3\x26\x30\x24"
                       b"\x30\x10\xa1\x03\x02\x01\x17"
                       b"\xa2\x09\x04\x07\x00\x00\x00\x00\x00\x00\x00"
                       b"\x30\x10\xa1\x03\x02\x01\x17"
                       b"\xa2\x09\x04\x07\x00\x00\x00\x00\x00\x00\x00")
            krb_sock.sendto(krb_req, (ip, 88))
            try:
                resp_krb, _ = krb_sock.recvfrom(4096)
                if resp_krb:
                    results.append(ScriptResult(
                        "krb5-enum-users",
                        "Kerberos KDC responding — user enumeration via AS-REQ possible"))
            except socket.timeout:
                pass
            krb_sock.close()
        except Exception:
            pass

    # ── IPMI ──────────────────────────────────────────────────────────────────
    if port == 623 and wants("default"):
        try:
            ipmi_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ipmi_sock.settimeout(3.0)
            # RMCP Presence Ping
            ipmi_sock.sendto(
                b"\x06\x00\xff\x06\x00\x00\x00\x00\x00\x00\x11\xbe\x00\x00\x00\x00",
                (ip, 623))
            try:
                resp_ipmi, _ = ipmi_sock.recvfrom(512)
                if resp_ipmi:
                    results.append(ScriptResult(
                        "ipmi-version",
                        "IPMI/RMCP responding — check for Cipher 0 auth bypass",
                        vuln=False))
            except socket.timeout:
                pass
            ipmi_sock.close()
        except Exception:
            pass
        # ipmi-cipher-zero CVE-2013-4786
        if wants("vuln"):
            try:
                cs0 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                cs0.settimeout(3.0)
                cs0.sendto(
                    b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x10"
                    b"\x10\x00\x00\x00" + b"\x00" * 4
                    + b"\x00\x00\x00\x08\xc0\x00\x00\x00"
                    + b"\x00\x00\x00\x08\x01\x00\x00\x00"
                    + b"\x00\x00\x00\x08\x01\x00\x00\x00",
                    (ip, 623))
                try:
                    resp_cs0, _ = cs0.recvfrom(512)
                    if resp_cs0 and len(resp_cs0) > 16:
                        results.append(ScriptResult(
                            "ipmi-cipher-zero",
                            "IPMI Cipher 0 auth bypass likely present!",
                            vuln=True, cve="CVE-2013-4786"))
                except socket.timeout:
                    pass
                cs0.close()
            except Exception:
                pass

    # ── HTTP EXTRA SCRIPTS ────────────────────────────────────────────────────
    if is_http:
        # http-trace
        if wants("vuln"):
            try:
                sock_tr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_tr.settimeout(3.0)
                sock_tr.connect((ip, port))
                sock_tr.send(
                    f"TRACE / HTTP/1.0\r\nHost: {ip}\r\n"
                    f"X-Zscan: trace-test\r\n\r\n".encode())
                resp_tr = b""
                try:
                    while len(resp_tr) < 4096:
                        c = sock_tr.recv(2048)
                        if not c: break
                        resp_tr += c
                except Exception:
                    pass
                sock_tr.close()
                r_str = resp_tr.decode("utf-8", errors="replace")
                if "x-zscan" in r_str.lower() and "trace-test" in r_str.lower():
                    results.append(ScriptResult(
                        "http-trace",
                        "HTTP TRACE enabled — Cross-Site Tracing (XST) vulnerability",
                        vuln=True))
            except Exception:
                pass

        # http-webdav-scan
        if wants("vuln"):
            try:
                sock_wv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_wv.settimeout(3.0)
                sock_wv.connect((ip, port))
                sock_wv.send(
                    f"PROPFIND / HTTP/1.0\r\nHost: {ip}\r\n"
                    f"Depth: 0\r\nContent-Length: 0\r\n\r\n".encode())
                resp_wv = b""
                try:
                    while len(resp_wv) < 8192:
                        c = sock_wv.recv(4096)
                        if not c: break
                        resp_wv += c
                except Exception:
                    pass
                sock_wv.close()
                r_wv = resp_wv.decode("utf-8", errors="replace")
                if "207" in r_wv[:30] or "multistatus" in r_wv.lower():
                    results.append(ScriptResult(
                        "http-webdav-scan",
                        "WebDAV enabled (PROPFIND returned 207 Multi-Status)",
                        vuln=True))
            except Exception:
                pass

        # http-aspnet-debug
        if wants("vuln"):
            try:
                sock_as = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_as.settimeout(3.0)
                sock_as.connect((ip, port))
                sock_as.send(
                    f"DEBUG / HTTP/1.1\r\nHost: {ip}\r\n"
                    f"Command: stop-debug\r\n\r\n".encode())
                resp_as = sock_as.recv(512).decode("utf-8", errors="replace")
                sock_as.close()
                if resp_as.startswith("HTTP") and (" 200 " in resp_as[:30]):
                    results.append(ScriptResult(
                        "http-aspnet-debug",
                        "ASP.NET DEBUG method enabled",
                        vuln=True))
            except Exception:
                pass

        # http-generator
        if wants("safe"):
            _, _, body_gen = _http_get(ip, port)
            m_gen = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                body_gen, re.IGNORECASE)
            if not m_gen:
                m_gen = re.search(
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
                    body_gen, re.IGNORECASE)
            if m_gen:
                results.append(ScriptResult(
                    "http-generator",
                    f"Generator: {m_gen.group(1)[:80]}"))

        # http-php-version
        if wants("safe"):
            st_php, hdrs_php, _ = _http_get(ip, port)
            xpb = hdrs_php.get("x-powered-by", "")
            if "php" in xpb.lower():
                old = any(v in xpb for v in ("5.", "7.0", "7.1", "7.2"))
                results.append(ScriptResult(
                    "http-php-version",
                    f"PHP detected: {xpb}",
                    vuln=old))

        # http-apache-server-status
        if wants("discovery"):
            st_ss, _, body_ss = _http_get(ip, port, "/server-status")
            if st_ss == 200 and ("Apache" in body_ss or "server-status" in body_ss.lower()):
                results.append(ScriptResult(
                    "http-apache-server-status",
                    "Apache mod_status page exposed — information disclosure",
                    vuln=True))

        # http-cookie-flags
        if wants("safe"):
            _, hdrs_ck, _ = _http_get(ip, port)
            ck = hdrs_ck.get("set-cookie", "")
            if ck:
                issues = []
                if "httponly" not in ck.lower():
                    issues.append("no HttpOnly")
                if port in (443, 8443) and "secure" not in ck.lower():
                    issues.append("no Secure flag")
                if "samesite" not in ck.lower():
                    issues.append("no SameSite")
                if issues:
                    results.append(ScriptResult(
                        "http-cookie-flags",
                        f"Cookie issues: {', '.join(issues)}",
                        vuln=True))

        # http-cross-domain-policy
        if wants("safe"):
            st_cdp, _, body_cdp = _http_get(ip, port, "/crossdomain.xml")
            if st_cdp == 200 and "cross-domain" in body_cdp.lower():
                vuln_cdp = 'domain="*"' in body_cdp
                results.append(ScriptResult(
                    "http-cross-domain-policy",
                    f"crossdomain.xml found{' — wildcard access!' if vuln_cdp else ''}",
                    vuln=vuln_cdp))

        # http-jboss-vuln (CVE-2010-0738)
        if wants("vuln"):
            st_jb, _, body_jb = _http_get(ip, port, "/jmx-console/")
            if st_jb == 200 and ("jmx" in body_jb.lower() or "jboss" in body_jb.lower()):
                results.append(ScriptResult(
                    "http-vuln-cve2010-0738",
                    "JBoss JMX Console unauthenticated access!",
                    vuln=True, cve="CVE-2010-0738"))

        # http-spring-boot-actuator
        if wants("vuln"):
            for act_path in ("/actuator", "/actuator/env", "/actuator/heapdump"):
                st_ac, _, body_ac = _http_get(ip, port, act_path)
                if st_ac == 200 and ("_links" in body_ac or "propertySources" in body_ac
                                     or act_path == "/actuator/heapdump"):
                    results.append(ScriptResult(
                        "http-spring-boot-actuator",
                        f"Spring Boot Actuator exposed at {act_path} — potential info disclosure",
                        vuln=True))
                    break

        # http-enum (common paths discovery)
        if wants("discovery"):
            enum_paths = [
                ("/admin", "Admin panel"),
                ("/phpmyadmin", "phpMyAdmin"),
                ("/wp-admin/", "WordPress admin"),
                ("/wp-login.php", "WordPress login"),
                ("/administrator/", "Joomla admin"),
                ("/manager/html", "Tomcat Manager"),
                ("/jmx-console", "JBoss JMX"),
                ("/web-console", "JBoss Web Console"),
                ("/jenkins/", "Jenkins"),
                ("/kibana/", "Kibana"),
                ("/grafana/", "Grafana"),
                ("/.env", "Env config file"),
                ("/phpinfo.php", "PHP info"),
                ("/server-status", "Apache status"),
                ("/swagger-ui.html", "Swagger UI"),
                ("/api/swagger.json", "Swagger JSON"),
                ("/console", "Admin console"),
                ("/.git/config", "Git config"),
                ("/backup.zip", "Backup archive"),
                ("/web.config", "IIS config"),
                ("/elmah.axd", "ELMAH error log"),
                ("/trace.axd", "ASP.NET trace"),
                ("/_all_dbs", "CouchDB/DB listing"),
            ]
            found = []
            for path, desc in enum_paths:
                try:
                    st_e, _, _ = _http_get(ip, port, path, timeout=1.5)
                    if st_e in (200, 301, 302, 403):
                        found.append(f"{path}[{st_e}]({desc})")
                except Exception:
                    pass
            if found:
                results.append(ScriptResult(
                    "http-enum",
                    " | ".join(found[:6]),
                    vuln=any("[200]" in p for p in found)))

        # http-default-accounts (basic check)
        if wants("auth"):
            for path, user, pwd in [("/manager/html", "tomcat", "tomcat"),
                                     ("/admin", "admin", "admin"),
                                     ("/admin", "admin", "")]:
                try:
                    import base64
                    cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    sock_da = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock_da.settimeout(3.0)
                    sock_da.connect((ip, port))
                    sock_da.send(
                        f"GET {path} HTTP/1.0\r\nHost: {ip}\r\n"
                        f"Authorization: Basic {cred}\r\n\r\n".encode())
                    resp_da = sock_da.recv(128).decode("utf-8", errors="replace")
                    sock_da.close()
                    if resp_da.startswith("HTTP") and " 200 " in resp_da[:30]:
                        results.append(ScriptResult(
                            "http-default-accounts",
                            f"Default creds work: {path} → {user}:{pwd}",
                            vuln=True))
                        break
                except Exception:
                    pass

        # http-vuln-cve2017-5638 (Apache Struts)
        if wants("vuln"):
            try:
                sock_st = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_st.settimeout(5.0)
                sock_st.connect((ip, port))
                # Safe OGNL expression — just tests if header gets evaluated
                ognl = ("%{#context['com.opensymphony.xwork2"
                        ".dispatcher.HttpServletResponse']"
                        ".addHeader('X-Struts-Zscan','DETECT')}")
                sock_st.send(
                    f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
                    f"Content-Type: {ognl}\r\n\r\n".encode())
                resp_st = b""
                try:
                    resp_st = sock_st.recv(2048)
                except Exception:
                    pass
                sock_st.close()
                if b"x-struts-zscan" in resp_st.lower():
                    results.append(ScriptResult(
                        "http-vuln-cve2017-5638",
                        "Apache Struts OGNL injection confirmed!",
                        vuln=True, cve="CVE-2017-5638"))
            except Exception:
                pass

        # http-vuln-cve2014-3704 (Drupageddon)
        if wants("vuln"):
            st_dr, _, body_dr = _http_get(ip, port, "/user/login")
            if st_dr == 200 and "drupal" in body_dr.lower():
                results.append(ScriptResult(
                    "http-drupal-enum",
                    "Drupal login detected — check CVE-2014-3704 (Drupageddon)",
                    vuln=False, cve="CVE-2014-3704"))

        # http-vuln-cve2012-1823 (PHP-CGI)
        if wants("vuln"):
            st_pc, _, body_pc = _http_get(ip, port, "/?-s")
            if st_pc == 200 and "<?php" in body_pc.lower():
                results.append(ScriptResult(
                    "http-vuln-cve2012-1823",
                    "PHP-CGI source code disclosure via ?-s (CVE-2012-1823)",
                    vuln=True, cve="CVE-2012-1823"))

        # http-wordpress-users
        if wants("discovery"):
            st_wp, _, body_wp = _http_get(ip, port, "/wp-login.php")
            if st_wp == 200 and "WordPress" in body_wp:
                _, hdrs_wp2, _ = _http_get(ip, port, "/?author=1")
                loc = hdrs_wp2.get("location", "")
                m_u = re.search(r"/author/([^/]+)/", loc)
                if m_u:
                    results.append(ScriptResult(
                        "http-wordpress-users",
                        f"WordPress username via author redirect: {m_u.group(1)}",
                        vuln=True))

        # http-iis-short-name
        if wants("vuln"):
            _, hdrs_iis, _ = _http_get(ip, port)
            if "IIS" in hdrs_iis.get("server", ""):
                try:
                    sock_iis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock_iis.settimeout(3.0)
                    sock_iis.connect((ip, port))
                    sock_iis.send(
                        f"GET /*~1*/.aspx HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    resp_iis = sock_iis.recv(256).decode("utf-8", errors="replace")
                    sock_iis.close()
                    if resp_iis and "404" not in resp_iis[:30]:
                        results.append(ScriptResult(
                            "http-iis-short-name-brute",
                            "IIS short-name (8.3) vulnerability may be present",
                            vuln=True))
                except Exception:
                    pass

    # ── SMB2 TIME ─────────────────────────────────────────────────────────────
    if is_smb and wants("default"):
        try:
            sock_s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_s2.settimeout(5.0)
            sock_s2.connect((ip, 445))
            # Minimal SMB2 NEGOTIATE to get server time
            hdr = (b"\xfe\x53\x4d\x42"          # SMB2 magic
                   b"\x40\x00"                    # StructureSize
                   b"\x00\x00\x00\x00\x00\x00"   # Credit/Status/Command/Credits
                   b"\x00\x00\x00\x00"            # Flags
                   b"\x00\x00\x00\x00"            # NextCommand
                   + b"\x01\x00\x00\x00\x00\x00\x00\x00"  # MessageID
                   + b"\x00" * 12                 # ProcID/TreeID/SessionID
                   + b"\x00" * 16)                # Signature
            body = (b"\x24\x00\x03\x00\x01\x00\x00\x00"
                    b"\x7f\x00\x00\x00" + b"\x00" * 16
                    + b"\x00\x00\x00\x00\x00\x00"
                    b"\x02\x02\x10\x02\x00\x03")
            nb = struct.pack(">I", len(hdr) + len(body))
            sock_s2.send(b"\x00" + nb[1:] + hdr + body)
            resp_s2 = sock_s2.recv(4096)
            sock_s2.close()
            off = resp_s2.find(b"\xfe\x53\x4d\x42")
            if off >= 0 and len(resp_s2) > off + 64 + 48:
                try:
                    ft = struct.unpack_from("<Q", resp_s2, off + 64 + 40)[0]
                    if ft > 116444736000000000:
                        unix_ts = (ft - 116444736000000000) / 10000000
                        dt_s2 = datetime.datetime.utcfromtimestamp(unix_ts)
                        results.append(ScriptResult(
                            "smb2-time",
                            f"SMB2 time: {dt_s2.strftime('%Y-%m-%d %H:%M:%S')} UTC"))
                except Exception:
                    pass
        except Exception:
            pass

    # ── GENERIC SERVICE INFO ─────────────────────────────────────────────────
    if not results and banner and wants("default"):
        results.append(ScriptResult(
            "service-info",
            banner_str.split("\n")[0].strip()[:100]))

    return results

# ─────────────────────────────────────────────────────────────────────────────
# SCAN RESULT STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

class PortResult:
    def __init__(self, port: int, proto: str, state: str,
                 service: str = "", version: str = "",
                 banner: bytes = b"",
                 scripts: List[ScriptResult] = None):
        self.port    = port
        self.proto   = proto
        self.state   = state
        self.service = service
        self.version = version
        self.banner  = banner
        self.scripts = scripts or []

    def to_dict(self):
        return {
            "port": self.port,
            "proto": self.proto,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner.decode("utf-8", errors="replace")[:200],
            "scripts": [{"name": s.name, "output": s.output,
                          "vuln": s.vuln, "cve": s.cve}
                         for s in self.scripts],
        }


class HostResult:
    def __init__(self, ip: str):
        self.ip     = ip
        self.state  = "up"
        self.ports  : List[PortResult] = []
        self.os     = {}
        self.hostname = ""
        self.scan_time = datetime.datetime.now().isoformat()

    def to_dict(self):
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "os": self.os,
            "scan_time": self.scan_time,
            "ports": [p.to_dict() for p in self.ports],
        }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ZScanner:
    def __init__(self, args):
        self.args    = args
        self.timing  = TIMING[args.T]
        self.timeout = args.timeout or self.timing["timeout"]
        self.workers = args.min_rate or self.timing["workers"]
        self.delay   = self.timing["delay"]
        self.results : List[HostResult] = []
        self.lock    = threading.Lock()
        self._done   = 0
        self._total  = 0

    def _progress(self, ip: str, port: int, state: str):
        self._done += 1
        if not self.args.quiet:
            col = G if state == PORT_OPEN else (Y if state == PORT_FILTERED else D)
            print(f"\r  {D}[{self._done}/{self._total}]{RST} "
                  f"{ip}:{port} {col}{state}{RST}          ", end="", flush=True)

    def scan_port(self, ip: str, port: int, scan_type: str,
                  src_ip: str) -> PortResult:
        """Scan a single port and return result."""
        state = PORT_FILTERED
        proto = "tcp"

        if scan_type == "sS":
            state = tcp_syn_scan(ip, port, self.timeout, src_ip)
        elif scan_type == "sT":
            state = tcp_connect_scan(ip, port, self.timeout)
        elif scan_type == "sU":
            proto = "udp"
            state = udp_scan(ip, port, self.timeout, src_ip)
        elif scan_type == "sF":
            state = tcp_flag_scan(ip, port, TH_FIN, self.timeout, src_ip)
        elif scan_type == "sN":
            state = tcp_flag_scan(ip, port, 0, self.timeout, src_ip)
        elif scan_type == "sX":
            state = tcp_flag_scan(ip, port, TH_FIN | TH_URG | TH_PSH,
                                  self.timeout, src_ip)

        if self.delay:
            time.sleep(self.delay)

        self._progress(ip, port, state)

        svc = SERVICE_DB.get(port, ("unknown", b""))[0]
        version = ""
        banner  = b""
        scripts = []

        # Version and script scanning on open ports
        if state in (PORT_OPEN,) and (self.args.sV or self.args.script):
            if proto == "tcp":
                banner = grab_banner(ip, port, timeout=self.timeout + 1)
                if banner and self.args.sV:
                    version = fingerprint_banner(banner, port)
            if self.args.script:
                cats = self.args.script if self.args.script != ["all"] \
                    else ["all"]
                scripts = run_scripts(ip, port, svc, banner, cats)

        return PortResult(port, proto, state, svc, version, banner, scripts)

    def scan_host(self, ip: str, ports: List[int],
                  scan_type: str) -> HostResult:
        """Scan all ports on a single host."""
        host = HostResult(ip)

        # Hostname resolution
        try:
            host.hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        # OS detection
        if self.args.O:
            host.os = os_detect(ip, self.timeout)

        src_ip = _get_local_ip(ip)
        self._total = len(ports)
        self._done  = 0

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.workers) as ex:
            futures = {ex.submit(self.scan_port, ip, p, scan_type, src_ip): p
                       for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    port_res = fut.result()
                    if port_res.state != PORT_CLOSED or self.args.show_closed:
                        with self.lock:
                            host.ports.append(port_res)
                except Exception as e:
                    pass

        host.ports.sort(key=lambda x: x.port)
        return host

    def run(self, targets: List[str], ports: List[int],
            scan_type: str) -> List[HostResult]:
        results = []
        for ip in targets:
            if not self.args.quiet:
                print(f"\n{C}Scanning {B}{ip}{RST} "
                      f"({len(ports)} ports, -{scan_type}, "
                      f"-T{self.args.T})...{RST}")
            h = self.scan_host(ip, ports, scan_type)
            results.append(h)
            self.results.append(h)
            if not self.args.quiet:
                print()  # newline after progress
        return results

# ─────────────────────────────────────────────────────────────────────────────
# TARGET PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_targets(target_str: str) -> List[str]:
    """Parse IPs, CIDRs, ranges, hostnames."""
    targets = []
    parts = [p.strip() for p in target_str.split(",") if p.strip()]

    for part in parts:
        # CIDR
        if "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                targets.extend(str(h) for h in net.hosts())
                continue
            except ValueError:
                pass
        # Range  192.168.1.1-10
        if re.match(r"[\d\.]+\-\d+$", part):
            base, end = part.rsplit("-", 1)
            base_parts = base.split(".")
            start = int(base_parts[-1])
            end_n = int(end)
            prefix = ".".join(base_parts[:-1])
            for i in range(start, end_n + 1):
                targets.append(f"{prefix}.{i}")
            continue
        # Hostname or single IP
        try:
            ip = socket.gethostbyname(part)
            targets.append(ip)
        except Exception:
            print(f"{Y}[!] Could not resolve: {part}{RST}")

    return targets


def parse_ports(port_str: str) -> List[int]:
    """Parse port ranges like 22,80,443 or 1-1024 or -."""
    ports = []
    if port_str == "-":
        return list(range(1, 65536))
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part and not part.startswith("-"):
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return sorted(set(ports))

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT FORMATTERS
# ─────────────────────────────────────────────────────────────────────────────

def print_terminal(results: List[HostResult], args):
    print(f"\n{B}{'═'*64}{RST}")
    for host in results:
        hostname = f" ({host.hostname})" if host.hostname else ""
        os_str   = f"  OS: {host.os.get('os','?')} " \
                   f"(TTL={host.os.get('ttl','?')})" if host.os else ""
        print(f"\n{B}{C}Host: {host.ip}{hostname}{RST}{os_str}")
        print(f"{D}{'─'*64}{RST}")
        print(f"{'PORT':<10}{'STATE':<14}{'SERVICE':<16}VERSION")
        print(f"{D}{'─'*64}{RST}")

        open_ports = [p for p in host.ports
                      if p.state in (PORT_OPEN, PORT_OPEN_FILT)]
        other_ports = [p for p in host.ports
                       if p.state not in (PORT_OPEN, PORT_OPEN_FILT)]

        for pr in open_ports:
            state_col = G if pr.state == PORT_OPEN else Y
            ver = pr.version[:35] if pr.version else ""
            print(f"{pr.port}/{pr.proto:<5} "
                  f"{state_col}{pr.state:<13}{RST}"
                  f"{pr.service:<16}{ver}")
            for sr in pr.scripts:
                vuln_tag = f" {R}[VULN]{RST}" if sr.vuln else ""
                cve_tag  = f" {Y}({sr.cve}){RST}" if sr.cve else ""
                print(f"  |_{B}{sr.name}{RST}{vuln_tag}{cve_tag}")
                print(f"    {D}{sr.output}{RST}")

        if args.show_closed and other_ports:
            for pr in other_ports[:20]:
                state_col = D
                print(f"{D}{pr.port}/{pr.proto:<5} "
                      f"{pr.state:<13}{pr.service}{RST}")

        vuln_count = sum(1 for p in host.ports
                         for s in p.scripts if s.vuln)
        print(f"\n{D}  {len(open_ports)} open port(s)"
              + (f", {R}{vuln_count} vulnerability/ies{RST}" if vuln_count else "")
              + f"{RST}")
    print(f"\n{B}{'═'*64}{RST}\n")


def save_json(results: List[HostResult], filename: str):
    data = {
        "tool": TOOL,
        "version": VERSION,
        "scan_date": datetime.datetime.now().isoformat(),
        "hosts": [h.to_dict() for h in results],
        "summary": {
            "total_hosts": len(results),
            "hosts_up": sum(1 for h in results if h.state == "up"),
            "total_open_ports": sum(
                1 for h in results for p in h.ports
                if p.state == PORT_OPEN),
            "total_vulns": sum(
                1 for h in results for p in h.ports
                for s in p.scripts if s.vuln),
        }
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{G}[+] JSON report saved: {filename}{RST}")


def save_xml(results: List[HostResult], filename: str):
    ts = datetime.datetime.now().isoformat()
    lines = [
        '<?xml version="1.0"?>',
        f'<zscanrun tool="{TOOL}" version="{VERSION}" start="{ts}">',
    ]
    for host in results:
        lines.append(f'  <host>')
        lines.append(f'    <address addr="{host.ip}" addrtype="ipv4"/>')
        if host.hostname:
            lines.append(f'    <hostname name="{host.hostname}"/>')
        if host.os:
            lines.append(f'    <os><osmatch name="{host.os.get("os","?")}"/></os>')
        lines.append(f'    <ports>')
        for p in host.ports:
            lines.append(
                f'      <port protocol="{p.proto}" portid="{p.port}">')
            lines.append(f'        <state state="{p.state}"/>')
            lines.append(
                f'        <service name="{p.service}" version="{p.version}"/>')
            for s in p.scripts:
                vuln = ' vuln="true"' if s.vuln else ''
                cve  = f' cve="{s.cve}"' if s.cve else ''
                lines.append(
                    f'        <script id="{s.name}"{vuln}{cve} '
                    f'output="{s.output[:200]}"/>')
            lines.append(f'      </port>')
        lines.append(f'    </ports>')
        lines.append(f'  </host>')
    lines.append('</zscanrun>')
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"{G}[+] XML report saved: {filename}{RST}")


def save_grepable(results: List[HostResult], filename: str):
    ts = datetime.datetime.now().isoformat()
    lines = [f"# ZScan {VERSION} scan initiated {ts}"]
    for host in results:
        ports_str = ", ".join(
            f"{p.port}/{p.proto}/{p.state}/{p.service}"
            for p in host.ports if p.state == PORT_OPEN)
        hostname = host.hostname or "unknown"
        lines.append(f"Host: {host.ip} ({hostname})\tPorts: {ports_str}")
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"{G}[+] Grepable report saved: {filename}{RST}")

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def banner_art():
    print(f"""
{C}███████╗███████╗ ██████╗ █████╗ ███╗   ██╗{RST}
{C}╚══███╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║{RST}
{C}  ███╔╝ ███████╗██║     ███████║██╔██╗ ██║{RST}
{C}  ███╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║{RST}
{C}███████╗███████║╚██████╗██║  ██║██║ ╚████║{RST}
{C}╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{RST}
{D}  Air-gap Network Scanner v{VERSION}  |  stdlib only{RST}
""")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zscan",
        description="ZScan — Air-gap safe network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN TYPES:
  -sS    TCP SYN scan          (root — fast, stealthy)
  -sT    TCP Connect scan      (no root — reliable)
  -sU    UDP scan              (root required)
  -sF    TCP FIN scan          (root required)
  -sN    TCP NULL scan         (root required)
  -sX    TCP XMAS scan         (root required)
  -sn    Ping sweep only       (host discovery)

EXAMPLES:
  zscan.py 192.168.1.0/24 -sn                          # host discovery
  zscan.py 192.168.1.1 -sT -p 22,80,443 -sV            # connect scan + version
  zscan.py 10.0.0.1 -sS -p 1-1024 -O --script vuln     # SYN + OS + vuln scripts
  zscan.py 10.0.0.0/24 -sT --top-ports 100 -T4         # fast subnet scan
  zscan.py 192.168.1.1 -sS -p - -oJ scan.json          # all ports, JSON output
  zscan.py 192.168.1.1 -sU -p 53,161,500               # UDP scan
  zscan.py 192.168.1.1 -sT -sV --script all -oX r.xml  # everything
        """,
    )
    p.add_argument("target", help="Target(s): IP, CIDR, range, hostname")

    # Scan types
    sg = p.add_argument_group("Scan Types")
    sg.add_argument("-sS", action="store_true", help="TCP SYN scan (root)")
    sg.add_argument("-sT", action="store_true", help="TCP Connect scan")
    sg.add_argument("-sU", action="store_true", help="UDP scan (root)")
    sg.add_argument("-sF", action="store_true", help="TCP FIN scan (root)")
    sg.add_argument("-sN", action="store_true", help="TCP NULL scan (root)")
    sg.add_argument("-sX", action="store_true", help="TCP XMAS scan (root)")
    sg.add_argument("-sn", action="store_true", help="Ping sweep / discovery only")

    # Port specification
    pg = p.add_argument_group("Port Specification")
    pg.add_argument("-p", dest="ports", default=None,
                    help="Ports: 22,80,443 or 1-1024 or - (all). Default: top 1000")
    pg.add_argument("--top-ports", type=int, dest="top_ports", default=None,
                    help="Scan top N most common ports (e.g. --top-ports 100)")

    # Detection
    dg = p.add_argument_group("Detection")
    dg.add_argument("-sV", action="store_true",
                    help="Version/banner detection")
    dg.add_argument("-O", action="store_true", help="OS detection")
    dg.add_argument("--script", nargs="?", const="default",
                    metavar="CATEGORY",
                    help=("Run embedded scripts. Categories: "
                          "default, safe, vuln, auth, discovery, all. "
                          "Comma-separate multiple: --script vuln,auth"))

    # Timing
    tg = p.add_argument_group("Timing")
    tg.add_argument("-T", type=int, default=3, choices=range(6),
                    help="Timing template 0-5 (T0=slowest, T5=fastest). Default: T3")
    tg.add_argument("--min-rate", type=int, dest="min_rate", default=None,
                    help="Override max parallel workers")
    tg.add_argument("--timeout", type=float, default=None,
                    help="Per-port timeout in seconds (overrides -T)")

    # Output
    og = p.add_argument_group("Output")
    og.add_argument("-oJ", dest="oJ", metavar="FILE", help="JSON output file")
    og.add_argument("-oX", dest="oX", metavar="FILE", help="XML output file")
    og.add_argument("-oG", dest="oG", metavar="FILE", help="Grepable output file")
    og.add_argument("--open", action="store_true",
                    help="Show only open ports")
    og.add_argument("--show-closed", action="store_true", dest="show_closed",
                    help="Show closed/filtered ports too")
    og.add_argument("-q", "--quiet", action="store_true",
                    help="Suppress progress output")
    og.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose output")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        banner_art()

    # Determine scan type
    scan_type = "sT"  # default — no root needed
    if args.sS: scan_type = "sS"
    elif args.sU: scan_type = "sU"
    elif args.sF: scan_type = "sF"
    elif args.sN: scan_type = "sN"
    elif args.sX: scan_type = "sX"

    if scan_type in ("sS", "sU", "sF", "sN", "sX") and not IS_ROOT and not IS_WINDOWS:
        print(f"{Y}[!] {scan_type} scan requires root — falling back to -sT{RST}")
        scan_type = "sT"

    # Parse script categories
    if args.script:
        script_cats = [c.strip().lower() for c in args.script.split(",")]
    else:
        script_cats = []
    args.script = script_cats if script_cats else None

    # Parse targets
    targets = parse_targets(args.target)
    if not targets:
        print(f"{R}[!] No valid targets found{RST}")
        sys.exit(1)

    if not args.quiet:
        print(f"{D}Targets    : {len(targets)} host(s){RST}")
        print(f"{D}Scan type  : -{scan_type} ({TIMING[args.T]['name']}){RST}")

    # Parse ports
    if args.sn:
        ports = []
    elif args.ports:
        ports = parse_ports(args.ports)
    elif args.top_ports:
        n = min(args.top_ports, len(TOP_1000))
        ports = TOP_1000[:n]
    else:
        ports = TOP_1000  # default: top 1000

    if not args.quiet and ports:
        print(f"{D}Ports      : {len(ports)} port(s){RST}")

    start = time.time()

    # Host discovery (ping sweep)
    if len(targets) > 1 and not args.sn:
        if not args.quiet:
            print(f"\n{C}[*] Host discovery...{RST}")
        timing = TIMING[args.T]
        live = discover_hosts(targets, timing["timeout"], timing["workers"])
        if not args.quiet:
            print(f"    {G}{len(live)}/{len(targets)} host(s) up{RST}")
        if not live:
            print(f"{Y}[!] No live hosts found{RST}")
            sys.exit(0)
        targets = live
    elif args.sn:
        if not args.quiet:
            print(f"\n{C}[*] Ping sweep...{RST}")
        timing = TIMING[args.T]
        live = discover_hosts(targets, timing["timeout"], timing["workers"])
        for ip in live:
            print(f"  {G}Host: {ip} (up){RST}")
        print(f"\n{G}{len(live)} host(s) up{RST}")
        sys.exit(0)

    # Port scanning
    scanner = ZScanner(args)
    results = scanner.run(targets, ports, scan_type)

    elapsed = time.time() - start

    # Terminal output
    if not args.quiet:
        print_terminal(results, args)
        open_count = sum(1 for h in results for p in h.ports
                         if p.state == PORT_OPEN)
        vuln_count = sum(1 for h in results for p in h.ports
                         for s in p.scripts if s.vuln)
        print(f"{D}Scan complete in {elapsed:.2f}s | "
              f"{len(results)} host(s) | "
              f"{open_count} open port(s)"
              + (f" | {R}{vuln_count} vuln(s){RST}" if vuln_count else "")
              + f"{RST}")

    # File outputs
    if args.oJ:
        save_json(results, args.oJ)
    if args.oX:
        save_xml(results, args.oX)
    if args.oG:
        save_grepable(results, args.oG)


if __name__ == "__main__":
    main()
