#Requires -Version 5.1
<#
.SYNOPSIS
    ZScan v2.1.0 — Air-gap Safe Network Scanner (PowerShell Edition)

.DESCRIPTION
    ZScan.ps1 — Windows network scanner with embedded NSE-equivalent scripts.
    No dependencies. No internet. No installs. Runs on any Windows 10/11/Server
    with PowerShell 5.1+ — which is every modern Windows system.

    WHAT'S NEW IN v2.1:
      HTTP: OPTIONS-based method detection (PUT/DELETE/TRACE/WebDAV etc.)
      HTTP: http-webdav-scan — detects PROPFIND/MKCOL/LOCK/UNLOCK exposure
      HTTP: http-open-proxy — CONNECT method detection
      HTTP: http-trace — TRACE XST vulnerability check
      HTTP: non-standard ports now get full HTTP script suite (33033, 45332 etc.)
      SSL:  cert check now uses raw SslStream — works on ANY port (44330 etc.)
      SSL:  protocol version check (TLSv1/SSLv3 flagged as weak)
      FTP:  directory listing now grouped into single result (cleaner output)
      Service: banner-based name upgrade (unknown ports now show http/ftp/ssh etc.)
      Banner: TLS fallback probe for non-standard SSL ports
      Banner: HTTP probe sent on all non-raw-service ports

.EXAMPLE
    .\zscan.ps1 -Target 192.168.1.0/24 -ScanType Ping
    .\zscan.ps1 -Target 192.168.1.1 -Ports "22,80,443" -ServiceDetection
    .\zscan.ps1 -Target 10.0.0.1 -Ports "30021" -Scripts All -ServiceDetection
    .\zscan.ps1 -Target 10.0.0.1 -TopPorts 100 -Scripts All -OutputJSON scan.json
    .\zscan.ps1 -Target 10.0.0.0/24 -Ports "1-1024" -T 4 -OutputHTML report.html
    .\zscan.ps1 -Target 192.168.1.1 -ScanType UDP -Ports "53,161,500"

.NOTES
    Version  : 2.0.0
    License  : MIT
    For authorised security testing only.
    AIR-GAP SAFE: Uses only System.Net.Sockets + System.Net — built into .NET Framework
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Target,

    [ValidateSet("TCP","UDP","Ping")]
    [string]$ScanType = "TCP",

    [string]$Ports = "",

    [int]$TopPorts = 0,

    [ValidateRange(0,5)]
    [int]$T = 3,

    [switch]$ServiceDetection,
    [switch]$OSDetect,

    # Scripts: default | safe | vuln | auth | discovery | all  (comma-sep)
    [string]$Scripts = "",

    [string]$OutputJSON = "",
    [string]$OutputHTML = "",
    [string]$OutputCSV  = "",

    [switch]$ShowClosed,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$VERSION = "2.1.0"

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-C { param([string]$Text,[string]$Fg="White",[switch]$NoNL)
    if ($NoColor) { $Fg="White" }
    if ($NoNL)    { Write-Host $Text -ForegroundColor $Fg -NoNewline }
    else          { Write-Host $Text -ForegroundColor $Fg }
}
function Write-Info  { param([string]$t) if (!$Quiet) { Write-C $t Cyan  } }
function Write-Ok    { param([string]$t) Write-C $t Green  }
function Write-Warn  { param([string]$t) Write-C $t Yellow }
function Write-Err   { param([string]$t) Write-C $t Red    }
function Write-Dim   { param([string]$t) if (!$Quiet) { Write-C $t DarkGray } }

# ─────────────────────────────────────────────────────────────────────────────
# TIMING TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
$Timing = @{
    0 = @{Workers=10;   Timeout=5000; Name="paranoid"}
    1 = @{Workers=50;   Timeout=3000; Name="sneaky"}
    2 = @{Workers=100;  Timeout=2000; Name="polite"}
    3 = @{Workers=300;  Timeout=1000; Name="normal"}
    4 = @{Workers=500;  Timeout=500;  Name="aggressive"}
    5 = @{Workers=1000; Timeout=200;  Name="insane"}
}
$Prof    = $Timing[$T]
$TIMEOUT = $Prof.Timeout
$WORKERS = $Prof.Workers

# ─────────────────────────────────────────────────────────────────────────────
# PORT / SERVICE DATABASE
# ─────────────────────────────────────────────────────────────────────────────
$ServiceDB = @{
    20="ftp-data";  21="ftp";           22="ssh";       23="telnet"
    25="smtp";      53="dns";           69="tftp";      79="finger"
    80="http";      88="kerberos";      102="iso-tsap"; 110="pop3"
    111="rpcbind";  119="nntp";         123="ntp";      135="msrpc"
    137="netbios-ns";139="netbios-ssn"; 143="imap";     161="snmp"
    179="bgp";      389="ldap";         443="https";    445="smb"
    465="smtps";    500="isakmp";       502="modbus";   514="syslog"
    515="printer";  587="submission";   631="ipp";      636="ldaps"
    873="rsync";    990="ftps";         993="imaps";    995="pop3s"
    1080="socks";   1433="ms-sql-s";    1521="oracle";  1723="pptp"
    2049="nfs";     2121="ftp-proxy";   2375="docker";  2376="docker-tls"
    3000="http";    3306="mysql";       3389="ms-wbt-server"
    3632="distccd"; 5000="http";        5432="postgresql"
    5900="vnc";     5985="wsman";       6379="redis";   6443="kubernetes"
    7070="realserver"; 8080="http-proxy"; 8443="https-alt"
    8888="http";    9090="http";        9200="elasticsearch"
    10250="kubelet"; 11211="memcache";  27017="mongod"; 27018="mongod"
    50000="ibm-db2"
}

$Top100  = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,
             3306,3389,5900,8080,8443,8888,9090,9200,27017,20,69,79,88,102,
             106,113,119,137,138,179,194,389,427,497,500,514,515,543,544,
             548,554,587,631,646,873,990,1025,1026,1027,1028,1433,1720,1755,
             1900,2000,2001,2049,2121,2717,3000,3128,3632,4899,5000,5009,
             5051,5060,5101,5190,5357,5432,5631,5666,5800,5985,6000,6001,
             6646,7070,8008,8009,8010,8031,8181,8192,49152,49153,49154,49155,49156)
$Top1000 = ($Top100 + (1..1024)) | Sort-Object -Unique | Select-Object -First 1000

# ─────────────────────────────────────────────────────────────────────────────
# TARGET EXPANSION
# ─────────────────────────────────────────────────────────────────────────────
function Expand-Targets([string]$Str) {
    $IPs = [System.Collections.Generic.List[string]]::new()
    foreach ($part in ($Str -split ",")) {
        $part = $part.Trim()
        if ($part -match "^(\d+\.\d+\.\d+\.\d+)/(\d+)$") {
            $baseIP = $Matches[1]; $prefix = [int]$Matches[2]
            $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
            [Array]::Reverse($ipBytes)
            $ipInt   = [BitConverter]::ToUInt32($ipBytes, 0)
            $mask    = if ($prefix -eq 0) { 0 } else { ([uint32]0xFFFFFFFF -shl (32-$prefix)) -band 0xFFFFFFFF }
            $netInt  = $ipInt -band $mask
            $hostMax = (-bnot $mask) -band 0xFFFFFFFF
            for ($i = 1; $i -lt $hostMax; $i++) {
                $b = [BitConverter]::GetBytes([uint32]($netInt + $i))
                [Array]::Reverse($b)
                $IPs.Add("$($b[0]).$($b[1]).$($b[2]).$($b[3])")
            }
            continue
        }
        if ($part -match "^([\d\.]+)-(\d+)$") {
            $base = $Matches[1]; $end = [int]$Matches[2]
            $parts = $base -split "\."
            $start = [int]$parts[-1]; $pfx = ($parts[0..($parts.Count-2)]) -join "."
            for ($i = $start; $i -le $end; $i++) { $IPs.Add("$pfx.$i") }
            continue
        }
        try {
            $r = [System.Net.Dns]::GetHostAddresses($part) |
                 Where-Object { $_.AddressFamily -eq "InterNetwork" } |
                 Select-Object -First 1
            if ($r) { $IPs.Add($r.ToString()) }
        } catch { Write-Warn "[!] Could not resolve: $part" }
    }
    return $IPs
}

# ─────────────────────────────────────────────────────────────────────────────
# PORT EXPANSION
# ─────────────────────────────────────────────────────────────────────────────
function Expand-Ports([string]$Str) {
    if ($Str -eq "-") { return 1..65535 }
    $ports = [System.Collections.Generic.List[int]]::new()
    foreach ($part in ($Str -split ",")) {
        $part = $part.Trim()
        if ($part -match "^(\d+)-(\d+)$") {
            $s=[int]$Matches[1]; $e=[int]$Matches[2]
            for ($i=$s; $i -le $e; $i++) { $ports.Add($i) }
        } elseif ($part -match "^\d+$") {
            $ports.Add([int]$part)
        }
    }
    return ($ports | Sort-Object -Unique)
}

# ─────────────────────────────────────────────────────────────────────────────
# HOST DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
function Test-HostUp([string]$IP, [int]$TMs=1000) {
    try {
        $ping  = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($IP, $TMs)
        if ($reply.Status -eq "Success") { return $true }
    } catch {}
    foreach ($port in @(80,443,22,445,3389)) {
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $ar  = $tcp.BeginConnect($IP, $port, $null, $null)
            $ok  = $ar.AsyncWaitHandle.WaitOne($TMs, $false)
            if ($ok -and $tcp.Connected) { $tcp.Close(); return $true }
            $tcp.Close()
        } catch {}
    }
    return $false
}

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────
function Test-TCPPort([string]$IP, [int]$Port, [int]$TMs=1000) {
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TMs, $false)
        if ($ok -and $tcp.Connected) { $tcp.Close(); return "open" }
        $tcp.Close(); return "filtered"
    } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq "ConnectionRefused") { return "closed" }
        return "filtered"
    } catch { return "filtered" }
}

function Test-UDPPort([string]$IP, [int]$Port, [int]$TMs=2000) {
    $probes = @{
        53  = [byte[]](0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01)
        161 = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,
                        0xa0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0e,0x30,0x0c,
                        0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00)
        123 = [byte[]](0x1b) + ([byte[]](0x00)*47)
        500 = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
    }
    try {
        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Client.ReceiveTimeout = $TMs
        $probe = if ($probes.ContainsKey($Port)) { $probes[$Port] } else { [byte[]](0x00)*8 }
        $udp.Send($probe, $probe.Length, $IP, $Port) | Out-Null
        try {
            $ep   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $data = $udp.Receive([ref]$ep)
            $udp.Close()
            if ($data -and $data.Length -gt 0) { return "open" }
        } catch [System.Net.Sockets.SocketException] {
            $udp.Close()
            if ($_.Exception.SocketErrorCode -eq "ConnectionReset") { return "closed" }
            return "open|filtered"
        }
        return "open|filtered"
    } catch { return "filtered" }
}

# ─────────────────────────────────────────────────────────────────────────────
# BANNER GRABBING  (v2.1: HTTP probe on unknown ports + TLS fallback)
# ─────────────────────────────────────────────────────────────────────────────
function Get-Banner([string]$IP, [int]$Port, [int]$TMs=3000) {
    $SslPorts  = @(443,8443,993,995,465,636,44330)
    $HttpPorts = @(80,8080,8443,443,8888,9090,9200,5000,3000,7070,8000,
                   2375,6443,10250,33033,45332,45443)
    # Non-HTTP raw-read ports — don't send HTTP probe to these
    $RawPorts  = @(22,21,25,110,143,3306,5432,6379,27017,3389,5900)

    function Read-Stream($stream, $TMs2) {
        $buf = [byte[]]::new(8192)
        $sb  = [System.Text.StringBuilder]::new()
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $TMs2 -and $sb.Length -lt 4096) {
            if ($stream.DataAvailable) {
                $n = $stream.Read($buf,0,$buf.Length)
                if ($n -eq 0) { break }
                $sb.Append([System.Text.Encoding]::UTF8.GetString($buf,0,$n)) | Out-Null
            } else {
                Start-Sleep -Milliseconds 50
                if ($sw.ElapsedMilliseconds -gt 1000 -and $sb.Length -gt 0) { break }
            }
        }
        return $sb.ToString()
    }

    # ── Plain TCP attempt ─────────────────────────────────────────────────────
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP,$Port,$null,$null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TMs,$false)) { $tcp.Close(); return "" }
        $stream = $tcp.GetStream()
        $stream.ReadTimeout  = $TMs
        $stream.WriteTimeout = $TMs

        # Wrap SSL for known TLS ports
        if ($Port -in $SslPorts) {
            try {
                $sslStream = [System.Net.Security.SslStream]::new($stream,$false,{$true})
                $sslStream.AuthenticateAsClient($IP)
                $stream = $sslStream
            } catch {}
        }

        # Send HTTP GET for HTTP ports or any port not in RawPorts
        if ($Port -in $HttpPorts -or $Port -notin $RawPorts) {
            $req   = "GET / HTTP/1.0`r`nHost: $IP`r`nUser-Agent: Mozilla/5.0`r`nConnection: close`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
            try { $stream.Write($bytes,0,$bytes.Length) } catch {}
        }

        $result = Read-Stream $stream $TMs
        $tcp.Close()
        if ($result) { return $result }
    } catch {}

    # ── TLS fallback for non-standard ports ───────────────────────────────────
    if ($Port -notin $SslPorts) {
        try {
            $tcp2 = [System.Net.Sockets.TcpClient]::new()
            $ar2  = $tcp2.BeginConnect($IP,$Port,$null,$null)
            if ($ar2.AsyncWaitHandle.WaitOne($TMs,$false) -and $tcp2.Connected) {
                $stream2 = $tcp2.GetStream()
                $stream2.ReadTimeout = $TMs
                try {
                    $sslStream2 = [System.Net.Security.SslStream]::new($stream2,$false,{$true})
                    $sslStream2.AuthenticateAsClient($IP)
                    $req2   = "GET / HTTP/1.0`r`nHost: $IP`r`nConnection: close`r`n`r`n"
                    $bytes2 = [System.Text.Encoding]::ASCII.GetBytes($req2)
                    $sslStream2.Write($bytes2,0,$bytes2.Length)
                    $result2 = Read-Stream $sslStream2 $TMs
                    $tcp2.Close()
                    if ($result2) { return $result2 }
                } catch {}
            }
            $tcp2.Close()
        } catch {}
    }

    return ""
}

# ─────────────────────────────────────────────────────────────────────────────
# VERSION FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────
function Get-Version([string]$Banner, [int]$Port) {
    $patterns = @(
        @{Re="SSH-[\d\.]+-OpenSSH[_\-](\S+)";        Tmpl="OpenSSH {1}"}
        @{Re="SSH-[\d\.]+-(\S+)";                     Tmpl="SSH {1}"}
        @{Re="Server:\s*(Apache[^\r\n]+)";            Tmpl="{1}"}
        @{Re="Server:\s*(nginx[^\r\n]+)";             Tmpl="{1}"}
        @{Re="Server:\s*(Microsoft-IIS[^\r\n]+)";     Tmpl="{1}"}
        @{Re="Server:\s*([^\r\n]+)";                  Tmpl="{1}"}
        @{Re="220[\s\-]+(FileZilla[^\r\n]+)";         Tmpl="FTP: {1}"}
        @{Re="220[\s\-]+(vsftpd[^\r\n]+)";            Tmpl="FTP: {1}"}
        @{Re="220[\s\-]+(ProFTPD[^\r\n]+)";           Tmpl="FTP: {1}"}
        @{Re="220[\s\-]+(Pure-FTPd[^\r\n]+)";         Tmpl="FTP: {1}"}
        @{Re="220[\s\-]+([^\r\n]+)";                  Tmpl="FTP/SMTP: {1}"}
        @{Re="redis_version:(\S+)";                   Tmpl="Redis {1}"}
        @{Re='"version"\s*:\s*"([^"]+)"';             Tmpl="Elasticsearch {1}"}
        @{Re="STAT version (\S+)";                    Tmpl="Memcached {1}"}
        @{Re="Docker/(\S+)";                          Tmpl="Docker {1}"}
        @{Re='[Vv]ersion[:\s]+([\d\.]+)';             Tmpl="v{1}"}
    )
    foreach ($p in $patterns) {
        if ($Banner -match $p.Re) {
            $r = $p.Tmpl
            for ($i=1; $i -le ($Matches.Count-1); $i++) {
                $r = $r.Replace("{$i}", $Matches[$i].Trim())
            }
            return $r.Substring(0,[Math]::Min(80,$r.Length))
        }
    }
    $svc  = if ($ServiceDB.ContainsKey($Port)) { $ServiceDB[$Port] } else { "unknown" }
    # For any HTTP response without a matched Server: pattern, return status
    if ($Banner -match "^HTTP/[\d\.]+ (\d+)") { return "HTTP $($Matches[1])" }
    $line = ($Banner -split "`n")[0].Trim()
    if ($line.Length -gt 3) { return "$svc`: $($line.Substring(0,[Math]::Min(60,$line.Length)))" }
    return $svc
}

# ─────────────────────────────────────────────────────────────────────────────
# OS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
function Get-OSGuess([string]$IP) {
    try {
        $ping  = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($IP, 2000)
        if ($reply.Status -eq "Success") {
            $ttl = $reply.Options.Ttl
            $os  = switch ($true) {
                ($ttl -le 32)  { "Solaris/AIX (older)" }
                ($ttl -le 64)  { "Linux / macOS / Android / iOS" }
                ($ttl -le 128) { "Windows (10/11/Server)" }
                ($ttl -le 255) { "Cisco IOS / Network device" }
                default        { "Unknown" }
            }
            return @{ OS=$os; TTL=$ttl; Method="icmp-ttl" }
        }
    } catch {}
    return @{ OS="Unknown"; TTL=0; Method="none" }
}

# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPER
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-ZHttp([string]$IP, [int]$Port, [string]$Path="/", [int]$TMs=5000) {
    $ssl = $Port -in @(443,8443)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP,$Port,$null,$null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TMs,$false)) { $tcp.Close(); return @{S=0;H=@{};B=""} }
        $stream = $tcp.GetStream()
        $stream.ReadTimeout  = $TMs
        $stream.WriteTimeout = $TMs
        if ($ssl) {
            try {
                $ss = [System.Net.Security.SslStream]::new($stream,$false,{$true})
                $ss.AuthenticateAsClient($IP); $stream = $ss
            } catch {}
        }
        $req   = "GET $Path HTTP/1.0`r`nHost: $IP`r`nUser-Agent: Mozilla/5.0`r`nConnection: close`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes,0,$bytes.Length)
        $buf = [byte[]]::new(32768); $sb = [System.Text.StringBuilder]::new()
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $TMs -and $sb.Length -lt 32768) {
            if ($stream.DataAvailable) {
                $n = $stream.Read($buf,0,$buf.Length)
                if ($n -eq 0) { break }
                $sb.Append([System.Text.Encoding]::UTF8.GetString($buf,0,$n)) | Out-Null
            } else { Start-Sleep -Ms 50; if ($sw.ElapsedMilliseconds -gt 2000 -and $sb.Length -gt 0) { break } }
        }
        $tcp.Close()
        $raw = $sb.ToString(); $lines = $raw -split "`r`n"
        $status = 0; $headers = @{}; $bodyIdx = 0
        if ($lines[0] -match "HTTP/[\d\.]+ (\d+)") { $status = [int]$Matches[1] }
        for ($i=1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -eq "") { $bodyIdx = $i+1; break }
            if ($lines[$i] -match "^([^:]+):\s*(.+)$") { $headers[$Matches[1].ToLower()] = $Matches[2].Trim() }
        }
        $body = $lines[$bodyIdx..($lines.Count-1)] -join "`r`n"
        return @{ S=$status; H=$headers; B=$body }
    } catch { return @{S=0;H=@{};B=""} }
}

# ─────────────────────────────────────────────────────────────────────────────
# FTP HELPERS  (v2 — full session)
# ─────────────────────────────────────────────────────────────────────────────
function Connect-FTP([string]$IP, [int]$Port, [int]$TMs=5000) {
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP,$Port,$null,$null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TMs,$false)) { $tcp.Close(); return $null, "" }
        $stream = $tcp.GetStream(); $stream.ReadTimeout = $TMs
        $buf = [byte[]]::new(4096); $n = $stream.Read($buf,0,$buf.Length)
        $banner = [System.Text.Encoding]::ASCII.GetString($buf,0,$n)
        return $tcp, $banner
    } catch { return $null, "" }
}

function Send-FTPCmd($Tcp, [string]$Cmd, [int]$TMs=5000) {
    try {
        $stream = $Tcp.GetStream(); $stream.ReadTimeout = $TMs
        $bytes  = [System.Text.Encoding]::ASCII.GetBytes("$Cmd`r`n")
        $stream.Write($bytes,0,$bytes.Length)
        $buf  = [byte[]]::new(4096); $data = ""
        $sw   = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $TMs) {
            if ($stream.DataAvailable) {
                $n    = $stream.Read($buf,0,$buf.Length)
                $data += [System.Text.Encoding]::ASCII.GetString($buf,0,$n)
                $last  = ($data -split "`n")[-1]
                if ($last -match "^\d{3} ") { break }
            } else { Start-Sleep -Ms 50 }
        }
        return $data.Trim()
    } catch { return "" }
}

function Get-PASVSocket([string]$IP, [string]$PASVResp, [int]$TMs=5000) {
    if ($PASVResp -match "\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)") {
        $dataIP   = "$($Matches[1]).$($Matches[2]).$($Matches[3]).$($Matches[4])"
        $dataPort = ([int]$Matches[5] -shl 8) + [int]$Matches[6]
        # NAT fallback
        if ($dataIP -match "^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)") { $dataIP = $IP }
        try {
            $dsock = [System.Net.Sockets.TcpClient]::new()
            $ar    = $dsock.BeginConnect($dataIP,$dataPort,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne($TMs,$false) -and $dsock.Connected) { return $dsock }
            $dsock.Close()
        } catch {}
    }
    return $null
}

function Get-FTPDirListing([string]$IP, [int]$Port, [int]$TMs=5000) {
    $tcp, $banner = Connect-FTP $IP $Port $TMs
    if ($null -eq $tcp) { return @() }
    try {
        $r1 = Send-FTPCmd $tcp "USER anonymous" $TMs
        if ($r1 -match "^331") { Send-FTPCmd $tcp "PASS anonymous@example.com" $TMs | Out-Null }
        $r2 = Send-FTPCmd $tcp "PASS anonymous@example.com" 1000
        # Check auth state
        $pasv = Send-FTPCmd $tcp "PASV" $TMs
        $dsock = Get-PASVSocket $IP $pasv $TMs
        if ($null -eq $dsock) { return @() }
        Send-FTPCmd $tcp "LIST" $TMs | Out-Null
        $ds   = $dsock.GetStream(); $ds.ReadTimeout = $TMs
        $buf  = [byte[]]::new(65536); $sb = [System.Text.StringBuilder]::new()
        $sw   = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $TMs) {
            if ($ds.DataAvailable) {
                $n = $ds.Read($buf,0,$buf.Length)
                if ($n -eq 0) { break }
                $sb.Append([System.Text.Encoding]::ASCII.GetString($buf,0,$n)) | Out-Null
            } else { Start-Sleep -Ms 50; if ($sw.ElapsedMilliseconds -gt 2000 -and $sb.Length -gt 0) { break } }
        }
        $dsock.Close()
        return ($sb.ToString() -split "`n" | Where-Object { $_.Trim() })
    } catch { return @() }
    finally { try { $tcp.Close() } catch {} }
}

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPT RUNNER
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-Scripts([string]$IP, [int]$Port, [string]$Service, [string]$Banner, [string[]]$Categories) {
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $runAll  = $Categories -contains "all" -or $Categories.Count -eq 0
    function Wants([string]$c) { return $runAll -or $Categories -contains $c }
    function Add-R([string]$Name,[string]$Out,[bool]$Vuln=$false,[string]$CVE="") {
        $results.Add([PSCustomObject]@{Name=$Name;Output=$Out;Vuln=$Vuln;CVE=$CVE})
    }

    # Service detection — banner-based so non-standard ports are identified correctly
    $bannerIsHTTP  = $Banner -match "^HTTP/|Server:\s*\S|<html" 
    $bannerIsFTP   = ($Banner -match "^220[\s\-]") -and ($Banner -notmatch "SMTP|ESMTP")
    $bannerIsSSH   = $Banner -match "^SSH-"
    $bannerIsSMTP  = $Banner -match "^220[\s\-].*(SMTP|ESMTP|mail)"

    $isFTP     = $Service -in @("ftp","ftp-proxy","ftps","ftp-data") -or
                 $Port -in @(20,21,990,2121) -or $bannerIsFTP
    $isHTTP    = $Service -in @("http","https","http-proxy","https-alt") -or
                 $Port -in @(80,8080,8443,443,8888,8000,9090,9200,5000,3000,7070,33033,45332,45443) -or
                 $bannerIsHTTP
    $isSSH     = $Service -eq "ssh" -or $Port -eq 22 -or $bannerIsSSH
    $isSMB     = $Service -in @("smb","netbios-ssn") -or $Port -in @(139,445)
    $isSMTP    = $Service -in @("smtp","submission","smtps") -or $Port -in @(25,465,587) -or $bannerIsSMTP
    $isDNS     = $Service -eq "dns" -or $Port -eq 53
    $isSNMP    = $Service -eq "snmp" -or $Port -eq 161
    $isRDP     = $Service -eq "ms-wbt-server" -or $Port -eq 3389
    $isSSL     = $Service -in @("https","imaps","pop3s","smtps","ssl") -or
                 $Port -in @(443,8443,993,995,465,44330) -or
                 "ssl" -in $Service.ToLower()
    $isRedis   = $Service -eq "redis" -or $Port -eq 6379
    $isMySQL   = $Service -eq "mysql" -or $Port -eq 3306
    $isElastic = $Port -eq 9200 -or $Service -eq "elasticsearch"
    $isLDAP    = $Service -in @("ldap","ldaps") -or $Port -in @(389,636,3268)
    $isVNC     = $Service -eq "vnc" -or $Port -eq 5900
    $isNTP     = $Service -eq "ntp" -or $Port -eq 123
    $isRsync   = $Service -eq "rsync" -or $Port -eq 873
    $isDocker  = $Port -in @(2375,2376)
    $isK8s     = $Port -in @(6443,10250)
    $isIMAP    = $Service -in @("imap","imaps") -or $Port -in @(143,993)
    $isPOP3    = $Service -in @("pop3","pop3s") -or $Port -in @(110,995)
    $isModbus  = $Port -eq 502
    $isTelnet  = $Service -eq "telnet" -or $Port -eq 23

    # ── Banner ────────────────────────────────────────────────────────────────
    if ((Wants "default") -and $Banner) {
        $fl = ($Banner -split "`n")[0].Trim()
        if ($fl.Length -gt 2) {
            Add-R "banner" $fl.Substring(0,[Math]::Min(120,$fl.Length))
        }
    }

    # ── FTP Scripts (v2.1) ────────────────────────────────────────────────────
    if ($isFTP -and (Wants "default")) {
        $ftpTcp, $ftpBanner = Connect-FTP $IP $Port 5000
        if ($ftpTcp) {
            $r1 = Send-FTPCmd $ftpTcp "USER anonymous" 5000
            if ($r1 -match "^331") { $r2 = Send-FTPCmd $ftpTcp "PASS anonymous@example.com" 5000 }
            else                   { $r2 = $r1 }

            if ($r2 -match "^230") {
                # Collect directory listing first
                $pasvResp = Send-FTPCmd $ftpTcp "PASV" 5000
                $dataTcp  = Get-PASVSocket $IP $pasvResp 5000
                $listLines = @()
                if ($dataTcp) {
                    Send-FTPCmd $ftpTcp "LIST" 5000 | Out-Null
                    $ds  = $dataTcp.GetStream(); $ds.ReadTimeout = 5000
                    $buf = [byte[]]::new(65536); $sb2 = [System.Text.StringBuilder]::new()
                    $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
                    while ($sw2.ElapsedMilliseconds -lt 5000) {
                        if ($ds.DataAvailable) {
                            $n = $ds.Read($buf,0,$buf.Length)
                            if ($n -eq 0) { break }
                            $sb2.Append([System.Text.Encoding]::ASCII.GetString($buf,0,$n)) | Out-Null
                        } else { Start-Sleep -Ms 50; if ($sw2.ElapsedMilliseconds -gt 2000 -and $sb2.Length -gt 0) { break } }
                    }
                    $dataTcp.Close()
                    $listLines = $sb2.ToString() -split "`n" | Where-Object {$_.Trim()}
                }
                # Single result with full listing embedded
                $listStr = "Anonymous FTP login allowed (FTP code 230)"
                if ($listLines) {
                    $listStr += "`n" + ($listLines | ForEach-Object { "    | $($_.TrimEnd())" }) -join "`n"
                } else {
                    $listStr += "`n    | (PASV failed — could not open data channel)"
                }
                Add-R "ftp-anon" $listStr $true

                # ftp-syst
                $systResp = Send-FTPCmd $ftpTcp "SYST" 5000
                if ($systResp -match "^215") {
                    Add-R "ftp-syst" "SYST: $($systResp.Substring(4).Trim())"
                }
                # ftp-bounce
                if (Wants "vuln") {
                    $portResp = Send-FTPCmd $ftpTcp "PORT 192,0,2,1,0,80" 5000
                    if ($portResp -match "^200") {
                        Add-R "ftp-bounce" "bounce working!" $true
                    } else {
                        Add-R "ftp-bounce" "bounce not allowed ($($portResp.Substring(0,[Math]::Min(3,$portResp.Length))))"
                    }
                }
            } else {
                Add-R "ftp-anon" "Anonymous login denied"
            }
            try { $ftpTcp.Close() } catch {}
        }
        # ftp-vsftpd-backdoor (CVE-2011-2523)
        if ((Wants "vuln") -and $Banner -match "vsftpd 2\.3\.4") {
            Add-R "ftp-vsftpd-backdoor" "vsftpd 2.3.4 — check for backdoor on port 6200" $true "CVE-2011-2523"
        }
    }

    # ── HTTP Scripts ──────────────────────────────────────────────────────────
    if ($isHTTP -and (Wants "default")) {
        $r = Invoke-ZHttp $IP $Port
        if ($r.B -match "<title[^>]*>(.*?)</title>") {
            Add-R "http-title" $Matches[1].Trim().Substring(0,[Math]::Min(100,$Matches[1].Trim().Length))
        }
        if ($r.H.ContainsKey("server")) { Add-R "http-server-header" $r.H["server"] }

        # http-methods + http-webdav-scan + http-open-proxy
        try {
            $optTcp = [System.Net.Sockets.TcpClient]::new()
            $arOpt  = $optTcp.BeginConnect($IP,$Port,$null,$null)
            if ($arOpt.AsyncWaitHandle.WaitOne(5000,$false) -and $optTcp.Connected) {
                $optStream = $optTcp.GetStream(); $optStream.ReadTimeout = 5000
                $optReq    = [System.Text.Encoding]::ASCII.GetBytes("OPTIONS / HTTP/1.0`r`nHost: $IP`r`n`r`n")
                $optStream.Write($optReq,0,$optReq.Length)
                $optBuf = [byte[]]::new(8192); $optSB = [System.Text.StringBuilder]::new()
                $optSW  = [System.Diagnostics.Stopwatch]::StartNew()
                while ($optSW.ElapsedMilliseconds -lt 3000 -and $optSB.Length -lt 4096) {
                    if ($optStream.DataAvailable) {
                        $n = $optStream.Read($optBuf,0,$optBuf.Length)
                        if ($n -eq 0) { break }
                        $optSB.Append([System.Text.Encoding]::UTF8.GetString($optBuf,0,$n)) | Out-Null
                    } else { Start-Sleep -Ms 50; if ($optSW.ElapsedMilliseconds -gt 1000 -and $optSB.Length -gt 0) { break } }
                }
                $optTcp.Close()
                $optStr = $optSB.ToString()
                if ($optStr -match "(?:Allow|Public):\s*([^\r\n]+)") {
                    $methodsStr  = $Matches[1].Trim()
                    $riskyList   = @("PUT","DELETE","CONNECT","TRACE","PATCH","PROPFIND","PROPPATCH","COPY","MOVE","MKCOL","LOCK","UNLOCK")
                    $risky       = $methodsStr -split "," | ForEach-Object {$_.Trim()} | Where-Object {$_ -in $riskyList}
                    $out         = "Supported Methods: $methodsStr"
                    if ($risky) { $out += "`n      Potentially risky: $($risky -join ', ')" }
                    Add-R "http-methods" $out ($risky.Count -gt 0)
                    # WebDAV check
                    $webdavMethods = @("PROPFIND","PROPPATCH","MKCOL","COPY","MOVE","LOCK","UNLOCK")
                    $wdFound = $methodsStr -split "," | ForEach-Object {$_.Trim()} | Where-Object {$_ -in $webdavMethods}
                    if ($wdFound) {
                        $dateMatch = if ($optStr -match "Date:\s*([^\r\n]+)") { $Matches[1].Trim() } else { "unknown" }
                        $svrHdr    = if ($r.H.ContainsKey("server")) { $r.H["server"] } else { "unknown" }
                        Add-R "http-webdav-scan" "WebDAV enabled | Server: $svrHdr | Date: $dateMatch`n      Allowed: $methodsStr" $true
                    }
                    # Open proxy
                    if ($methodsStr -match "CONNECT") {
                        Add-R "http-open-proxy" "Potentially OPEN proxy — CONNECT method supported" $true
                    }
                }
            }
        } catch {}

        # http-trace
        try {
            $trTcp = [System.Net.Sockets.TcpClient]::new()
            $arTr  = $trTcp.BeginConnect($IP,$Port,$null,$null)
            if ($arTr.AsyncWaitHandle.WaitOne(3000,$false) -and $trTcp.Connected) {
                $trS  = $trTcp.GetStream(); $trS.ReadTimeout = 3000
                $trReq = [System.Text.Encoding]::ASCII.GetBytes("TRACE / HTTP/1.0`r`nHost: $IP`r`n`r`n")
                $trS.Write($trReq,0,$trReq.Length)
                $trBuf = [byte[]]::new(1024); $n = $trS.Read($trBuf,0,$trBuf.Length); $trTcp.Close()
                $trStr = [System.Text.Encoding]::ASCII.GetString($trBuf,0,$n)
                if ($trStr -match "^HTTP/[\d\.]+ 200") { Add-R "http-trace" "HTTP TRACE method enabled — XST vulnerability" $true }
            }
        } catch {}

        if ((Wants "safe")) {
            $secH = @("x-frame-options","x-xss-protection","x-content-type-options",
                      "strict-transport-security","content-security-policy","referrer-policy")
            $miss = $secH | Where-Object { -not $r.H.ContainsKey($_) }
            if ($miss) { Add-R "http-security-headers" "Missing: $($miss -join ', ')" $true }
            else       { Add-R "http-security-headers" "All key security headers present" }
        }
        if ($r.H.ContainsKey("access-control-allow-origin")) {
            $acao = $r.H["access-control-allow-origin"]
            Add-R "http-cors" "CORS: $acao" ($acao -eq "*")
        }
        if ($r.S -eq 401 -and $r.H.ContainsKey("www-authenticate")) {
            Add-R "http-auth" "Auth required: $($r.H['www-authenticate'])"
        }
        if ((Wants "safe")) {
            $r2 = Invoke-ZHttp $IP $Port "/robots.txt"
            if ($r2.S -eq 200 -and $r2.B -match "Disallow:") {
                $dis = ($r2.B -split "`n" | Where-Object {$_ -match "^Disallow:"} | Select-Object -First 5) -join " | "
                Add-R "http-robots.txt" "Disallowed: $dis"
            }
        }
        if ((Wants "vuln")) {
            $rg = Invoke-ZHttp $IP $Port "/.git/HEAD"
            if ($rg.S -eq 200 -and $rg.B -match "ref:") {
                Add-R "http-git" "Git repository exposed at /.git/HEAD" $true
            }
            foreach ($ep in @("/../../../etc/passwd","/%2e%2e/%2e%2e/etc/passwd")) {
                $rp = Invoke-ZHttp $IP $Port $ep
                if ($rp.S -eq 200 -and $rp.B -match "root:x:") {
                    Add-R "http-passwd" "Directory traversal via: $ep" $true; break
                }
            }
            if ($r.H.ContainsKey("x-powered-by") -and $r.H["x-powered-by"] -match "php") {
                Add-R "http-php-version" "PHP: $($r.H['x-powered-by'])" $true
            }
            $ra = Invoke-ZHttp $IP $Port "/actuator"
            if ($ra.S -eq 200 -and ($ra.B -match "_links|actuator")) {
                Add-R "http-spring-boot-actuator" "Spring Boot Actuator exposed" $true
            }
            $rw = Invoke-ZHttp $IP $Port "/wp-json/wp/v2/users"
            if ($rw.S -eq 200 -and $rw.B -match '"slug"') {
                $slugs = [regex]::Matches($rw.B,'"slug"\s*:\s*"([^"]+)"') | Select-Object -First 5 | ForEach-Object {$_.Groups[1].Value}
                Add-R "http-wordpress-users" "WordPress users: $($slugs -join ', ')" $true
            }
            $enumPaths = @("/admin","/administrator","/manager","/login","/phpmyadmin",
                           "/phpinfo.php","/.env","/.htaccess","/backup","/config.php",
                           "/web.config","/server-status","/server-info")
            $found = foreach ($ep in $enumPaths) {
                $re = Invoke-ZHttp $IP $Port $ep
                if ($re.S -in @(200,401,403)) { "$ep [$($re.S)]" }
            }
            if ($found) { Add-R "http-enum" "Paths: $($found -join ', ')" }
        }
        if ((Wants "safe")) {
            $allTxt = (($r.H.Values) -join " ").ToLower() + $r.B.Substring(0,[Math]::Min(500,$r.B.Length)).ToLower()
            $wafs   = @{"Cloudflare"=@("cf-ray","cloudflare");"AWS WAF"=@("x-amzn-requestid","awselb");
                        "ModSecurity"=@("mod_security","modsecurity");"F5"=@("bigip","f5-bigip")}
            foreach ($w in $wafs.Keys) {
                if ($wafs[$w] | Where-Object {$allTxt -like "*$_*"}) { Add-R "http-waf-detect" "WAF: $w"; break }
            }
        }
    }

    # ── SSH Scripts ───────────────────────────────────────────────────────────
    if ($isSSH -and (Wants "default")) {
        Add-R "ssh-hostkey" (($Banner -split "`n")[0].Trim().Substring(0,[Math]::Min(80,($Banner -split "`n")[0].Trim().Length)))
        if ($Banner -match "SSH-1") {
            Add-R "ssh-weak-version" "SSHv1 detected — deprecated and insecure" $true "CVE-2001-0553"
        }
    }

    # ── SMB Scripts ───────────────────────────────────────────────────────────
    if ($isSMB -and (Wants "default")) {
        try {
            $smb = [System.Net.Sockets.TcpClient]::new()
            $ar  = $smb.BeginConnect($IP,$Port,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $smb.Connected) {
                $ss  = $smb.GetStream(); $ss.ReadTimeout = 3000
                $neg = [byte[]](0x00,0x00,0x00,0x85,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,
                                0x18,0x53,0xC8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0xFF,0xFE,0x00,0x00,0x00,0x00,0x00,0x62,0x00,
                                0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00,
                                0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x30,0x30,0x32,0x00,
                                0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x3F,0x3F,0x3F,0x00)
                $ss.Write($neg,0,$neg.Length)
                $buf = [byte[]]::new(4096); $n = $ss.Read($buf,0,$buf.Length)
                $smb.Close()
                if ($n -gt 36 -and $buf[4] -eq 0xFF -and $buf[5] -eq 0x53) {
                    Add-R "smb-protocols" "SMBv1 supported — potentially vulnerable to EternalBlue" $true "CVE-2017-0144"
                } else { Add-R "smb-protocols" "SMBv1 not detected (SMBv2/3 likely)" }
            }
        } catch {}
    }

    # ── SMTP Scripts ──────────────────────────────────────────────────────────
    if ($isSMTP -and (Wants "default")) {
        try {
            $sm  = [System.Net.Sockets.TcpClient]::new()
            $ar  = $sm.BeginConnect($IP,$Port,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $sm.Connected) {
                $ss = $sm.GetStream(); $ss.ReadTimeout = 3000
                $buf = [byte[]]::new(4096); $ss.Read($buf,0,$buf.Length) | Out-Null
                $ehlo = [System.Text.Encoding]::ASCII.GetBytes("EHLO zscan.local`r`n")
                $ss.Write($ehlo,0,$ehlo.Length)
                $n   = $ss.Read($buf,0,$buf.Length)
                $eR  = [System.Text.Encoding]::ASCII.GetString($buf,0,$n)
                $cmds = ($eR -split "`n" | Where-Object {$_ -match "^250"} | ForEach-Object {($_ -replace "^250[\-\s]","").Trim()} | Select-Object -First 8) -join ", "
                Add-R "smtp-commands" "EHLO: $cmds"
                if ((Wants "vuln")) {
                    $mf = [System.Text.Encoding]::ASCII.GetBytes("MAIL FROM:<t@zscan.local>`r`n")
                    $ss.Write($mf,0,$mf.Length); $ss.Read($buf,0,$buf.Length) | Out-Null
                    $rt = [System.Text.Encoding]::ASCII.GetBytes("RCPT TO:<t@external-example.com>`r`n")
                    $ss.Write($rt,0,$rt.Length); $n2 = $ss.Read($buf,0,$buf.Length)
                    $rR = [System.Text.Encoding]::ASCII.GetString($buf,0,$n2)
                    if ($rR -match "^250") { Add-R "smtp-open-relay" "Server may be an open relay!" $true }
                    else                   { Add-R "smtp-open-relay" "Relay denied" }
                }
                if ((Wants "auth")) {
                    $vf = [System.Text.Encoding]::ASCII.GetBytes("VRFY root`r`n")
                    $ss.Write($vf,0,$vf.Length); $n3 = $ss.Read($buf,0,$buf.Length)
                    $vR = [System.Text.Encoding]::ASCII.GetString($buf,0,$n3)
                    if ($vR -match "^(250|252)") { Add-R "smtp-enum-users" "VRFY accepted — user enum possible" $true }
                    else                          { Add-R "smtp-enum-users" "VRFY rejected" }
                }
                $sm.Close()
            }
        } catch {}
    }

    # ── DNS Scripts ───────────────────────────────────────────────────────────
    if ($isDNS -and (Wants "default")) {
        try {
            $dnsQ = [byte[]](0xaa,0xbb,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                              0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01)
            $udp  = [System.Net.Sockets.UdpClient]::new(); $udp.Client.ReceiveTimeout = 3000
            $udp.Send($dnsQ,$dnsQ.Length,$IP,53) | Out-Null
            $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
            $dr = $udp.Receive([ref]$ep); $udp.Close()
            if ($dr.Count -gt 2) {
                $ra = ($dr[3] -band 0x80) -shr 7
                if ($ra) { Add-R "dns-recursion" "Recursion available — open resolver possible" $true }
                else     { Add-R "dns-recursion" "Recursion not available" }
            }
        } catch {}
    }

    # ── SNMP Scripts ──────────────────────────────────────────────────────────
    if ($isSNMP -and (Wants "default")) {
        foreach ($comm in @("public","private","community","manager","admin")) {
            try {
                $cb   = [System.Text.Encoding]::ASCII.GetBytes($comm)
                $oid  = [byte[]](0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00)
                $inner = [byte[]](0x02,0x01,0x00,0x02,0x01,0x00,0x02,0x01,0x00) + [byte[]](0x30,0x0e) + $oid
                $pdu  = [byte[]](0xa0) + [byte[]]($inner.Length) + $inner
                $inner2 = [byte[]](0x02,0x01,0x00) + [byte[]](0x04,$cb.Length) + $cb + $pdu
                $msg  = [byte[]](0x30) + [byte[]]($inner2.Length) + $inner2
                $snmp = [System.Net.Sockets.UdpClient]::new(); $snmp.Client.ReceiveTimeout = 2000
                $snmp.Send($msg,$msg.Length,$IP,161) | Out-Null
                $ep2  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
                $sr   = $snmp.Receive([ref]$ep2); $snmp.Close()
                if ($sr -and $sr.Length -gt 0) {
                    Add-R "snmp-info" "Community '$comm' accepted — SNMP accessible without auth" $true; break
                }
            } catch {}
        }
    }

    # ── LDAP Scripts ──────────────────────────────────────────────────────────
    if ($isLDAP -and (Wants "default")) {
        try {
            $bind = [byte[]](0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00)
            $lt   = [System.Net.Sockets.TcpClient]::new()
            $ar   = $lt.BeginConnect($IP,$Port,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $lt.Connected) {
                $ls = $lt.GetStream(); $ls.ReadTimeout = 3000
                $ls.Write($bind,0,$bind.Length)
                $lbuf = [byte[]]::new(128); $n = $ls.Read($lbuf,0,$lbuf.Length)
                $lt.Close()
                if ($n -gt 7 -and $lbuf[7] -eq 0) { Add-R "ldap-rootdse" "LDAP anonymous bind accepted" $true }
                else                                { Add-R "ldap-rootdse" "LDAP anonymous bind rejected" }
            }
        } catch {}
    }

    # ── Redis Scripts ─────────────────────────────────────────────────────────
    if ($isRedis -and (Wants "default")) {
        try {
            $rt  = [System.Net.Sockets.TcpClient]::new()
            $ar  = $rt.BeginConnect($IP,6379,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $rt.Connected) {
                $rs  = $rt.GetStream(); $rs.ReadTimeout = 3000
                $cmd = [System.Text.Encoding]::ASCII.GetBytes("*1`r`n`$4`r`nINFO`r`n")
                $rs.Write($cmd,0,$cmd.Length)
                $buf = [byte[]]::new(4096); $sb3 = [System.Text.StringBuilder]::new()
                $sw3 = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw3.ElapsedMilliseconds -lt 3000 -and $sb3.Length -lt 4096) {
                    if ($rs.DataAvailable) { $n=$rs.Read($buf,0,$buf.Length); $sb3.Append([System.Text.Encoding]::ASCII.GetString($buf,0,$n)) | Out-Null }
                    else { Start-Sleep -Ms 50; if ($sw3.ElapsedMilliseconds -gt 1000 -and $sb3.Length -gt 0) { break } }
                }
                $rt.Close()
                $rInfo = $sb3.ToString()
                if ($rInfo -match "redis_version") {
                    $ver = if ($rInfo -match "redis_version:(\S+)") { $Matches[1] } else { "?" }
                    Add-R "redis-info" "Redis $ver — accessible without auth" $true
                }
            }
        } catch {}
    }

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    if ($isElastic -and (Wants "default")) {
        $re = Invoke-ZHttp $IP 9200 "/"
        if ($re.B -match "elasticsearch|cluster_name") {
            $ver = if ($re.B -match '"number"\s*:\s*"([^"]+)"') {$Matches[1]} else {"?"}
            Add-R "elasticsearch-info" "Elasticsearch $ver accessible without auth" $true
        }
    }

    # ── MySQL ─────────────────────────────────────────────────────────────────
    if ($isMySQL -and (Wants "default")) {
        try {
            $my = [System.Net.Sockets.TcpClient]::new()
            $ar = $my.BeginConnect($IP,3306,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $my.Connected) {
                $ms = $my.GetStream(); $ms.ReadTimeout = 3000
                $buf = [byte[]]::new(1024); $n = $ms.Read($buf,0,$buf.Length)
                $my.Close()
                if ($n -gt 5 -and $buf[4] -eq 0x0a) {
                    $ve = 5; while ($ve -lt $n -and $buf[$ve] -ne 0) { $ve++ }
                    $ver = [System.Text.Encoding]::ASCII.GetString($buf,5,$ve-5)
                    Add-R "mysql-info" "MySQL version: $ver"
                }
            }
        } catch {}
    }

    # ── NTP Scripts ───────────────────────────────────────────────────────────
    if ($isNTP -and (Wants "default")) {
        try {
            $ntpR = [byte[]]::new(48); $ntpR[0]=0x1b
            $nu   = [System.Net.Sockets.UdpClient]::new(); $nu.Client.ReceiveTimeout = 3000
            $nu.Send($ntpR,48,$IP,123) | Out-Null
            $ep3  = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
            $nr   = $nu.Receive([ref]$ep3); $nu.Close()
            if ($nr.Count -ge 48) {
                $ver     = ($nr[0] -shr 3) -band 0x7
                $stratum = $nr[1]
                $bytes   = [byte[]]($nr[43],$nr[42],$nr[41],$nr[40])
                $tsInt   = [BitConverter]::ToUInt32($bytes,0)
                if ($tsInt -gt 2208988800) {
                    $dt = (Get-Date "1900-01-01").AddSeconds($tsInt)
                    Add-R "ntp-info" "NTPv$ver stratum=$stratum time=$($dt.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                }
            }
        } catch {}
        if ((Wants "vuln")) {
            try {
                $mlR = [byte[]](0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00)
                $mu  = [System.Net.Sockets.UdpClient]::new(); $mu.Client.ReceiveTimeout = 3000
                $mu.Send($mlR,$mlR.Length,$IP,123) | Out-Null
                $ep4 = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
                $mr  = $mu.Receive([ref]$ep4); $mu.Close()
                if ($mr.Count -gt 100) { Add-R "ntp-monlist" "monlist enabled — DDoS amplification ($($mr.Count)B)" $true "CVE-2013-5211" }
            } catch {}
        }
    }

    # ── VNC Scripts ───────────────────────────────────────────────────────────
    if ($isVNC -and (Wants "default")) {
        try {
            $vt = [System.Net.Sockets.TcpClient]::new()
            $ar = $vt.BeginConnect($IP,5900,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $vt.Connected) {
                $vs = $vt.GetStream(); $vs.ReadTimeout = 3000
                $vb = [byte[]]::new(64); $n = $vs.Read($vb,0,$vb.Length)
                $vt.Close()
                $vStr = [System.Text.Encoding]::ASCII.GetString($vb,0,$n).Trim()
                Add-R "vnc-info" "Protocol: $($vStr.Substring(0,[Math]::Min(40,$vStr.Length)))"
                if ($vStr -match "RFB 003\.00[37]") { Add-R "realvnc-auth-bypass" "Old VNC version — check for auth bypass" $true "CVE-2006-2369" }
            }
        } catch {}
    }

    # ── IMAP Scripts ──────────────────────────────────────────────────────────
    if ($isIMAP -and (Wants "default")) {
        try {
            $it = [System.Net.Sockets.TcpClient]::new()
            $ar = $it.BeginConnect($IP,$Port,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $it.Connected) {
                $is2 = $it.GetStream(); $is2.ReadTimeout = 3000
                $ib  = [byte[]]::new(2048); $is2.Read($ib,0,$ib.Length) | Out-Null
                $cap = [System.Text.Encoding]::ASCII.GetBytes("a001 CAPABILITY`r`n")
                $is2.Write($cap,0,$cap.Length)
                $n   = $is2.Read($ib,0,$ib.Length); $it.Close()
                $cs  = [System.Text.Encoding]::ASCII.GetString($ib,0,$n)
                if ($cs -match "\* CAPABILITY([^\r\n]+)") {
                    Add-R "imap-capabilities" $Matches[1].Trim().Substring(0,[Math]::Min(100,$Matches[1].Trim().Length))
                }
            }
        } catch {}
    }

    # ── POP3 Scripts ──────────────────────────────────────────────────────────
    if ($isPOP3 -and (Wants "default")) {
        try {
            $pt = [System.Net.Sockets.TcpClient]::new()
            $ar = $pt.BeginConnect($IP,$Port,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $pt.Connected) {
                $ps2 = $pt.GetStream(); $ps2.ReadTimeout = 3000
                $pb  = [byte[]]::new(1024); $ps2.Read($pb,0,$pb.Length) | Out-Null
                $ca  = [System.Text.Encoding]::ASCII.GetBytes("CAPA`r`n")
                $ps2.Write($ca,0,$ca.Length)
                $n   = $ps2.Read($pb,0,$pb.Length); $pt.Close()
                $pc  = [System.Text.Encoding]::ASCII.GetString($pb,0,$n)
                $items = ($pc -split "`n" | Where-Object {$_ -match "^\w"} | Select-Object -First 6) -join ", "
                if ($items) { Add-R "pop3-capabilities" "Capabilities: $items" }
            }
        } catch {}
    }

    # ── RDP Scripts ───────────────────────────────────────────────────────────
    if ($isRDP -and (Wants "default")) {
        try {
            $rt2 = [System.Net.Sockets.TcpClient]::new()
            $ar  = $rt2.BeginConnect($IP,3389,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $rt2.Connected) {
                $rs2 = $rt2.GetStream(); $rs2.ReadTimeout = 3000
                $x224 = [byte[]](0x03,0x00,0x00,0x13,0x0E,0xE0,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00)
                $rs2.Write($x224,0,$x224.Length)
                $rb = [byte[]]::new(1024); $n = $rs2.Read($rb,0,$rb.Length); $rt2.Close()
                if ($n -gt 0 -and $rb[0] -eq 0x03) { Add-R "rdp-enum-encryption" "RDP responding — verify NLA/CredSSP is enforced" }
            }
        } catch {}
    }

    # ── SSL Cert (v2.1 — raw SslStream, works on any port including 44330) ────
    if ($isSSL -and (Wants "default")) {
        try {
            $sslTcp = [System.Net.Sockets.TcpClient]::new()
            $arSSL  = $sslTcp.BeginConnect($IP,$Port,$null,$null)
            if ($arSSL.AsyncWaitHandle.WaitOne(5000,$false) -and $sslTcp.Connected) {
                $sslStream = [System.Net.Security.SslStream]::new(
                    $sslTcp.GetStream(), $false, {$true})
                $sslStream.AuthenticateAsClient($IP)
                $cert = $sslStream.RemoteCertificate
                $sslTcp.Close()
                if ($cert) {
                    $certX509  = [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
                    $exp       = $certX509.NotAfter
                    $notBefore = $certX509.NotBefore
                    $days      = ($exp - (Get-Date)).Days
                    $cn        = $certX509.Subject
                    $issuer    = $certX509.Issuer
                    $proto     = $sslStream.SslProtocol
                    if ($days -lt 0) {
                        Add-R "ssl-cert" "EXPIRED $([Math]::Abs($days))d ago | $cn`n      Not valid after: $($exp.ToString('yyyy-MM-dd')) | Protocol: $proto" $true
                    } elseif ($days -lt 30) {
                        Add-R "ssl-cert" "Expires in ${days}d (SOON) | $cn" $true
                    } else {
                        Add-R "ssl-cert" "Valid ${days}d remaining | $cn`n      Not before: $($notBefore.ToString('yyyy-MM-dd')) | Not after: $($exp.ToString('yyyy-MM-dd')) | Protocol: $proto"
                    }
                    # Weak protocol check
                    if ($proto -in @("Tls","Ssl3","Ssl2")) {
                        Add-R "ssl-enum-ciphers" "Weak protocol: $proto" $true
                    }
                }
            } else { $sslTcp.Close() }
        } catch {}
    }

    # ── Rsync Scripts ─────────────────────────────────────────────────────────
    if ($isRsync -and (Wants "default")) {
        try {
            $ryt = [System.Net.Sockets.TcpClient]::new()
            $ar  = $ryt.BeginConnect($IP,873,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $ryt.Connected) {
                $rys = $ryt.GetStream(); $rys.ReadTimeout = 3000
                $ryb = [byte[]]::new(1024); $rys.Read($ryb,0,$ryb.Length) | Out-Null
                $hello = [System.Text.Encoding]::ASCII.GetBytes("@RSYNCD: 31`n`n")
                $rys.Write($hello,0,$hello.Length)
                $sb4 = [System.Text.StringBuilder]::new()
                $sw4 = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw4.ElapsedMilliseconds -lt 3000 -and $sb4.Length -lt 4096) {
                    if ($rys.DataAvailable) {
                        $n = $rys.Read($ryb,0,$ryb.Length)
                        $sb4.Append([System.Text.Encoding]::ASCII.GetString($ryb,0,$n)) | Out-Null
                        if ($sb4.ToString() -match "@RSYNCD: EXIT") { break }
                    } else { Start-Sleep -Ms 50 }
                }
                $ryt.Close()
                $mods = ($sb4.ToString() -split "`n" | Where-Object {$_ -match "^\w" -and $_ -notmatch "@RSYNCD"} | Select-Object -First 10) -join ", "
                if ($mods) { Add-R "rsync-list-modules" "Modules: $mods" $true }
            }
        } catch {}
    }

    # ── Docker Scripts ────────────────────────────────────────────────────────
    if ($isDocker -and (Wants "default")) {
        $dr = Invoke-ZHttp $IP $Port "/version"
        if ($dr.S -eq 200 -and $dr.B -match "ApiVersion") {
            $ver = if ($dr.B -match '"Version"\s*:\s*"([^"]+)"') {$Matches[1]} else {"?"}
            Add-R "docker-version" "Docker $ver API — container escape risk!" $true
        }
    }

    # ── Kubernetes Scripts ────────────────────────────────────────────────────
    if ($isK8s -and (Wants "default")) {
        $kr = Invoke-ZHttp $IP $Port "/version"
        if ($kr.S -eq 200 -and $kr.B -match "gitVersion") {
            $ver = if ($kr.B -match '"gitVersion"\s*:\s*"([^"]+)"') {$Matches[1]} else {"?"}
            Add-R "kubernetes-api" "Kubernetes $ver API accessible without auth" $true
        }
    }

    # ── Modbus Scripts ────────────────────────────────────────────────────────
    if ($isModbus -and (Wants "default")) {
        try {
            $mbt = [System.Net.Sockets.TcpClient]::new()
            $ar  = $mbt.BeginConnect($IP,502,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $mbt.Connected) {
                $mbs = $mbt.GetStream(); $mbs.ReadTimeout = 3000
                $req = [byte[]](0x00,0x01,0x00,0x00,0x00,0x06,0xff,0x11,0x00,0x00,0x00,0x00)
                $mbs.Write($req,0,$req.Length)
                $mbb = [byte[]]::new(256); $n = $mbs.Read($mbb,0,$mbb.Length); $mbt.Close()
                if ($n -gt 6) { Add-R "modbus-discover" "Modbus responding ($n bytes) — ICS/SCADA exposure!" $true }
            }
        } catch {}
    }

    # ── Telnet Scripts ────────────────────────────────────────────────────────
    if ($isTelnet -and (Wants "default")) {
        try {
            $tt = [System.Net.Sockets.TcpClient]::new()
            $ar = $tt.BeginConnect($IP,23,$null,$null)
            if ($ar.AsyncWaitHandle.WaitOne(3000,$false) -and $tt.Connected) {
                $ts  = $tt.GetStream(); $ts.ReadTimeout = 3000
                $tb  = [byte[]]::new(512); $n = $ts.Read($tb,0,$tb.Length); $tt.Close()
                $tStr = [System.Text.Encoding]::ASCII.GetString($tb,0,$n) -replace "[^\x20-\x7e]",""
                if ($tStr.Trim().Length -gt 0) {
                    Add-R "telnet-ntlm-info" "Banner: $($tStr.Trim().Substring(0,[Math]::Min(80,$tStr.Trim().Length)))" $true
                }
            }
        } catch {}
    }

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
$startTime = Get-Date
$tStart    = [System.Diagnostics.Stopwatch]::StartNew()
$IPs       = Expand-Targets $Target

# Resolve port list
if ($Ports -ne "") {
    $PortList = Expand-Ports $Ports
} elseif ($TopPorts -gt 0) {
    $PortList = if ($TopPorts -ge 1000) { $Top1000 } elseif ($TopPorts -ge 100) { $Top100 } else { $Top100 | Select-Object -First $TopPorts }
} else {
    $PortList = $Top1000
}

$ScriptCats = if ($Scripts -ne "") { $Scripts -split "," | ForEach-Object {$_.Trim().ToLower()} } else { @() }
$doScripts  = $ScriptCats.Count -gt 0 -or $Scripts -ne ""
$doBanner   = $ServiceDetection -or $doScripts

# Print banner
Write-C "`n$('─'*65)" White
Write-C " ⚡ ZScan v$VERSION — Air-gap Safe Network Scanner" Yellow
Write-C " Target: $Target  Ports: $($PortList.Count)  Timing: T$T ($($Prof.Name))" White
if ($doScripts) { Write-C " Scripts: $($Scripts)" Cyan }
Write-C "$('─'*65)" White
Write-C ""

$allResults   = [System.Collections.Generic.List[PSCustomObject]]::new()
$globalVulns  = 0
$totalOpen    = 0

foreach ($IP in $IPs) {
    # Host discovery for multi-target
    if ($IPs.Count -gt 1 -or $ScanType -eq "Ping") {
        if (-not (Test-HostUp $IP $TIMEOUT)) {
            Write-Dim "  [skip] $IP — host down"
            continue
        }
        Write-Ok "[+] Host up: $IP"
        if ($ScanType -eq "Ping") { continue }
    }

    $hostData = [PSCustomObject]@{
        IP      = $IP
        OS      = ""
        TTL     = 0
        Ports   = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    if ($OSDetect) {
        $od = Get-OSGuess $IP
        $hostData.OS  = $od.OS
        $hostData.TTL = $od.TTL
        Write-C "  OS: $($od.OS) (TTL=$($od.TTL) via $($od.Method))" Cyan
    }

    Write-C "  PORT      STATE          SERVICE           VERSION" White

    # Thread pool scan
    $portResults = [System.Collections.Concurrent.ConcurrentQueue[PSCustomObject]]::new()
    $jobs        = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()

    $scriptBlock = {
        param($ip, $port, $scanType, $TMs, $doBanner, $doScripts, $scriptCats, $ServiceDB)
        $state = switch ($scanType) {
            "UDP" { Test-UDPPort $ip $port $TMs }
            default { Test-TCPPort $ip $port $TMs }
        }
        if ($state -ne "open" -and $state -ne "open|filtered") { return $null }
        $svc     = if ($ServiceDB.ContainsKey($port)) { $ServiceDB[$port] } else { "unknown" }
        $banner  = ""
        $version = $svc
        if ($doBanner) {
            $banner  = Get-Banner $ip $port $TMs
            $version = Get-Version $banner $port
        }
        $scripts = @()
        if ($doScripts -and $banner -ne $null) {
            $scripts = Invoke-Scripts $ip $port $svc $banner $scriptCats
        }
        return [PSCustomObject]@{
            Port     = $port
            State    = $state
            Service  = $svc
            Version  = $version
            Banner   = $banner
            Scripts  = $scripts
        }
    }

    # Throttled parallel execution using RunspacePool
    $rsPool = [runspacefactory]::CreateRunspacePool(1, $WORKERS)
    $rsPool.Open()
    $running = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($port in $PortList) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $rsPool
        $ps.AddScript({
            param($ip,$port,$scanType,$TMs)
            $state = if ($scanType -eq "UDP") {
                try {
                    $udp = [System.Net.Sockets.UdpClient]::new(); $udp.Client.ReceiveTimeout=$TMs
                    $udp.Send([byte[]](0x00)*8,8,$ip,$port) | Out-Null
                    try { $ep=[System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0); $udp.Receive([ref]$ep) | Out-Null; "open" }
                    catch { if ($_.Exception.SocketErrorCode -eq "ConnectionReset") {"closed"} else {"open|filtered"} }
                    finally { $udp.Close() }
                } catch { "filtered" }
            } else {
                try {
                    $tcp=[System.Net.Sockets.TcpClient]::new(); $ar=$tcp.BeginConnect($ip,$port,$null,$null)
                    $ok=$ar.AsyncWaitHandle.WaitOne($TMs,$false)
                    if ($ok -and $tcp.Connected) { $tcp.Close(); "open" } else { $tcp.Close(); "filtered" }
                } catch [System.Net.Sockets.SocketException] {
                    if ($_.Exception.SocketErrorCode -eq "ConnectionRefused") {"closed"} else {"filtered"}
                } catch { "filtered" }
            }
            [PSCustomObject]@{Port=$port;State=$state}
        }) | Out-Null
        $ps.AddArgument($IP) | Out-Null
        $ps.AddArgument($port) | Out-Null
        $ps.AddArgument($ScanType) | Out-Null
        $ps.AddArgument($TIMEOUT) | Out-Null
        $running.Add(@{PS=$ps; Handle=$ps.BeginInvoke()})
    }

    foreach ($r in $running) {
        $res = $r.PS.EndInvoke($r.Handle)
        $r.PS.Dispose()
        if ($res -and ($res.State -eq "open" -or $res.State -eq "open|filtered")) {
            $port    = $res.Port
            $state   = $res.State
            $svc     = if ($ServiceDB.ContainsKey($port)) { $ServiceDB[$port] } else { "unknown" }
            $banner  = if ($doBanner) { Get-Banner $IP $port $TIMEOUT } else { "" }

            # Upgrade service name from banner when port is unknown
            if ($svc -eq "unknown" -and $banner) {
                if ($banner -match "^SSH-")                          { $svc = "ssh" }
                elseif ($banner -match "^220[\s\-].*(FileZilla|ftp)" -and $banner -notmatch "SMTP") { $svc = "ftp" }
                elseif ($banner -match "^220[\s\-].*(SMTP|ESMTP)")   { $svc = "smtp" }
                elseif ($banner -match "^HTTP/|Server:\s*\S")        { $svc = "http" }
                elseif ($banner -match "^\+OK")                      { $svc = "pop3" }
                elseif ($banner -match "^\* OK")                     { $svc = "imap" }
                elseif ($banner -match "redis_version")              { $svc = "redis" }
            }

            $version = if ($doBanner) { Get-Version $banner $port } else { $svc }
            $scrs    = if ($doScripts) { Invoke-Scripts $IP $port $svc $banner $ScriptCats } else { @() }

            $fc = if ($state -eq "open") { "Green" } else { "Yellow" }
            Write-C ("  {0,-9} {1,-14} {2,-18} {3}" -f "$port/tcp", $state, $svc, $version) $fc
            foreach ($s in $scrs) {
                $tag = if ($s.Vuln) { " [VULN]" } else { "" }
                $cve = if ($s.CVE)  { " ($($s.CVE))" } else { "" }
                $col = if ($s.Vuln) { "Red" } else { "DarkGray" }
                # Handle multiline output — first line on same row as script name, rest indented
                $outLines = $s.Output -split "`n"
                Write-C "    |_$($s.Name)$tag$cve" $col
                Write-C "      $($outLines[0])" DarkGray
                for ($li = 1; $li -lt $outLines.Count; $li++) {
                    Write-C $outLines[$li] DarkGray
                }
                if ($s.Vuln) { $globalVulns++ }
            }
            $totalOpen++
            $hostData.Ports.Add([PSCustomObject]@{
                Port    = $port
                State   = $state
                Service = $svc
                Version = $version
                Banner  = $banner.Substring(0,[Math]::Min(200,$banner.Length))
                Scripts = $scrs
            })
        }
    }

    $rsPool.Close()
    $rsPool.Dispose()
    $allResults.Add($hostData)
    Write-C ""
    Write-Ok "  [*] $totalOpen open port(s) found" -NoNL
    if ($globalVulns -gt 0) { Write-C "  ⚠ $globalVulns vuln(s) detected" Red -NoNL }
    Write-C ""
}

$elapsed = "$([Math]::Round($tStart.Elapsed.TotalSeconds,2))s"
Write-C "$('─'*65)" White
Write-C " Done in $elapsed" White
Write-C ""

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
if ($OutputJSON -ne "") {
    $out = @{
        version    = $VERSION
        start_time = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        elapsed    = $elapsed
        target     = $Target
        hosts      = $allResults
    }
    $out | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputJSON -Encoding UTF8
    Write-Ok "[+] JSON output: $OutputJSON"
}

if ($OutputCSV -ne "") {
    $rows = foreach ($h in $allResults) {
        foreach ($p in $h.Ports) {
            [PSCustomObject]@{
                IP      = $h.IP
                Port    = $p.Port
                State   = $p.State
                Service = $p.Service
                Version = $p.Version
                Vulns   = ($p.Scripts | Where-Object {$_.Vuln} | ForEach-Object {"$($_.Name)($($_.CVE))"}) -join "; "
            }
        }
    }
    $rows | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
    Write-Ok "[+] CSV output: $OutputCSV"
}

if ($OutputHTML -ne "") {
    $htmlRows = foreach ($h in $allResults) {
        foreach ($p in $h.Ports) {
            $scripts = ($p.Scripts | ForEach-Object {
                $vClass = if ($_.Vuln) { " class='vuln'" } else { "" }
                "<div$vClass><b>$($_.Name)</b>$(if($_.CVE){" <span class='cve'>$($_.CVE)</span>"}) — $($_.Output)</div>"
            }) -join ""
            "<tr><td>$($h.IP)</td><td>$($p.Port)</td><td>$($p.State)</td><td>$($p.Service)</td><td>$($p.Version)</td><td class='scripts'>$scripts</td></tr>"
        }
    }
    $html = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>ZScan $VERSION — $Target</title>
<style>
body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:20px}
h1{color:#58a6ff}table{border-collapse:collapse;width:100%}
th{background:#161b22;color:#58a6ff;padding:8px;text-align:left;border-bottom:1px solid #30363d}
td{padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:top}
tr:hover td{background:#161b22}.vuln{color:#f85149;font-weight:bold}
.cve{color:#d29922;font-size:.85em}.scripts{font-size:.9em}
</style></head><body>
<h1>⚡ ZScan $VERSION</h1>
<p>Target: <b>$Target</b> | Scan: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) | Elapsed: $elapsed</p>
<table>
<tr><th>IP</th><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Scripts</th></tr>
$($htmlRows -join "`n")
</table></body></html>
"@
    Set-Content -Path $OutputHTML -Value $html -Encoding UTF8
    Write-Ok "[+] HTML output: $OutputHTML"
}
