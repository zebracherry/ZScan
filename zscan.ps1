#Requires -Version 5.1
<#
.SYNOPSIS
    ZScan - Air-gap Safe Network Scanner (PowerShell Edition)
.DESCRIPTION
    ZScan.ps1 — Windows network scanner with embedded NSE-equivalent scripts.
    No dependencies. No internet. No installs. Runs on any Windows 10/11/Server
    with PowerShell 5.1+ (which is every modern Windows system).

    Features:
      TCP Connect scan (-ScanType TCP)
      UDP scan         (-ScanType UDP)
      Ping sweep       (-ScanType Ping)
      Version/banner detection (-ServiceDetection)
      OS detection     (-OSDetect)
      Embedded script checks (-Scripts)
      HTML + JSON + CSV + Terminal output

    LIMITATIONS vs Python version:
      No SYN/FIN/NULL/XMAS scan (requires raw sockets — not available in PS)
      UDP scan is limited (no ICMP unreachable parsing in pure PS)

    AIR-GAP SAFE: Uses only System.Net.Sockets — built into .NET Framework
                  No PowerShell modules to install. Works offline.

.EXAMPLE
    .\zscan.ps1 -Target 192.168.1.0/24 -ScanType Ping
    .\zscan.ps1 -Target 192.168.1.1 -Ports "22,80,443" -ServiceDetection
    .\zscan.ps1 -Target 10.0.0.1 -TopPorts 100 -Scripts All -OutputJSON scan.json
    .\zscan.ps1 -Target 10.0.0.0/24 -Ports "1-1024" -T 4 -OutputHTML report.html
    .\zscan.ps1 -Target 192.168.1.1 -ScanType UDP -Ports "53,161,500"

.NOTES
    Version: 1.0.0
    For authorised security testing only.
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

    [string]$Scripts = "",      # default | safe | vuln | auth | discovery | all (comma-sep)

    [string]$OutputJSON = "",
    [string]$OutputHTML = "",
    [string]$OutputCSV  = "",

    [switch]$ShowClosed,
    [switch]$Quiet,
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Color {
    param([string]$Text, [string]$Color="White", [switch]$NoNewline)
    if ($NoColor) { $Color = "White" }
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else            { Write-Host $Text -ForegroundColor $Color }
}

# ─────────────────────────────────────────────────────────────────────────────
# TIMING TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
$TimingProfiles = @{
    0 = @{Workers=10;  Timeout=5000; Name="paranoid"}
    1 = @{Workers=50;  Timeout=3000; Name="sneaky"}
    2 = @{Workers=100; Timeout=2000; Name="polite"}
    3 = @{Workers=300; Timeout=1000; Name="normal"}
    4 = @{Workers=500; Timeout=500;  Name="aggressive"}
    5 = @{Workers=1000;Timeout=200;  Name="insane"}
}
$Profile   = $TimingProfiles[$T]
$TIMEOUT   = $Profile.Timeout
$WORKERS   = $Profile.Workers

# ─────────────────────────────────────────────────────────────────────────────
# PORT DATABASE
# ─────────────────────────────────────────────────────────────────────────────
$ServiceDB = @{
    21="ftp"; 22="ssh"; 23="telnet"; 25="smtp"; 53="dns"; 69="tftp"
    79="finger"; 80="http"; 88="kerberos"; 110="pop3"; 111="rpcbind"
    119="nntp"; 135="msrpc"; 137="netbios-ns"; 139="netbios-ssn"
    143="imap"; 161="snmp"; 179="bgp"; 389="ldap"; 443="https"
    445="smb"; 465="smtps"; 500="isakmp"; 514="syslog"; 515="printer"
    587="submission"; 631="ipp"; 636="ldaps"; 873="rsync"; 993="imaps"
    995="pop3s"; 1080="socks"; 1433="ms-sql-s"; 1521="oracle"
    1723="pptp"; 2049="nfs"; 3000="http"; 3306="mysql"
    3389="ms-wbt-server"; 5432="postgresql"; 5900="vnc"
    5985="wsman"; 6379="redis"; 8080="http-proxy"; 8443="https-alt"
    8888="http"; 9200="elasticsearch"; 9090="http"; 11211="memcache"
    27017="mongod"; 50000="ibm-db2"
}

$Top100 = @(21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
            1723,3306,3389,5900,8080,8443,8888,9090,9200,27017,
            20,69,79,88,102,106,113,119,137,138,179,194,389,427,
            497,500,514,515,543,544,548,554,587,631,646,873,990,
            1025,1026,1027,1028,1433,1720,1755,1900,2000,2001,2049,
            2121,2717,3000,3128,3632,4899,5000,5009,5051,5060,5101,
            5190,5357,5432,5631,5666,5800,5985,6000,6001,6646,7070,
            8008,8009,8010,8031,8181,8192,49152,49153,49154,49155,49156)

$Top1000 = ($Top100 + (1..1024)) | Sort-Object -Unique | Select-Object -First 1000

# ─────────────────────────────────────────────────────────────────────────────
# TARGET PARSING
# ─────────────────────────────────────────────────────────────────────────────
function Expand-Targets {
    param([string]$TargetStr)
    $IPs = [System.Collections.Generic.List[string]]::new()

    foreach ($part in ($TargetStr -split ",")) {
        $part = $part.Trim()

        # CIDR
        if ($part -match "^(\d+\.\d+\.\d+\.\d+)/(\d+)$") {
            $baseIP  = $Matches[1]
            $prefix  = [int]$Matches[2]
            $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
            [Array]::Reverse($ipBytes)
            $ipInt   = [BitConverter]::ToUInt32($ipBytes, 0)
            $mask    = if ($prefix -eq 0) { 0 } else { ([uint32]0xFFFFFFFF -shl (32 - $prefix)) -band 0xFFFFFFFF }
            $netInt  = $ipInt -band $mask
            $hostMax = (-bnot $mask) -band 0xFFFFFFFF
            for ($i = 1; $i -lt $hostMax; $i++) {
                $hostInt = $netInt + $i
                $b = [BitConverter]::GetBytes([uint32]$hostInt)
                [Array]::Reverse($b)
                $IPs.Add("$($b[0]).$($b[1]).$($b[2]).$($b[3])")
            }
            continue
        }

        # Range e.g. 192.168.1.1-20
        if ($part -match "^([\d\.]+)-(\d+)$") {
            $base  = $Matches[1]
            $end   = [int]$Matches[2]
            $parts = $base -split "\."
            $start = [int]$parts[-1]
            $pfx   = ($parts[0..($parts.Count-2)]) -join "."
            for ($i = $start; $i -le $end; $i++) { $IPs.Add("$pfx.$i") }
            continue
        }

        # Single IP or hostname
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($part) |
                        Where-Object { $_.AddressFamily -eq "InterNetwork" } |
                        Select-Object -First 1
            if ($resolved) { $IPs.Add($resolved.ToString()) }
        } catch {
            Write-Color "[!] Could not resolve: $part" Yellow
        }
    }
    return $IPs
}

# ─────────────────────────────────────────────────────────────────────────────
# PORT PARSING
# ─────────────────────────────────────────────────────────────────────────────
function Expand-Ports {
    param([string]$PortStr)
    $ports = [System.Collections.Generic.List[int]]::new()
    if ($PortStr -eq "-") {
        return 1..65535
    }
    foreach ($part in ($PortStr -split ",")) {
        $part = $part.Trim()
        if ($part -match "^(\d+)-(\d+)$") {
            $s = [int]$Matches[1]; $e = [int]$Matches[2]
            for ($i = $s; $i -le $e; $i++) { $ports.Add($i) }
        } elseif ($part -match "^\d+$") {
            $ports.Add([int]$part)
        }
    }
    return ($ports | Sort-Object -Unique)
}

# ─────────────────────────────────────────────────────────────────────────────
# HOST DISCOVERY (TCP ping — no raw sockets in PS)
# ─────────────────────────────────────────────────────────────────────────────
function Test-HostUp {
    param([string]$IP, [int]$TimeoutMs = 1000)

    # Method 1: ICMP (uses .NET, no raw socket)
    try {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($IP, $TimeoutMs)
        if ($reply.Status -eq "Success") { return $true }
    } catch {}

    # Method 2: TCP ping on common ports
    foreach ($port in @(80, 443, 22, 445, 3389)) {
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $ar  = $tcp.BeginConnect($IP, $port, $null, $null)
            $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            if ($ok -and $tcp.Connected) { $tcp.Close(); return $true }
            $tcp.Close()
        } catch {}
    }
    return $false
}

# ─────────────────────────────────────────────────────────────────────────────
# TCP CONNECT SCAN
# ─────────────────────────────────────────────────────────────────────────────
function Test-TCPPort {
    param([string]$IP, [int]$Port, [int]$TimeoutMs = 1000)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tcp.Connected) {
            $tcp.Close()
            return "open"
        }
        $tcp.Close()
        # Check for connection refused (socket error)
        return "filtered"
    } catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq "ConnectionRefused") {
            return "closed"
        }
        return "filtered"
    } catch {
        return "filtered"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# UDP SCAN  (limited — no ICMP unreachable in pure PS)
# ─────────────────────────────────────────────────────────────────────────────
function Test-UDPPort {
    param([string]$IP, [int]$Port, [int]$TimeoutMs = 2000)

    # DNS probe
    $probes = @{
        53   = [byte[]](0x00,0x01,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,
                        0x00,0x01,0x00,0x01)
        161  = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,
                        0x63,0xa0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,
                        0x30,0x0e,0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,
                        0x01,0x00,0x05,0x00)
        500  = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00)
    }

    try {
        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Client.ReceiveTimeout = $TimeoutMs

        $probe = if ($probes.ContainsKey($Port)) { $probes[$Port] } else { [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00) }
        $udp.Send($probe, $probe.Length, $IP, $Port) | Out-Null

        try {
            $ep   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $data = $udp.Receive([ref]$ep)
            $udp.Close()
            if ($data -and $data.Length -gt 0) { return "open" }
        } catch [System.Net.Sockets.SocketException] {
            $udp.Close()
            # WSAECONNRESET = ICMP port unreachable on Windows
            if ($_.Exception.SocketErrorCode -eq "ConnectionReset") { return "closed" }
            return "open|filtered"
        }
        return "open|filtered"
    } catch {
        return "filtered"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# BANNER GRABBING
# ─────────────────────────────────────────────────────────────────────────────
function Get-Banner {
    param([string]$IP, [int]$Port, [int]$TimeoutMs = 3000)

    $HttpPorts = @(80,8080,8443,443,8888,9090,9200,5000,3000,7070,8000)
    $SslPorts  = @(443,8443,993,995,465,636)

    try {
        $tcp  = [System.Net.Sockets.TcpClient]::new()
        $ar   = $tcp.BeginConnect($IP, $Port, $null, $null)
        $ok   = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not ($ok -and $tcp.Connected)) { $tcp.Close(); return "" }

        $stream = $tcp.GetStream()
        $stream.ReadTimeout  = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        # Wrap SSL if needed
        if ($Port -in $SslPorts) {
            try {
                $sslStream = [System.Net.Security.SslStream]::new(
                    $stream, $false,
                    { param($s,$c,$ch,$e) $true }  # ignore cert errors
                )
                $sslStream.AuthenticateAsClient($IP)
                $stream = $sslStream
            } catch {}
        }

        # Send HTTP probe for HTTP ports
        if ($Port -in $HttpPorts) {
            $req = "GET / HTTP/1.0`r`nHost: $IP`r`nUser-Agent: Mozilla/5.0`r`nConnection: close`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
            $stream.Write($bytes, 0, $bytes.Length)
        }

        # Read response
        $buf = [byte[]]::new(8192)
        $total = [System.Text.StringBuilder]::new()
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMs -and $total.Length -lt 4096) {
            if ($stream.DataAvailable) {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -eq 0) { break }
                $total.Append([System.Text.Encoding]::UTF8.GetString($buf, 0, $n)) | Out-Null
            } else {
                Start-Sleep -Milliseconds 50
                if ($stopwatch.ElapsedMilliseconds -gt 1000 -and $total.Length -gt 0) { break }
            }
        }

        $tcp.Close()
        return $total.ToString()
    } catch {
        return ""
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# VERSION FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────
function Get-ServiceVersion {
    param([string]$Banner, [int]$Port)

    $patterns = @(
        @{ Re = "SSH-[\d\.]+-OpenSSH[_\-](\S+)";  Tmpl = "OpenSSH {1}" }
        @{ Re = "SSH-[\d\.]+-(\S+)";               Tmpl = "SSH {1}" }
        @{ Re = "Server:\s*(Apache[^\r\n]+)";      Tmpl = "{1}" }
        @{ Re = "Server:\s*(nginx[^\r\n]+)";       Tmpl = "{1}" }
        @{ Re = "Server:\s*(Microsoft-IIS[^\r\n]+)";Tmpl = "{1}" }
        @{ Re = "Server:\s*([^\r\n]+)";            Tmpl = "{1}" }
        @{ Re = "220[\s\-]+(.*?)\r?\n";            Tmpl = "FTP/SMTP: {1}" }
        @{ Re = "redis_version:(\S+)";             Tmpl = "Redis {1}" }
        @{ Re = '"version"\s*:\s*"([^"]+)"';       Tmpl = "Elasticsearch {1}" }
        @{ Re = "STAT version (\S+)";              Tmpl = "Memcached {1}" }
        @{ Re = '[Vv]ersion[:\s]+([\d\.]+)';       Tmpl = "v{1}" }
    )

    foreach ($p in $patterns) {
        if ($Banner -match $p.Re) {
            $result = $p.Tmpl
            for ($i = 1; $i -le $Matches.Count - 1; $i++) {
                $result = $result.Replace("{$i}", $Matches[$i].Trim())
            }
            return $result.Substring(0, [Math]::Min(80, $result.Length))
        }
    }

    # Fallback: first meaningful line
    $svc = if ($ServiceDB.ContainsKey($Port)) { $ServiceDB[$Port] } else { "unknown" }
    $firstLine = ($Banner -split "`n")[0].Trim()
    if ($firstLine.Length -gt 3) {
        return "$svc`: $($firstLine.Substring(0, [Math]::Min(60, $firstLine.Length)))"
    }
    return $svc
}

# ─────────────────────────────────────────────────────────────────────────────
# OS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
function Get-OSGuess {
    param([string]$IP)

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
                default         { "Unknown" }
            }
            return @{ OS = $os; TTL = $ttl; Method = "icmp-ttl" }
        }
    } catch {}

    return @{ OS = "Unknown"; TTL = 0; Method = "none" }
}

# ─────────────────────────────────────────────────────────────────────────────
# EMBEDDED SCRIPT CHECKS (NSE-equivalent)
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-HttpGet {
    param([string]$IP, [int]$Port, [string]$Path="/", [int]$TimeoutMs=5000)

    $ssl = $Port -in @(443,8443)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $tcp.Close()
            return @{Status=0; Headers=@{}; Body=""}
        }

        $stream = $tcp.GetStream()
        $stream.ReadTimeout  = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        if ($ssl) {
            try {
                $sslStream = [System.Net.Security.SslStream]::new(
                    $stream, $false, { $true })
                $sslStream.AuthenticateAsClient($IP)
                $stream = $sslStream
            } catch {}
        }

        $req   = "GET $Path HTTP/1.0`r`nHost: $IP`r`nUser-Agent: Mozilla/5.0`r`nConnection: close`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)

        $buf   = [byte[]]::new(32768)
        $total = [System.Text.StringBuilder]::new()
        $sw    = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $TimeoutMs -and $total.Length -lt 32768) {
            if ($stream.DataAvailable) {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -eq 0) { break }
                $total.Append([System.Text.Encoding]::UTF8.GetString($buf, 0, $n)) | Out-Null
            } else {
                Start-Sleep -Milliseconds 50
                if ($sw.ElapsedMilliseconds -gt 2000 -and $total.Length -gt 0) { break }
            }
        }
        $tcp.Close()

        $raw     = $total.ToString()
        $lines   = $raw -split "`r`n"
        $status  = 0
        $headers = @{}
        $bodyIdx = 0

        if ($lines[0] -match "HTTP/[\d\.]+ (\d+)") { $status = [int]$Matches[1] }
        for ($i = 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -eq "") { $bodyIdx = $i + 1; break }
            if ($lines[$i] -match "^([^:]+):\s*(.+)$") {
                $headers[$Matches[1].ToLower()] = $Matches[2].Trim()
            }
        }
        $body = $lines[$bodyIdx..($lines.Count-1)] -join "`r`n"

        return @{ Status=$status; Headers=$headers; Body=$body }
    } catch {
        return @{ Status=0; Headers=@{}; Body="" }
    }
}

function Run-Scripts {
    param([string]$IP, [int]$Port, [string]$Service, [string]$Banner,
          [string[]]$Categories)

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $runAll  = $Categories -contains "all" -or $Categories.Count -eq 0

    function Wants([string]$cat) {
        return $runAll -or $Categories -contains $cat
    }

    function Add-Result([string]$Name, [string]$Output,
                        [bool]$Vuln=$false, [string]$CVE="") {
        $results.Add([PSCustomObject]@{
            Name   = $Name
            Output = $Output
            Vuln   = $Vuln
            CVE    = $CVE
        })
    }

    $isHttp    = $Service -in @("http","https","http-proxy","https-alt") -or
                 $Port -in @(80,8080,8443,443,8888,9090,9200,5000,3000,7070,8000)
    $isSMB     = $Service -in @("smb","netbios-ssn","microsoft-ds") -or $Port -in @(139,445)
    $isFTP     = $Service -eq "ftp" -or $Port -eq 21
    $isSMTP    = $Service -in @("smtp","submission","smtps") -or $Port -in @(25,465,587)
    $isDNS     = $Service -eq "dns" -or $Port -eq 53
    $isSNMP    = $Service -eq "snmp" -or $Port -eq 161
    $isRDP     = $Service -eq "ms-wbt-server" -or $Port -eq 3389
    $isSSL     = $Service -in @("https","imaps","pop3s","smtps") -or $Port -in @(443,8443,993,995,465)
    $isRedis   = $Service -eq "redis" -or $Port -eq 6379
    $isMySQL   = $Service -eq "mysql" -or $Port -eq 3306
    $isElastic = $Port -eq 9200

    # ── Banner ────────────────────────────────────────────────────────────────
    if ((Wants "default") -and $Banner) {
        $firstLine = ($Banner -split "`n")[0].Trim()
        if ($firstLine.Length -gt 2) {
            Add-Result "banner" $firstLine.Substring(0,[Math]::Min(120,$firstLine.Length))
        }
    }

    # ── HTTP Scripts ──────────────────────────────────────────────────────────
    if ($isHttp -and (Wants "default")) {
        $resp = Invoke-HttpGet -IP $IP -Port $Port

        # http-title
        if ($resp.Body -match "<title[^>]*>(.*?)</title>") {
            Add-Result "http-title" $Matches[1].Trim().Substring(0,[Math]::Min(100,$Matches[1].Trim().Length))
        }

        # http-server-header
        if ($resp.Headers.ContainsKey("server")) {
            Add-Result "http-server-header" $resp.Headers["server"]
        }

        # http-security-headers
        if (Wants "safe") {
            $secHeaders = @("x-frame-options","x-xss-protection",
                            "x-content-type-options","strict-transport-security",
                            "content-security-policy","referrer-policy")
            $missing = $secHeaders | Where-Object { -not $resp.Headers.ContainsKey($_) }
            if ($missing) {
                Add-Result "http-security-headers" "Missing: $($missing -join ', ')" $true
            } else {
                Add-Result "http-security-headers" "All key security headers present"
            }
        }

        # http-cors
        if ((Wants "safe") -and $resp.Headers.ContainsKey("access-control-allow-origin")) {
            $acao = $resp.Headers["access-control-allow-origin"]
            $vuln = $acao -eq "*"
            Add-Result "http-cors" "CORS: $acao" $vuln
        }

        # http-waf-detect
        if (Wants "safe") {
            $allText = ($resp.Headers.Values -join " ") + $resp.Body.Substring(0,[Math]::Min(500,$resp.Body.Length))
            $allText = $allText.ToLower()
            $wafs = @{
                "Cloudflare"  = @("cf-ray","cloudflare")
                "AWS WAF"     = @("x-amzn-requestid","awselb")
                "ModSecurity" = @("mod_security","modsecurity")
                "F5 BIG-IP"   = @("bigip","f5-bigip")
                "Akamai"      = @("akamai","akamaighost")
            }
            foreach ($wafName in $wafs.Keys) {
                $found = $wafs[$wafName] | Where-Object { $allText -like "*$_*" }
                if ($found) {
                    Add-Result "http-waf-detect" "WAF detected: $wafName"
                    break
                }
            }
        }

        # http-auth
        if ($resp.Status -eq 401 -and $resp.Headers.ContainsKey("www-authenticate")) {
            Add-Result "http-auth" "Authentication required: $($resp.Headers['www-authenticate'])"
        }

        # http-robots.txt
        if (Wants "safe") {
            $r2 = Invoke-HttpGet -IP $IP -Port $Port -Path "/robots.txt"
            if ($r2.Status -eq 200 -and $r2.Body -match "Disallow:") {
                $disallow = ($r2.Body -split "`n" | Where-Object { $_ -match "^Disallow:" } |
                             Select-Object -First 5) -join ", "
                Add-Result "http-robots.txt" "Disallowed: $disallow"
            }
        }

        # http-git
        if (Wants "vuln") {
            $r3 = Invoke-HttpGet -IP $IP -Port $Port -Path "/.git/HEAD"
            if ($r3.Status -eq 200 -and $r3.Body -match "ref:") {
                Add-Result "http-git" "Git repository exposed at /.git/HEAD" $true
            }
        }

        # http-passwd (directory traversal)
        if (Wants "vuln") {
            foreach ($path in @("/../../../etc/passwd","/%2e%2e/%2e%2e/etc/passwd")) {
                $r4 = Invoke-HttpGet -IP $IP -Port $Port -Path $path
                if ($r4.Status -eq 200 -and $r4.Body -match "root:x:") {
                    Add-Result "http-passwd" "Directory traversal: $path" $true
                    break
                }
            }
        }

        # http-internal-ip-disclosure
        if (Wants "vuln") {
            if ($resp.Body -match "\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b") {
                $leakedIP = $Matches[0]
                if ($leakedIP -ne $IP) {
                    Add-Result "http-internal-ip-disclosure" "Internal IP leaked: $leakedIP" $true
                }
            }
        }
    }

    # ── SMB Scripts ───────────────────────────────────────────────────────────
    if ($isSMB -and (Wants "default")) {
        try {
            $smb = [System.Net.Sockets.TcpClient]::new()
            $ar  = $smb.BeginConnect($IP, $Port, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne(3000, $false) -and $smb.Connected) {
                $stream = $smb.GetStream()
                $stream.ReadTimeout = 3000

                # SMBv1 negotiate
                $negotiate = [byte[]](
                    0x00,0x00,0x00,0x85,
                    0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,
                    0x18,0x53,0xC8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0xFF,0xFE,0x00,0x00,0x00,0x00,
                    0x00,0x62,0x00,
                    0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00,
                    0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x30,0x30,0x32,0x00,
                    0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x3F,0x3F,0x3F,0x00
                )
                $stream.Write($negotiate, 0, $negotiate.Length)

                $buf  = [byte[]]::new(4096)
                $n    = $stream.Read($buf, 0, $buf.Length)
                $smb.Close()

                if ($n -gt 36 -and $buf[4] -eq 0xFF -and $buf[5] -eq 0x53) {
                    # SMBv1 supported
                    Add-Result "smb-protocols" "SMBv1 supported — may be vulnerable to EternalBlue" $true "CVE-2017-0144"
                } else {
                    Add-Result "smb-protocols" "SMBv1 not detected (SMBv2/3 likely)"
                }
            }
        } catch {}

        # smb-vuln-ms17-010 (EternalBlue) — lightweight detection
        if (Wants "vuln") {
            try {
                $eb  = [System.Net.Sockets.TcpClient]::new()
                $ar2 = $eb.BeginConnect($IP, 445, $null, $null)
                if ($ar2.AsyncWaitHandle.WaitOne(3000, $false) -and $eb.Connected) {
                    $s2 = $eb.GetStream()
                    $s2.ReadTimeout = 3000

                    $pkt = [byte[]](
                        0x00,0x00,0x00,0x85,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,
                        0x18,0x01,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x08,0xFF,0xFE,0x00,0x00,0x40,0x00,0x00,0x62,0x00,
                        0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00,
                        0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x31,0x2E,0x30,0x00,
                        0x02,0x57,0x69,0x6E,0x64,0x6F,0x77,0x73,0x20,0x66,0x6F,0x72,0x20,
                        0x57,0x6F,0x72,0x6B,0x67,0x72,0x6F,0x75,0x70,0x73,0x20,0x33,0x2E,
                        0x31,0x61,0x00,0x02,0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,
                        0x00,0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x32,0x2E,0x31,0x00,0x02,
                        0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00
                    )
                    $s2.Write($pkt, 0, $pkt.Length)
                    $buf2 = [byte[]]::new(4096)
                    $n2   = $s2.Read($buf2, 0, $buf2.Length)
                    $eb.Close()

                    if ($n2 -gt 36 -and $buf2[4] -eq 0xFF -and $buf2[5] -eq 0x53) {
                        Add-Result "smb-vuln-ms17-010" "SMBv1 enabled — potentially vulnerable to EternalBlue/WannaCry. Verify patches." $true "CVE-2017-0144"
                    }
                }
            } catch {}
        }
    }

    # ── FTP Scripts ───────────────────────────────────────────────────────────
    if ($isFTP -and (Wants "default")) {
        try {
            $ftpConn = [System.Net.Sockets.TcpClient]::new()
            $ar3     = $ftpConn.BeginConnect($IP, 21, $null, $null)
            if ($ar3.AsyncWaitHandle.WaitOne(3000, $false) -and $ftpConn.Connected) {
                $fs   = $ftpConn.GetStream()
                $fs.ReadTimeout = 3000
                $buf3 = [byte[]]::new(1024)
                $n3   = $fs.Read($buf3, 0, $buf3.Length)
                $banFTP = [System.Text.Encoding]::ASCII.GetString($buf3, 0, $n3)

                # Anon login test
                $userBytes = [System.Text.Encoding]::ASCII.GetBytes("USER anonymous`r`n")
                $fs.Write($userBytes, 0, $userBytes.Length)
                $n3b = $fs.Read($buf3, 0, $buf3.Length)
                $r1FTP = [System.Text.Encoding]::ASCII.GetString($buf3, 0, $n3b)

                $passBytes = [System.Text.Encoding]::ASCII.GetBytes("PASS anonymous@`r`n")
                $fs.Write($passBytes, 0, $passBytes.Length)
                $n3c = $fs.Read($buf3, 0, $buf3.Length)
                $r2FTP = [System.Text.Encoding]::ASCII.GetString($buf3, 0, $n3c)
                $ftpConn.Close()

                if ($r2FTP -match "^230") {
                    Add-Result "ftp-anon" "Anonymous FTP login allowed!" $true
                } else {
                    Add-Result "ftp-anon" "Anonymous login denied"
                }

                # vsFTPd 2.3.4 backdoor check
                if ($banFTP -match "vsFTPd 2\.3\.4" -and (Wants "vuln")) {
                    Add-Result "ftp-vsftpd-backdoor" "vsFTPd 2.3.4 detected — check for backdoor on port 6200" $true "CVE-2011-2523"
                }
            }
        } catch {}
    }

    # ── SMTP Scripts ──────────────────────────────────────────────────────────
    if ($isSMTP -and (Wants "default")) {
        try {
            $smtpConn = [System.Net.Sockets.TcpClient]::new()
            $ar4      = $smtpConn.BeginConnect($IP, $Port, $null, $null)
            if ($ar4.AsyncWaitHandle.WaitOne(3000, $false) -and $smtpConn.Connected) {
                $ss   = $smtpConn.GetStream()
                $ss.ReadTimeout = 3000
                $buf4 = [byte[]]::new(4096)
                $ss.Read($buf4, 0, $buf4.Length) | Out-Null

                $ehlo = [System.Text.Encoding]::ASCII.GetBytes("EHLO zscan.local`r`n")
                $ss.Write($ehlo, 0, $ehlo.Length)
                $n4 = $ss.Read($buf4, 0, $buf4.Length)
                $ehloResp = [System.Text.Encoding]::ASCII.GetString($buf4, 0, $n4)
                $cmds = ($ehloResp -split "`n" | Where-Object { $_ -match "^250" } |
                          ForEach-Object { $_ -replace "^250[\-\s]",""} |
                          Select-Object -First 8) -join ", "
                Add-Result "smtp-commands" "EHLO response: $cmds"

                # Relay test
                if (Wants "vuln") {
                    $mailFrom = [System.Text.Encoding]::ASCII.GetBytes("MAIL FROM:<test@zscan.local>`r`n")
                    $ss.Write($mailFrom, 0, $mailFrom.Length)
                    $ss.Read($buf4, 0, $buf4.Length) | Out-Null
                    $rcptTo = [System.Text.Encoding]::ASCII.GetBytes("RCPT TO:<test@external-example.com>`r`n")
                    $ss.Write($rcptTo, 0, $rcptTo.Length)
                    $n4b   = $ss.Read($buf4, 0, $buf4.Length)
                    $rcptR = [System.Text.Encoding]::ASCII.GetString($buf4, 0, $n4b)
                    if ($rcptR -match "^250") {
                        Add-Result "smtp-open-relay" "Server may be an open mail relay!" $true
                    } else {
                        Add-Result "smtp-open-relay" "Relay denied"
                    }
                }
                $smtpConn.Close()
            }
        } catch {}

        # VRFY user enum
        if (Wants "auth") {
            try {
                $vrfyConn = [System.Net.Sockets.TcpClient]::new()
                $ar5      = $vrfyConn.BeginConnect($IP, $Port, $null, $null)
                if ($ar5.AsyncWaitHandle.WaitOne(3000, $false) -and $vrfyConn.Connected) {
                    $vs   = $vrfyConn.GetStream()
                    $vs.ReadTimeout = 3000
                    $buf5 = [byte[]]::new(1024)
                    $vs.Read($buf5, 0, $buf5.Length) | Out-Null
                    $vrfy = [System.Text.Encoding]::ASCII.GetBytes("VRFY root`r`n")
                    $vs.Write($vrfy, 0, $vrfy.Length)
                    $n5 = $vs.Read($buf5, 0, $buf5.Length)
                    $vrfyR = [System.Text.Encoding]::ASCII.GetString($buf5, 0, $n5)
                    $vrfyConn.Close()
                    if ($vrfyR -match "^(250|252)") {
                        Add-Result "smtp-enum-users" "VRFY command accepted — user enumeration possible" $true
                    } else {
                        Add-Result "smtp-enum-users" "VRFY command rejected"
                    }
                }
            } catch {}
        }
    }

    # ── RDP Scripts ───────────────────────────────────────────────────────────
    if ($isRDP -and (Wants "default")) {
        try {
            $rdpConn = [System.Net.Sockets.TcpClient]::new()
            $ar6     = $rdpConn.BeginConnect($IP, 3389, $null, $null)
            if ($ar6.AsyncWaitHandle.WaitOne(3000, $false) -and $rdpConn.Connected) {
                $rs   = $rdpConn.GetStream()
                $rs.ReadTimeout = 3000
                $x224 = [byte[]](0x03,0x00,0x00,0x13,0x0E,0xE0,0x00,0x00,
                                  0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x03,
                                  0x00,0x00,0x00)
                $rs.Write($x224, 0, $x224.Length)
                $buf6 = [byte[]]::new(1024)
                $n6   = $rs.Read($buf6, 0, $buf6.Length)
                $rdpConn.Close()
                if ($n6 -gt 0 -and $buf6[0] -eq 0x03) {
                    Add-Result "rdp-enum-encryption" "RDP responding — verify NLA/CredSSP is enforced"
                }
            }
        } catch {}
    }

    # ── SSL/TLS Scripts ───────────────────────────────────────────────────────
    if ($isSSL -and (Wants "default")) {
        try {
            $certReq = [System.Net.HttpWebRequest]::CreateHttp("https://${IP}:${Port}/")
            $certReq.Timeout = 5000
            $certReq.ServerCertificateValidationCallback = { $true }
            try {
                $certResp = $certReq.GetResponse()
                $cert = $certReq.ServicePoint.Certificate
                if ($cert) {
                    $expiry = [datetime]::ParseExact(
                        $cert.GetExpirationDateString(),
                        "M/d/yyyy H:mm:ss", $null)
                    $daysLeft = ($expiry - (Get-Date)).Days
                    $cn       = $cert.Subject
                    if ($daysLeft -lt 0) {
                        Add-Result "ssl-cert" "EXPIRED $([Math]::Abs($daysLeft))d ago! CN=$cn" $true
                    } elseif ($daysLeft -lt 30) {
                        Add-Result "ssl-cert" "Expires in ${daysLeft}d | $cn" $true
                    } else {
                        Add-Result "ssl-cert" "Expires in ${daysLeft}d | $cn"
                    }
                }
                $certResp.Close()
            } catch {}
        } catch {}
    }

    # ── Redis Scripts ─────────────────────────────────────────────────────────
    if ($isRedis -and (Wants "default")) {
        try {
            $redisConn = [System.Net.Sockets.TcpClient]::new()
            $ar7       = $redisConn.BeginConnect($IP, 6379, $null, $null)
            if ($ar7.AsyncWaitHandle.WaitOne(3000, $false) -and $redisConn.Connected) {
                $rds  = $redisConn.GetStream()
                $rds.ReadTimeout = 3000
                $cmd  = [System.Text.Encoding]::ASCII.GetBytes("*1`r`n`$4`r`nINFO`r`n")
                $rds.Write($cmd, 0, $cmd.Length)
                $buf7 = [byte[]]::new(4096)
                $n7   = $rds.Read($buf7, 0, $buf7.Length)
                $rInfo = [System.Text.Encoding]::ASCII.GetString($buf7, 0, $n7)
                $redisConn.Close()
                if ($rInfo -match "redis_version") {
                    $ver = if ($rInfo -match "redis_version:(\S+)") { $Matches[1] } else { "?" }
                    Add-Result "redis-info" "Redis $ver — accessible without authentication!" $true
                }
            }
        } catch {}
    }

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    if ($isElastic -and (Wants "default")) {
        $esResp = Invoke-HttpGet -IP $IP -Port 9200 -Path "/"
        if ($esResp.Body -match "elasticsearch|cluster_name") {
            Add-Result "elasticsearch-info" "Elasticsearch accessible without authentication!" $true
        }
    }

    # ── MySQL ─────────────────────────────────────────────────────────────────
    if ($isMySQL -and (Wants "default")) {
        try {
            $myConn = [System.Net.Sockets.TcpClient]::new()
            $ar8    = $myConn.BeginConnect($IP, 3306, $null, $null)
            if ($ar8.AsyncWaitHandle.WaitOne(3000, $false) -and $myConn.Connected) {
                $ms   = $myConn.GetStream()
                $ms.ReadTimeout = 3000
                $buf8 = [byte[]]::new(1024)
                $n8   = $ms.Read($buf8, 0, $buf8.Length)
                $myConn.Close()
                if ($n8 -gt 5 -and $buf8[4] -eq 0x0A) {
                    $verEnd = 5
                    while ($verEnd -lt $n8 -and $buf8[$verEnd] -ne 0x00) { $verEnd++ }
                    $ver = [System.Text.Encoding]::ASCII.GetString($buf8, 5, $verEnd - 5)
                    Add-Result "mysql-info" "MySQL version: $ver"
                }
            }
        } catch {}
    }

    # ── NTP Info ──────────────────────────────────────────────────────────────
    if (($Port -eq 123) -and (Wants "default")) {
        try {
            $ntpUdp = [System.Net.Sockets.UdpClient]::new()
            $ntpUdp.Client.ReceiveTimeout = 3000
            $ntpReq = [byte[]]::new(48); $ntpReq[0] = 0x1b
            $ntpUdp.Send($ntpReq, 48, $IP, 123) | Out-Null
            $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $resp = $ntpUdp.Receive([ref]$ep)
            $ntpUdp.Close()
            if ($resp.Count -ge 48) {
                $ver = ($resp[0] -shr 3) -band 0x7
                $stratum = $resp[1]
                $tsInt = [BitConverter]::ToUInt32([byte[]]($resp[43],$resp[42],$resp[41],$resp[40]), 0)
                if ($tsInt -gt 2208988800) {
                    $dt = (Get-Date "1/1/1900").AddSeconds($tsInt)
                    Add-Result "ntp-info" "NTPv$ver stratum=$stratum time=$($dt.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                }
            }
        } catch {}
        # ntp-monlist CVE-2013-5211
        if (Wants "vuln") {
            try {
                $nlUdp = [System.Net.Sockets.UdpClient]::new()
                $nlUdp.Client.ReceiveTimeout = 3000
                $nlReq = [byte[]](0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00)
                $nlUdp.Send($nlReq, $nlReq.Length, $IP, 123) | Out-Null
                $ep2 = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                $resp2 = $nlUdp.Receive([ref]$ep2)
                $nlUdp.Close()
                if ($resp2.Count -gt 100) {
                    Add-Result "ntp-monlist" "monlist enabled — DDoS amplification! ($($resp2.Count)B response)" $true "CVE-2013-5211"
                }
            } catch {}
        }
    }

    # ── IMAP Capabilities ─────────────────────────────────────────────────────
    if (($Port -in @(143,993)) -and (Wants "default")) {
        try {
            $imapConn = [System.Net.Sockets.TcpClient]::new()
            $arI = $imapConn.BeginConnect($IP, $Port, $null, $null)
            if ($arI.AsyncWaitHandle.WaitOne(3000,$false) -and $imapConn.Connected) {
                $is = $imapConn.GetStream(); $is.ReadTimeout = 3000
                $ibuf = [byte[]]::new(2048)
                $is.Read($ibuf, 0, $ibuf.Length) | Out-Null
                $capBytes = [System.Text.Encoding]::ASCII.GetBytes("a001 CAPABILITY`r`n")
                $is.Write($capBytes, 0, $capBytes.Length)
                $n = $is.Read($ibuf, 0, $ibuf.Length)
                $imapConn.Close()
                $caps = [System.Text.Encoding]::ASCII.GetString($ibuf, 0, $n)
                $capLine = ($caps -split "`n" | Where-Object { $_ -match "CAPABILITY" } | Select-Object -First 1) -replace "\* CAPABILITY",""
                Add-Result "imap-capabilities" $capLine.Trim().Substring(0,[Math]::Min(100,$capLine.Trim().Length))
            }
        } catch {}
    }

    # ── POP3 Capabilities ─────────────────────────────────────────────────────
    if (($Port -in @(110,995)) -and (Wants "default")) {
        try {
            $popConn = [System.Net.Sockets.TcpClient]::new()
            $arP = $popConn.BeginConnect($IP, $Port, $null, $null)
            if ($arP.AsyncWaitHandle.WaitOne(3000,$false) -and $popConn.Connected) {
                $ps = $popConn.GetStream(); $ps.ReadTimeout = 3000
                $pbuf = [byte[]]::new(1024)
                $ps.Read($pbuf, 0, $pbuf.Length) | Out-Null
                $capaBytes = [System.Text.Encoding]::ASCII.GetBytes("CAPA`r`n")
                $ps.Write($capaBytes, 0, $capaBytes.Length)
                $pn = $ps.Read($pbuf, 0, $pbuf.Length)
                $popConn.Close()
                $pcaps = [System.Text.Encoding]::ASCII.GetString($pbuf, 0, $pn)
                $items = ($pcaps -split "`n" | Where-Object { $_ -match "^\w" } | Select-Object -First 6) -join ", "
                Add-Result "pop3-capabilities" "Capabilities: $items"
            }
        } catch {}
    }

    # ── LDAP Anonymous Bind ────────────────────────────────────────────────────
    if (($Port -in @(389,636,3268,3269)) -and (Wants "default")) {
        try {
            $ldapConn = [System.Net.Sockets.TcpClient]::new()
            $arL = $ldapConn.BeginConnect($IP, $Port, $null, $null)
            if ($arL.AsyncWaitHandle.WaitOne(3000,$false) -and $ldapConn.Connected) {
                $ls = $ldapConn.GetStream(); $ls.ReadTimeout = 3000
                $ldapBind = [byte[]](0x30,0x0c,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x03,0x04,0x00,0x80,0x00)
                $ls.Write($ldapBind, 0, $ldapBind.Length)
                $lbuf = [byte[]]::new(128)
                $ln = $ls.Read($lbuf, 0, $lbuf.Length)
                $ldapConn.Close()
                if ($ln -gt 7 -and $lbuf[7] -eq 0) {
                    Add-Result "ldap-rootdse" "LDAP anonymous bind accepted — unauthenticated access" $true
                } else {
                    Add-Result "ldap-rootdse" "LDAP anonymous bind rejected"
                }
            }
        } catch {}
    }

    # ── Telnet ─────────────────────────────────────────────────────────────────
    if (($Port -eq 23) -and (Wants "default")) {
        try {
            $telConn = [System.Net.Sockets.TcpClient]::new()
            $arTel = $telConn.BeginConnect($IP, 23, $null, $null)
            if ($arTel.AsyncWaitHandle.WaitOne(3000,$false) -and $telConn.Connected) {
                $ts = $telConn.GetStream(); $ts.ReadTimeout = 3000
                $tbuf = [byte[]]::new(512)
                $tn = $ts.Read($tbuf, 0, $tbuf.Length)
                $telConn.Close()
                # Strip telnet IAC bytes (0xFF sequences)
                $cleaned = [System.Collections.Generic.List[byte]]::new()
                $i = 0
                while ($i -lt $tn) {
                    if ($tbuf[$i] -eq 0xFF -and $i+2 -lt $tn) { $i += 3 }
                    else { $cleaned.Add($tbuf[$i]); $i++ }
                }
                $banTel = [System.Text.Encoding]::ASCII.GetString($cleaned.ToArray()).Trim()
                Add-Result "telnet-ntlm-info" "Telnet (cleartext): $($banTel.Substring(0,[Math]::Min(80,$banTel.Length)))" $true
            }
        } catch {}
    }

    # ── RSYNC List Modules ─────────────────────────────────────────────────────
    if (($Port -eq 873) -and (Wants "default")) {
        try {
            $rsConn = [System.Net.Sockets.TcpClient]::new()
            $arRs = $rsConn.BeginConnect($IP, 873, $null, $null)
            if ($arRs.AsyncWaitHandle.WaitOne(3000,$false) -and $rsConn.Connected) {
                $rss = $rsConn.GetStream(); $rss.ReadTimeout = 3000
                $rsbuf = [byte[]]::new(4096)
                $rss.Read($rsbuf, 0, $rsbuf.Length) | Out-Null
                $rss.Write([byte[]](0x0a), 0, 1)
                $rn = $rss.Read($rsbuf, 0, $rsbuf.Length)
                $rsConn.Close()
                $mods = [System.Text.Encoding]::ASCII.GetString($rsbuf, 0, $rn)
                $modList = ($mods -split "`n" | Where-Object { $_ -match "`t" } | ForEach-Object { ($_ -split "`t")[0].Trim() } | Select-Object -First 5) -join ", "
                if ($modList) { Add-Result "rsync-list-modules" "Modules: $modList" $true }
            }
        } catch {}
    }

    # ── Docker Remote API ─────────────────────────────────────────────────────
    if (($Port -in @(2375,2376)) -and (Wants "default")) {
        $dResp = Invoke-HttpGet -IP $IP -Port $Port -Path "/version"
        if ($dResp.Body -match '"Version"' -or $dResp.Body -match 'docker') {
            $dVer = if ($dResp.Body -match '"Version":"([^"]+)"') { $Matches[1] } else { "?" }
            $dApi = if ($dResp.Body -match '"ApiVersion":"([^"]+)"') { $Matches[1] } else { "?" }
            Add-Result "docker-version" "Docker $dVer API $dApi — unauthenticated daemon!" ($Port -eq 2375)
        }
    }

    # ── Kubernetes API ─────────────────────────────────────────────────────────
    if (($Port -in @(6443,8001,10250)) -and (Wants "default")) {
        if ($Port -eq 10250) {
            $k8sR = Invoke-HttpGet -IP $IP -Port $Port -Path "/pods"
            if ($k8sR.Body -match "pods|containers") {
                Add-Result "kubernetes-kubelet" "Kubelet API unauthenticated — pod enumeration!" $true
            }
        } else {
            $k8sR2 = Invoke-HttpGet -IP $IP -Port $Port -Path "/api/v1/namespaces"
            if ($k8sR2.Body -match "items|namespaces") {
                Add-Result "kubernetes-api" "Kubernetes API unauthenticated — full cluster access!" $true
            }
        }
    }

    # ── MQTT ───────────────────────────────────────────────────────────────────
    if (($Port -in @(1883,8883)) -and (Wants "default")) {
        try {
            $mqConn = [System.Net.Sockets.TcpClient]::new()
            $arMq = $mqConn.BeginConnect($IP, $Port, $null, $null)
            if ($arMq.AsyncWaitHandle.WaitOne(3000,$false) -and $mqConn.Connected) {
                $mqs = $mqConn.GetStream(); $mqs.ReadTimeout = 3000
                $cid = [System.Text.Encoding]::ASCII.GetBytes("zscan")
                $mqPkt = [byte[]](0x10,(10+2+$cid.Length),0x00,0x04) + [System.Text.Encoding]::ASCII.GetBytes("MQTT") + [byte[]](0x04,0x00,0x00,0x3c,0x00,$cid.Length) + $cid
                $mqs.Write($mqPkt, 0, $mqPkt.Length)
                $mqbuf = [byte[]]::new(10)
                $mqn = $mqs.Read($mqbuf, 0, $mqbuf.Length)
                $mqConn.Close()
                if ($mqn -ge 4 -and $mqbuf[0] -eq 0x20) {
                    if ($mqbuf[3] -eq 0) { Add-Result "mqtt-subscribe" "MQTT broker accepts anonymous connections" $true }
                    else { Add-Result "mqtt-subscribe" "MQTT broker requires auth (rc=$($mqbuf[3]))" }
                }
            }
        } catch {}
    }

    # ── CouchDB ────────────────────────────────────────────────────────────────
    if (($Port -eq 5984) -and (Wants "default")) {
        $cdbR = Invoke-HttpGet -IP $IP -Port $Port -Path "/"
        if ($cdbR.Body -match "couchdb") {
            $cdbVer = if ($cdbR.Body -match '"version"\s*:\s*"([^"]+)"') { $Matches[1] } else { "?" }
            Add-Result "couchdb-databases" "CouchDB $cdbVer — unauthenticated access" $true
            $dbsR = Invoke-HttpGet -IP $IP -Port $Port -Path "/_all_dbs"
            if ($dbsR.Status -eq 200 -and $dbsR.Body -match "\[") {
                $dbs = ([regex]::Matches($dbsR.Body, '"([^"]+)"') | Select-Object -First 5 | ForEach-Object { $_.Groups[1].Value }) -join ", "
                Add-Result "couchdb-databases" "Databases: $dbs"
            }
        }
    }

    # ── PostgreSQL Empty Password ──────────────────────────────────────────────
    if (($Port -eq 5432) -and (Wants "auth")) {
        try {
            $pgConn = [System.Net.Sockets.TcpClient]::new()
            $arPg = $pgConn.BeginConnect($IP, 5432, $null, $null)
            if ($arPg.AsyncWaitHandle.WaitOne(3000,$false) -and $pgConn.Connected) {
                $pgs = $pgConn.GetStream(); $pgs.ReadTimeout = 3000
                $user = [System.Text.Encoding]::ASCII.GetBytes("postgres")
                $pgBody = [byte[]](0x00,0x00,0x03,0x00) + [System.Text.Encoding]::ASCII.GetBytes("user`0") + $user + [byte[]](0x00) + [System.Text.Encoding]::ASCII.GetBytes("database`0") + $user + [byte[]](0x00,0x00)
                $pgLen = [BitConverter]::GetBytes([int32](4 + $pgBody.Length)); [Array]::Reverse($pgLen)
                $pgs.Write($pgLen + $pgBody, 0, $pgLen.Length + $pgBody.Length)
                $pgbuf = [byte[]]::new(64)
                $pgn = $pgs.Read($pgbuf, 0, $pgbuf.Length)
                $pgConn.Close()
                if ($pgn -ge 9 -and $pgbuf[0] -eq [byte][char]'R') {
                    $method = [BitConverter]::ToInt32([byte[]]($pgbuf[8],$pgbuf[7],$pgbuf[6],$pgbuf[5]),0)
                    if ($method -eq 0) { Add-Result "pgsql-empty-password" "PostgreSQL accepts unauthenticated connection (user=postgres)!" $true }
                    else { Add-Result "pgsql-empty-password" "PostgreSQL auth required (method=$method)" }
                }
            }
        } catch {}
    }

    # ── JDWP (Java Debug Wire Protocol) ───────────────────────────────────────
    if (($Port -in @(5005,8000,9009,4000)) -and (Wants "vuln")) {
        try {
            $jdConn = [System.Net.Sockets.TcpClient]::new()
            $arJd = $jdConn.BeginConnect($IP, $Port, $null, $null)
            if ($arJd.AsyncWaitHandle.WaitOne(3000,$false) -and $jdConn.Connected) {
                $jds = $jdConn.GetStream(); $jds.ReadTimeout = 3000
                $hs = [System.Text.Encoding]::ASCII.GetBytes("JDWP-Handshake")
                $jds.Write($hs, 0, $hs.Length)
                $jdbuf = [byte[]]::new(14)
                $jdn = $jds.Read($jdbuf, 0, $jdbuf.Length)
                $jdConn.Close()
                if ($jdn -eq 14 -and [System.Text.Encoding]::ASCII.GetString($jdbuf) -eq "JDWP-Handshake") {
                    Add-Result "jdwp-version" "JDWP open — Java debug port allows remote code execution!" $true
                }
            }
        } catch {}
    }

    # ── Modbus / ICS ───────────────────────────────────────────────────────────
    if (($Port -eq 502) -and (Wants "default")) {
        try {
            $mbConn = [System.Net.Sockets.TcpClient]::new()
            $arMb = $mbConn.BeginConnect($IP, 502, $null, $null)
            if ($arMb.AsyncWaitHandle.WaitOne(3000,$false) -and $mbConn.Connected) {
                $mbs = $mbConn.GetStream(); $mbs.ReadTimeout = 3000
                $mbReq = [byte[]](0x00,0x01,0x00,0x00,0x00,0x05,0x00,0x2b,0x0e,0x01,0x00)
                $mbs.Write($mbReq, 0, $mbReq.Length)
                $mbbuf = [byte[]]::new(256)
                $mbn = $mbs.Read($mbbuf, 0, $mbbuf.Length)
                $mbConn.Close()
                if ($mbn -gt 8) { Add-Result "modbus-discover" "Modbus/TCP ICS device — exposed SCADA protocol!" $true }
            }
        } catch {}
    }

    # ── Siemens S7 (ISO-TSAP port 102) ────────────────────────────────────────
    if (($Port -eq 102) -and (Wants "default")) {
        try {
            $s7Conn = [System.Net.Sockets.TcpClient]::new()
            $arS7 = $s7Conn.BeginConnect($IP, 102, $null, $null)
            if ($arS7.AsyncWaitHandle.WaitOne(3000,$false) -and $s7Conn.Connected) {
                $s7s = $s7Conn.GetStream(); $s7s.ReadTimeout = 3000
                $s7pkt = [byte[]](0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,0x00,0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02)
                $s7s.Write($s7pkt, 0, $s7pkt.Length)
                $s7buf = [byte[]]::new(256)
                $s7n = $s7s.Read($s7buf, 0, $s7buf.Length)
                $s7Conn.Close()
                if ($s7n -gt 5 -and $s7buf[5] -eq 0xd0) { Add-Result "s7-info" "Siemens S7 PLC — ICS device exposed!" $true }
            }
        } catch {}
    }

    # ── SIP Methods ────────────────────────────────────────────────────────────
    if (($Port -in @(5060,5061)) -and (Wants "default")) {
        try {
            $sipUdp = [System.Net.Sockets.UdpClient]::new()
            $sipUdp.Client.ReceiveTimeout = 3000
            $sipOpts = "OPTIONS sip:$IP SIP/2.0`r`nVia: SIP/2.0/UDP ${IP}:5060;branch=z9hG4bK-zs`r`nFrom: <sip:zscan@$IP>;tag=zs`r`nTo: <sip:$IP>`r`nCall-ID: zscan@$IP`r`nCSeq: 1 OPTIONS`r`nContent-Length: 0`r`n`r`n"
            $sipBytes = [System.Text.Encoding]::ASCII.GetBytes($sipOpts)
            $sipUdp.Send($sipBytes, $sipBytes.Length, $IP, $Port) | Out-Null
            $sipEp = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $sipResp = [System.Text.Encoding]::ASCII.GetString($sipUdp.Receive([ref]$sipEp))
            $sipUdp.Close()
            $allow = ($sipResp -split "`r`n" | Where-Object { $_ -match "^Allow:" } | Select-Object -First 1) -replace "Allow:\s*",""
            $sipSrv = ($sipResp -split "`r`n" | Where-Object { $_ -match "^Server:" } | Select-Object -First 1) -replace "Server:\s*",""
            Add-Result "sip-methods" "Methods: $allow | Server: $sipSrv"
        } catch {}
    }

    # ── RTSP Methods ───────────────────────────────────────────────────────────
    if (($Port -in @(554,8554)) -and (Wants "default")) {
        try {
            $rtspConn = [System.Net.Sockets.TcpClient]::new()
            $arRt = $rtspConn.BeginConnect($IP, $Port, $null, $null)
            if ($arRt.AsyncWaitHandle.WaitOne(3000,$false) -and $rtspConn.Connected) {
                $rts = $rtspConn.GetStream(); $rts.ReadTimeout = 3000
                $rtReq = [System.Text.Encoding]::ASCII.GetBytes("OPTIONS rtsp://${IP}:${Port}/ RTSP/1.0`r`nCSeq: 1`r`n`r`n")
                $rts.Write($rtReq, 0, $rtReq.Length)
                $rtbuf = [byte[]]::new(2048)
                $rtn = $rts.Read($rtbuf, 0, $rtbuf.Length)
                $rtspConn.Close()
                $rtResp = [System.Text.Encoding]::ASCII.GetString($rtbuf, 0, $rtn)
                if ($rtResp -match "RTSP") {
                    $pub = ($rtResp -split "`r`n" | Where-Object { $_ -match "^Public:" } | Select-Object -First 1) -replace "Public:\s*",""
                    $rtSrv = ($rtResp -split "`r`n" | Where-Object { $_ -match "^Server:" } | Select-Object -First 1) -replace "Server:\s*",""
                    Add-Result "rtsp-methods" "Server: $rtSrv | Methods: $pub"
                }
            }
        } catch {}
    }

    # ── HTTP Extra Scripts ─────────────────────────────────────────────────────
    if ($isHttp -and (Wants "vuln")) {
        # http-trace
        try {
            $trConn = [System.Net.Sockets.TcpClient]::new()
            $arTr = $trConn.BeginConnect($IP, $Port, $null, $null)
            if ($arTr.AsyncWaitHandle.WaitOne(3000,$false) -and $trConn.Connected) {
                $trs = $trConn.GetStream(); $trs.ReadTimeout = 3000
                $trReq = [System.Text.Encoding]::ASCII.GetBytes("TRACE / HTTP/1.0`r`nHost: $IP`r`nX-Zscan: trace-test`r`n`r`n")
                $trs.Write($trReq, 0, $trReq.Length)
                $trbuf = [byte[]]::new(2048)
                $trn = $trs.Read($trbuf, 0, $trbuf.Length)
                $trConn.Close()
                $trResp = [System.Text.Encoding]::ASCII.GetString($trbuf, 0, $trn)
                if ($trResp -match "x-zscan" -and $trResp -match "trace-test") {
                    Add-Result "http-trace" "HTTP TRACE enabled — Cross-Site Tracing (XST) vulnerability" $true
                }
            }
        } catch {}

        # http-webdav-scan
        try {
            $wvConn = [System.Net.Sockets.TcpClient]::new()
            $arWv = $wvConn.BeginConnect($IP, $Port, $null, $null)
            if ($arWv.AsyncWaitHandle.WaitOne(3000,$false) -and $wvConn.Connected) {
                $wvs = $wvConn.GetStream(); $wvs.ReadTimeout = 3000
                $wvReq = [System.Text.Encoding]::ASCII.GetBytes("PROPFIND / HTTP/1.0`r`nHost: $IP`r`nDepth: 0`r`nContent-Length: 0`r`n`r`n")
                $wvs.Write($wvReq, 0, $wvReq.Length)
                $wvbuf = [byte[]]::new(4096)
                $wvn = $wvs.Read($wvbuf, 0, $wvbuf.Length)
                $wvConn.Close()
                $wvResp = [System.Text.Encoding]::ASCII.GetString($wvbuf, 0, $wvn)
                if ($wvResp -match "^HTTP/\S+ 207" -or $wvResp -match "multistatus") {
                    Add-Result "http-webdav-scan" "WebDAV enabled (PROPFIND 207 Multi-Status)" $true
                }
            }
        } catch {}

        # http-aspnet-debug
        try {
            $asConn = [System.Net.Sockets.TcpClient]::new()
            $arAs = $asConn.BeginConnect($IP, $Port, $null, $null)
            if ($arAs.AsyncWaitHandle.WaitOne(3000,$false) -and $asConn.Connected) {
                $ass = $asConn.GetStream(); $ass.ReadTimeout = 3000
                $asReq = [System.Text.Encoding]::ASCII.GetBytes("DEBUG / HTTP/1.1`r`nHost: $IP`r`nCommand: stop-debug`r`n`r`n")
                $ass.Write($asReq, 0, $asReq.Length)
                $asbuf = [byte[]]::new(256)
                $asn = $ass.Read($asbuf, 0, $asbuf.Length)
                $asConn.Close()
                $asResp = [System.Text.Encoding]::ASCII.GetString($asbuf, 0, $asn)
                if ($asResp -match "^HTTP/\S+ 200") { Add-Result "http-aspnet-debug" "ASP.NET DEBUG method enabled" $true }
            }
        } catch {}

        # http-vuln-cve2010-0738 (JBoss JMX)
        $jbR = Invoke-HttpGet -IP $IP -Port $Port -Path "/jmx-console/"
        if ($jbR.Status -eq 200 -and ($jbR.Body -match "jmx|jboss")) {
            Add-Result "http-vuln-cve2010-0738" "JBoss JMX Console unauthenticated access!" $true "CVE-2010-0738"
        }

        # http-vuln-cve2012-1823 (PHP-CGI)
        $pcR = Invoke-HttpGet -IP $IP -Port $Port -Path "/?-s"
        if ($pcR.Status -eq 200 -and $pcR.Body -match "<\?php") {
            Add-Result "http-vuln-cve2012-1823" "PHP-CGI source code disclosure (?-s)" $true "CVE-2012-1823"
        }

        # http-spring-boot-actuator
        $acR = Invoke-HttpGet -IP $IP -Port $Port -Path "/actuator"
        if ($acR.Status -eq 200 -and ($acR.Body -match "_links|propertySources")) {
            Add-Result "http-spring-boot-actuator" "Spring Boot Actuator exposed — info disclosure" $true
        }

        # http-drupal-enum
        $drR = Invoke-HttpGet -IP $IP -Port $Port -Path "/user/login"
        if ($drR.Status -eq 200 -and $drR.Body -match "drupal") {
            Add-Result "http-drupal-enum" "Drupal detected — check CVE-2014-3704" $false "CVE-2014-3704"
        }
    }

    if ($isHttp -and (Wants "safe")) {
        # http-generator
        $genR = Invoke-HttpGet -IP $IP -Port $Port
        if ($genR.Body -match '<meta[^>]+name=["\x27]generator["\x27][^>]+content=["\x27]([^"x27]+)["\x27]') {
            Add-Result "http-generator" "Generator: $($Matches[1].Substring(0,[Math]::Min(80,$Matches[1].Length)))"
        }

        # http-php-version
        if ($resp.Headers.ContainsKey("x-powered-by") -and $resp.Headers["x-powered-by"] -match "php") {
            $phpVer = $resp.Headers["x-powered-by"]
            $phpOld = $phpVer -match "5\.|7\.0|7\.1|7\.2"
            Add-Result "http-php-version" "PHP: $phpVer" $phpOld
        }
    }

    if ($isHttp -and (Wants "discovery")) {
        # http-enum
        $enumPaths = @(
            @("/admin","Admin panel"),@("/phpmyadmin","phpMyAdmin"),
            @("/wp-admin/","WordPress admin"),@("/wp-login.php","WP login"),
            @("/administrator/","Joomla"),@("/manager/html","Tomcat"),
            @("/jenkins/","Jenkins"),@("/.env","Env config"),
            @("/phpinfo.php","PHPinfo"),@("/server-status","Apache status"),
            @("/swagger-ui.html","Swagger"),@("/actuator","Spring Actuator"),
            @("/.git/config","Git config"),@("/console","Console")
        )
        $foundPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($ep in $enumPaths) {
            try {
                $er = Invoke-HttpGet -IP $IP -Port $Port -Path $ep[0] -TimeoutMs 1500
                if ($er.Status -in @(200,301,302,403)) {
                    $foundPaths.Add("$($ep[0])[$($er.Status)]($($ep[1]))")
                }
            } catch {}
        }
        if ($foundPaths.Count -gt 0) {
            $vuln = $foundPaths | Where-Object { $_ -match "\[200\]" }
            Add-Result "http-enum" ($foundPaths | Select-Object -First 5 | Join-String -Separator " | ") ($null -ne $vuln)
        }

        # http-apache-server-status
        $ssR = Invoke-HttpGet -IP $IP -Port $Port -Path "/server-status"
        if ($ssR.Status -eq 200 -and ($ssR.Body -match "Apache|server-status")) {
            Add-Result "http-apache-server-status" "Apache mod_status exposed — info disclosure" $true
        }
    }

    # ── SMB2 Time ──────────────────────────────────────────────────────────────
    if ($isSMB -and (Wants "default")) {
        try {
            $s2tConn = [System.Net.Sockets.TcpClient]::new()
            $arS2t = $s2tConn.BeginConnect($IP, 445, $null, $null)
            if ($arS2t.AsyncWaitHandle.WaitOne(3000,$false) -and $s2tConn.Connected) {
                $s2ts = $s2tConn.GetStream(); $s2ts.ReadTimeout = 3000
                # SMB2 NEGOTIATE
                $smb2hdr = [byte[]](0xfe,0x53,0x4d,0x42,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                $smb2body = [byte[]](0x24,0x00,0x03,0x00,0x01,0x00,0x00,0x00,0x7f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x02,0x10,0x02,0x00,0x03)
                $s2len = $smb2hdr.Length + $smb2body.Length
                $s2nb = [byte[]](0x00) + [byte[]](($s2len -shr 16) -band 0xFF,(($s2len -shr 8) -band 0xFF),($s2len -band 0xFF))
                $s2packet = $s2nb + $smb2hdr + $smb2body
                $s2ts.Write($s2packet, 0, $s2packet.Length)
                $s2tbuf = [byte[]]::new(4096)
                $s2tn = $s2ts.Read($s2tbuf, 0, $s2tbuf.Length)
                $s2tConn.Close()
                # Find SMB2 magic
                for ($s2i = 0; $s2i -lt $s2tn - 4; $s2i++) {
                    if ($s2tbuf[$s2i] -eq 0xfe -and $s2tbuf[$s2i+1] -eq 0x53 -and $s2tbuf[$s2i+2] -eq 0x4d -and $s2tbuf[$s2i+3] -eq 0x42) {
                        $bodyOff = $s2i + 64 + 40  # SMB2 header 64 + system-time offset 40
                        if ($s2tn -gt $bodyOff + 8) {
                            $ftBytes = $s2tbuf[$bodyOff..($bodyOff+7)]
                            [Array]::Reverse($ftBytes)
                            $ft = [BitConverter]::ToUInt64($ftBytes, 0)
                            # Reverse the byte order back for little-endian
                            $ft = [BitConverter]::ToUInt64($s2tbuf[$bodyOff..($bodyOff+7)], 0)
                            if ($ft -gt 116444736000000000) {
                                $unixSec = [double]($ft - 116444736000000000) / 10000000
                                $dt2 = (Get-Date "1/1/1970").AddSeconds($unixSec).ToUniversalTime()
                                Add-Result "smb2-time" "SMB2 server time: $($dt2.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
                            }
                        }
                        break
                    }
                }
            }
        } catch {}
    }

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
# SCAN WORKER
# ─────────────────────────────────────────────────────────────────────────────
function Scan-Port {
    param([string]$IP, [int]$Port, [string]$ScanMode, [int]$TimeoutMs,
          [bool]$DoVersion, [string[]]$ScriptCats)

    $state = switch ($ScanMode) {
        "TCP" { Test-TCPPort -IP $IP -Port $Port -TimeoutMs $TimeoutMs }
        "UDP" { Test-UDPPort -IP $IP -Port $Port -TimeoutMs $TimeoutMs }
        default { "filtered" }
    }

    $svc     = if ($ServiceDB.ContainsKey($Port)) { $ServiceDB[$Port] } else { "unknown" }
    $version = ""
    $banner  = ""
    $scripts = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($state -eq "open") {
        if ($DoVersion -or $ScriptCats.Count -gt 0) {
            $banner = Get-Banner -IP $IP -Port $Port -TimeoutMs ($TimeoutMs * 3)
            if ($DoVersion -and $banner) {
                $version = Get-ServiceVersion -Banner $banner -Port $Port
            }
        }
        if ($ScriptCats.Count -gt 0) {
            $sr = Run-Scripts -IP $IP -Port $Port -Service $svc -Banner $banner -Categories $ScriptCats
            foreach ($r in $sr) { $scripts.Add($r) }
        }
    }

    return [PSCustomObject]@{
        Port    = $Port
        Proto   = $ScanMode.ToLower()
        State   = $state
        Service = $svc
        Version = $version
        Banner  = $banner.Substring(0, [Math]::Min(200, $banner.Length))
        Scripts = $scripts
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────────────────────
function Save-HTMLReport {
    param([array]$HostResults, [string]$Filename)

    $ts         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalOpen  = ($HostResults | ForEach-Object { $_.Ports | Where-Object { $_.State -eq "open" } } | Measure-Object).Count
    $totalVulns = ($HostResults | ForEach-Object { $_.Ports | ForEach-Object { $_.Scripts | Where-Object { $_.Vuln } } } | Measure-Object).Count

    $rows = [System.Text.StringBuilder]::new()
    foreach ($h in $HostResults) {
        $hn  = if ($h.Hostname) { " ($($h.Hostname))" } else { "" }
        $osS = if ($h.OS.OS -ne "Unknown") { "<br><small>OS: $($h.OS.OS) (TTL=$($h.OS.TTL))</small>" } else { "" }

        foreach ($p in ($h.Ports | Where-Object { $_.State -eq "open" })) {
            $scriptHtml = ""
            foreach ($s in $p.Scripts) {
                $vTag = if ($s.Vuln) { " <span class='vuln-tag'>VULN</span>" } else { "" }
                $cTag = if ($s.CVE)  { " <small class='cve'>($($s.CVE))</small>" } else { "" }
                $scriptHtml += "<div class='script-row'><span class='script-name'>|_$($s.Name)</span>$vTag$cTag<br><span class='script-out'>$([System.Web.HttpUtility]::HtmlEncode($s.Output))</span></div>"
            }
            $rows.Append("<tr>
                <td><strong>$($h.IP)</strong>$hn$osS</td>
                <td class='port'>$($p.Port)/$($p.Proto)</td>
                <td class='open'>open</td>
                <td>$($p.Service)</td>
                <td>$($p.Version)</td>
                <td>$scriptHtml</td>
            </tr>") | Out-Null
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZScan Report - $ts</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--pass:#27ae60;--fail:#e74c3c;--warn:#f39c12;--accent:#1f6feb;--dim:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:20px;font-size:13px}
.logo{font-size:1.8rem;font-weight:900;background:linear-gradient(135deg,#58a6ff,#f39c12);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.meta{color:var(--dim);font-size:.8rem;margin-bottom:20px;line-height:1.8}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.card .num{font-size:1.8rem;font-weight:700}
.card .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--dim);margin-top:2px}
.controls{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.search{flex:1;min-width:200px;padding:8px 12px;border-radius:6px;background:var(--card);border:1px solid var(--border);color:var(--text);font-size:.82rem}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{background:var(--card);border-bottom:1px solid var(--border);padding:9px;text-align:left;font-weight:600;color:var(--dim);text-transform:uppercase;font-size:.7rem;letter-spacing:.4px}
td{padding:8px 9px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:rgba(255,255,255,.02)}
.open{color:var(--pass);font-weight:700}
.port{font-family:monospace;color:#79c0ff}
.vuln-tag{background:var(--fail);color:#fff;font-size:.68rem;padding:1px 6px;border-radius:3px;font-weight:700}
.cve{color:var(--warn)}
.script-row{margin-top:4px}
.script-name{font-family:monospace;font-size:.75rem;color:#79c0ff}
.script-out{color:var(--dim);font-size:.72rem}
footer{margin-top:24px;font-size:.7rem;color:#484f58;text-align:center}
</style>
</head>
<body>
<div class="logo">ZScan</div>
<div class="meta">
  Scan: <strong>$ts</strong> &nbsp;|&nbsp;
  Targets: <strong>$($HostResults.Count)</strong> &nbsp;|&nbsp;
  Type: <strong>$ScanType</strong> &nbsp;|&nbsp;
  Timing: <strong>T$T ($($Profile.Name))</strong>
</div>
<div class="cards">
  <div class="card"><div class="num" style="color:var(--pass)">$totalOpen</div><div class="lbl">Open Ports</div></div>
  <div class="card"><div class="num" style="color:var(--fail)">$totalVulns</div><div class="lbl">Findings</div></div>
  <div class="card"><div class="num">$($HostResults.Count)</div><div class="lbl">Hosts</div></div>
</div>
<div class="controls">
  <input class="search" type="text" id="s" placeholder="🔍 Search..." onkeyup="ft()">
</div>
<table id="t">
  <thead><tr>
    <th>Host</th><th>Port</th><th>State</th>
    <th>Service</th><th>Version</th><th>Scripts / Findings</th>
  </tr></thead>
  <tbody id="tb">$($rows.ToString())</tbody>
</table>
<footer>ZScan v1.0.0 (PowerShell) &nbsp;|&nbsp; Air-gap safe &nbsp;|&nbsp; $ts</footer>
<script>
function ft(){
  const q=document.getElementById('s').value.toLowerCase();
  document.querySelectorAll('#tb tr').forEach(r=>{
    r.style.display=(!q||r.innerText.toLowerCase().includes(q))?'':'none';
  });
}
</script>
</body>
</html>
"@
    # Use .NET HtmlEncode for script output (fallback if Web not available)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $html | Out-File -FilePath $Filename -Encoding UTF8
    Write-Color "[+] HTML report saved: $Filename" Green
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if (-not $Quiet) {
    Write-Color @"

███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
╚══███╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███╔╝ ███████╗██║     ███████║██╔██╗ ██║
  ███╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
  Air-gap Network Scanner v1.0.0  |  PowerShell Edition
"@ Cyan
}

$startTime = Get-Date

# Expand targets
if (-not $Quiet) { Write-Color "[*] Resolving targets..." Cyan }
$allTargets = Expand-Targets -TargetStr $Target
if ($allTargets.Count -eq 0) { Write-Color "[!] No valid targets." Yellow; exit 1 }

# Expand ports
$allPorts = if ($Ports) {
    Expand-Ports -PortStr $Ports
} elseif ($TopPorts -gt 0) {
    $Top1000 | Select-Object -First $TopPorts
} else {
    $Top1000
}

# Script categories
$scriptCats = @()
if ($Scripts) {
    $scriptCats = ($Scripts -split ",") | ForEach-Object { $_.Trim().ToLower() }
}

if (-not $Quiet) {
    Write-Color "[*] Targets   : $($allTargets.Count)" DarkGray
    Write-Color "[*] Ports     : $($allPorts.Count) ($ScanType, T$T / $($Profile.Name))" DarkGray
    if ($ServiceDetection) { Write-Color "[*] Version detection: ON" DarkGray }
    if ($Scripts)          { Write-Color "[*] Scripts   : $Scripts" DarkGray }
}

# Host discovery for subnets
$liveTargets = if ($allTargets.Count -gt 1 -and $ScanType -ne "Ping") {
    if (-not $Quiet) { Write-Color "`n[*] Host discovery..." Cyan }
    $live = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

    $allTargets | ForEach-Object -ThrottleLimit $WORKERS -Parallel {
        $ip = $_
        $t  = $using:TIMEOUT
        $l  = $using:live
        try {
            $ping  = [System.Net.NetworkInformation.Ping]::new()
            $reply = $ping.Send($ip, $t)
            if ($reply.Status -eq "Success") { $l.Add($ip) }
            else {
                foreach ($port in @(80,443,22,445)) {
                    $tcp = [System.Net.Sockets.TcpClient]::new()
                    $ar  = $tcp.BeginConnect($ip, $port, $null, $null)
                    if ($ar.AsyncWaitHandle.WaitOne($t, $false) -and $tcp.Connected) {
                        $l.Add($ip); $tcp.Close(); break
                    }
                    $tcp.Close()
                }
            }
        } catch {}
    } 2>$null

    $liveList = $live | Sort-Object { [version]$_ }
    if (-not $Quiet) { Write-Color "    $($liveList.Count)/$($allTargets.Count) host(s) up" Green }
    $liveList
} elseif ($ScanType -eq "Ping") {
    # Ping sweep mode
    if (-not $Quiet) { Write-Color "`n[*] Ping sweep..." Cyan }
    $live = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $allTargets | ForEach-Object -ThrottleLimit $WORKERS -Parallel {
        $ip = $_; $t = $using:TIMEOUT; $l = $using:live
        try {
            $ping = [System.Net.NetworkInformation.Ping]::new()
            if ($ping.Send($ip, $t).Status -eq "Success") { $l.Add($ip) }
        } catch {}
    } 2>$null
    foreach ($ip in ($live | Sort-Object)) { Write-Color "  Host: $ip (up)" Green }
    Write-Color "`n$($live.Count) host(s) up" Green
    exit 0
} else {
    $allTargets
}

if ($liveTargets.Count -eq 0) { Write-Color "[!] No live hosts found." Yellow; exit 0 }

# Port scan
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($ip in $liveTargets) {
    if (-not $Quiet) { Write-Host "`n" -NoNewline; Write-Color "Scanning $ip ($($allPorts.Count) ports)..." Cyan }

    $portResults = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
    $done = [ref]0

    $allPorts | ForEach-Object -ThrottleLimit $WORKERS -Parallel {
        $port      = $_
        $pip       = $using:ip
        $pScanType = $using:ScanType
        $pTimeout  = $using:TIMEOUT
        $pVersion  = $using:ServiceDetection
        $pScripts  = $using:scriptCats
        $pDb       = $using:ServiceDB
        $pResults  = $using:portResults

        function _TestTCP([string]$i,[int]$p,[int]$t) {
            try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $ar  = $tcp.BeginConnect($i, $p, $null, $null)
                $ok  = $ar.AsyncWaitHandle.WaitOne($t, $false)
                if ($ok -and $tcp.Connected) { $tcp.Close(); return "open" }
                $tcp.Close(); return "filtered"
            } catch { return "filtered" }
        }

        $state = _TestTCP $pip $port $pTimeout
        $svc   = if ($pDb.ContainsKey($port)) { $pDb[$port] } else { "unknown" }

        if ($state -eq "open") {
            $pResults.Add([PSCustomObject]@{
                Port    = $port
                Proto   = $pScanType.ToLower()
                State   = $state
                Service = $svc
                Version = ""
                Banner  = ""
                Scripts = @()
            })
        }
    } 2>$null

    # Version + script detection (sequential for open ports — avoids overload)
    $openPorts = $portResults | Where-Object { $_.State -eq "open" } | Sort-Object Port
    foreach ($pr in $openPorts) {
        if ($ServiceDetection -or $scriptCats.Count -gt 0) {
            $pr.Banner = Get-Banner -IP $ip -Port $pr.Port -TimeoutMs ($TIMEOUT * 3)
            if ($ServiceDetection -and $pr.Banner) {
                $pr.Version = Get-ServiceVersion -Banner $pr.Banner -Port $pr.Port
            }
            if ($scriptCats.Count -gt 0) {
                $pr.Scripts = Run-Scripts -IP $ip -Port $pr.Port -Service $pr.Service -Banner $pr.Banner -Categories $scriptCats
            }
        }
    }

    # OS detection
    $osInfo = @{ OS = "Unknown"; TTL = 0 }
    if ($OSDetect) { $osInfo = Get-OSGuess -IP $ip }

    # Hostname
    $hostname = ""
    try { $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}

    $hostObj = [PSCustomObject]@{
        IP       = $ip
        Hostname = $hostname
        OS       = $osInfo
        Ports    = @($openPorts)
    }
    $allResults.Add($hostObj)

    # Terminal output
    if (-not $Quiet) {
        $hnStr = if ($hostname) { " ($hostname)" } else { "" }
        $osStr = if ($osInfo.OS -ne "Unknown") { "  OS: $($osInfo.OS) TTL=$($osInfo.TTL)" } else { "" }
        Write-Host ""
        Write-Color "Host: $ip$hnStr$osStr" Cyan
        Write-Host ("{0,-10}{1,-14}{2,-16}VERSION" -f "PORT","STATE","SERVICE")
        Write-Host ("-" * 64)

        foreach ($pr in $openPorts) {
            Write-Color ("{0,-10}" -f "$($pr.Port)/$($pr.Proto)") White -NoNewline
            Write-Color ("{0,-14}" -f $pr.State) Green -NoNewline
            Write-Color ("{0,-16}" -f $pr.Service) White -NoNewline
            Write-Color $pr.Version White

            foreach ($s in $pr.Scripts) {
                $vStr = if ($s.Vuln) { " [VULN]" } else { "" }
                $cStr = if ($s.CVE)  { " ($($s.CVE))" } else { "" }
                Write-Color "  |_$($s.Name)$vStr$cStr" $(if ($s.Vuln) { "Red" } else { "DarkCyan" })
                Write-Color "    $($s.Output)" DarkGray
            }
        }
    }
}

$elapsed = ((Get-Date) - $startTime).TotalSeconds

if (-not $Quiet) {
    $openCount = ($allResults | ForEach-Object { $_.Ports | Where-Object { $_.State -eq "open" } } | Measure-Object).Count
    $vulnCount = ($allResults | ForEach-Object { $_.Ports | ForEach-Object { $_.Scripts | Where-Object { $_.Vuln } } } | Measure-Object).Count
    Write-Host ""
    Write-Color ("Scan complete in {0:F1}s | {1} host(s) | {2} open port(s){3}" -f `
        $elapsed, $allResults.Count, $openCount,
        $(if ($vulnCount -gt 0) { " | $vulnCount finding(s)" } else { "" })) DarkGray
}

# Output files
if ($OutputJSON) {
    $jsonData = @{
        tool       = "ZScan"
        version    = "1.0.0"
        scan_date  = (Get-Date -Format "o")
        scan_type  = $ScanType
        hosts      = $allResults | ForEach-Object {
            @{
                ip       = $_.IP
                hostname = $_.Hostname
                os       = $_.OS
                ports    = $_.Ports | ForEach-Object {
                    @{
                        port    = $_.Port
                        proto   = $_.Proto
                        state   = $_.State
                        service = $_.Service
                        version = $_.Version
                        scripts = $_.Scripts | ForEach-Object {
                            @{ name=$_.Name; output=$_.Output; vuln=$_.Vuln; cve=$_.CVE }
                        }
                    }
                }
            }
        }
    }
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJSON -Encoding UTF8
    Write-Color "[+] JSON report saved: $OutputJSON" Green
}

if ($OutputHTML) {
    Save-HTMLReport -HostResults $allResults -Filename $OutputHTML
}

if ($OutputCSV) {
    $csvRows = $allResults | ForEach-Object {
        $h = $_
        $_.Ports | Where-Object { $_.State -eq "open" } | ForEach-Object {
            [PSCustomObject]@{
                IP      = $h.IP
                Hostname= $h.Hostname
                Port    = $_.Port
                Proto   = $_.Proto
                State   = $_.State
                Service = $_.Service
                Version = $_.Version
                Vulns   = ($_.Scripts | Where-Object { $_.Vuln } | ForEach-Object { $_.Name }) -join ";"
            }
        }
    }
    $csvRows | Export-Csv -Path $OutputCSV -NoTypeInformation
    Write-Color "[+] CSV report saved: $OutputCSV" Green
}
