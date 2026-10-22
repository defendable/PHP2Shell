<#
.SYNOPSIS
    Fast parallel check for the presence of /index.php on a set of hosts/ports.
    A 200 OK is treated as "PHP present" and logged to CSV
    (Host, index.php, http.title).

.PARAMETER Target
    Target(s) to scan: a single IP, hostname, or CIDR range, or several separated
    by commas/spaces. Overrides the $Targets list in the CONFIG section.

.PARAMETER OutFile
    Output CSV path. Overrides the $OutputCsv default in the CONFIG section.

.DESCRIPTION
    Precedence for both arguments: command line first, then the value in the
    script's CONFIG section. If no target can be found in either place, the script
    exits gracefully.

    For every target x port a worker runspace does a quick TCP connect test and,
    if the port is open, a single HTTP GET for /index.php. Only a 200 response is
    recorded; everything else is ignored. TLS certificate errors are ignored.

.EXAMPLE
    .\phpfinder.ps1 10.0.0.0/24 results.csv
    .\phpfinder.ps1 -Target "10.0.0.1,10.0.0.2" -OutFile phpservers.csv

.NOTES
    Only run this against systems you own or are explicitly authorised to test.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)] [string]$Target,
    [Parameter(Position = 1)] [string]$OutFile,
    [switch]$ShowErrors        # print non-200 and failed probes, not just hits
)

#region ------------------------------ CONFIG ----------------------------------

# Default targets if none given on the command line. Single IPs, hostnames, CIDR.
$Targets = @(
    # '10.0.0.1'
    # '10.0.0.0/24'
)

# Ports to probe on each target.
$Ports = @(80, 443, 8080, 12380)

# Ports treated as HTTPS (all others HTTP). No scheme fallback - keep it fast.
$HttpsPorts = @(443, 8443, 12380)

# Default output CSV if none given on the command line.
$OutputCsv = ".\index-php-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"

# Speed knobs.
$Threads          = 100    # concurrent workers
$ConnectTimeoutMs = 500    # TCP connect test per port
$HttpTimeoutSec   = 5      # HTTP GET timeout

# User agent sent with each request.
$UserAgent = 'Identifying servers that have index.php'

#endregion ---------------------------------------------------------------------


#region ----------------------- RESOLVE ARGUMENTS ------------------------------
# Command line wins; otherwise fall back to the CONFIG values above.
if ($PSBoundParameters.ContainsKey('Target') -and $Target) {
    $Targets = $Target -split '[\s,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
if ($PSBoundParameters.ContainsKey('OutFile') -and $OutFile) {
    $OutputCsv = $OutFile
}

$Targets = @($Targets | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_) })
if ($Targets.Count -eq 0) {
    Write-Host "No targets specified on the command line or in the script's `$Targets list. Nothing to do." -ForegroundColor Red
    exit 1
}
if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    Write-Host "No output file specified on the command line or in the script's `$OutputCsv. Nothing to do." -ForegroundColor Red
    exit 1
}
#endregion ---------------------------------------------------------------------


#region ----------------------- TARGET EXPANSION -------------------------------
function Expand-Cidr {
    param([string]$Cidr)
    $ip, $plen = $Cidr -split '/'
    $plen  = [int]$plen
    $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($bytes)
    $ipUint    = [System.BitConverter]::ToUInt32($bytes, 0)
    $maskUint  = [uint32]([uint64]4294967295 - ([uint64][math]::Pow(2, 32 - $plen) - 1))
    $network   = [uint64]$ipUint -band [uint64]$maskUint
    $broadcast = $network + ([uint64]4294967295 - [uint64]$maskUint)
    $start = $network; $end = $broadcast
    if ($plen -lt 31) { $start = $network + 1; $end = $broadcast - 1 }
    for ([uint64]$i = $start; $i -le $end; $i++) {
        $b = [System.BitConverter]::GetBytes([uint32]$i)
        [Array]::Reverse($b)
        ([System.Net.IPAddress]::new($b)).ToString()
    }
}

$allTargets = New-Object System.Collections.Generic.List[string]
foreach ($t in $Targets) {
    $t = $t.Trim()
    if ($t -match '/\d+$') { Expand-Cidr $t | ForEach-Object { $allTargets.Add($_) } }
    else                   { $allTargets.Add($t) }
}
#endregion ---------------------------------------------------------------------


#region -------------------------- WORKER --------------------------------------
# Always returns a PSCustomObject describing the probe outcome:
#   Category = 'hit' | 'non200' | 'closed' | 'error'
$worker = {
    param($Target, $Port, $Scheme, $UserAgent, $ConnectTimeoutMs, $HttpTimeoutSec)

    $origin = '{0}://{1}:{2}' -f $Scheme, $Target, $Port
    $out = [pscustomobject]@{ Host = $origin; Category = 'closed'; Code = $null; Title = ''; Error = '' }

    # Fast fail on closed ports.
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($Target, $Port, $null, $null)
        if (-not ($iar.AsyncWaitHandle.WaitOne($ConnectTimeoutMs) -and $tcp.Connected)) { return $out }
        $tcp.EndConnect($iar)
    } catch { $out.Error = $_.Exception.Message; return $out } finally { $tcp.Close() }

    $params = @{
        Uri = "$origin/index.php"; Method = 'Get'; TimeoutSec = $HttpTimeoutSec
        UserAgent = $UserAgent; UseBasicParsing = $true
        MaximumRedirection = 0; ErrorAction = 'Stop'
    }
    # PS7: ignore cert errors per request (HTTPS only). PS 5.1 relies on the
    # process-wide callback set in the RUN section instead.
    if ($Scheme -eq 'https' -and $PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $r   = Invoke-WebRequest @params
            $code = [int]$r.StatusCode
            if ($code -eq 200) {
                $title = ''
                $m = [regex]::Match([string]$r.Content, '<title[^>]*>(.*?)</title>', 'IgnoreCase, Singleline')
                if ($m.Success) { $title = ($m.Groups[1].Value -replace '\s+', ' ').Trim() }
                $out.Category = 'hit'; $out.Code = $code; $out.Title = $title
            } else {
                $out.Category = 'non200'; $out.Code = $code
            }
            return $out
        }
        catch {
            $resp = $_.Exception.Response
            if ($resp) {
                # A real HTTP reply (redirect / 4xx / 5xx) - server is alive, just not 200.
                $code = $null; try { $code = [int]$resp.StatusCode } catch { }
                $out.Category = 'non200'; $out.Code = $code; $out.Error = $_.Exception.Message
                return $out
            }
            # No response: transient (timeout / reset). Retry once, then give up.
            if ($attempt -lt 2) { Start-Sleep -Milliseconds 200; continue }
            $out.Category = 'error'; $out.Error = $_.Exception.Message
            return $out
        }
    }
}
#endregion ---------------------------------------------------------------------


#region ----------------------------- RUN --------------------------------------
# Windows PowerShell 5.1 has no per-request -SkipCertificateCheck, so ignore cert
# errors via the process-wide callback. Save and restore it so running this in an
# interactive session doesn't leave certificate validation disabled afterwards.
# PS7 workers use -SkipCertificateCheck per request and don't touch this.
$is51 = $PSVersionTable.PSVersion.Major -lt 6
$savedCertCallback = $null
$savedSecProtocol  = $null
if ($is51) {
    $savedCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    $savedSecProtocol  = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.SecurityProtocolType]::Tls12 -bor
        [System.Net.SecurityProtocolType]::Tls11 -bor
        [System.Net.SecurityProtocolType]::Tls
}

try {

Write-Host ("Scanning {0} host(s) x {1} port(s) with {2} threads..." -f `
            $allTargets.Count, $Ports.Count, $Threads) -ForegroundColor Cyan

$pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$pool.Open()

$jobs = New-Object System.Collections.Generic.List[object]
foreach ($target in $allTargets) {
    foreach ($port in $Ports) {
        $scheme = if ($HttpsPorts -contains $port) { 'https' } else { 'http' }
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker).
            AddArgument($target).AddArgument($port).AddArgument($scheme).
            AddArgument($UserAgent).AddArgument($ConnectTimeoutMs).AddArgument($HttpTimeoutSec)
        $jobs.Add([pscustomobject]@{ Pipe = $ps; Async = $ps.BeginInvoke() })
    }
}

$results = New-Object System.Collections.Generic.List[object]
$hits = 0; $non200 = 0; $errors = 0; $closed = 0
$done = 0; $total = $jobs.Count
foreach ($job in $jobs) {
    $res = $null
    try {
        $out = $job.Pipe.EndInvoke($job.Async)
        if ($out -and $out.Count -gt 0) { $res = $out[0] }   # unwrap the PSDataCollection
    } catch { }
    $job.Pipe.Dispose()

    $done++
    Write-Progress -Activity 'Scanning' -Status "$done/$total" -PercentComplete (($done / $total) * 100)

    if (-not $res) { continue }
    switch ($res.Category) {
        'hit' {
            $hits++
            $results.Add([pscustomobject]@{
                'Host'       = $res.Host
                'index.php'  = 'Yes'
                'http.title' = $res.Title
            })
            Write-Host ("[FOUND] {0}/index.php  {1}" -f $res.Host, $res.Title) -ForegroundColor Yellow
        }
        'non200' {
            $non200++
            if ($ShowErrors) {
                $codeText = if ($null -ne $res.Code) { $res.Code } else { '---' }
                Write-Host ("[{0}] {1}/index.php" -f $codeText, $res.Host) -ForegroundColor DarkGray
            }
        }
        'error'  {
            $errors++
            if ($ShowErrors) { Write-Host ("[ERR] {0}  {1}" -f $res.Host, $res.Error) -ForegroundColor Red }
        }
        'closed' { $closed++ }
    }
}
Write-Progress -Activity 'Scanning' -Completed
$pool.Close(); $pool.Dispose()

# Always write the CSV - headers even when there were no hits.
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
} else {
    '"Host","index.php","http.title"' | Set-Content -Path $OutputCsv -Encoding UTF8
}

Write-Host ("`nDone. {0} hit, {1} non-200, {2} error, {3} closed/no-response (of {4} probes)." -f `
            $hits, $non200, $errors, $closed, $total) -ForegroundColor Green
Write-Host ("Results written to {0}" -f $OutputCsv) -ForegroundColor Green
if ($errors -gt 0 -and -not $ShowErrors) {
    Write-Host "Tip: re-run with -ShowErrors to see why the failing probes failed." -ForegroundColor DarkYellow
}

}
finally {
    # Restore the original cert/TLS settings (5.1 only), even on failure.
    if ($is51) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $savedCertCallback
        [System.Net.ServicePointManager]::SecurityProtocol = $savedSecProtocol
    }
}
#endregion ---------------------------------------------------------------------