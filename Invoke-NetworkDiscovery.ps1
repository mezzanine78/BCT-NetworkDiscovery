<#
Invoke-NetworkDiscovery.ps1 - unattended two-stage nmap network discovery for MSP client onboarding.
BCT / MSP Bergin CT. Replaces Advanced IP Scanner; output feeds the client network diagram.

  1. Discovery : nmap -sn          -> live hosts, reverse DNS, MAC, vendor
  2. Ports/OS  : nmap -sS -sV -O   -> open ports, services, OS guess (live hosts only)

Runs under Windows PowerShell 5.1 (Server 2016+) and pwsh 7, elevated or as SYSTEM (N-central,
scheduled task). Never prompts. Results are read from nmap XML (no text parsing).

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-NetworkDiscovery.ps1 -ClientCode CLIENT
  & ([scriptblock]::Create((irm <raw-url>/Invoke-NetworkDiscovery.ps1))) -ClientCode CLIENT
  $env:BCT_CLIENTCODE='CLIENT'; irm <raw-url>/install.ps1 | iex

Npcap: the free Npcap installer has no silent mode (/S is Npcap OEM only), so this script never
installs it. With Npcap present and running it does the full privileged scan. Without it, it falls
back to an unprivileged TCP connect scan (-sT, no ARP/MAC/vendor, no OS detection), logs a WARNING,
records ScanMode=Unprivileged in <ClientCode>_scan_info.txt and exits 3. MAC/Vendor/OS stay blank.

Exit codes (N-central):
  0 = completed, full privileged scan (Npcap)
  1 = error (bad parameters, nmap failed, output not writable, ...)
  2 = nmap unavailable (not found and could not be installed / does not run)
  3 = completed in DEGRADED mode (no Npcap: connect scan, no MAC/vendor/OS) - 0 with -DegradedIsSuccess
  4 = completed but no live hosts found (check subnets / routing)

Every parameter can also come from an environment variable (parameter wins): BCT_CLIENTCODE,
BCT_SUBNETS, BCT_OUTPUTDIR, BCT_PORTS, BCT_TIMING, BCT_MAXRATE, BCT_VERSIONINTENSITY, BCT_NOOSDETECT,
BCT_ALLOWLARGESUBNET, BCT_USECHOCOLATEY, BCT_CHOCOTIMEOUTSEC, BCT_NMAPPATH, BCT_NMAPZIPURL, BCT_TOOLSDIR,
BCT_LOGDIR, BCT_FORCEUNPRIVILEGED, BCT_DEGRADEDISSUCCESS. Switches accept 1/true/yes/on.
No secrets in this file.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Used inside the & { } block')]
[CmdletBinding()]
param(
    [string]$ClientCode = '',          # REQUIRED (or env BCT_CLIENTCODE). Letters, digits, - and _ only.
    [string[]]$Subnets = @(),          # e.g. 192.168.1.0/24. Omit to auto-detect local IPv4 subnets.
    [string]$OutputDir = '',           # default C:\BCT\Scans\<ClientCode>
    [string]$Ports = '',               # default: the management/web-UI list below
    [string]$Timing = '',              # T0-T5 (or -T4 / 4), default T4. T3 for fragile/slow links.
    [int]$MaxRate = -1,                # packets/sec cap for the port scan, default 30, 0 = no cap
    [int]$VersionIntensity = -1,       # -sV intensity 0-9, default 2
    [switch]$NoOsDetect,               # skip -O OS fingerprinting
    [switch]$AllowLargeSubnet,         # allow subnets bigger than /22
    [switch]$UseChocolatey,            # try 'choco install nmap' before the zip fallback (see README)
    [int]$ChocoTimeoutSec = 0,         # kill choco after this many seconds, default 600
    [string]$NmapPath = '',            # explicit nmap.exe
    [string]$NmapZipUrl = '',          # default https://nmap.org/dist/nmap-7.92-win32.zip
    [string]$ToolsDir = '',            # default C:\BCT\Tools (zip is extracted to <ToolsDir>\nmap)
    [string]$LogDir = '',              # default C:\BCT\Logs
    [switch]$ForceUnprivileged,        # always use the connect-scan mode (testing)
    [switch]$DegradedIsSuccess         # exit 0 instead of 3 when Npcap is missing
)

# Captured here because inside the & { } block $MyInvocation describes the block, not the script.
$__BCTScriptPath = $MyInvocation.MyCommand.Path

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference    = 'SilentlyContinue'
    $ScriptVersion = '1.0.0'
    $Tag = '[net-discovery]'
    $DefaultPorts  = '22,80,81,135,139,443,445,3000,3389,5000,5001,8000,8080,8443,8888,9000,9090,9443'
    $DefaultZipUrl = 'https://nmap.org/dist/nmap-7.92-win32.zip'
    # SHA256 of the official nmap-7.92-win32.zip (last free Windows zip; later zips are Nmap OEM only)
    $DefaultZipSha256 = 'B54C54D4B478CAD19567A504C7C6B7230DFD80ACD881DC2E9015A628A3EFA71E'
    $HostColumns = @('IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'OSAccuracy', 'OpenPorts')
    $PortColumns = @('IP', 'Hostname', 'Port', 'Protocol', 'Service', 'Product', 'Version', 'Extra')
    $state = @{ TranscriptOn = $false; Warnings = New-Object System.Collections.Generic.List[string] }

    # ======================= helpers (pure: unit-tested in tests/) =======================
    function Write-BctLog([string]$Msg, [string]$Level = 'INFO') {
        $line = '{0} {1} {2,-5} {3}' -f $Tag, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
        if ($Level -eq 'WARN' -and $state) { $state.Warnings.Add($Msg) }
        Write-Host $line
    }

    function Exit-Discovery([int]$Code, [string]$Msg) {
        if ($Code -eq 1 -or $Code -eq 2) { Write-BctLog "FAILED: $Msg (exit $Code)" 'ERROR' } else { Write-BctLog "$Msg (exit $Code)" }
        if ($state.TranscriptOn) { try { Stop-Transcript | Out-Null } catch { $null = $_ } }
        $global:LASTEXITCODE = $Code
        # Run as a .ps1 file: exit only ends the script. Run as an irm scriptblock: exit only when
        # non-interactive (SYSTEM / RMM / -Command), so an interactive console is not closed on you.
        if ($__BCTScriptPath -or -not [Environment]::UserInteractive -or
            ([Environment]::GetCommandLineArgs() -match '^-(c|command|noni|noninteractive|file|f|encodedcommand|e|ec)$')) {
            exit $Code
        }
    }

    function Test-EnvFlag([string]$Name) {
        $v = [Environment]::GetEnvironmentVariable($Name)
        return ([string]$v -match '^\s*(1|true|yes|on)\s*$')
    }

    function Resolve-Setting($Value, [string]$EnvName, $Default) {
        # parameter (non-empty / >= 0) > environment variable > default
        # Numeric settings (int default): a negative value means 'not given'.
        if ($Default -is [int]) {
            $v = 0
            if ($null -ne $Value -and [int]::TryParse("$Value", [ref]$v) -and $v -ge 0) { return $v }
        }
        elseif ($null -ne $Value -and "$Value" -ne '') { return $Value }
        $e = [Environment]::GetEnvironmentVariable($EnvName)
        if ($null -ne $e -and $e.Trim() -ne '') {
            if ($Default -is [int]) {
                $n = 0
                if (-not [int]::TryParse($e.Trim(), [ref]$n)) { throw "$EnvName='$e' is not a whole number" }
                return $n
            }
            return $e.Trim()
        }
        return $Default
    }

    function Split-ListValue([string[]]$Value) {
        # "a, b;c d" or @('a','b') -> @('a','b','c','d')
        $out = @()
        foreach ($v in @($Value)) {
            if ($null -eq $v) { continue }
            $out += @(([string]$v) -split '[,;\s]+' | Where-Object { $_ -ne '' })
        }
        return , $out
    }

    function ConvertTo-NmapTiming([string]$Value) {
        $t = ([string]$Value).Trim()
        if ($t -match '^-?[Tt]?([0-5])$') { return "-T$($Matches[1])" }
        throw "Timing '$Value' is not valid (use T0-T5)"
    }

    function Test-PortSpec([string]$Value) {
        return ([string]$Value -match '^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$')
    }

    function Test-ClientCode([string]$Value) {
        return ([string]$Value -match '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$')
    }

    function ConvertTo-UInt32Address([string]$IPAddress) {
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ip) -or
            $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "'$IPAddress' is not an IPv4 address"
        }
        $b = $ip.GetAddressBytes()
        return ([uint32]$b[0] * 16777216) + ([uint32]$b[1] * 65536) + ([uint32]$b[2] * 256) + [uint32]$b[3]
    }

    function ConvertFrom-UInt32Address([uint32]$Value) {
        return '{0}.{1}.{2}.{3}' -f (($Value -shr 24) -band 255), (($Value -shr 16) -band 255), (($Value -shr 8) -band 255), ($Value -band 255)
    }

    function ConvertTo-PrefixLength([string]$SubnetMask) {
        $m = ConvertTo-UInt32Address $SubnetMask
        $len = 0; $seenZero = $false
        for ($i = 31; $i -ge 0; $i--) {
            $bit = ($m -shr $i) -band 1
            if ($bit -eq 1) { if ($seenZero) { throw "'$SubnetMask' is not a contiguous subnet mask" }; $len++ }
            else { $seenZero = $true }
        }
        return $len
    }

    function Get-NetworkCidr([string]$IPAddress, [int]$PrefixLength) {
        if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { throw "prefix length $PrefixLength is out of range" }
        $a = ConvertTo-UInt32Address $IPAddress
        if ($PrefixLength -eq 0) { $mask = [uint32]0 }
        else { $mask = [uint32]([uint64]4294967295 - ([uint64][math]::Pow(2, 32 - $PrefixLength) - 1)) }
        return '{0}/{1}' -f (ConvertFrom-UInt32Address ([uint32]($a -band $mask))), $PrefixLength
    }

    function Get-PrefixFromSpec([string]$Spec) {
        # prefix length of a CIDR target, 32 for a single IP, $null for nmap octet ranges
        if ($Spec -match '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') { return [int]$Matches[3] }
        if ($Spec -match '^\d{1,3}(\.\d{1,3}){3}$') { return 32 }
        return $null
    }

    function Test-TargetSpec([string]$Spec) {
        # IPv4, IPv4/prefix, or nmap octet ranges (192.168.1.10-50). Never a leading '-' (no option injection).
        if ($Spec -match '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') {
            $null = ConvertTo-UInt32Address $Matches[1]
            return ([int]$Matches[3] -le 32)
        }
        if ($Spec -match '^\d{1,3}(\.\d{1,3}){3}$') { try { $null = ConvertTo-UInt32Address $Spec; return $true } catch { return $false } }
        if ($Spec -match '^\d{1,3}(-\d{1,3})?(\.\d{1,3}(-\d{1,3})?){3}$') { return $true }
        return $false
    }

    function Select-ScanSubnet([object[]]$Candidates, [bool]$AllowLarge) {
        # Candidates: objects with IPAddress, PrefixLength, InterfaceAlias. Returns one decision per
        # candidate: Cidr, Include, Reason. Skips loopback, APIPA, /32 and (unless allowed) > /22.
        $seen = @{}
        foreach ($c in @($Candidates)) {
            if (-not $c) { continue }
            $ip = [string]$c.IPAddress; $len = [int]$c.PrefixLength; $alias = [string]$c.InterfaceAlias
            $r = [pscustomobject]@{ Cidr = ''; IPAddress = $ip; PrefixLength = $len; InterfaceAlias = $alias; Include = $false; Reason = '' }
            try { $r.Cidr = Get-NetworkCidr $ip $len } catch { $r.Reason = "invalid: $($_.Exception.Message)"; $r; continue }
            if ($ip -like '127.*')          { $r.Reason = 'loopback' }
            elseif ($ip -like '169.254.*')  { $r.Reason = 'APIPA (no DHCP lease)' }
            elseif ($len -ge 32)            { $r.Reason = 'host route /32' }
            elseif ($len -lt 22 -and -not $AllowLarge) { $r.Reason = "larger than /22 (use -AllowLargeSubnet)" }
            elseif ($seen.ContainsKey($r.Cidr)) { $r.Reason = 'duplicate' }
            else { $r.Include = $true; $r.Reason = 'ok'; $seen[$r.Cidr] = $true }
            $r
        }
    }

    function Get-NmapArgumentSet {
        param(
            [ValidateSet('Discovery', 'PortScan')][string]$Stage,
            [bool]$Privileged, [string]$TimingArg, [string[]]$Targets, [string]$PortList,
            [int]$Intensity, [bool]$OsDetect, [int]$Rate, [string]$TargetFile, [string]$OutBase
        )
        $a = @()
        if (-not $Privileged) { $a += '--unprivileged' }
        if ($Stage -eq 'Discovery') {
            $a += @('-sn', $TimingArg)
            # Without Npcap there is no ARP/ICMP: ping with TCP connect to the scan ports instead of only 80/443.
            if (-not $Privileged) { $a += "-PS$PortList" }
            $a += $Targets
        }
        else {
            $a += @($TimingArg, '-Pn')                       # hosts already confirmed up in stage 1
            if ($Privileged) { $a += '-sS' } else { $a += '-sT' }
            $a += @('-sV', '--version-intensity', [string]$Intensity, '-p', $PortList, '--open')
            if ($OsDetect -and $Privileged) { $a += @('-O', '--osscan-limit') }
            if ($Rate -gt 0) { $a += @('--max-rate', [string]$Rate) }
            $a += @('-iL', $TargetFile)
        }
        $a += @('-oA', $OutBase)
        return , $a
    }

    function Get-NmapHost {
        # Reads an nmap XML file and returns one object per host that is up (same logic as the original).
        param([Parameter(Mandatory)][string]$XmlPath)
        if (-not (Test-Path -LiteralPath $XmlPath)) { return }
        [xml]$xml = Get-Content -LiteralPath $XmlPath -Raw
        foreach ($h in @($xml.nmaprun.host)) {
            if (-not $h -or $h.status.state -ne 'up') { continue }
            $addrs = @($h.address)
            $ipv4  = $addrs | Where-Object { $_.addrtype -eq 'ipv4' } | Select-Object -First 1
            $mac   = $addrs | Where-Object { $_.addrtype -eq 'mac' }  | Select-Object -First 1
            $openPorts = @($h.ports.port) | Where-Object { $_ -and $_.state.state -eq 'open' }
            $osMatch   = @($h.os.osmatch) | Where-Object { $_ } | Select-Object -First 1
            if (-not $ipv4) { continue }
            [pscustomobject]@{
                IP         = $ipv4.addr
                Hostname   = (@($h.hostnames.hostname) | Where-Object { $_ } | Select-Object -First 1).name
                MAC        = $mac.addr
                Vendor     = $mac.vendor
                OS         = $osMatch.name
                OSAccuracy = $osMatch.accuracy
                OpenPorts  = (($openPorts | ForEach-Object { "$($_.portid)/$($_.protocol)" }) -join ' ')
                PortNodes  = $openPorts     # kept for the ports CSV, not exported
            }
        }
    }

    function Get-IpSortKey([string]$IP) {
        try { return [version]$IP } catch { return [version]'255.255.255.255' }
    }

    function ConvertTo-HostRow([object[]]$LiveHosts, [object[]]$ScanHosts) {
        # One row per live device. MAC/vendor come from discovery (ARP); only on the local L2 segment.
        $byIp = @{}
        foreach ($s in @($ScanHosts)) { if ($s -and $s.IP) { $byIp[$s.IP] = $s } }
        $rows = foreach ($d in @($LiveHosts)) {
            if (-not $d) { continue }
            $s = $byIp[$d.IP]
            $hn = $d.Hostname; if (-not $hn -and $s) { $hn = $s.Hostname }
            $mc = $d.MAC;      if (-not $mc -and $s) { $mc = $s.MAC }
            $vn = $d.Vendor;   if (-not $vn -and $s) { $vn = $s.Vendor }
            $os = $null; $oa = $null; $op = $null
            if ($s) { $os = $s.OS; $oa = $s.OSAccuracy; $op = $s.OpenPorts }
            [pscustomobject]@{ IP = $d.IP; Hostname = $hn; MAC = $mc; Vendor = $vn; OS = $os; OSAccuracy = $oa; OpenPorts = $op }
        }
        @($rows) | Where-Object { $_ } | Sort-Object { Get-IpSortKey $_.IP }
    }

    function ConvertTo-PortRow([object[]]$ScanHosts) {
        $rows = foreach ($s in @($ScanHosts)) {
            if (-not $s) { continue }
            foreach ($p in @($s.PortNodes)) {
                if (-not $p) { continue }
                [pscustomobject]@{
                    IP = $s.IP; Hostname = $s.Hostname; Port = [int]$p.portid; Protocol = $p.protocol
                    Service = $p.service.name; Product = $p.service.product; Version = $p.service.version; Extra = $p.service.extrainfo
                }
            }
        }
        @($rows) | Where-Object { $_ } | Sort-Object { Get-IpSortKey $_.IP }, Port
    }

    function Export-ReportCsv([object[]]$Rows, [string]$Path, [string[]]$Columns) {
        # Same columns/encoding as the original Export-Csv; writes a header-only file when there are no rows.
        $Rows = @($Rows | Where-Object { $_ })
        if ($Rows.Count -gt 0) {
            $Rows | Select-Object -Property $Columns | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        }
        else {
            Set-Content -LiteralPath $Path -Value (($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',') -Encoding UTF8
        }
    }

    # ======================= Windows-side helpers =======================
    function Test-IsAdmin {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Sync-SessionPath {
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    }

    function Get-LocalIPv4Candidate {
        $list = @()
        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $up = @{}
            foreach ($i in @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected -ErrorAction SilentlyContinue)) { $up[[int]$i.InterfaceIndex] = $true }
            foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                if ($a.AddressState -ne 'Preferred') { continue }
                if (-not $up.ContainsKey([int]$a.InterfaceIndex)) { continue }
                $list += [pscustomobject]@{ IPAddress = $a.IPAddress; PrefixLength = [int]$a.PrefixLength; InterfaceAlias = $a.InterfaceAlias }
            }
        }
        if ($list.Count -eq 0) {
            foreach ($n in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' -ErrorAction SilentlyContinue)) {
                $ips = @($n.IPAddress); $masks = @($n.IPSubnet)
                for ($k = 0; $k -lt $ips.Count; $k++) {
                    if ($ips[$k] -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
                    try { $len = ConvertTo-PrefixLength $masks[$k] } catch { continue }
                    $list += [pscustomobject]@{ IPAddress = $ips[$k]; PrefixLength = $len; InterfaceAlias = $n.Description }
                }
            }
        }
        return , $list
    }

    function Find-Nmap([string]$Explicit, [string]$Tools) {
        if ($Explicit) {
            if (Test-Path -LiteralPath $Explicit -PathType Leaf) { return (Resolve-Path -LiteralPath $Explicit).Path }
            Write-BctLog "-NmapPath '$Explicit' not found; searching the usual places" 'WARN'
        }
        $cmd = Get-Command nmap.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
        $cands = @()
        foreach ($pf in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) { if ($pf) { $cands += (Join-Path $pf 'Nmap\nmap.exe') } }
        $cands += (Join-Path $Tools 'nmap\nmap.exe')
        foreach ($c in $cands) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
        $z = Get-ChildItem -Path (Join-Path $Tools 'nmap') -Filter nmap.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($z) { return $z.FullName }
        return $null
    }

    function Invoke-NativeText([string]$Exe, [string[]]$Arguments) {
        # Runs a console program and returns stdout+stderr as text. EAP is relaxed locally because
        # Windows PowerShell 5.1 turns native stderr lines into terminating errors under 'Stop'.
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $o = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } | Out-String }
        finally { $ErrorActionPreference = $old }
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $o }
    }

    function Invoke-TaskKill([int]$ProcessId) {
        $r = Invoke-NativeText 'taskkill.exe' @('/T', '/F', '/PID', [string]$ProcessId)
        Write-BctLog ("taskkill: " + ($r.Text -replace '\s+', ' ').Trim())
    }

    function Install-NmapChocolatey {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Official Chocolatey bootstrap, only with -UseChocolatey')]
        param([int]$TimeoutSec, [string]$LogFolder)
        # The community nmap package runs the free GUI installers (nmap + Npcap) driven by AutoHotkey;
        # it has no switch to skip Npcap and can hang with no desktop (SYSTEM). Hard timeout + kill.
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-BctLog 'Chocolatey not found; installing it from community.chocolatey.org'
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Sync-SessionPath
        }
        $choco = Get-Command choco -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $choco) { Write-BctLog 'choco still not available; skipping Chocolatey' 'WARN'; return }
        $out = Join-Path $LogFolder ('choco-nmap-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Write-BctLog "choco install nmap -y --no-progress (timeout ${TimeoutSec}s, output $out)"
        $p = Start-Process -FilePath $choco.Source -ArgumentList @('install', 'nmap', '-y', '--no-progress', '--limit-output') `
             -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            Write-BctLog "choco did not finish in ${TimeoutSec}s (GUI installer waiting with no desktop?); killing it" 'WARN'
            Invoke-TaskKill $p.Id
            foreach ($n in @('AutoHotkey*', 'nmap-*-setup', 'npcap-*')) { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
            return
        }
        Write-BctLog "choco exited $($p.ExitCode)"
        Sync-SessionPath
    }

    function Install-NmapZip([string]$Url, [string]$Tools, [string]$ExpectedSha256) {
        $dest = Join-Path $Tools 'nmap'
        $tmp  = Join-Path $env:TEMP ('bct-nmap-' + [guid]::NewGuid().ToString('N') + '.zip')
        try {
            Write-BctLog "downloading $Url"
            Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing
            $hash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
            if ($ExpectedSha256 -and $hash -ne $ExpectedSha256) { throw "SHA256 mismatch for $Url (got $hash)" }
            Write-BctLog "SHA256 $hash"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Expand-Archive -LiteralPath $tmp -DestinationPath $dest -Force
            Write-BctLog "extracted to $dest (the bundled npcap-*.exe is NOT run: free Npcap has no silent install)"
        }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    function Test-NmapRun([string]$Exe) {
        try {
            $r = Invoke-NativeText $Exe @('--version')
            if ($r.ExitCode -eq 0 -and $r.Text -match 'Nmap version\s+(\S+)') { return $Matches[1] }
            Write-BctLog "nmap --version exit $($r.ExitCode)" 'WARN'
        }
        catch { Write-BctLog "nmap --version failed: $($_.Exception.Message)" 'WARN' }
        return $null
    }

    function Install-VcRuntime([string]$NmapExe) {
        # The zip build needs the VC++ 2015-2022 x86 runtime; Microsoft's VC_redist is silent-capable.
        $vc = Get-ChildItem -LiteralPath (Split-Path $NmapExe) -Filter 'VC_redist.x86.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $vc) { return $false }
        Write-BctLog "installing VC++ x86 runtime silently ($($vc.Name) /install /quiet /norestart)"
        $p = Start-Process -FilePath $vc.FullName -ArgumentList @('/install', '/quiet', '/norestart') -PassThru
        if (-not $p.WaitForExit(600000)) { Invoke-TaskKill $p.Id; Write-BctLog 'VC_redist timed out' 'WARN'; return $false }
        Write-BctLog "VC_redist exited $($p.ExitCode)"
        return (@(0, 1638, 3010) -contains $p.ExitCode)
    }

    function Get-NpcapStatus([string]$Exe) {
        # Npcap counts only if the driver service exists, is running, its wpcap.dll is present and
        # nmap itself does not complain about missing Npcap functions.
        $r = [pscustomobject]@{ Present = $false; Running = $false; Version = ''; Usable = $false; Detail = '' }
        $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap'
        if (-not (Test-Path $svcKey)) { $r.Detail = 'npcap driver service not installed'; return $r }
        $r.Present = $true
        $q = (Invoke-NativeText 'sc.exe' @('query', 'npcap')).Text
        if ($q -notmatch 'STATE\s*:\s*4\s+RUNNING') {
            Write-BctLog 'npcap driver present but not running; trying sc.exe start npcap' 'WARN'
            $null = Invoke-NativeText 'sc.exe' @('start', 'npcap')
            Start-Sleep -Seconds 2
            $q = (Invoke-NativeText 'sc.exe' @('query', 'npcap')).Text
        }
        $r.Running = ($q -match 'STATE\s*:\s*4\s+RUNNING')
        $dll = Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'
        if (Test-Path -LiteralPath $dll) { $r.Version = (Get-Item -LiteralPath $dll).VersionInfo.ProductVersion }
        else { $r.Detail = "$dll missing"; return $r }
        if (-not $r.Running) { $r.Detail = 'npcap driver not running'; return $r }
        $il = (Invoke-NativeText $Exe @('--iflist')).Text
        if ($il -match 'Could not import all necessary Npcap functions|Resorting to connect') { $r.Detail = 'nmap cannot load Npcap'; return $r }
        $r.Usable = $true; $r.Detail = 'ok'
        return $r
    }

    function Invoke-Nmap([string]$Exe, [string[]]$Arguments) {
        Write-BctLog ("nmap " + ($Arguments -join ' '))
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # nmap writes warnings to stderr
        try { & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host "  $_" }; $rc = $LASTEXITCODE }
        finally { $ErrorActionPreference = $old }
        if ($rc -ne 0) { throw "nmap failed with exit code $rc" }
    }

    # ======================= main =======================
    # tests/ load only the functions above (via the PowerShell AST); this block never runs in tests.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        # ----- resolve settings: parameter > env var > default -----
        $ClientCode = [string](Resolve-Setting $ClientCode 'BCT_CLIENTCODE' '')
        if (-not $ClientCode) { Exit-Discovery 1 'ClientCode is required (-ClientCode CLIENT or env BCT_CLIENTCODE)'; return }
        if (-not (Test-ClientCode $ClientCode)) { Exit-Discovery 1 "ClientCode '$ClientCode' may only contain letters, digits, - and _ (max 32)"; return }
        $LogDir    = [string](Resolve-Setting $LogDir 'BCT_LOGDIR' 'C:\BCT\Logs')
        $ToolsDir  = [string](Resolve-Setting $ToolsDir 'BCT_TOOLSDIR' 'C:\BCT\Tools')
        $OutputDir = [string](Resolve-Setting $OutputDir 'BCT_OUTPUTDIR' ('C:\BCT\Scans\' + $ClientCode))
        $Ports     = [string](Resolve-Setting $Ports 'BCT_PORTS' $DefaultPorts)
        $TimingArg = ConvertTo-NmapTiming ([string](Resolve-Setting $Timing 'BCT_TIMING' 'T4'))
        $MaxRate   = [int](Resolve-Setting $MaxRate 'BCT_MAXRATE' 30)
        $VersionIntensity = [int](Resolve-Setting $VersionIntensity 'BCT_VERSIONINTENSITY' 2)
        if ($ChocoTimeoutSec -le 0) { $ChocoTimeoutSec = -1 }   # 0 = not given
        $ChocoTimeoutSec  = [int](Resolve-Setting $ChocoTimeoutSec 'BCT_CHOCOTIMEOUTSEC' 600)
        $NmapPath   = [string](Resolve-Setting $NmapPath 'BCT_NMAPPATH' '')
        $NmapZipUrl = [string](Resolve-Setting $NmapZipUrl 'BCT_NMAPZIPURL' $DefaultZipUrl)
        $osDetect   = -not ($NoOsDetect -or (Test-EnvFlag 'BCT_NOOSDETECT'))
        $allowLarge = [bool]($AllowLargeSubnet -or (Test-EnvFlag 'BCT_ALLOWLARGESUBNET'))
        $useChoco   = [bool]($UseChocolatey -or (Test-EnvFlag 'BCT_USECHOCOLATEY'))
        $forceUnpriv = [bool]($ForceUnprivileged -or (Test-EnvFlag 'BCT_FORCEUNPRIVILEGED'))
        $degradedOk = [bool]($DegradedIsSuccess -or (Test-EnvFlag 'BCT_DEGRADEDISSUCCESS'))
        $subnetList = Split-ListValue $Subnets
        if ($subnetList.Count -eq 0) { $subnetList = Split-ListValue @([string](Resolve-Setting '' 'BCT_SUBNETS' '')) }

        if (-not (Test-PortSpec $Ports)) { Exit-Discovery 1 "Ports '$Ports' is not a valid list (e.g. 22,80,443,8000-8100)"; return }
        if ($VersionIntensity -gt 9) { Exit-Discovery 1 'VersionIntensity must be 0-9'; return }

        # ----- folders + transcript -----
        foreach ($d in @($LogDir, $OutputDir)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $logFile = Join-Path $LogDir ("NetworkDiscovery_{0}_{1}.log" -f $ClientCode, $stamp)
        try { Start-Transcript -LiteralPath $logFile -Force | Out-Null; $state.TranscriptOn = $true } catch { Write-BctLog "transcript not started: $($_.Exception.Message)" 'WARN' }
        $started = Get-Date
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Exit-Discovery 1 'this script runs on Windows only'; return }
        Write-BctLog "Invoke-NetworkDiscovery $ScriptVersion on $env:COMPUTERNAME as $([Security.Principal.WindowsIdentity]::GetCurrent().Name), PowerShell $($PSVersionTable.PSVersion)"
        Write-BctLog "client $ClientCode, output $OutputDir, log $logFile"

        $isAdmin = Test-IsAdmin
        if (-not $isAdmin) { Write-BctLog 'not elevated: privileged scan (ARP/SYN/OS) impossible, using connect scan' 'WARN' }

        # ----- targets -----
        if ($subnetList.Count -eq 0) {
            Write-BctLog 'no -Subnets given: auto-detecting local IPv4 subnets'
            $decisions = @(Select-ScanSubnet (Get-LocalIPv4Candidate) $allowLarge)
            foreach ($x in $decisions) {
                $lvl = 'INFO'; if (-not $x.Include -and $x.Reason -like 'larger*') { $lvl = 'WARN' }
                Write-BctLog ("  {0}/{1} on '{2}' -> {3}: {4}" -f $x.IPAddress, $x.PrefixLength, $x.InterfaceAlias, $x.Cidr, $x.Reason) $lvl
            }
            $subnetList = @($decisions | Where-Object { $_.Include } | ForEach-Object { $_.Cidr })
            if ($subnetList.Count -eq 0) { Exit-Discovery 1 'no usable local IPv4 subnet found (pass -Subnets, or -AllowLargeSubnet for > /22)'; return }
        }
        else {
            foreach ($s in $subnetList) {
                if (-not (Test-TargetSpec $s)) { Exit-Discovery 1 "target '$s' is not an IPv4 address, CIDR or nmap octet range"; return }
                $pl = Get-PrefixFromSpec $s
                if ($null -ne $pl -and $pl -lt 22 -and -not $allowLarge) { Exit-Discovery 1 "target '$s' is larger than /22; add -AllowLargeSubnet if that is intended"; return }
            }
        }
        Write-BctLog ("targets: " + ($subnetList -join ' '))

        # ----- nmap -----
        $nmap = Find-Nmap $NmapPath $ToolsDir
        if (-not $nmap -and $useChoco) {
            try { Install-NmapChocolatey $ChocoTimeoutSec $LogDir } catch { Write-BctLog "Chocolatey install failed: $($_.Exception.Message)" 'WARN' }
            $nmap = Find-Nmap $NmapPath $ToolsDir
        }
        if (-not $nmap) {
            $sha = ''; if ($NmapZipUrl -eq $DefaultZipUrl) { $sha = $DefaultZipSha256 }
            try { Install-NmapZip $NmapZipUrl $ToolsDir $sha } catch { Write-BctLog "zip install failed: $($_.Exception.Message)" 'WARN' }
            $nmap = Find-Nmap $NmapPath $ToolsDir
        }
        if (-not $nmap) { Exit-Discovery 2 'nmap not found and could not be installed'; return }
        $nmapVer = Test-NmapRun $nmap
        if (-not $nmapVer -and (Install-VcRuntime $nmap)) { $nmapVer = Test-NmapRun $nmap }
        if (-not $nmapVer) { Exit-Discovery 2 "nmap at $nmap does not run (missing VC++ x86 runtime?)"; return }
        Write-BctLog "nmap $nmapVer at $nmap"

        # ----- scan mode -----
        $npcap = Get-NpcapStatus $nmap
        $privileged = ($npcap.Usable -and $isAdmin -and -not $forceUnpriv)
        if ($privileged) { $scanMode = 'Privileged'; Write-BctLog "Npcap $($npcap.Version) OK: full scan (ARP, MAC/vendor, SYN, OS detection)" }
        else {
            $scanMode = 'Unprivileged'
            $why = $npcap.Detail; if ($forceUnpriv) { $why = '-ForceUnprivileged' } elseif (-not $isAdmin) { $why = 'not elevated' }
            Write-BctLog "DEGRADED MODE ($why): TCP connect scan (-sT --unprivileged). No ARP, no MAC/Vendor, no OS detection; hosts that answer none of the scan ports are missed. Install Npcap once by hand (https://npcap.com/#download) or use Npcap OEM - see README." 'WARN'
        }

        $DiscoveryBase  = Join-Path $OutputDir "${ClientCode}_discovery"
        $PortScanBase   = Join-Path $OutputDir "${ClientCode}_portscan"
        $LiveHostsFile  = Join-Path $OutputDir "${ClientCode}_livehosts.txt"
        $HostsCsvOutput = Join-Path $OutputDir "${ClientCode}_hosts.csv"
        $PortsCsvOutput = Join-Path $OutputDir "${ClientCode}_ports.csv"
        $InfoFile       = Join-Path $OutputDir "${ClientCode}_scan_info.txt"

        # ----- 1. discovery -----
        Write-BctLog "=== 1. Discovery sweep ($($subnetList -join ' ')) ==="
        $discArgs = Get-NmapArgumentSet -Stage Discovery -Privileged $privileged -TimingArg $TimingArg -Targets $subnetList -PortList $Ports -OutBase $DiscoveryBase
        Invoke-Nmap $nmap $discArgs
        $LiveHosts = @(Get-NmapHost -XmlPath "$DiscoveryBase.xml")
        Write-BctLog "found $($LiveHosts.Count) live host(s)"

        $ScanHosts = @()
        if ($LiveHosts.Count -gt 0) {
            $LiveHosts | ForEach-Object { $_.IP } | Set-Content -LiteralPath $LiveHostsFile -Encoding ASCII
            # ----- 2. ports / services / OS -----
            Write-BctLog '=== 2. Port, service and OS scan ==='
            $portArgs = Get-NmapArgumentSet -Stage PortScan -Privileged $privileged -TimingArg $TimingArg -PortList $Ports `
                        -Intensity $VersionIntensity -OsDetect $osDetect -Rate $MaxRate -TargetFile $LiveHostsFile -OutBase $PortScanBase
            Invoke-Nmap $nmap $portArgs
            $ScanHosts = @(Get-NmapHost -XmlPath "$PortScanBase.xml")
        }
        else { Write-BctLog 'no live hosts found: check the subnets and that this machine is on (or routed to) them' 'WARN' }

        # ----- 3. CSVs (same columns as the original) -----
        $HostRows = @(ConvertTo-HostRow $LiveHosts $ScanHosts)
        $PortRows = @(ConvertTo-PortRow $ScanHosts)
        Export-ReportCsv $HostRows $HostsCsvOutput $HostColumns
        Export-ReportCsv $PortRows $PortsCsvOutput $PortColumns
        if ($LiveHosts.Count -gt 0 -and $PortRows.Count -eq 0) { Write-BctLog 'no open ports found on the scanned ports' 'WARN' }

        $info = @(
            "ClientCode: $ClientCode"
            "Computer: $env:COMPUTERNAME"
            "Started: $($started.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
            "Finished: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))"
            "ScanMode: $scanMode"
            "Npcap: $(if ($npcap.Present) { "$($npcap.Version) ($($npcap.Detail))" } else { $npcap.Detail })"
            "Nmap: $nmapVer ($nmap)"
            "Targets: $($subnetList -join ' ')"
            "Ports: $Ports"
            "Timing: $TimingArg  MaxRate: $MaxRate  VersionIntensity: $VersionIntensity  OsDetect: $($osDetect -and $privileged)"
            "LiveHosts: $($LiveHosts.Count)  OpenPortRows: $($PortRows.Count)"
            "Script: Invoke-NetworkDiscovery $ScriptVersion"
            "Log: $logFile"
        )
        if ($scanMode -ne 'Privileged') { $info += 'WARNING: degraded connect scan - MAC, Vendor, OS and OSAccuracy columns are blank; hosts with none of the scan ports open are not listed.' }
        foreach ($w in $state.Warnings) { $info += "WARN: $w" }
        Set-Content -LiteralPath $InfoFile -Value $info -Encoding UTF8

        Write-BctLog "hosts CSV : $HostsCsvOutput ($($HostRows.Count) rows)"
        Write-BctLog "ports CSV : $PortsCsvOutput ($($PortRows.Count) rows)"
        Write-BctLog "scan info : $InfoFile"
        Write-BctLog "raw nmap  : $DiscoveryBase.* , $PortScanBase.*"

        if ($LiveHosts.Count -eq 0) { Exit-Discovery 4 'completed: no live hosts found'; return }
        if ($scanMode -ne 'Privileged' -and -not $degradedOk) { Exit-Discovery 3 "completed in DEGRADED mode ($($HostRows.Count) hosts)"; return }
        Exit-Discovery 0 "completed: $scanMode scan, $($HostRows.Count) hosts, $($PortRows.Count) open ports"
    }
    catch {
        Exit-Discovery 1 $_.Exception.Message
    }
}
