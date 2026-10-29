<#
Mock/unit tests for Invoke-NetworkDiscovery.ps1. Runs anywhere pwsh 7 / PS 5.1 runs (Linux too):
the script's functions are loaded through the PowerShell AST, so no scan or install ever runs.

  pwsh -NoProfile -File tests/Test-NetworkDiscovery.ps1
  $env:BCT_TEST_NMAP = '/path/to/nmap'   # optional: also do a real -sT scan of 127.0.0.1 only
  $env:BCT_TEST_LIVE = '1'                # optional: live check of nmap.org (setup.exe + SHA256) and npcap.com/dist
Exit code = number of failed tests.
#>
$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$main   = Join-Path $root 'Invoke-NetworkDiscovery.ps1'
$fix    = Join-Path $PSScriptRoot 'fixtures'
$out    = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Path $out -Force | Out-Null
$script:fail = 0; $script:pass = 0

function Assert([bool]$Cond, [string]$Name) {
    if ($Cond) { $script:pass++; Write-Host "  PASS $Name" }
    else { $script:fail++; Write-Host "  FAIL $Name" -ForegroundColor Red }
}
function Assert-Throw([scriptblock]$Block, [string]$Name) {
    $threw = $false; try { & $Block | Out-Null } catch { $threw = $true }
    Assert $threw $Name
}

# ---- load the functions (and only the functions) from the main script ----
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($main, [ref]$tokens, [ref]$errors)
Assert ($errors.Count -eq 0) 'main script parses'
$Tag = '[test]'   # used by Write-BctLog in the loaded functions
$null = $Tag
$state = @{ TranscriptOn = $false; Warnings = New-Object System.Collections.Generic.List[string] }
$null = $state
$funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($f in $funcs) { . ([scriptblock]::Create($f.Extent.Text)) }
Write-Host "loaded $($funcs.Count) functions"
$HostColumns = @('IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'OSAccuracy', 'OpenPorts')
$PortColumns = @('IP', 'Hostname', 'Port', 'Protocol', 'Service', 'Product', 'Version', 'Extra')

Write-Host 'subnet math'
Assert ((Get-NetworkCidr '192.168.1.57' 24) -eq '192.168.1.0/24') '192.168.1.57/24 -> 192.168.1.0/24'
Assert ((Get-NetworkCidr '10.1.2.3' 22) -eq '10.1.0.0/22') '10.1.2.3/22 -> 10.1.0.0/22'
Assert ((Get-NetworkCidr '172.16.5.130' 25) -eq '172.16.5.128/25') '172.16.5.130/25 -> .128/25'
Assert ((Get-NetworkCidr '192.168.1.57' 32) -eq '192.168.1.57/32') '/32 keeps host'
Assert ((Get-NetworkCidr '255.255.255.255' 0) -eq '0.0.0.0/0') '/0'
Assert ((Get-NetworkCidr '192.168.100.200' 30) -eq '192.168.100.200/30') '/30'
Assert-Throw { Get-NetworkCidr '192.168.1.300' 24 } 'bad IP throws'
Assert-Throw { Get-NetworkCidr '192.168.1.1' 33 } 'bad prefix throws'
Assert ((ConvertTo-PrefixLength '255.255.255.0') -eq 24) 'mask /24'
Assert ((ConvertTo-PrefixLength '255.255.252.0') -eq 22) 'mask /22'
Assert ((ConvertTo-PrefixLength '255.255.255.255') -eq 32) 'mask /32'
Assert-Throw { ConvertTo-PrefixLength '255.0.255.0' } 'non-contiguous mask throws'

Write-Host 'subnet selection (auto-detect filter)'
$cands = @(
    [pscustomobject]@{ IPAddress = '192.168.1.57'; PrefixLength = 24; InterfaceAlias = 'Ethernet' }
    [pscustomobject]@{ IPAddress = '192.168.1.99'; PrefixLength = 24; InterfaceAlias = 'Ethernet 2' }
    [pscustomobject]@{ IPAddress = '127.0.0.1'; PrefixLength = 8; InterfaceAlias = 'Loopback' }
    [pscustomobject]@{ IPAddress = '169.254.10.20'; PrefixLength = 16; InterfaceAlias = 'Ethernet 3' }
    [pscustomobject]@{ IPAddress = '172.20.0.5'; PrefixLength = 16; InterfaceAlias = 'vEthernet' }
    [pscustomobject]@{ IPAddress = '10.8.0.6'; PrefixLength = 32; InterfaceAlias = 'VPN' }
    [pscustomobject]@{ IPAddress = '10.50.4.9'; PrefixLength = 22; InterfaceAlias = 'Site' }
)
$sel = @(Select-ScanSubnet $cands $false)
$inc = @($sel | Where-Object Include | ForEach-Object Cidr)
Assert ($inc.Count -eq 2 -and $inc[0] -eq '192.168.1.0/24' -and $inc[1] -eq '10.50.4.0/22') "includes 192.168.1.0/24 and 10.50.4.0/22 only (got $($inc -join ','))"
Assert (($sel | Where-Object IPAddress -eq '192.168.1.99').Reason -eq 'duplicate') 'duplicate network skipped'
Assert (($sel | Where-Object IPAddress -eq '127.0.0.1').Reason -eq 'loopback') 'loopback skipped'
Assert (($sel | Where-Object IPAddress -eq '169.254.10.20').Reason -like 'APIPA*') 'APIPA skipped'
Assert (($sel | Where-Object IPAddress -eq '172.20.0.5').Reason -like 'larger than /22*') '/16 skipped without -AllowLargeSubnet'
Assert (($sel | Where-Object IPAddress -eq '10.8.0.6').Reason -like 'host route*') '/32 skipped'
$sel2 = @(Select-ScanSubnet $cands $true | Where-Object Include | ForEach-Object Cidr)
Assert ($sel2 -contains '172.20.0.0/16') '/16 included with -AllowLargeSubnet'

Write-Host 'target / parameter validation'
foreach ($t in @('192.168.1.0/24', '192.168.1.5', '192.168.1.10-50', '10.0.0-3.1-254')) { Assert (Test-TargetSpec $t) "valid target $t" }
foreach ($t in @('-oN', '--script=x', '192.168.1.0/33', '192.168.1.256', 'example.com', '1.2.3.4;calc', '')) { Assert (-not (Test-TargetSpec $t)) "invalid target '$t'" }
Assert ((Get-PrefixFromSpec '192.168.0.0/16') -eq 16) 'prefix from CIDR'
Assert ($null -eq (Get-PrefixFromSpec '192.168.1.1-50')) 'prefix from range is null'
Assert (Test-PortSpec '22,80,81,135,139,443,445,3000,3389,5000,5001,8000,8080,8443,8888,9000,9090,9443') 'default port list valid'
Assert (Test-PortSpec '1-1024,8080') 'port range valid'
Assert (-not (Test-PortSpec '22,-sC')) 'port injection rejected'
Assert (-not (Test-PortSpec '')) 'empty ports rejected'
Assert (Test-ClientCode 'CLIENT') 'ClientCode CLIENT ok'
Assert (Test-ClientCode 'ABC-01_x') 'ClientCode ABC-01_x ok'
Assert (-not (Test-ClientCode '..\evil')) 'ClientCode path traversal rejected'
Assert (-not (Test-ClientCode 'a b')) 'ClientCode space rejected'
Assert ((ConvertTo-NmapTiming 'T3') -eq '-T3') 'timing T3'
Assert ((ConvertTo-NmapTiming '-T4') -eq '-T4') 'timing -T4'
Assert ((ConvertTo-NmapTiming '5') -eq '-T5') 'timing 5'
Assert-Throw { ConvertTo-NmapTiming 'T9' } 'timing T9 throws'

Write-Host 'env var handling'
$env:BCT_T_STR = ' fromenv '; $env:BCT_T_INT = '45'; $env:BCT_T_BAD = 'x'; $env:BCT_T_FLAG = 'Yes'; $env:BCT_T_NOFLAG = '0'
Assert ((Resolve-Setting 'param' 'BCT_T_STR' 'def') -eq 'param') 'param beats env'
Assert ((Resolve-Setting '' 'BCT_T_STR' 'def') -eq 'fromenv') 'env used (trimmed) when param empty'
Assert ((Resolve-Setting '' 'BCT_T_NONE' 'def') -eq 'def') 'default when neither'
Assert ((Resolve-Setting -1 'BCT_T_INT' 30) -eq 45) 'int from env'
Assert ((Resolve-Setting 0 'BCT_T_INT' 30) -eq 0) 'explicit 0 beats env'
Assert ((Resolve-Setting -1 'BCT_T_NONE' 30) -eq 30) 'int default'
Assert-Throw { Resolve-Setting -1 'BCT_T_BAD' 30 } 'non-numeric env int throws'
Assert (Test-EnvFlag 'BCT_T_FLAG') 'flag Yes = on'
Assert (-not (Test-EnvFlag 'BCT_T_NOFLAG')) 'flag 0 = off'
Assert (-not (Test-EnvFlag 'BCT_T_NONE')) 'flag unset = off'
$l = Split-ListValue @('192.168.1.0/24, 192.168.2.0/24;192.168.3.0/24  192.168.4.0/24')
Assert ($l.Count -eq 4 -and $l[3] -eq '192.168.4.0/24') 'BCT_SUBNETS split on , ; space'
$l = Split-ListValue @('192.168.1.0/24', '192.168.2.0/24')
Assert ($l.Count -eq 2) 'array param kept'
Assert ((Split-ListValue @('')).Count -eq 0) 'empty -> 0 items'
Remove-Item Env:BCT_T_STR, Env:BCT_T_INT, Env:BCT_T_BAD, Env:BCT_T_FLAG, Env:BCT_T_NOFLAG

Write-Host 'nmap argument sets'
$d = Get-NmapArgumentSet -Stage Discovery -Privileged $true -TimingArg '-T4' -Targets @('192.168.1.0/24') -PortList '22,80' -OutBase 'X'
Assert (($d -join ' ') -eq '-sn -T4 192.168.1.0/24 -oA X') "privileged discovery = original ($($d -join ' '))"
$d = Get-NmapArgumentSet -Stage Discovery -Privileged $false -TimingArg '-T4' -Targets @('192.168.1.0/24') -PortList '22,80' -OutBase 'X'
Assert (($d -join ' ') -eq '--unprivileged -sn -T4 -PS22,80 192.168.1.0/24 -oA X') "unprivileged discovery ($($d -join ' '))"
$p = Get-NmapArgumentSet -Stage PortScan -Privileged $true -TimingArg '-T4' -PortList '22,80' -Intensity 2 -OsDetect $true -Rate 30 -TargetFile 'L' -OutBase 'P'
Assert (($p -join ' ') -eq '-T4 -Pn -sS -sV --version-intensity 2 -p 22,80 --open -O --osscan-limit --max-rate 30 -iL L -oA P') "privileged port scan = original ($($p -join ' '))"
$p = Get-NmapArgumentSet -Stage PortScan -Privileged $false -TimingArg '-T3' -PortList '22' -Intensity 2 -OsDetect $true -Rate 0 -TargetFile 'L' -OutBase 'P'
Assert (($p -join ' ') -eq '--unprivileged -T3 -Pn -sT -sV --version-intensity 2 -p 22 --open -iL L -oA P') "unprivileged port scan: -sT, no -O ($($p -join ' '))"
$p = Get-NmapArgumentSet -Stage PortScan -Privileged $true -TimingArg '-T4' -PortList '22' -Intensity 2 -OsDetect $false -Rate 30 -TargetFile 'L' -OutBase 'P'
Assert (-not ($p -contains '-O')) '-NoOsDetect drops -O'

Write-Host 'nmap XML -> CSV (privileged)'
$live = @(Get-NmapHost -XmlPath (Join-Path $fix 'priv_discovery.xml'))
$scan = @(Get-NmapHost -XmlPath (Join-Path $fix 'priv_portscan.xml'))
Assert ($live.Count -eq 3) 'discovery: 3 up hosts (down host ignored)'
Assert ($scan.Count -eq 3) 'port scan: 3 hosts'
$hr = @(ConvertTo-HostRow $live $scan); $pr = @(ConvertTo-PortRow $scan)
Assert (($hr | ForEach-Object IP) -join ',' -eq '192.168.1.2,192.168.1.10,192.168.1.100') 'hosts sorted numerically by IP'
$nas = $hr | Where-Object IP -eq '192.168.1.10'
Assert ($nas.MAC -eq '00:11:32:AA:BB:CC' -and $nas.Vendor -eq 'Synology Incorporated') 'MAC/vendor from discovery'
Assert ($nas.OS -eq 'Linux 4.15 - 5.19' -and $nas.OSAccuracy -eq '98') 'first osmatch used'
Assert ($nas.OpenPorts -eq '5001/tcp 22/tcp 443/tcp') "OpenPorts string ($($nas.OpenPorts))"
Assert (($hr | Where-Object IP -eq '192.168.1.2').Hostname -eq 'fw.example.local') 'hostname falls back to port scan'
Assert (($hr | Where-Object IP -eq '192.168.1.100').OpenPorts -eq '') 'host with no open ports has empty OpenPorts'
Assert ($pr.Count -eq 4) "4 port rows (got $($pr.Count))"
Assert ((($pr | ForEach-Object { "$($_.IP):$($_.Port)" }) -join ',') -eq '192.168.1.2:443,192.168.1.10:22,192.168.1.10:443,192.168.1.10:5001') 'ports sorted by IP then port'
$ssh = $pr | Where-Object Port -eq 22
Assert ($ssh.Product -eq 'OpenSSH' -and $ssh.Version -eq '8.2' -and $ssh.Extra -eq 'protocol 2.0' -and $ssh.Service -eq 'ssh') 'service fields'
$hcsv = Join-Path $out 'CLIENT_hosts.csv'; $pcsv = Join-Path $out 'CLIENT_ports.csv'
Export-ReportCsv $hr $hcsv $HostColumns; Export-ReportCsv $pr $pcsv $PortColumns
$h1 = (Get-Content $hcsv -TotalCount 1).TrimStart([char]0xFEFF)
Assert ($h1 -eq '"IP","Hostname","MAC","Vendor","OS","OSAccuracy","OpenPorts"') "hosts CSV header identical ($h1)"
$p1 = (Get-Content $pcsv -TotalCount 1).TrimStart([char]0xFEFF)
Assert ($p1 -eq '"IP","Hostname","Port","Protocol","Service","Product","Version","Extra"') "ports CSV header identical ($p1)"
Assert ((Import-Csv $hcsv).Count -eq 3) 'hosts CSV round-trips'

Write-Host 'nmap XML -> CSV (unprivileged -sT)'
$live = @(Get-NmapHost -XmlPath (Join-Path $fix 'unpriv_discovery.xml'))
$scan = @(Get-NmapHost -XmlPath (Join-Path $fix 'unpriv_portscan.xml'))
$hr = @(ConvertTo-HostRow $live $scan); $pr = @(ConvertTo-PortRow $scan)
Assert ($hr.Count -eq 2) '2 hosts (one without open ports still listed)'
Assert (-not ($hr | Where-Object { $_.MAC -or $_.Vendor -or $_.OS })) 'MAC/Vendor/OS blank in connect mode'
Assert ((($hr | Where-Object IP -eq '192.168.1.20').OpenPorts) -eq '3389/tcp 80/tcp') 'OpenPorts in connect mode'
Assert ($pr.Count -eq 2 -and $pr[0].Port -eq 80) 'port rows sorted'

Write-Host 'empty results'
$none = @(Get-NmapHost -XmlPath (Join-Path $fix 'does-not-exist.xml'))
Assert ($none.Count -eq 0) 'missing XML -> no hosts'
$ecsv = Join-Path $out 'EMPTY_ports.csv'
Export-ReportCsv @() $ecsv $PortColumns
Assert ((Get-Content $ecsv).Count -eq 1 -and @(Import-Csv $ecsv).Count -eq 0) 'header-only CSV when no rows'

Write-Host 'latest nmap version (saved nmap.org/dist listing)'
$listing = Get-Content -LiteralPath (Join-Path $fix 'nmap_dist_listing.html') -Raw
$lt = Select-LatestNmapSetup $listing 'https://nmap.org/dist/'
Assert ($null -ne $lt) 'listing parsed'
Assert ($lt.VersionText -eq '7.993' -and $lt.Version -eq [version]'7.993') "latest = 7.993 (got $($lt.VersionText))"
Assert ($lt.FileName -eq 'nmap-7.993-setup.exe') 'file name'
Assert ($lt.Url -eq 'https://nmap.org/dist/nmap-7.993-setup.exe') 'download URL'
Assert ($lt.DigestUrl -eq 'https://nmap.org/dist/sigs/nmap-7.993-setup.exe.digest.txt') 'digest URL'
$mix = 'nmap-7.92-setup.exe nmap-7.99-setup.exe nmap-7.100BETA1-setup.exe nmap-8.00SVN-setup.exe nmap-6.25-vs9-setup.exe xnmap-9.9-setup.exe nmap-7.98-setup.exe.asc'
Assert ((Select-LatestNmapSetup $mix).VersionText -eq '7.99') 'BETA/SVN/vs9/xnmap ignored, highest stable wins'
Assert ((Select-LatestNmapSetup 'nmap-7.99-setup.exe nmap-7.991-setup.exe nmap-7.100-setup.exe').VersionText -eq '7.991') 'sorted as [version] (7.991 > 7.100 > 7.99), not as text'
Assert ((Select-LatestNmapSetup 'nmap-7.99-setup.exe nmap-8.0-setup.exe').VersionText -eq '8.0') 'major bump wins'
Assert ($null -eq (Select-LatestNmapSetup '<html>nothing here</html>')) 'no setup.exe -> $null'
Assert ((Select-LatestNmapSetup 'nmap-7.99-setup.exe' 'https://mirror.example/nmap').Url -eq 'https://mirror.example/nmap/nmap-7.99-setup.exe') 'base URL without trailing slash'
Assert ((ConvertTo-NmapVersion '7.92') -eq [version]'7.92') 'version 7.92'
Assert ((ConvertTo-NmapVersion '7.92SVN') -eq [version]'7.92') 'version 7.92SVN'
Assert ($null -eq (ConvertTo-NmapVersion '')) 'empty version -> $null'
Assert ($null -eq (ConvertTo-NmapVersion 'abc')) 'garbage version -> $null'

Write-Host 'SHA256 from nmap.org digest files'
$d1 = Get-Content -LiteralPath (Join-Path $fix 'nmap-7.993-setup.exe.digest.txt') -Raw
$d2 = Get-Content -LiteralPath (Join-Path $fix 'nmap-7.99-setup.exe.digest.txt') -Raw
Assert ((Get-DigestSha256 $d1) -eq '22E5928D1738A1B94FFD3643014F52CB87D467DBEC4CFF9E5F721FE0B3782F1B') 'SHA256 parsed (one-line format, 7.993)'
Assert ((Get-DigestSha256 $d2) -eq 'FDA839F35D9F8F18A11670E17D0332CE9D05A3556C5A20E91B0B56C57774F611') 'SHA256 parsed (wrapped format, 7.99)'
Assert ($null -eq (Get-DigestSha256 'MD5 = 01 0F 9F 76')) 'no SHA256 line -> $null'
Assert ($null -eq (Get-DigestSha256 'SHA256 = 22E5928D 1738A1B9')) 'truncated SHA256 -> $null'
Assert ($null -eq (Get-DigestSha256 '')) 'empty digest -> $null'
$sampleExe = Join-Path $out 'fake-setup.exe'
Set-Content -LiteralPath $sampleExe -Value 'not really nmap' -Encoding ASCII
$fakeHash = (Get-FileHash -LiteralPath $sampleExe -Algorithm SHA256).Hash
Assert ((Test-Sha256Match $fakeHash $fakeHash.ToLowerInvariant()) -eq 'Match') 'hash match (case-insensitive)'
Assert ((Test-Sha256Match $fakeHash (Get-DigestSha256 $d1)) -eq 'Mismatch') 'hash mismatch -> Mismatch (abort)'
Assert ((Test-Sha256Match $fakeHash $null) -eq 'Unknown') 'no published hash -> Unknown (warn, continue)'
Assert ((Test-Sha256Match $fakeHash '') -eq 'Unknown') 'empty published hash -> Unknown'

Write-Host 'session checks (Npcap prompt / UAC)'
$ok = Test-InteractiveSession -UserInteractive $true -IsSystem $false -SessionId 2 -CommandLineArgs @('pwsh.exe') -HostName 'ConsoleHost'
Assert ($ok.Allowed) 'signed-in pwsh console allowed'
$ok = Test-InteractiveSession -UserInteractive $true -IsSystem $false -SessionId 1 -CommandLineArgs @('powershell.exe', '-NoProfile', '-Command', 'irm x | iex') -HostName 'ConsoleHost'
Assert ($ok.Allowed) '-Command alone still allowed (desktop present)'
$no = Test-InteractiveSession -UserInteractive $true -IsSystem $true -SessionId 0 -CommandLineArgs @('powershell.exe')
Assert (-not $no.Allowed -and $no.Reason -like '*SYSTEM*') "SYSTEM refused ($($no.Reason))"
$no = Test-InteractiveSession -UserInteractive $false -IsSystem $false -SessionId 1
Assert (-not $no.Allowed -and $no.Reason -like 'non-interactive*') 'non-interactive refused'
$no = Test-InteractiveSession -UserInteractive $true -IsSystem $false -SessionId 0
Assert (-not $no.Allowed -and $no.Reason -like 'session 0*') 'session 0 refused'
$no = Test-InteractiveSession -UserInteractive $true -IsSystem $false -SessionId 1 -CommandLineArgs @('pwsh.exe', '-NonInteractive', '-File', 'x.ps1')
Assert (-not $no.Allowed -and $no.Reason -like '*-NonInteractive*') '-NonInteractive refused'
$no = Test-InteractiveSession -UserInteractive $true -IsSystem $false -SessionId 1 -HostName 'ServerRemoteHost'
Assert (-not $no.Allowed -and $no.Reason -like '*remoting*') 'remoting session refused'

Write-Host 'Npcap: latest free installer (saved npcap.com/dist listing)'
$nlisting = Get-Content -LiteralPath (Join-Path $fix 'npcap_dist_listing.html') -Raw
$nl = Select-LatestNpcapSetup $nlisting 'https://npcap.com/dist/'
Assert ($null -ne $nl -and $nl.VersionText -eq '1.90') "latest Npcap = 1.90 (got $($nl.VersionText))"
Assert ($nl.Url -eq 'https://npcap.com/dist/npcap-1.90.exe' -and $nl.FileName -eq 'npcap-1.90.exe') 'Npcap URL / file name'
Assert ($nl.DigestUrl -eq '') 'npcap.com publishes no digest'
$nmix = 'npcap-1.82-debug.exe npcap-1.90-oem.exe npcap-1.95-DebugSymbols.zip npcap-1.96.zip npcap-sdk-1.17.zip npcap-nmap-9.9.exe npcap-1.10.exe npcap-1.89.exe npcap-0.9997.exe'
Assert ((Select-LatestNpcapSetup $nmix).VersionText -eq '1.89') 'debug/oem/zip/sdk/npcap-nmap ignored; 1.89 > 1.10 > 0.9997'
Assert ((Select-LatestNpcapSetup 'npcap-1.90.exe npcap-1.100.exe').VersionText -eq '1.100') 'Npcap sorted as [version]'
Assert ($null -eq (Select-LatestNpcapSetup 'npcap-sdk-1.17.zip')) 'no installer -> $null'

Write-Host 'Authenticode publisher check'
$subjNew = 'CN=Nmap Software LLC, O=Nmap Software LLC, L=Beaverton, S=Oregon, C=US, SERIALNUMBER=6397588'
$subjOld = 'CN="Insecure.Com LLC", O="Insecure.Com LLC", L=Seattle, S=Washington, C=US'
Assert ((Test-PublisherSignature 'Valid' $subjNew) -eq 'Valid') 'valid + Nmap Software LLC -> Valid'
Assert ((Test-PublisherSignature 'Valid' 'CN=Insecure.Com LLC, O=Insecure.Com LLC, C=US') -eq 'Valid') 'valid + Insecure.Com LLC -> Valid'
Assert ((Test-PublisherSignature 'Valid' 'CN=Evil Nmap Software LLC Clone, O=Evil') -eq 'Invalid') 'valid but other publisher -> Invalid'
Assert ((Test-PublisherSignature 'Valid' $subjOld) -eq 'Valid') 'quoted Insecure.Com LLC subject -> Valid'
Assert ((Test-PublisherSignature 'Valid' 'CN=Nmap Software LLC Fake, O=Other') -eq 'Invalid') 'prefix look-alike -> Invalid'
Assert ((Test-PublisherSignature 'NotSigned' '') -eq 'Invalid') 'unsigned -> Invalid'
Assert ((Test-PublisherSignature 'HashMismatch' $subjNew) -eq 'Invalid') 'tampered -> Invalid'
Assert ((Test-PublisherSignature 'NotTrusted' $subjNew) -eq 'Invalid') 'untrusted -> Invalid'
Assert ((Test-PublisherSignature 'UnknownError' $subjNew) -eq 'Unknown') 'unknown status -> Unknown (warn)'

Write-Host 'silent latest-nmap decision matrix'
function Get-D($dis, $adm, $uac, $have, $latest, $np) { Get-SilentNmapDecision -DisabledReason $dis -IsAdmin $adm -CanPromptUac $uac -InstalledVersion $have -LatestVersion $latest -NpcapInstalled $np }
$dd = Get-D '' $true $false '' '7.993' $true
Assert ($dd.Install -and -not $dd.UseRunAs -and $dd.Reason -like 'nmap not installed*silently') 'SYSTEM/elevated, no nmap, Npcap present -> silent install'
$dd = Get-D '' $true $false '7.92' '7.993' $true
Assert ($dd.Install -and $dd.Reason -like '*7.92 is older than 7.993*') 'SYSTEM/elevated, 7.92 zip -> silent upgrade'
$dd = Get-D '' $true $false '7.99' '7.993' $true
Assert ($dd.Install) '7.99 -> 7.993 upgrade'
$dd = Get-D '' $true $false '7.993' '7.993' $true
Assert (-not $dd.Install -and $dd.Reason -like '*already the latest*') 'already latest -> no install'
$dd = Get-D '' $true $false '8.0' '7.993' $true
Assert (-not $dd.Install) 'newer dev build -> no install'
$dd = Get-D '' $true $false '' '7.993' $false
Assert (-not $dd.Install -and $dd.Reason -like '*cannot run silently without Npcap*') 'SYSTEM, no Npcap -> skip (installer would show a dialog), fall back to zip'
$dd = Get-D '' $true $false '7.92' '7.993' $false
Assert (-not $dd.Install) 'old nmap, no Npcap -> skip'
$dd = Get-D '' $true $false '' '' $true
Assert (-not $dd.Install -and $dd.Reason -like '*unknown*') 'nmap.org unreachable -> skip, fall back'
$dd = Get-D '-SkipLatestNmap / BCT_SKIPLATESTNMAP' $true $false '' '7.993' $true
Assert (-not $dd.Install -and $dd.Reason -like 'skipped: -SkipLatestNmap*') '-SkipLatestNmap -> skip'
$dd = Get-D '' $false $false '' '7.993' $true
Assert (-not $dd.Install -and $dd.Reason -like '*not elevated*') 'not elevated, no prompt allowed -> skip'
$dd = Get-D '' $false $true '' '7.993' $true
Assert ($dd.Install -and $dd.UseRunAs) 'not elevated, signed-in + -InteractiveInstall -> UAC prompt'

Write-Host 'Npcap prompt decision'
$desk = [pscustomobject]@{ Allowed = $true; Reason = 'interactive desktop session' }
$sys  = Test-InteractiveSession -UserInteractive $true -IsSystem $true -SessionId 0
$noni = Test-InteractiveSession -UserInteractive $true -IsSystem $false -SessionId 1 -CommandLineArgs @('powershell.exe', '-NonInteractive')
$np = Get-NpcapPromptDecision -NpcapInstalled $true -AllowPrompt $true -Session $desk
Assert (-not $np.Prompt -and $np.Reason -like 'Npcap already*') 'Npcap present -> zero prompts'
$np = Get-NpcapPromptDecision -NpcapInstalled $false -AllowPrompt $true -Session $desk
Assert ($np.Prompt) 'Npcap missing + -InteractiveInstall + desktop -> prompt'
$np = Get-NpcapPromptDecision -NpcapInstalled $false -AllowPrompt $false -Session $desk
Assert (-not $np.Prompt -and $np.Reason -like '*-InteractiveInstall*') 'Npcap missing, switch off -> no prompt (degraded)'
$np = Get-NpcapPromptDecision -NpcapInstalled $false -AllowPrompt $true -Session $sys
Assert (-not $np.Prompt -and $np.Reason -like '*SYSTEM*') 'Npcap missing as SYSTEM -> no prompt (degraded)'
$np = Get-NpcapPromptDecision -NpcapInstalled $false -AllowPrompt $true -Session $noni
Assert (-not $np.Prompt -and $np.Reason -like '*NonInteractive*') 'Npcap missing, -NonInteractive -> no prompt'
$np = Get-NpcapPromptDecision -NpcapInstalled $false -AllowPrompt $true -Session $null
Assert (-not $np.Prompt) 'no session info -> no prompt'
$mainText0 = Get-Content -LiteralPath $main -Raw
Assert ($mainText0 -match "NmapSilentArgs = @\('/S', '/NPCAP=NO', '/ZENMAP=NO'\)") 'silent args /S /NPCAP=NO /ZENMAP=NO'
Assert ($mainText0 -match '(?s)Install-NmapSilent.*Install-NmapChocolatey \$ChocoTimeoutSec.*Install-NmapZip \$NmapZipUrl') 'chain order in main: silent latest -> choco -> 7.92 zip'

Write-Host 'switch / env precedence'
Remove-Item Env:BCT_INTERACTIVEINSTALL -ErrorAction SilentlyContinue
Assert (-not ([bool]($false -or (Test-EnvFlag 'BCT_INTERACTIVEINSTALL')))) 'default off'
$env:BCT_INTERACTIVEINSTALL = '1'
Assert ([bool]($false -or (Test-EnvFlag 'BCT_INTERACTIVEINSTALL'))) 'BCT_INTERACTIVEINSTALL=1 turns it on'
Remove-Item Env:BCT_INTERACTIVEINSTALL
Assert ([bool]($true -or (Test-EnvFlag 'BCT_INTERACTIVEINSTALL'))) '-InteractiveInstall turns it on without env'
$mainText = Get-Content -LiteralPath $main -Raw
Assert ($mainText -match '\$interactiveInstall = \[bool\]\(\$InteractiveInstall -or \(Test-EnvFlag ''BCT_INTERACTIVEINSTALL''\)\)') 'main script resolves switch > env'
Assert ($mainText -match '\$skipLatest = \[bool\]\(\$SkipLatestNmap -or \(Test-EnvFlag ''BCT_SKIPLATESTNMAP''\)\)') 'main script resolves -SkipLatestNmap > env'
$inst = Join-Path $root 'install.ps1'
$itok = $null; $ierr = $null
$iast = [System.Management.Automation.Language.Parser]::ParseFile($inst, [ref]$itok, [ref]$ierr)
Assert ($ierr.Count -eq 0) 'install.ps1 parses'
Assert (@($iast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) -contains 'InteractiveInstall') 'install.ps1 has -InteractiveInstall'
Assert ((Get-Content -LiteralPath $inst -Raw) -match '@fwd') 'install.ps1 passes it through to the main script'

if ($env:BCT_TEST_LIVE) {
    Write-Host 'live: nmap.org latest setup.exe + published SHA256, npcap.com latest installer'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $live = Select-LatestNmapSetup ([string](Invoke-WebRequest -Uri 'https://nmap.org/dist/' -UseBasicParsing).Content)
    Assert ($null -ne $live -and $live.Version -ge [version]'7.99') "live latest found: $($live.FileName)"
    $dgLive = [string](Invoke-WebRequest -Uri $live.DigestUrl -UseBasicParsing).Content
    $shaLive = Get-DigestSha256 $dgLive
    Assert ($shaLive -match '^[0-9A-F]{64}$') "live SHA256 for $($live.FileName): $shaLive"
    $head = Invoke-WebRequest -Uri $live.Url -Method Head -UseBasicParsing
    Assert ($head.StatusCode -eq 200) "live setup.exe reachable ($($live.Url), $($head.Headers['Content-Length']) bytes)"
    $nlive = Select-LatestNpcapSetup ([string](Invoke-WebRequest -Uri 'https://npcap.com/dist/' -UseBasicParsing).Content)
    Assert ($null -ne $nlive -and $nlive.Version -ge [version]'1.80') "live latest Npcap found: $($nlive.FileName)"
    $nhead = Invoke-WebRequest -Uri $nlive.Url -Method Head -UseBasicParsing
    Assert ($nhead.StatusCode -eq 200) "live Npcap installer reachable ($($nlive.Url), $($nhead.Headers['Content-Length']) bytes)"
}
else { Write-Host 'live nmap.org check skipped (set BCT_TEST_LIVE=1)' }

if ($env:BCT_TEST_NMAP) {
    Write-Host 'real nmap: unprivileged scan of 127.0.0.1 only'
    $base = Join-Path $out 'LOCAL_discovery'; $pbase = Join-Path $out 'LOCAL_portscan'; $lf = Join-Path $out 'LOCAL_livehosts.txt'
    $da = Get-NmapArgumentSet -Stage Discovery -Privileged $false -TimingArg '-T4' -Targets @('127.0.0.1') -PortList '8000,22' -OutBase $base
    & $env:BCT_TEST_NMAP @da | Out-Null
    Assert ($LASTEXITCODE -eq 0) "nmap discovery exit 0 ($($da -join ' '))"
    $live = @(Get-NmapHost -XmlPath "$base.xml")
    Assert ($live.Count -eq 1 -and $live[0].IP -eq '127.0.0.1') 'real discovery XML parsed: 127.0.0.1 up'
    $live | ForEach-Object { $_.IP } | Set-Content -Path $lf -Encoding ASCII
    $pa = Get-NmapArgumentSet -Stage PortScan -Privileged $false -TimingArg '-T4' -PortList '8000,22' -Intensity 2 -OsDetect $true -Rate 30 -TargetFile $lf -OutBase $pbase
    & $env:BCT_TEST_NMAP @pa | Out-Null
    Assert ($LASTEXITCODE -eq 0) "nmap port scan exit 0 ($($pa -join ' '))"
    $scan = @(Get-NmapHost -XmlPath "$pbase.xml")
    $pr = @(ConvertTo-PortRow $scan)
    Assert (@($pr | Where-Object Port -eq 8000).Count -eq 1) "real port XML parsed: 8000/tcp open (service $(($pr | Where-Object Port -eq 8000).Service), product $(($pr | Where-Object Port -eq 8000).Product))"
    $hr = @(ConvertTo-HostRow $live $scan)
    Export-ReportCsv $hr (Join-Path $out 'LOCAL_hosts.csv') $HostColumns
    Export-ReportCsv $pr (Join-Path $out 'LOCAL_ports.csv') $PortColumns
    Assert ($hr[0].OpenPorts -match '8000/tcp') "real hosts row OpenPorts=$($hr[0].OpenPorts)"
}
else { Write-Host 'real nmap test skipped (set BCT_TEST_NMAP)' }

Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail)
exit $script:fail
