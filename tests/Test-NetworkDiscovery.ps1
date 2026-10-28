<#
Mock/unit tests for Invoke-NetworkDiscovery.ps1. Runs anywhere pwsh 7 / PS 5.1 runs (Linux too):
the script's functions are loaded through the PowerShell AST, so no scan or install ever runs.

  pwsh -NoProfile -File tests/Test-NetworkDiscovery.ps1
  $env:BCT_TEST_NMAP = '/path/to/nmap'   # optional: also do a real -sT scan of 127.0.0.1 only
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
