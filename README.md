# BCT-NetworkDiscovery

Unattended two-stage **nmap** network discovery for onboarding MSP clients. It replaces Advanced IP Scanner, and its output feeds the client network diagram.

1. **Discovery** (`nmap -sn`) finds live hosts, reverse DNS, MAC and vendor.
2. **Ports / services / OS** (`nmap -sS -sV -O`) runs on the live hosts only and finds open ports, products and an OS guess.

It runs on **Windows PowerShell 5.1 (Server 2016 and later)** and **pwsh 7**, either elevated or as **SYSTEM** (N-central or a scheduled task). It never prompts and never opens a GUI, unless you ask for `-InteractiveInstall` (below).

## Quick start

Run either of these from an elevated PowerShell or an RMM script.

**Env var form (`irm | iex`):**

```powershell
$env:BCT_CLIENTCODE = 'CLIENT'; $env:BCT_SUBNETS = '192.168.1.0/24'
irm https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/install.ps1 | iex
```

**Scriptblock form (parameters):**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/Invoke-NetworkDiscovery.ps1))) -ClientCode CLIENT -Subnets 192.168.1.0/24
```

**Local file:**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-NetworkDiscovery.ps1 -ClientCode CLIENT
```

**Signed in at the PC? Get the latest nmap + Npcap (`-InteractiveInstall`):**

```powershell
$env:BCT_CLIENTCODE = 'CLIENT'; $env:BCT_INTERACTIVEINSTALL = '1'; irm https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/install.ps1 | iex
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/Invoke-NetworkDiscovery.ps1))) -ClientCode CLIENT -InteractiveInstall
```

Clear it again afterwards in the same window with `Remove-Item Env:BCT_INTERACTIVEINSTALL`. See [Interactive install of the latest nmap](#interactive-install-of-the-latest-nmap--interactiveinstall).

If you leave out `-Subnets`, the script auto-detects the local IPv4 subnets. It uses only connected adapters with a preferred address and skips loopback, APIPA (169.254.x) and /32. It also skips anything larger than /22 unless you add `-AllowLargeSubnet`.

Both one-liners force TLS 1.2 on. In an interactive console they set `$LASTEXITCODE` and leave the window open. Run non-interactively (SYSTEM, `-Command`, `-File`), they exit with the code.

## Parameters and environment variables

Every parameter can also be set with an environment variable. If both are set, the parameter wins. Switches accept `1`, `true`, `yes` or `on`.

| Parameter | Env var | Default | Notes |
|---|---|---|---|
| `-ClientCode` | `BCT_CLIENTCODE` | (required) | Letters, digits, `-` and `_`, up to 32 characters. Used in file names. |
| `-Subnets` | `BCT_SUBNETS` | auto-detect | IPv4, CIDR or nmap octet ranges (`192.168.1.10-50`). The env var can be separated by commas, semicolons or spaces. |
| `-OutputDir` | `BCT_OUTPUTDIR` | `C:\BCT\Scans\<ClientCode>` | |
| `-Ports` | `BCT_PORTS` | `22,80,81,135,139,443,445,3000,3389,5000,5001,8000,8080,8443,8888,9000,9090,9443` | Management and web-UI ports |
| `-Timing` | `BCT_TIMING` | `T4` | `T0` to `T5`. Use `T3` for fragile or slow links. |
| `-MaxRate` | `BCT_MAXRATE` | `30` | Packets per second for the port scan. `0` means no cap. |
| `-VersionIntensity` | `BCT_VERSIONINTENSITY` | `2` | `-sV` intensity, 0 to 9 |
| `-NoOsDetect` | `BCT_NOOSDETECT` | off | Skips `-O` |
| `-AllowLargeSubnet` | `BCT_ALLOWLARGESUBNET` | off | Allows targets larger than /22. Applies to auto-detected and explicit subnets. |
| `-UseChocolatey` | `BCT_USECHOCOLATEY` | off | Tries `choco install nmap` first. See the caveat below. |
| `-ChocoTimeoutSec` | `BCT_CHOCOTIMEOUTSEC` | `600` | Kills choco and the installers it started once this runs out |
| `-NmapPath` | `BCT_NMAPPATH` | search | Explicit path to `nmap.exe` |
| `-NmapZipUrl` | `BCT_NMAPZIPURL` | `https://nmap.org/dist/nmap-7.92-win32.zip` | SHA256 is checked when the default is used |
| `-ToolsDir` | `BCT_TOOLSDIR` | `C:\BCT\Tools` | The zip is extracted to `<ToolsDir>\nmap` |
| `-LogDir` | `BCT_LOGDIR` | `C:\BCT\Logs` | Transcript `NetworkDiscovery_<ClientCode>_<yyyyMMdd-HHmmss>.log` |
| `-ForceUnprivileged` | `BCT_FORCEUNPRIVILEGED` | off | Always uses connect-scan mode (for testing) |
| `-DegradedIsSuccess` | `BCT_DEGRADEDISSUCCESS` | off | Exits 0 instead of 3 when Npcap is missing |
| `-InteractiveInstall` | `BCT_INTERACTIVEINSTALL` | off | Signed-in technician only: downloads the latest `nmap-<ver>-setup.exe` and opens the GUI installer (nmap + Npcap). Ignored as SYSTEM. |

`install.ps1` also accepts `-InteractiveInstall` itself (`& ([scriptblock]::Create((irm <install.ps1 url>))) -InteractiveInstall`) and passes it on. It also reads `BCT_SCRIPT_URL` (default: this repo's `main` branch) and `BCT_SCRIPTDIR` (default `C:\BCT\Scripts`, where it saves a copy for scheduled tasks). It runs the script in memory, so the execution policy doesn't block it.

## How nmap is found or installed

The script looks in these places, in order:

1. `-NmapPath`
2. `nmap.exe` on PATH
3. `C:\Program Files (x86)\Nmap`
4. `C:\Program Files\Nmap`
5. `C:\BCT\Tools\nmap`

If none of them has nmap:

- **`-UseChocolatey`** (opt-in) runs `choco install nmap -y` with a hard timeout. The community package has no switch to skip Npcap. It runs the free nmap and Npcap GUI installers and clicks through them with AutoHotkey. As SYSTEM there is no desktop, so it often hangs. The script kills it when the timeout runs out and moves on to the zip.
- **The zip (default fallback)** is `https://nmap.org/dist/nmap-7.92-win32.zip`. That is the **last free Windows zip** (Aug 2021), because nmap.org now ships zip builds to Nmap OEM customers only. The script checks its SHA256 and extracts it to `C:\BCT\Tools\nmap`. If `nmap.exe` won't start, it silently installs the bundled Microsoft `VC_redist.x86.exe` (`/install /quiet /norestart`). The zip also contains `npcap-1.50.exe`, but the script **never runs it**.

For current nmap, install it once by hand with the normal `nmap-<ver>-setup.exe`, or let `-InteractiveInstall` do it for you (next section). The script then finds it in Program Files (x86).

## Interactive install of the latest nmap (`-InteractiveInstall`)

For when you are signed in to the client PC and run PowerShell yourself (not SYSTEM). Free Npcap has no silent install, so the script opens the normal installer and you click through it.

1. It checks that a person can see a GUI. As **SYSTEM**, in session 0, in a remoting session, or with `-NonInteractive`, it logs why it skipped and uses the unattended chain above.
2. It reads <https://nmap.org/dist/> and picks the highest stable `nmap-<ver>-setup.exe` (sorted as a version, BETA builds ignored).
3. It runs the installer only if nmap is **missing**, **older** than that version (for example the 7.92 zip), or **Npcap is missing**. Otherwise it logs `already the latest` and carries on.
4. It downloads the installer to `C:\BCT\Tools\installers` (TLS 1.2) and checks the SHA256 against `https://nmap.org/dist/sigs/<file>.digest.txt`. If the hash can't be fetched, it warns and continues. If the hash **doesn't match**, it deletes the file and doesn't run it.
5. It opens the installer and waits (`Start-Process -Wait`). Keep **Npcap** ticked; Npcap opens its own installer. If PowerShell isn't elevated, you get a UAC prompt, but that run is still a degraded scan, so use an elevated PowerShell for the full scan.
6. It re-detects `C:\Program Files (x86)\Nmap\nmap.exe` and Npcap and continues with the scan. The exit codes are unchanged. `<ClientCode>_scan_info.txt` records what it decided under `InteractiveInstall:`.

## Npcap caveat (read this)

Nmap needs the **Npcap** driver for ARP discovery, MAC/vendor lookup, SYN scans and OS detection.

- The **free Npcap installer has no silent mode**. `/S` works with **Npcap OEM** only ([Npcap Users' Guide: installer options](https://npcap.com/guide/npcap-users-guide.html)). The free license is also limited to about five installs, and redistribution needs an OEM license ([npcap.com/oem](https://npcap.com/oem/)).
- This tool therefore **never installs Npcap unattended** and never uses a redistributed or cracked OEM build. With `-InteractiveInstall` it only opens the official nmap installer for a signed-in person to click through.
- Npcap counts as present when the `npcap` driver service exists and is running, `System32\Npcap\wpcap.dll` exists and `nmap --iflist` loads it. If the driver is installed but stopped, the script tries `sc start npcap` once.

**Without Npcap, the scan runs in degraded mode:** `--unprivileged`, TCP connect discovery (`-sn -PS<ports>`) and a connect port scan (`-sT -sV`).

- There's no ARP or ICMP, so a host that answers on none of the scan ports isn't found.
- The **MAC, Vendor, OS and OSAccuracy columns are blank**.
- The log gets a `WARN` line, `<ClientCode>_scan_info.txt` says `ScanMode: Unprivileged`, and the exit code is **3**.

**One-time manual step for full scans**, done per scanning machine:

- **Option A:** sign in interactively and install Npcap from <https://npcap.com/#download>, with the defaults. Or install nmap with `nmap-<ver>-setup.exe`, which includes Npcap. After that, every unattended run as SYSTEM is a full scan.
- **Option B:** buy **Npcap OEM**. Its silent installer can be pushed from N-central (`npcap-<ver>-oem.exe /S`) as a separate job before this script runs.

## Outputs

These go in `-OutputDir`. The file names and CSV columns are the same as the original scan script.

| File | Contents |
|---|---|
| `<ClientCode>_hosts.csv` | One row per device: `IP,Hostname,MAC,Vendor,OS,OSAccuracy,OpenPorts` |
| `<ClientCode>_ports.csv` | One row per open port: `IP,Hostname,Port,Protocol,Service,Product,Version,Extra` |
| `<ClientCode>_livehosts.txt` | Live IPs from discovery |
| `<ClientCode>_discovery.{xml,nmap,gnmap}` / `<ClientCode>_portscan.{xml,nmap,gnmap}` | Raw nmap output |
| `<ClientCode>_scan_info.txt` | New. Scan mode, Npcap and nmap versions, targets, counts and warnings. |

If there are no rows, the CSVs are still written, with the header only. The original wrote no ports CSV in that case.

## Exit codes (N-central)

| Code | Meaning | Suggested N-central action |
|---|---|---|
| 0 | Completed with a full privileged scan (Npcap) | OK |
| 1 | Error: bad parameter, nmap failed, output not writable, not Windows | Failed |
| 2 | nmap unavailable: not found, couldn't be installed, or won't run | Failed |
| 3 | Completed in **degraded** mode (no Npcap, or not elevated). 0 if `-DegradedIsSuccess` is set. | Warning: do the one-time Npcap step |
| 4 | Completed, but no live hosts found | Warning: check subnets and routing |

## N-central deployment

1. **Automation Manager / Scripting.** Add a PowerShell script task that runs as **LocalSystem**, using the env var one-liner:

   ```powershell
   $env:BCT_CLIENTCODE = 'CLIENT'
   # $env:BCT_SUBNETS = '192.168.1.0/24,192.168.2.0/24'   # optional
   irm https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/install.ps1 | iex
   ```

   Treat exit codes 1 and 2 as failures and 3 and 4 as warnings. Collect the CSVs from `C:\BCT\Scans\CLIENT\`.
2. The scan takes from a few seconds to several minutes per /24. That depends on `-MaxRate`, the timing and how many hosts are live. Set the N-central script timeout to 60 minutes or more.

## Scheduled task example

`install.ps1` saves a copy in `C:\BCT\Scripts`. Alternatively, put the script there yourself.

```powershell
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\BCT\Scripts\Invoke-NetworkDiscovery.ps1" -ClientCode CLIENT -Subnets 192.168.1.0/24'
$t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 02:00
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskPath '\BCT\' -TaskName 'BCT Network Discovery' -Action $a -Trigger $t -Principal $p
```

## Tests

```bash
pwsh -NoProfile -File tests/Test-NetworkDiscovery.ps1                       # unit/mock tests, any OS
BCT_TEST_NMAP=/usr/bin/nmap pwsh -NoProfile -File tests/Test-NetworkDiscovery.ps1  # + real -sT scan of 127.0.0.1 only
BCT_TEST_LIVE=1 pwsh -NoProfile -File tests/Test-NetworkDiscovery.ps1        # + live nmap.org latest setup.exe / SHA256 check
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path . -Recurse -Settings tests/PSScriptAnalyzerSettings.psd1"
```

The tests load only the functions, through the PowerShell AST, so nothing is scanned or installed. The fixtures in `tests/fixtures` mimic privileged and `-sT` nmap XML output, plus a saved nmap.org/dist listing and two `.digest.txt` files for the `-InteractiveInstall` version and hash tests.
