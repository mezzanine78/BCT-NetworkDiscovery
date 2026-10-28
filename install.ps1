<#
install.ps1 - one-line bootstrap for Invoke-NetworkDiscovery.ps1 (BCT / MSP Bergin CT).
irm | iex safe: everything runs inside & { }, and exit is only called when non-interactive
(SYSTEM / RMM / -Command), so an interactive console is never closed.

  $env:BCT_CLIENTCODE = 'CLIENT'; $env:BCT_SUBNETS = '192.168.1.0/24'
  irm https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/install.ps1 | iex

Parameters come from BCT_* environment variables (see README). It downloads the main script
from the repo's main branch (override with BCT_SCRIPT_URL), keeps a copy in C:\BCT\Scripts
(BCT_SCRIPTDIR) for scheduled tasks, and runs it in memory, so the execution policy does not
block it. Exit code / $LASTEXITCODE is the main script's (0/1/2/3/4, see README).
No secrets in this file.
#>
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference    = 'SilentlyContinue'
    $Tag = '[net-discovery-install]'
    $DefaultUrl = 'https://raw.githubusercontent.com/mezzanine78/BCT-NetworkDiscovery/main/Invoke-NetworkDiscovery.ps1'

    function Write-BctLog([string]$Msg, [string]$Level = 'INFO') {
        Write-Host ('{0} {1} {2,-5} {3}' -f $Tag, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg)
    }
    function Exit-Install([int]$Code, [string]$Msg) {
        if ($Code -ne 0) { Write-BctLog "FAILED: $Msg (exit $Code)" 'ERROR' }
        $global:LASTEXITCODE = $Code
        if (-not [Environment]::UserInteractive -or
            ([Environment]::GetCommandLineArgs() -match '^-(c|command|noni|noninteractive|file|f|encodedcommand|e|ec)$')) {
            exit $Code
        }
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $url = $env:BCT_SCRIPT_URL; if (-not $url) { $url = $DefaultUrl }
        $dir = $env:BCT_SCRIPTDIR;  if (-not $dir) { $dir = 'C:\BCT\Scripts' }
        if (-not $env:BCT_CLIENTCODE) { Exit-Install 1 'set $env:BCT_CLIENTCODE first (e.g. $env:BCT_CLIENTCODE = ''CLIENT'')'; return }

        Write-BctLog "downloading $url"
        $text = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
        if ($text -is [byte[]]) { $text = [Text.Encoding]::UTF8.GetString($text) }
        $text = ([string]$text).TrimStart([char]0xFEFF)

        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        if ($errors -and $errors.Count -gt 0) { Exit-Install 1 "downloaded script does not parse: $($errors[0].Message)"; return }

        try {
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $copy = Join-Path $dir 'Invoke-NetworkDiscovery.ps1'
            Set-Content -LiteralPath $copy -Value $text -Encoding UTF8
            Write-BctLog "saved a copy to $copy"
        }
        catch { Write-BctLog "could not save a copy to ${dir}: $($_.Exception.Message)" 'WARN' }

        # Parameters are read from BCT_* env vars by the script itself.
        $global:LASTEXITCODE = 0
        & ([scriptblock]::Create($text))
        $rc = $global:LASTEXITCODE
        Exit-Install $rc "Invoke-NetworkDiscovery finished with $rc"
    }
    catch {
        Exit-Install 1 $_.Exception.Message
    }
}
