@{
    Severity     = @('Error', 'Warning', 'Information')
    # Write-Host is deliberate: it lands in the transcript without polluting function output.
    ExcludeRules = @('PSAvoidUsingWriteHost', 'PSAvoidUsingPositionalParameters')
    Rules        = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1', '7.0') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @('win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core') }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @('win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework', 'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core') }
    }
}
