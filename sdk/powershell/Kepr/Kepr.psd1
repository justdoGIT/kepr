@{
    RootModule        = 'Kepr.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '6f1b1d0e-2c51-4d0e-9c0a-5d9a7a3f4e11'
    Author            = 'kepr contributors'
    Description       = 'Read and store credentials in the local kepr daemon (Unix socket; Linux and macOS).'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Get-KeprSecret', 'Set-KeprSecret', 'New-KeprSecret', 'Remove-KeprSecret', 'Get-KeprCredential')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
