# Kepr.psm1 — PowerShell wrapper over the .NET client (sdk/dotnet).
# Build the assembly into ./lib first:  dotnet build sdk/dotnet/src -c Release -o sdk/powershell/Kepr/lib

Set-StrictMode -Version Latest

$dll = Join-Path $PSScriptRoot 'lib/Kepr.dll'
if (-not (Test-Path $dll)) {
    throw "Kepr.dll not found at $dll. Build it: dotnet build sdk/dotnet/src -c Release -o '$(Join-Path $PSScriptRoot 'lib')'"
}
Add-Type -Path $dll

function New-KeprClient {
    param([string]$SocketPath, [int]$TimeoutSeconds = 65)
    $timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    if ($SocketPath) { [Kepr.KeprClient]::new($SocketPath, $timeout) } else { [Kepr.KeprClient]::new($null, $timeout) }
}

function Get-KeprSecret {
    <#
    .SYNOPSIS
        The value of a kepr credential, as a SecureString (or plain text with -AsPlainText).
    .NOTES
        Sealed agent keys and SSH keys are never returned: the daemon refuses. Names are upper-cased.
    #>
    [CmdletBinding()]
    [OutputType([securestring], [string])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Name,
        [switch]$AsPlainText,
        [string]$SocketPath,
        [int]$TimeoutSeconds = 65
    )
    process {
        $value = (New-KeprClient $SocketPath $TimeoutSeconds).Get($Name)
        if ($AsPlainText) { return $value }
        $secure = [securestring]::new()
        foreach ($c in $value.ToCharArray()) { $secure.AppendChar($c) }
        $secure.MakeReadOnly()
        $secure
    }
}

function Set-KeprSecret {
    <#
    .SYNOPSIS
        Store a value (a SecureString or string) under a name.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(Mandatory, Position = 1)]$Value,
        [long]$TtlSeconds,
        [switch]$RequiresConsent,
        [switch]$RequiresFido2,
        [string]$SocketPath
    )
    if ($Value -is [securestring]) {
        $Value = [System.Net.NetworkCredential]::new('', $Value).Password
    }
    elseif ($Value -isnot [string]) {
        throw 'Value must be a SecureString or a string'
    }
    $opts = [Kepr.SetOptions]::new($null, $(if ($PSBoundParameters.ContainsKey('TtlSeconds')) { [Nullable[long]]$TtlSeconds } else { $null }), [bool]$RequiresConsent, [bool]$RequiresFido2)
    if ($PSCmdlet.ShouldProcess($Name, 'store credential')) {
        $null = (New-KeprClient $SocketPath).Set($Name, $Value, $opts)
    }
}

function New-KeprSecret {
    <#
    .SYNOPSIS
        Have the daemon generate and store a value; it is never sent back.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [ValidateSet('hex', 'base62', 'pass', 'uuid', 'words')][string]$Kind = 'hex',
        [string]$SocketPath
    )
    if ($PSCmdlet.ShouldProcess($Name, "generate $Kind credential")) {
        $null = (New-KeprClient $SocketPath).Generate($Name, $Kind)
    }
}

function Remove-KeprSecret {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$SocketPath
    )
    if ($PSCmdlet.ShouldProcess($Name, 'delete credential')) {
        (New-KeprClient $SocketPath).Delete($Name)
    }
}

function Get-KeprCredential {
    <#
    .SYNOPSIS
        Metadata for the caller's credentials (never values).
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Name, [string]$SocketPath)
    $client = New-KeprClient $SocketPath
    if ($Name) {
        $one = $client.Info($Name)
        if ($one) { $one | ConvertFrom-Json -Depth 8 }
    }
    else {
        foreach ($c in $client.Credentials()) { $c.ToJsonString() | ConvertFrom-Json -Depth 8 }
    }
}

Export-ModuleMember -Function Get-KeprSecret, Set-KeprSecret, New-KeprSecret, Remove-KeprSecret, Get-KeprCredential
