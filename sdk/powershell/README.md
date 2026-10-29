# kepr PowerShell module

`Get-KeprSecret`, `Set-KeprSecret`, `New-KeprSecret`, `Remove-KeprSecret` and
`Get-KeprCredential` over the .NET client in `sdk/dotnet`. PowerShell 7.2+ on
Linux or macOS (the daemon listens on a Unix socket; there is no Windows
daemon).

```powershell
dotnet build sdk/dotnet/src -c Release -o sdk/powershell/Kepr/lib
Import-Module ./sdk/powershell/Kepr

New-KeprSecret API_TOKEN -Kind base62          # generated in the daemon, never sent back
$secure = Get-KeprSecret DB_PASS               # a SecureString
Get-KeprSecret DB_PASS -AsPlainText            # a string: keep it short-lived
Get-KeprCredential                             # metadata only
```

Sealed agent keys and SSH keys are never returned; the daemon refuses, the
same as for the CLI. Test: `Invoke-Pester sdk/powershell/tests` (Pester 5).
