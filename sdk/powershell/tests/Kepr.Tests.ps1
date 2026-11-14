#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Run: pwsh -Command Invoke-Pester sdk/powershell/tests
# Needs the module's lib/ built (see Kepr.psm1).

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../Kepr/Kepr.psd1') -Force
    if (-not ('KeprFake.Daemon' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
namespace KeprFake {
  public sealed class Daemon : IDisposable {
    public readonly string Path;
    public readonly List<string> Requests = new List<string>();
    private readonly Socket server;
    private readonly Thread thread;
    public Daemon(string[] replies) {
      Path = System.IO.Path.Combine(Directory.CreateTempSubdirectory("kepr").FullName, "kepr.sock");
      server = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
      server.Bind(new UnixDomainSocketEndPoint(Path));
      server.Listen(4);
      thread = new Thread(() => {
        try { foreach (var reply in replies) {
          using (var c = server.Accept()) {
            var head = Read(c, 4);
            int n = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
            lock (Requests) Requests.Add(Encoding.UTF8.GetString(Read(c, n)));
            var body = Encoding.UTF8.GetBytes(reply);
            var frame = new byte[4 + body.Length];
            frame[0] = (byte)(body.Length >> 24); frame[1] = (byte)(body.Length >> 16);
            frame[2] = (byte)(body.Length >> 8); frame[3] = (byte)body.Length;
            body.CopyTo(frame, 4);
            c.Send(frame);
          }
        }
} catch { }
      });
      thread.IsBackground = true;
      thread.Start();
    }
    private static byte[] Read(Socket s, int n) {
      var b = new byte[n];
      for (int got = 0; got < n;) { int r = s.Receive(b, got, n - got, SocketFlags.None); if (r == 0) break; got += r; }
      return b;
    }
    public void Done() { thread.Join(2000); }
    public void Dispose() { Done(); server.Dispose(); }
  }
}
'@
    }
    function New-Fake([string[]]$Replies) { [KeprFake.Daemon]::new($Replies) }
}

Describe 'Kepr module' {
    It 'Get-KeprSecret returns a SecureString by default and text with -AsPlainText' {
        $f = New-Fake @('{"kind":"get_ok","name":"DB","value":"s3cret"}', '{"kind":"get_ok","name":"DB","value":"s3cret"}')
        try {
            $secure = Get-KeprSecret db_pass -SocketPath $f.Path
            $secure | Should -BeOfType [securestring]
            [System.Net.NetworkCredential]::new('', $secure).Password | Should -Be 's3cret'
            Get-KeprSecret db_pass -AsPlainText -SocketPath $f.Path | Should -Be 's3cret'
            $f.Done()
            $f.Requests[0] | Should -Be '{"cmd":"get","name":"DB_PASS"}'
        }
        finally { $f.Dispose() }
    }

    It 'a refusal from the daemon is an error that never carries a value' {
        $f = New-Fake @('{"kind":"err","error":"credential unavailable"}')
        try {
            { Get-KeprSecret x -SocketPath $f.Path -ErrorAction Stop } | Should -Throw '*credential unavailable*'
        }
        finally { $f.Dispose() }
    }

    It 'Set-KeprSecret sends the value and the options' {
        $f = New-Fake @('{"kind":"set_ok","name":"K","cred_name":"x","password_protected":false}')
        try {
            Set-KeprSecret k 'v' -TtlSeconds 60 -RequiresConsent -SocketPath $f.Path
            $f.Done()
            $f.Requests[0] | Should -Be '{"cmd":"set","name":"K","value":"v","ttl_secs":60,"requires_consent":true}'
        }
        finally { $f.Dispose() }
    }

    It 'New-KeprSecret asks the daemon to generate' {
        $f = New-Fake @('{"kind":"set_ok","name":"K","cred_name":"x","password_protected":false}')
        try {
            New-KeprSecret k -Kind base62 -SocketPath $f.Path
            $f.Done()
            $f.Requests[0] | Should -Match '"generate":"base62"'
            $f.Requests[0] | Should -Not -Match '"value"'
        }
        finally { $f.Dispose() }
    }

    It 'Remove-KeprSecret deletes' {
        $f = New-Fake @('{"kind":"delete_ok","name":"K"}')
        try {
            Remove-KeprSecret k -Confirm:$false -SocketPath $f.Path
            $f.Done()
            $f.Requests[0] | Should -Be '{"cmd":"delete","name":"K"}'
        }
        finally { $f.Dispose() }
    }

    It 'Get-KeprCredential lists metadata without the on-disk name' {
        $f = New-Fake @('{"kind":"list_ok","credentials":[{"name":"A","size":3,"cred_name":"kepr-1-a","tags":["prod"]}]}')
        try {
            $c = Get-KeprCredential -SocketPath $f.Path
            $c.name | Should -Be 'A'
            $c.sealed | Should -BeFalse
            $c.PSObject.Properties.Name | Should -Not -Contain 'cred_name'
        }
        finally { $f.Dispose() }
    }

    It 'a daemon that is not there names the socket' {
        { Get-KeprSecret x -SocketPath '/nonexistent/kepr.sock' -ErrorAction Stop } | Should -Throw '*/nonexistent/kepr.sock*'
    }
}
