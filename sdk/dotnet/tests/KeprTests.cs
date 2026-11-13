using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Kepr;
using Xunit;

namespace Kepr.Tests;

/// <summary>Answers each connection with the next canned reply and records the request.</summary>
sealed class FakeDaemon : IDisposable
{
    public readonly string Path;
    public readonly List<string> Requests = new();
    private readonly Socket _server;
    private readonly Thread _thread;

    public FakeDaemon(params string[] replies)
    {
        var dir = Directory.CreateTempSubdirectory("kepr").FullName;
        Path = System.IO.Path.Combine(dir, "kepr.sock");
        _server = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _server.Bind(new UnixDomainSocketEndPoint(Path));
        _server.Listen(4);
        _thread = new Thread(() =>
        {
            try { foreach (var reply in replies)
            {
                using var c = _server.Accept();
                var head = ReadExact(c, 4);
                var n = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
                lock (Requests) Requests.Add(Encoding.UTF8.GetString(ReadExact(c, n)));
                var body = Encoding.UTF8.GetBytes(reply);
                var frame = new byte[4 + body.Length];
                frame[0] = (byte)(body.Length >> 24);
                frame[1] = (byte)(body.Length >> 16);
                frame[2] = (byte)(body.Length >> 8);
                frame[3] = (byte)body.Length;
                body.CopyTo(frame, 4);
                c.Send(frame);
            } } catch { }
        }) { IsBackground = true };
        _thread.Start();
    }

    private static byte[] ReadExact(Socket s, int n)
    {
        var b = new byte[n];
        for (var got = 0; got < n;)
        {
            var r = s.Receive(b, got, n - got, SocketFlags.None);
            if (r == 0) break;
            got += r;
        }
        return b;
    }

    public void Done() => _thread.Join(2000);

    public void Dispose()
    {
        Done();
        _server.Dispose();
    }
}

public class KeprTests
{
    [Fact]
    public void GetUppercasesAndReturnsTheValue()
    {
        using var f = new FakeDaemon("{\"kind\":\"get_ok\",\"name\":\"DB\",\"value\":\"s3\\\"cret\\u00e9\"}");
        Assert.Equal("s3\"creté", new KeprClient(f.Path).Get("db_pass"));
        f.Done();
        Assert.Equal("{\"cmd\":\"get\",\"name\":\"DB_PASS\"}", f.Requests[0]);
    }

    [Fact]
    public void SetSendsOptionsAndValidates()
    {
        using (var f = new FakeDaemon("{\"kind\":\"set_ok\",\"name\":\"K\",\"cred_name\":\"x\",\"password_protected\":true}"))
        {
            new KeprClient(f.Path).Set("k", "v", new SetOptions(TtlSecs: 60, RequiresConsent: true));
            f.Done();
            Assert.Equal("{\"cmd\":\"set\",\"name\":\"K\",\"value\":\"v\",\"ttl_secs\":60,\"requires_consent\":true}", f.Requests[0]);
        }
        var k = new KeprClient("/nonexistent");
        Assert.Contains("non-empty", Assert.Throws<KeprException>(() => k.Set("k", "")).Message);
        Assert.Contains("not both", Assert.Throws<KeprException>(() => k.Set("k", "v", new SetOptions(Generate: "hex"))).Message);
        Assert.Contains("generate must be one of", Assert.Throws<KeprException>(() => k.Generate("k", "rot13")).Message);
        Assert.Contains("non-empty", Assert.Throws<KeprException>(() => k.Get("")).Message);
    }

    [Fact]
    public void GenerateDefaultsToHex()
    {
        using var f = new FakeDaemon("{\"kind\":\"set_ok\",\"name\":\"K\",\"cred_name\":\"x\",\"password_protected\":false}");
        new KeprClient(f.Path).Set("k", null);
        f.Done();
        Assert.Contains("\"generate\":\"hex\"", f.Requests[0]);
    }

    [Fact]
    public void CredentialsDropTheDiskName()
    {
        using var f = new FakeDaemon("{\"kind\":\"list_ok\",\"credentials\":[{\"name\":\"A\",\"size\":3,\"cred_name\":\"kepr-1-a\",\"tags\":[\"prod\"]}]}");
        var c = new KeprClient(f.Path).Credentials()[0];
        Assert.False(c.ContainsKey("cred_name"));
        Assert.False(c["sealed"]!.GetValue<bool>());
        Assert.Equal("prod", c["tags"]![0]!.GetValue<string>());
        Assert.Equal(3, c["size"]!.GetValue<int>());
    }

    [Fact]
    public void ErrorsAndUnexpectedRepliesAreExceptions()
    {
        using var f = new FakeDaemon("{\"kind\":\"err\",\"error\":\"credential unavailable\"}", "{\"kind\":\"pong\"}", "{\"kind\":\"fido2_needed\"}");
        var k = new KeprClient(f.Path);
        Assert.Contains("credential unavailable", Assert.Throws<KeprException>(() => k.Get("x")).Message);
        Assert.Contains("unexpected reply: pong", Assert.Throws<KeprException>(() => k.Get("x")).Message);
        Assert.Contains("FIDO2", Assert.Throws<KeprException>(() => k.Get("x")).Message);
    }

    [Fact]
    public void AnUnreachableDaemonNamesTheSocket()
    {
        var e = Assert.Throws<KeprException>(() => new KeprClient("/nonexistent/kepr.sock").Ping());
        Assert.Contains("/nonexistent/kepr.sock", e.Message);
    }

    [Fact]
    public void ASilentDaemonTimesOut()
    {
        var dir = Directory.CreateTempSubdirectory("kepr").FullName;
        var path = System.IO.Path.Combine(dir, "kepr.sock");
        using var server = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        server.Bind(new UnixDomainSocketEndPoint(path));
        server.Listen(1);
        var t = new Thread(() =>
        {
            try
            {
                using var c = server.Accept(); // accepts, reads nothing, never answers
                Thread.Sleep(3000);
            }
            catch (SocketException) { }
        }) { IsBackground = true };
        t.Start();
        var sw = Stopwatch.StartNew();
        var e = Assert.Throws<KeprException>(() => new KeprClient(path, TimeSpan.FromMilliseconds(300)).Ping());
        Assert.Contains("timed out", e.Message);
        Assert.InRange(sw.ElapsedMilliseconds, 250, 2500);
        Assert.Throws<KeprException>(() => new KeprClient(path, TimeSpan.Zero));
    }

    [Fact]
    public void OversizeRequestsAndRepliesAreRefused()
    {
        var big = new JsonObject { ["cmd"] = "x", ["pad"] = new string('a', KeprClient.MaxMsgBytes) };
        Assert.Contains("request too large", Assert.Throws<KeprException>(() => new KeprClient("/nonexistent").Request(big)).Message);
        using var f = new FakeDaemon("{\"kind\":\"pong\",\"pad\":\"" + new string('a', KeprClient.MaxMsgBytes) + "\"}");
        Assert.Contains("reply too large", Assert.Throws<KeprException>(() => new KeprClient(f.Path).Ping()).Message);
    }

    [Fact]
    public void SshSignRoundTripsBase64()
    {
        using var f = new FakeDaemon("{\"kind\":\"ssh_sign_ok\",\"signature_b64\":\"" + Convert.ToBase64String(new byte[] { 1, 2, 3 }) + "\"}");
        Assert.Equal(new byte[] { 1, 2, 3 }, new KeprClient(f.Path).SshSign("k", new byte[] { 9 }));
        f.Done();
        Assert.Contains("\"data_b64\":\"CQ==\"", f.Requests[0]);
    }

    [Fact]
    public void SocketPathFollowsTheEnvironment()
    {
        string? E(Dictionary<string, string> m, string k) => m.TryGetValue(k, out var v) ? v : null;
        Assert.Equal("/run/kepr/kepr.sock", KeprClient.SocketPath(k => E(new() { ["KEPR_SYSTEM_MODE"] = "1" }, k)));
        Assert.Equal("/run/user/1/kepr/kepr.sock", KeprClient.SocketPath(k => E(new() { ["XDG_RUNTIME_DIR"] = "/run/user/1" }, k)));
        Assert.Equal("/h/.local/state/kepr/runtime/kepr/kepr.sock", KeprClient.SocketPath(k => E(new() { ["HOME"] = "/h" }, k)));
    }

    [Fact]
    public void ASocketServedByAnotherUserIsRefused()
    {
        if (!OperatingSystem.IsLinux() || Environment.UserName == "root") return;
        using var f = new FakeDaemon("{\"kind\":\"pong\"}");
        Environment.SetEnvironmentVariable("KEPR_SYSTEM_MODE", "1"); // expects root
        try
        {
            var e = Assert.Throws<KeprException>(() => new KeprClient(f.Path).Ping());
            Assert.Contains("expected credential daemon", e.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable("KEPR_SYSTEM_MODE", null);
        }
    }
}
