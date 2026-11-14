using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Kepr;

/// <summary>The daemon refused the request, or could not be reached.</summary>
public sealed class KeprException : Exception
{
    public KeprException(string message) : base(message) { }
    public KeprException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Options for <see cref="KeprClient.Set"/>.</summary>
public sealed record SetOptions(string? Generate = null, long? TtlSecs = null, bool RequiresConsent = false, bool RequiresFido2 = false)
{
    public static readonly SetOptions None = new();
    public SetOptions(long? ttlSecs, bool requiresConsent, bool requiresFido2) : this(null, ttlSecs, requiresConsent, requiresFido2) { }
}

/// <summary>
/// Thin client for the kepr credential daemon. Same wire format as the CLI: one JSON request per
/// connection, framed by a 4-byte big-endian length, over the per-user Unix socket
/// (<c>$XDG_RUNTIME_DIR/kepr/kepr.sock</c>, or <c>/run/kepr/kepr.sock</c> with
/// <c>KEPR_SYSTEM_MODE=1</c>). The daemon identifies the caller by its socket credentials and applies
/// uid namespacing, audit, consent and the sealed-key rules; sealed credentials and SSH keys are never
/// returned by <see cref="Get"/>. On Linux the client also checks who answers the socket.
/// <para>.NET strings cannot be wiped from memory: keep values in scope briefly, and prefer
/// <c>kepr exec</c> / <c>kepr agent run</c> for child processes.</para>
/// </summary>
public sealed class KeprClient
{
    public const int MaxMsgBytes = 65536;

    /// <summary>Default bound on the whole request (a consent prompt can take a minute).</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(65);

    public static readonly IReadOnlySet<string> GenerateKinds =
        new HashSet<string> { "hex", "base62", "pass", "uuid", "words" };

    private readonly string _socket;
    private readonly TimeSpan _timeout;

    public KeprClient() : this(null, null) { }

    /// <param name="socketPath">Default: as the CLI resolves it.</param>
    /// <param name="timeout">Bounds the wait for the reply; a silent daemon cannot hang the caller.</param>
    public KeprClient(string? socketPath, TimeSpan? timeout = null)
    {
        _socket = socketPath ?? SocketPath(Environment.GetEnvironmentVariable);
        _timeout = timeout ?? DefaultTimeout;
        if (_timeout <= TimeSpan.Zero) throw new KeprException("timeout must be positive");
    }

    /// <summary>Where the daemon listens, as the CLI resolves it.</summary>
    public static string SocketPath(Func<string, string?> env)
    {
        if (env("KEPR_SYSTEM_MODE") is not null) return "/run/kepr/kepr.sock";
        var runtime = env("XDG_RUNTIME_DIR");
        if (runtime is null)
        {
            var home = env("HOME") ?? "/tmp";
            runtime = home + "/.local/state/kepr/runtime";
        }
        return Path.Combine(runtime, "kepr", "kepr.sock");
    }

    /// <summary>Send one raw request (<c>{"cmd": ...}</c>); returns the reply object.</summary>
    public JsonObject Request(JsonObject req)
    {
        var payload = Encoding.UTF8.GetBytes(req.ToJsonString());
        if (payload.Length > MaxMsgBytes) throw new KeprException("request too large");
        using var cts = new CancellationTokenSource(_timeout);
        try
        {
            return Exchange(payload, cts.Token);
        }
        catch (OperationCanceledException)
        {
            throw new KeprException("timed out");
        }
        catch (SocketException e)
        {
            throw new KeprException(
                $"cannot reach the credential service at {_socket} ({e.SocketErrorCode}); start it with `kepr-daemon --user`", e);
        }
        catch (IOException e)
        {
            throw new KeprException($"cannot reach the credential service at {_socket} ({e.GetType().Name})", e);
        }
    }

    private JsonObject Exchange(byte[] payload, CancellationToken ct)
    {
        using var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        s.ConnectAsync(new UnixDomainSocketEndPoint(_socket), ct).AsTask().GetAwaiter().GetResult();
        CheckPeer(s);
        var frame = new byte[4 + payload.Length];
        frame[0] = (byte)(payload.Length >> 24);
        frame[1] = (byte)(payload.Length >> 16);
        frame[2] = (byte)(payload.Length >> 8);
        frame[3] = (byte)payload.Length;
        payload.CopyTo(frame, 4);
        for (var sent = 0; sent < frame.Length;)
            sent += s.SendAsync(frame.AsMemory(sent), SocketFlags.None, ct).AsTask().GetAwaiter().GetResult();
        var head = ReadExact(s, 4, ct);
        var n = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
        if (n < 0 || n > MaxMsgBytes) throw new KeprException("reply too large");
        var body = ReadExact(s, n, ct);
        JsonNode? parsed;
        try
        {
            parsed = JsonNode.Parse(body);
        }
        catch (JsonException)
        {
            throw new KeprException("malformed reply");
        }
        if (parsed is not JsonObject resp) throw new KeprException("malformed reply");
        if (resp["kind"]?.GetValue<string>() == "err")
            throw new KeprException(resp["error"] is JsonValue v && v.TryGetValue<string>(out var e) ? e : "request failed");
        return resp;
    }

    private static byte[] ReadExact(Socket s, int n, CancellationToken ct)
    {
        var buf = new byte[n];
        for (var got = 0; got < n;)
        {
            var r = s.ReceiveAsync(buf.AsMemory(got), SocketFlags.None, ct).AsTask().GetAwaiter().GetResult();
            if (r == 0) throw new KeprException("connection closed by the credential service");
            got += r;
        }
        return buf;
    }

    /// <summary>This process's effective uid, from /proc (no native call needed).</summary>
    private static uint? EffectiveUid()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/self/status"))
            {
                if (!line.StartsWith("Uid:", StringComparison.Ordinal)) continue;
                var f = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries); // Uid: real effective saved fs
                return f.Length > 2 ? uint.Parse(f[2]) : null;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException) { }
        return null;
    }

    /// <summary>Refuse a socket whose server is not root's (system mode) or this user's (SO_PEERCRED, Linux).</summary>
    private static void CheckPeer(Socket s)
    {
        if (!OperatingSystem.IsLinux()) return;
        var cred = new byte[12]; // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
        const int SolSocket = 1, SoPeerCred = 17;
        s.GetRawSocketOption(SolSocket, SoPeerCred, cred);
        var uid = BitConverter.ToUInt32(cred, 4);
        uint? want = Environment.GetEnvironmentVariable("KEPR_SYSTEM_MODE") is not null ? 0u : EffectiveUid();
        if (want is { } w && uid != w) throw new KeprException("the socket is not served by the expected credential daemon");
    }

    private static string Upper(string? name)
    {
        if (string.IsNullOrEmpty(name)) throw new KeprException("credential name must be a non-empty string");
        return name.ToUpperInvariant();
    }

    private static JsonObject Cmd(string cmd, string? name = null)
    {
        var o = new JsonObject { ["cmd"] = cmd };
        if (name is not null) o["name"] = Upper(name);
        return o;
    }

    private JsonObject Expect(JsonObject req, string kind)
    {
        var r = Request(req);
        var k = r["kind"]?.GetValue<string>();
        if (k == kind) return r;
        if (k == "fido2_needed") throw new KeprException("this credential needs a FIDO2 touch; use `kepr get`");
        throw new KeprException($"unexpected reply: {k}");
    }

    /// <summary>The credential's value.</summary>
    public string Get(string name) => Expect(Cmd("get", name), "get_ok")["value"]!.GetValue<string>();

    /// <summary>Store <paramref name="value"/>, or (null) have the daemon generate one; a generated value is never sent back.</summary>
    public JsonObject Set(string name, string? value, SetOptions? options = null)
    {
        var o = options ?? SetOptions.None;
        var req = Cmd("set", name);
        if (value is not null)
        {
            if (!string.IsNullOrEmpty(o.Generate)) throw new KeprException("pass a value or generate, not both");
            if (value.Length == 0) throw new KeprException("value must be a non-empty string");
            req["value"] = value;
        }
        else
        {
            var kind = string.IsNullOrEmpty(o.Generate) ? "hex" : o.Generate;
            if (!GenerateKinds.Contains(kind))
                throw new KeprException("generate must be one of " + string.Join(", ", GenerateKinds.Order()));
            req["generate"] = kind;
        }
        if (o.TtlSecs is { } ttl) req["ttl_secs"] = ttl;
        if (o.RequiresConsent) req["requires_consent"] = true;
        if (o.RequiresFido2) req["requires_fido2"] = true;
        return Expect(req, "set_ok");
    }

    /// <summary>Have the daemon generate and store a value of <paramref name="kind"/> (hex, base62, pass, uuid, words).</summary>
    public JsonObject Generate(string name, string kind = "hex") => Set(name, null, new SetOptions(Generate: kind));

    public void Delete(string name) => Expect(Cmd("delete", name), "delete_ok");

    /// <summary>Raw credential records, as the daemon sends them.</summary>
    public JsonArray List() => Expect(Cmd("list"), "list_ok")["credentials"]!.AsArray();

    /// <summary><see cref="List"/> without the on-disk name; metadata only, never values.</summary>
    public IReadOnlyList<JsonObject> Credentials()
    {
        var outList = new List<JsonObject>();
        foreach (var node in List())
        {
            var rec = node!;
            var m = (JsonObject)rec.DeepClone();
            m.Remove("cred_name");
            m["sealed"] = rec["sealed"] is JsonValue v && v.TryGetValue<bool>(out var b) && b;
            outList.Add(m);
        }
        return outList;
    }

    /// <summary>Metadata for one credential, or null.</summary>
    public JsonObject? Info(string name)
    {
        var n = Upper(name);
        return Credentials().FirstOrDefault(c => c["name"]?.GetValue<string>() == n);
    }

    public byte[] SshSign(string name, byte[] data)
    {
        var req = Cmd("sshsign", name);
        req["data_b64"] = Convert.ToBase64String(data);
        return Convert.FromBase64String(Expect(req, "ssh_sign_ok")["signature_b64"]!.GetValue<string>());
    }

    public JsonObject Status() => Expect(Cmd("status"), "status_ok");

    public bool Ping()
    {
        Expect(Cmd("ping"), "pong");
        return true;
    }
}
