package io.kepr;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Thin client for the kepr credential daemon. Same wire format as the CLI:
 * one JSON request per connection, framed by a 4-byte big-endian length, over
 * the per-user Unix socket (Java 16+). The daemon identifies callers by socket
 * credentials and applies the same rules as for the CLI (uid namespacing,
 * audit, consent, sealed keys never returned).
 *
 * <p>Java strings can't be wiped from memory: keep values in scope briefly, and
 * prefer {@code kepr exec} / {@code kepr agent run} for child processes.
 */
public final class Kepr {
    static final int MAX_MSG_BYTES = 65536;
    public static final Set<String> GENERATE_KINDS = Set.of("hex", "base62", "pass", "uuid", "words");

    /** Default for the whole request, like the other SDKs (a consent prompt can take a minute). */
    public static final long DEFAULT_TIMEOUT_MS = 65_000;

    private final Path socket;
    private final long timeoutMs;

    public Kepr() {
        this(socketPath(System.getenv()));
    }

    public Kepr(Path socket) {
        this(socket, DEFAULT_TIMEOUT_MS);
    }

    /** {@code timeoutMs} bounds the wait for the reply; a silent daemon cannot hang the caller. */
    public Kepr(Path socket, long timeoutMs) {
        if (timeoutMs <= 0) throw new KeprException("timeout must be positive");
        this.socket = socket;
        this.timeoutMs = timeoutMs;
    }

    /** Where the daemon listens, as the CLI resolves it. */
    public static Path socketPath(Map<String, String> env) {
        if (env.get("KEPR_SYSTEM_MODE") != null) return Path.of("/run/kepr/kepr.sock");
        String runtime = env.get("XDG_RUNTIME_DIR");
        if (runtime == null) {
            String home = env.getOrDefault("HOME", "/tmp");
            runtime = home + "/.local/state/kepr/runtime";
        }
        return Path.of(runtime, "kepr", "kepr.sock");
    }

    /** Send one raw request ({"cmd": ...}); returns the reply object. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> request(Map<String, Object> req) {
        byte[] payload = Json.write(req).getBytes(StandardCharsets.UTF_8);
        if (payload.length > MAX_MSG_BYTES) throw new KeprException("request too large");
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(socket));
            ByteBuffer out = ByteBuffer.allocate(4 + payload.length).putInt(payload.length).put(payload);
            out.flip();
            while (out.hasRemaining()) ch.write(out);
            ch.configureBlocking(false);
            long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
            ByteBuffer head = readExact(ch, 4, deadline);
            int n = head.getInt();
            if (n < 0 || n > MAX_MSG_BYTES) throw new KeprException("reply too large");
            String body = new String(readExact(ch, n, deadline).array(), StandardCharsets.UTF_8);
            Object parsed = Json.parse(body);
            if (!(parsed instanceof Map)) throw new KeprException("malformed reply");
            Map<String, Object> resp = (Map<String, Object>) parsed;
            if ("err".equals(resp.get("kind"))) {
                Object e = resp.get("error");
                throw new KeprException(e instanceof String s ? s : "request failed");
            }
            return resp;
        } catch (IOException e) {
            throw new KeprException("cannot reach the credential service at " + socket
                    + " (" + e.getClass().getSimpleName() + "); start it with `kepr-daemon --user`", e);
        }
    }

    /** Read exactly {@code n} bytes before {@code deadline} (System.nanoTime), else "timed out". */
    private static ByteBuffer readExact(SocketChannel ch, int n, long deadline) throws IOException {
        ByteBuffer b = ByteBuffer.allocate(n);
        try (Selector sel = Selector.open()) {
            ch.register(sel, SelectionKey.OP_READ);
            while (b.hasRemaining()) {
                int r = ch.read(b);
                if (r < 0) throw new KeprException("connection closed by the credential service");
                if (r > 0) continue;
                long left = (deadline - System.nanoTime()) / 1_000_000L;
                if (left <= 0) throw new KeprException("timed out");
                sel.select(left);
                sel.selectedKeys().clear();
            }
        }
        b.flip();
        return b;
    }

    private static String upper(String name) {
        if (name == null || name.isEmpty()) throw new KeprException("credential name must be a non-empty string");
        return name.toUpperCase();
    }

    private static Map<String, Object> cmd(String cmd, String name) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("cmd", cmd);
        if (name != null) m.put("name", upper(name));
        return m;
    }

    private Map<String, Object> expect(Map<String, Object> req, String kind) {
        Map<String, Object> r = request(req);
        Object k = r.get("kind");
        if (!kind.equals(k)) {
            if ("fido2_needed".equals(k)) throw new KeprException("this credential needs a FIDO2 touch; use `kepr get`");
            throw new KeprException("unexpected reply: " + k);
        }
        return r;
    }

    public String get(String name) {
        return (String) expect(cmd("get", name), "get_ok").get("value");
    }

    /** Options for {@link #set}. */
    public record SetOptions(String generate, Long ttlSecs, boolean requiresConsent, boolean requiresFido2) {
        public static final SetOptions NONE = new SetOptions(null, null, false, false);
    }

    /** Store {@code value}, or (null) have the daemon generate one; a generated value is never sent back. */
    public Map<String, Object> set(String name, String value, SetOptions o) {
        Map<String, Object> req = cmd("set", name);
        if (value != null) {
            if (o.generate() != null) throw new KeprException("pass a value or generate, not both");
            if (value.isEmpty()) throw new KeprException("value must be a non-empty string");
            req.put("value", value);
        } else {
            String kind = o.generate() == null ? "hex" : o.generate();
            if (!GENERATE_KINDS.contains(kind)) {
                throw new KeprException("generate must be one of " + new ArrayList<>(new java.util.TreeSet<>(GENERATE_KINDS)));
            }
            req.put("generate", kind);
        }
        if (o.ttlSecs() != null) req.put("ttl_secs", o.ttlSecs());
        if (o.requiresConsent()) req.put("requires_consent", true);
        if (o.requiresFido2()) req.put("requires_fido2", true);
        return expect(req, "set_ok");
    }

    public Map<String, Object> set(String name, String value) {
        return set(name, value, SetOptions.NONE);
    }

    /** Have the daemon generate and store a value of {@code kind} (hex, base62, pass, uuid, words). */
    public Map<String, Object> generate(String name, String kind) {
        return set(name, null, new SetOptions(kind, null, false, false));
    }

    public void delete(String name) {
        expect(cmd("delete", name), "delete_ok");
    }

    /** Raw credential records, as the daemon sends them. */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list() {
        return (List<Map<String, Object>>) (List<?>) expect(cmd("list", null), "list_ok").get("credentials");
    }

    /** {@code list} without the on-disk name; metadata only, never values. */
    public List<Map<String, Object>> credentials() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : list()) {
            Map<String, Object> m = new LinkedHashMap<>(rec);
            m.remove("cred_name");
            m.put("sealed", Boolean.TRUE.equals(rec.get("sealed")));
            out.add(m);
        }
        return out;
    }

    /** Metadata for one credential, or null. */
    public Map<String, Object> info(String name) {
        String n = upper(name);
        return credentials().stream().filter(c -> n.equals(c.get("name"))).findFirst().orElse(null);
    }

    public byte[] sshSign(String name, byte[] data) {
        Map<String, Object> req = cmd("sshsign", name);
        req.put("data_b64", Base64.getEncoder().encodeToString(data));
        return Base64.getDecoder().decode((String) expect(req, "ssh_sign_ok").get("signature_b64"));
    }

    public Map<String, Object> status() {
        return expect(cmd("status", null), "status_ok");
    }

    public boolean ping() {
        expect(cmd("ping", null), "pong");
        return true;
    }
}
