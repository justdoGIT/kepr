package io.kepr;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Plain-main tests against a fake daemon; run by test.sh (no test framework needed). */
public final class KeprTest {
    /** Answers each connection with the next canned reply and records the request. */
    static final class Fake implements AutoCloseable {
        final Path sock;
        final List<String> requests = new ArrayList<>();
        final ServerSocketChannel server;
        final Thread thread;

        Fake(Path dir, String... replies) throws IOException {
            sock = dir.resolve("kepr.sock");
            server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            server.bind(UnixDomainSocketAddress.of(sock));
            thread = new Thread(() -> {
                try {
                    for (String reply : replies) {
                        try (SocketChannel c = server.accept()) {
                            ByteBuffer head = ByteBuffer.allocate(4);
                            while (head.hasRemaining()) c.read(head);
                            head.flip();
                            ByteBuffer body = ByteBuffer.allocate(head.getInt());
                            while (body.hasRemaining()) c.read(body);
                            requests.add(new String(body.array(), StandardCharsets.UTF_8));
                            byte[] out = reply.getBytes(StandardCharsets.UTF_8);
                            ByteBuffer w = ByteBuffer.allocate(4 + out.length).putInt(out.length).put(out);
                            w.flip();
                            while (w.hasRemaining()) c.write(w);
                        }
                    }
                } catch (IOException ignored) {
                }
            });
            thread.start();
        }

        /** Wait until every canned reply was served. */
        void done() {
            try {
                thread.join(2000);
            } catch (InterruptedException ignored) {
            }
        }

        public void close() throws IOException {
            done();
            server.close();
        }
    }

    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    static void expectError(Runnable r, String contains) {
        try {
            r.run();
        } catch (KeprException e) {
            check(e.getMessage().contains(contains), "message " + e.getMessage() + " lacks " + contains);
            return;
        }
        throw new AssertionError("expected KeprException containing " + contains);
    }

    static Path tmp() throws IOException {
        return Files.createTempDirectory("kepr");
    }

    public static void main(String[] args) throws Exception {
        getUppercasesAndReturnsValue();
        setSendsOptionsAndValidates();
        generateDefaultsToHex();
        credentialsDropTheDiskName();
        errorsAndUnexpectedReplies();
        unreachableDaemonNamesTheSocket();
        silentDaemonTimesOut();
        sshSignRoundTripsBase64();
        jsonRoundTrip();
        socketPathFollowsEnvironment();
        System.out.println("ok");
    }

    static void getUppercasesAndReturnsValue() throws Exception {
        try (Fake f = new Fake(tmp(), "{\"kind\":\"get_ok\",\"name\":\"DB\",\"value\":\"s3\\\"cret\\u00e9\"}")) {
            check("s3\"creté".equals(new Kepr(f.sock).get("db_pass")), "value");
            f.done();
            check(f.requests.get(0).equals("{\"cmd\":\"get\",\"name\":\"DB_PASS\"}"), f.requests.get(0));
        }
    }

    static void setSendsOptionsAndValidates() throws Exception {
        String ok = "{\"kind\":\"set_ok\",\"name\":\"K\",\"cred_name\":\"x\",\"password_protected\":true}";
        try (Fake f = new Fake(tmp(), ok)) {
            new Kepr(f.sock).set("k", "v", new Kepr.SetOptions(null, 60L, true, false));
            f.done();
            check(f.requests.get(0).equals(
                    "{\"cmd\":\"set\",\"name\":\"K\",\"value\":\"v\",\"ttl_secs\":60,\"requires_consent\":true}"),
                    f.requests.get(0));
        }
        Kepr k = new Kepr(Path.of("/nonexistent"));
        expectError(() -> k.set("k", ""), "non-empty");
        expectError(() -> k.set("k", "v", new Kepr.SetOptions("hex", null, false, false)), "not both");
        expectError(() -> k.generate("k", "rot13"), "generate must be one of");
        expectError(() -> k.get(""), "non-empty");
    }

    static void generateDefaultsToHex() throws Exception {
        String ok = "{\"kind\":\"set_ok\",\"name\":\"K\",\"cred_name\":\"x\",\"password_protected\":false}";
        try (Fake f = new Fake(tmp(), ok)) {
            new Kepr(f.sock).set("k", null);
            f.done();
            check(f.requests.get(0).contains("\"generate\":\"hex\""), f.requests.get(0));
        }
    }

    static void credentialsDropTheDiskName() throws Exception {
        String rec = "{\"kind\":\"list_ok\",\"credentials\":[{\"name\":\"A\",\"size\":3,\"cred_name\":\"kepr-1-a\","
                + "\"tags\":[\"prod\"]}]}";
        try (Fake f = new Fake(tmp(), rec)) {
            Map<String, Object> c = new Kepr(f.sock).credentials().get(0);
            check(!c.containsKey("cred_name"), "cred_name kept");
            check(Boolean.FALSE.equals(c.get("sealed")), "sealed default");
            check(c.get("tags").equals(List.of("prod")), "tags");
            check(Long.valueOf(3).equals(c.get("size")), "size");
        }
    }

    static void errorsAndUnexpectedReplies() throws Exception {
        try (Fake f = new Fake(tmp(), "{\"kind\":\"err\",\"error\":\"credential unavailable\"}",
                "{\"kind\":\"pong\"}", "{\"kind\":\"fido2_needed\"}")) {
            Kepr k = new Kepr(f.sock);
            expectError(() -> k.get("x"), "credential unavailable");
            expectError(() -> k.get("x"), "unexpected reply: pong");
            expectError(() -> k.get("x"), "FIDO2");
        }
    }

    static void unreachableDaemonNamesTheSocket() {
        expectError(() -> new Kepr(Path.of("/nonexistent/kepr.sock")).ping(), "/nonexistent/kepr.sock");
    }

    static void silentDaemonTimesOut() throws Exception {
        Path dir = tmp();
        Path sock = dir.resolve("kepr.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            Thread t = new Thread(() -> {
                try {
                    SocketChannel c = server.accept();
                    Thread.sleep(3000); // accepts, reads nothing, never answers
                    c.close();
                } catch (Exception ignored) {
                }
            });
            t.setDaemon(true);
            t.start();
            long start = System.nanoTime();
            expectError(() -> new Kepr(sock, 300).ping(), "timed out");
            long ms = (System.nanoTime() - start) / 1_000_000L;
            check(ms >= 250 && ms < 2500, "timed out after " + ms + " ms");
        }
        expectError(() -> new Kepr(sock, 0), "positive");
        stalledPeerWithFullBufferTimesOutOnWrite();
    }

    /** A peer that never reads: a request bigger than the socket buffers must still time out. */
    static void stalledPeerWithFullBufferTimesOutOnWrite() throws Exception {
        Path sock = tmp().resolve("kepr.sock");
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(sock));
            Thread t = new Thread(() -> {
                try {
                    SocketChannel c = server.accept();
                    Thread.sleep(3000);
                    c.close();
                } catch (Exception ignored) {
                }
            });
            t.setDaemon(true);
            t.start();
            java.util.Map<String, Object> big = new java.util.LinkedHashMap<>();
            big.put("cmd", "x");
            big.put("pad", "a".repeat(Kepr.MAX_MSG_BYTES - 64));
            long start = System.nanoTime();
            expectError(() -> new Kepr(sock, 300).request(big), "timed out");
            check((System.nanoTime() - start) / 1_000_000L < 2500, "write timeout too slow");
        }
    }

    static void sshSignRoundTripsBase64() throws Exception {
        try (Fake f = new Fake(tmp(), "{\"kind\":\"ssh_sign_ok\",\"signature_b64\":\"AQI=\"}")) {
            byte[] sig = new Kepr(f.sock).sshSign("key", "data".getBytes(StandardCharsets.UTF_8));
            f.done();
            check(sig.length == 2 && sig[0] == 1 && sig[1] == 2, "signature");
            check(f.requests.get(0).contains("\"data_b64\":\"ZGF0YQ==\""), f.requests.get(0));
        }
    }

    static void jsonRoundTrip() {
        Object v = Json.parse("{\"a\":[1,2.5,true,null,\"x\\n\"],\"b\":{}}");
        check(Json.write(v).equals("{\"a\":[1,2.5,true,null,\"x\\n\"],\"b\":{}}"), Json.write(v));
        expectError(() -> Json.parse("{\"a\":"), "malformed");
        expectError(() -> Json.parse("{} x"), "malformed");
    }

    static void socketPathFollowsEnvironment() {
        check(Kepr.socketPath(Map.of("KEPR_SYSTEM_MODE", "1")).toString().equals("/run/kepr/kepr.sock"), "system");
        check(Kepr.socketPath(Map.of("XDG_RUNTIME_DIR", "/r")).toString().equals("/r/kepr/kepr.sock"), "xdg");
        check(Kepr.socketPath(Map.of("HOME", "/h")).toString()
                .equals("/h/.local/state/kepr/runtime/kepr/kepr.sock"), "home");
    }
}
