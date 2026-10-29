package io.kepr.idea;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs the kepr CLI (no shell, fixed argv) and returns its standard output. */
final class Cli {
    private Cli() {}

    static String kepr() {
        String bin = System.getenv("KEPR_BIN");
        return bin == null || bin.isEmpty() ? "kepr" : bin;
    }

    static String run(List<String> argv) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(argv).redirectErrorStream(false).start();
        p.getOutputStream().close();
        byte[] out = p.getInputStream().readNBytes(1 << 20);
        if (!p.waitFor(10, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("kepr did not answer");
        }
        return new String(out, StandardCharsets.UTF_8);
    }
}
