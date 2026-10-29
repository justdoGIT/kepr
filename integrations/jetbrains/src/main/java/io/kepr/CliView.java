package io.kepr;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * What the IDE shows, from the kepr CLI's JSON ({@code kepr ls --json}, {@code kepr status --json}).
 * No IntelliJ classes here, so it compiles and tests with a plain JDK. None of the inputs holds a value,
 * so none can be shown.
 */
public final class CliView {
    private CliView() {}

    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_]{1,128}$");

    /** Metadata of one credential. */
    public record Cred(String name, String modified, String expiresAt, String recordType, List<String> tags, boolean sealed) {
        public String subtitle() {
            List<String> bits = new ArrayList<>();
            bits.add(recordType == null ? "value" : recordType);
            if (sealed) bits.add("sealed");
            if (!tags.isEmpty()) bits.add(String.join(",", tags));
            bits.add(expiresAt == null ? "no expiry" : "expires " + expiresAt);
            return String.join(" · ", bits);
        }

        /** Sealed keys are write-only: only an agent gate can use them. */
        public boolean copyable() {
            return !sealed;
        }
    }

    public enum State { LOCKED, UNLOCKED, OFFLINE }

    public record Status(State state, String detail) {
        public String text() {
            return switch (state) {
                case LOCKED -> "kepr: locked";
                case UNLOCKED -> "kepr: unlocked";
                case OFFLINE -> "kepr: offline";
            };
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(String json) {
        Object o = Json.parse(json);
        if (!(o instanceof Map)) throw new KeprException("unexpected reply from kepr");
        return (Map<String, Object>) o;
    }

    public static Status parseStatus(String json) {
        Map<String, Object> r;
        try {
            r = object(json);
        } catch (KeprException e) {
            return new Status(State.OFFLINE, "kepr gave no usable JSON");
        }
        if ("err".equals(r.get("kind"))) {
            return new Status(State.OFFLINE, r.get("error") instanceof String s ? s : "kepr failed");
        }
        if (!"status_ok".equals(r.get("kind"))) return new Status(State.OFFLINE, "unexpected reply from kepr");
        if (Boolean.TRUE.equals(r.get("locked"))) return new Status(State.LOCKED, "Run `kepr unlock` in a terminal.");
        boolean pw = Boolean.TRUE.equals(r.get("password_protected"));
        return new Status(State.UNLOCKED, pw ? "unlocked" : "open (no passphrase set)");
    }

    /** Credentials from {@code kepr ls --json}, sorted by name; throws {@link KeprException} on an error reply. */
    @SuppressWarnings("unchecked")
    public static List<Cred> parseList(String json) {
        Map<String, Object> r = object(json);
        if ("err".equals(r.get("kind"))) throw new KeprException(r.get("error") instanceof String s ? s : "kepr failed");
        if (!"list_ok".equals(r.get("kind")) || !(r.get("credentials") instanceof List<?> items)) {
            throw new KeprException("unexpected reply from kepr");
        }
        List<Cred> out = new ArrayList<>();
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> m) || !(m.get("name") instanceof String name)) continue;
            List<String> tags = new ArrayList<>();
            if (m.get("tags") instanceof List<?> ts) for (Object t : ts) tags.add(String.valueOf(t));
            out.add(new Cred(
                    name,
                    m.get("modified") == null ? "" : String.valueOf(m.get("modified")),
                    m.get("expires_at") instanceof String s ? s : null,
                    m.get("record_type") instanceof String s ? s : null,
                    tags,
                    Boolean.TRUE.equals(m.get("sealed"))));
        }
        out.sort(Comparator.comparing(Cred::name));
        return out;
    }

    /** argv for copying through the CLI, or null for a name that is not safe as one argument. */
    public static List<String> copyCommand(String kepr, String name) {
        return name != null && NAME.matcher(name).matches() ? List.of(kepr, "copy", name) : null;
    }
}
