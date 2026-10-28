package io.kepr;

import java.util.List;

/** Plain-main tests (no framework); run by test.sh. */
public final class CliViewTest {
    static void check(boolean ok, String what) {
        if (!ok) throw new AssertionError(what);
    }

    public static void main(String[] args) {
        List<CliView.Cred> l = CliView.parseList("{\"kind\":\"list_ok\",\"count\":3,\"credentials\":["
                + "{\"name\":\"ZED\",\"modified\":\"m\",\"cred_name\":\"kepr-1-zed\"},"
                + "{\"name\":\"ALPHA\",\"tags\":[\"prod\",\"db\"],\"expires_at\":\"2027-01-01\",\"record_type\":\"database\"},"
                + "{\"name\":\"KEY\",\"sealed\":true,\"modified\":\"y\"},{\"x\":1}]}");
        check(l.size() == 3, "three named credentials");
        check(l.get(0).name().equals("ALPHA") && l.get(1).name().equals("KEY") && l.get(2).name().equals("ZED"), "sorted");
        check(l.get(0).tags().equals(List.of("prod", "db")), "tags");
        check(l.get(1).sealed() && !l.get(1).copyable() && l.get(2).copyable(), "sealed is write-only");
        check(l.get(0).subtitle().equals("database · prod,db · expires 2027-01-01"), l.get(0).subtitle());
        check(l.get(2).subtitle().equals("value · no expiry"), l.get(2).subtitle());

        for (String bad : new String[] {"{\"kind\":\"err\",\"error\":\"locked\"}", "{\"kind\":\"pong\"}", "[]", "not json"}) {
            try {
                CliView.parseList(bad);
                throw new AssertionError("accepted " + bad);
            } catch (KeprException expected) {
                // fine
            }
        }

        check(CliView.parseStatus("{\"kind\":\"status_ok\",\"locked\":true}").state() == CliView.State.LOCKED, "locked");
        CliView.Status open = CliView.parseStatus("{\"kind\":\"status_ok\",\"locked\":false}");
        check(open.state() == CliView.State.UNLOCKED && open.detail().contains("no passphrase"), "open");
        check(CliView.parseStatus("{\"kind\":\"status_ok\",\"locked\":false,\"password_protected\":true}").text().equals("kepr: unlocked"), "text");
        check(CliView.parseStatus("{\"kind\":\"err\",\"error\":\"cannot connect\"}").state() == CliView.State.OFFLINE, "err");
        check(CliView.parseStatus("garbage").state() == CliView.State.OFFLINE, "garbage");

        check(CliView.copyCommand("kepr", "DB_PASS").equals(List.of("kepr", "copy", "DB_PASS")), "copy argv");
        for (String bad : new String[] {"", "a b", "a;b", "../x", "-rf", "A".repeat(129)}) {
            check(CliView.copyCommand("kepr", bad) == null, "unsafe name " + bad);
        }
        check(CliView.copyCommand("kepr", null) == null, "null name");
        System.out.println("ok");
    }
}
