# kepr Java client

Talks to the kepr daemon over its Unix socket, the same way the CLI does.
Needs Java 16+ (Unix domain sockets) and no other dependency.

```java
import io.kepr.Kepr;

Kepr kepr = new Kepr();                         // per-user socket; KEPR_SYSTEM_MODE=1 for the system one
kepr.set("DB_PASS", "hunter2", new Kepr.SetOptions(null, 3600L, false, false));
kepr.generate("API_TOKEN", "base62");           // generated in the daemon, never sent back
String v = kepr.get("db_pass");                 // names are upper-cased
var meta = kepr.credentials();                  // metadata only: name, size, sealed, tags ...
kepr.delete("DB_PASS");
```

Sealed credentials, SSH keys and share keys are never returned by `get`, the
same as for the CLI; the daemon applies uid namespacing, audit, consent and
FIDO2 rules to every call. Java strings cannot be wiped from memory, so keep
values in scope briefly and prefer `kepr exec` / `kepr agent run` for child
processes.

Test: `./test.sh` (compiles with `javac -Xlint:all` and runs the fake-daemon tests).
