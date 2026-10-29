# kepr .NET client

Talks to the kepr daemon over its Unix socket, the same way the CLI does.
.NET 8, no dependency beyond the base class library. Windows has no daemon
(Unix-domain sockets only), so this is for Linux and macOS hosts.

```csharp
using Kepr;

var kepr = new KeprClient();                    // per-user socket; KEPR_SYSTEM_MODE=1 for the system one
kepr.Set("DB_PASS", "hunter2", new SetOptions(TtlSecs: 3600));
kepr.Generate("API_TOKEN", "base62");           // generated in the daemon, never sent back
string v = kepr.Get("db_pass");                 // names are upper-cased
var meta = kepr.Credentials();                  // metadata only: name, size, sealed, tags ...
kepr.Delete("DB_PASS");
```

Sealed credentials, SSH keys and share keys are never returned by `Get`, the
same as for the CLI; the daemon applies uid namespacing, audit, consent and
FIDO2 rules to every call. On Linux the client checks the socket's peer
credentials and refuses a server that is not your user's daemon (root's in
system mode). .NET strings cannot be wiped from memory, so keep values in
scope briefly and prefer `kepr exec` / `kepr agent run` for child processes.

Requests time out after 65 s as a whole (`new KeprClient(path, TimeSpan)` to
change it). Test: `dotnet test sdk/dotnet/tests`.
