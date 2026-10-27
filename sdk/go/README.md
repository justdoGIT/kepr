# kepr Go client

A thin client for the local kepr daemon (standard library only). It uses
the same socket and wire format as the `kepr` CLI, so the daemon applies the
same rules (per-user namespacing, audit, consent, sealed keys never returned).

```go
c := kepr.New()
token, err := c.Get("GITHUB_TOKEN")
err = c.Set("DB_PASSWORD", "", kepr.SetOptions{Generate: "words", TTLSecs: 3600})
err = c.Generate("SESSION_KEY", "base62", kepr.SetOptions{RequiresConsent: true})
creds, err := c.Credentials()          // []kepr.CredInfo: metadata only, never values
info, err := c.Info("DB_PASSWORD")     // nil when absent
err = c.Delete("SESSION_KEY")

f, n, err := c.FetchFD("DB_PASSWORD")  // sealed memfd, close-on-exec
defer f.Close()
```

`FetchFD` needs a daemon with pull-on-demand fd delivery (plan T3.06);
older daemons answer it with an error.

Tests: `go test ./...` (set `KEPR_SDK_LIVE=1` to also run the live round trip
against a daemon).
