# kepr Go client

A thin client for the local kepr daemon (standard library only). It uses
the same socket and wire format as the `kepr` CLI, so the daemon applies the
same rules (per-user namespacing, audit, consent, sealed keys never returned).

```go
c := kepr.New()
token, err := c.Get("GITHUB_TOKEN")
err = c.Set("DB_PASSWORD", "", kepr.SetOptions{Generate: "words", TTLSecs: 3600})
```

Tests: `go test ./...` (set `KEPR_SDK_LIVE=1` to also run the live round trip
against a daemon).
