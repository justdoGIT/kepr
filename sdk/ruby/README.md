# kepr Ruby client

Talks to the kepr daemon over its Unix socket, the same way the CLI does.
No dependencies beyond the Ruby standard library (Ruby 2.7+).

```ruby
require 'kepr'

kepr = Kepr::Client.new            # per-user socket; KEPR_SYSTEM_MODE=1 for the system one
kepr.set('DB_PASS', 'hunter2', ttl_secs: 3600)
kepr.generate('API_TOKEN', 'base62')   # generated in the daemon, never sent back
kepr.get('db_pass')                    # names are upper-cased
kepr.credentials                       # metadata only: name, size, sealed, tags ...
kepr.delete('DB_PASS')
```

Sealed credentials, SSH keys and share keys are never returned by `get`, the
same as for the CLI; the daemon applies uid namespacing, audit, consent and
FIDO2 rules to every call. Ruby strings cannot be wiped from memory, so keep
values in scope briefly and prefer `kepr exec` / `kepr agent run` for child
processes.

Test: `ruby test/test_kepr.rb`
