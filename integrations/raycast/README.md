# kepr for Raycast

A **List Credentials** command: name, type, tags, expiry and lock state from
`kepr ls --json` and `kepr status --json`, never a value. **Copy Value** runs
`kepr copy NAME`, which puts the value on the clipboard and clears it after
a delay; the extension never reads or shows it. Sealed agent keys have no
copy action (they are write-only).

It talks to the CLI, not the socket. Raycast does not inherit your shell's
`PATH`: set `KEPR_BIN` or install `kepr` in `/usr/local/bin`.

Test (the parsing): `node --test integrations/raycast/test/*.test.js`.
`icon.png` is yours to add before publishing; publishing to the Raycast Store
is out of scope here.
