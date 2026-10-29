# kepr for JetBrains IDEs

A status bar widget (`kepr: locked` / `unlocked` / `offline`) and a **kepr**
tool window listing credential names, type, tags and expiry. **Copy** runs
`kepr copy NAME`; the CLI puts the value on the clipboard and clears it later
and this plugin never reads or shows it. Sealed agent keys have no copy.
It uses `kepr status --json` and `kepr ls --json`, not the socket. Set
`KEPR_BIN` if the IDE does not see `kepr` on its `PATH`.

- `./test.sh` compiles and tests the IDE-independent part (`CliView`) with a
  plain JDK.
- `gradle buildPlugin` builds the plugin (needs network for the IntelliJ
  Platform). The widget, tool window and `plugin.xml` have not been built or
  run in CI; marketplace publishing is out of scope.
