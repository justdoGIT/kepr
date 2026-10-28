# kepr for iTerm2

A status bar component: `kepr: locked`, `kepr: unlocked` or `kepr: offline`,
from `kepr status --json` every 10 seconds. Clicking it lists credential
names from `kepr ls --json`; never a value.

Install: copy `kepr_iterm2.py` and `kepr_status.py` into
`~/Library/ApplicationSupport/iTerm2/Scripts/AutoLaunch/`, then add **kepr** in
Preferences > Profiles > Session > Status Bar. Set `KEPR_BIN` if `kepr` is not
on iTerm2's `PATH`.

Test (the parsing): `python3 -m unittest discover -s integrations/iterm2/test`.
The iTerm2 glue needs iTerm2 itself and is not run in CI.
