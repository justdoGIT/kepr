# VHS tape script for recording Kepr terminal demo
# Output: .github/assets/demo.gif

Output .github/assets/demo.gif

Require kepr

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Charm"

# Scene 1: Store credential interactively
Type "kepr set OPENAI_API_KEY --value sk-proj-1234567890abcdef" Sleep 500ms Enter
Sleep 1.5s

# Scene 2: RAM delivery via memfd
Type "kepr exec --memfd OPENAI_API_KEY -- bash -c 'cat /proc/$PPID/environ | grep OPENAI_API_KEY || echo \"CLEAN: No secret in /proc!\"'" Sleep 500ms Enter
Sleep 2s

# Scene 3: Argon2id Lock & Unlock
Type "kepr lock" Sleep 500ms Enter
Sleep 1s
Type "kepr status" Sleep 500ms Enter
Sleep 1.5s
