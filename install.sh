#!/usr/bin/env bash
# install.sh — build and install kepr
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# What this does:
#   1. Build release binaries
#   2. Create 'kepr' system group
#   3. Add current user to 'kepr' group
#   4. Install binaries to /usr/local/bin and /usr/local/sbin
#   5. Install systemd service
#   6. Start daemon

set -euo pipefail

GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'
ok()   { echo -e "${GRN}  ✓  $*${RST}"; }
info() { echo -e "${CYN}  ·  $*${RST}"; }
warn() { echo -e "${YLW}  ⚠  $*${RST}"; }

INSTALL_USER="${SUDO_USER:-$USER}"

echo -e "\n${CYN}━━━ Building kepr ━━━${RST}"
cargo build --release
ok "Build complete"

echo -e "\n${CYN}━━━ Creating system group ━━━${RST}"
if ! getent group kepr > /dev/null 2>&1; then
    sudo groupadd --system kepr
    ok "Group 'kepr' created"
else
    ok "Group 'kepr' already exists"
fi

info "Adding ${INSTALL_USER} to 'kepr' group"
sudo usermod -aG kepr "$INSTALL_USER"
ok "${INSTALL_USER} added to kepr group"
warn "Log out and back in for group membership to take effect"
warn "Or run: newgrp kepr"

echo -e "\n${CYN}━━━ Installing binaries ━━━${RST}"
sudo cp target/release/kepr                    /usr/local/bin/kepr
sudo cp target/release/kepr-daemon             /usr/local/sbin/kepr-daemon
sudo cp target/release/docker-credential-kepr  /usr/local/bin/docker-credential-kepr

sudo chown root:root /usr/local/bin/kepr
sudo chown root:root /usr/local/sbin/kepr-daemon
sudo chown root:root /usr/local/bin/docker-credential-kepr
sudo chmod 755 /usr/local/bin/kepr
sudo chmod 700 /usr/local/sbin/kepr-daemon   # root-only execution
sudo chmod 755 /usr/local/bin/docker-credential-kepr

ok "kepr                      → /usr/local/bin/kepr"
ok "kepr-daemon               → /usr/local/sbin/kepr-daemon"
ok "docker-credential-kepr    → /usr/local/bin/docker-credential-kepr"

echo -e "\n${CYN}━━━ Installing shell completion ━━━${RST}"
# Prefer the directory bash-completion itself advertises via pkg-config;
# fall back to the Debian/Ubuntu default. Skip with a warning if the
# parent path isn't present — the system likely has no bash-completion
# installed and the script would do nothing useful.
BASH_COMPDIR="$(pkg-config --variable=completionsdir bash-completion 2>/dev/null || true)"
if [[ -z "$BASH_COMPDIR" ]]; then
    BASH_COMPDIR="/usr/share/bash-completion/completions"
fi
if [[ -d "$(dirname "$BASH_COMPDIR")" ]]; then
    sudo install -d -m 0755 "$BASH_COMPDIR"
    sudo install -m 0644 completions/kepr.bash "$BASH_COMPDIR/kepr"
    ok "bash completion → $BASH_COMPDIR/kepr"
    info "Reload: source $BASH_COMPDIR/kepr   (or open a new shell)"
else
    warn "bash-completion not detected — skipping completion install"
fi

echo -e "\n${CYN}━━━ Installing systemd service ━━━${RST}"
sudo cp systemd/kepr.service /etc/systemd/system/kepr.service
sudo systemctl daemon-reload
sudo systemctl enable kepr.service
sudo systemctl restart kepr.service
sleep 1

if sudo systemctl is-active --quiet kepr.service; then
    ok "kepr.service is running"
else
    echo "kepr.service failed to start:"
    sudo journalctl -u kepr.service -n 20 --no-pager
    exit 1
fi

echo -e "\n${CYN}━━━ Setup complete ━━━${RST}"
echo -e "
  ${GRN}kepr is ready.${RST}

  First, reload your group membership:
    ${CYN}newgrp kepr${RST}
    or log out and back in

  Then test:
    ${CYN}kepr set TEST_KEY --generate${RST}
    ${CYN}kepr get TEST_KEY${RST}
    ${CYN}kepr list${RST}

  View audit log:
    ${CYN}journalctl -t kepr-daemon -f${RST}

  Fix .agentrc (remove sudo):
    ${CYN}export OPENCLAW_GATEWAY_TOKEN=\"\$(kepr get OPENCLAW_GATEWAY_TOKEN --quiet)\"${RST}
"
