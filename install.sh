#!/usr/bin/env bash
# install.sh — build and install credman
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# What this does:
#   1. Build release binaries
#   2. Create 'credman' system group
#   3. Add current user to 'credman' group
#   4. Install binaries to /usr/local/bin and /usr/local/sbin
#   5. Install systemd service
#   6. Start daemon

set -euo pipefail

GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'
ok()   { echo -e "${GRN}  ✓  $*${RST}"; }
info() { echo -e "${CYN}  ·  $*${RST}"; }
warn() { echo -e "${YLW}  ⚠  $*${RST}"; }

INSTALL_USER="${SUDO_USER:-$USER}"

echo -e "\n${CYN}━━━ Building credman ━━━${RST}"
cargo build --release
ok "Build complete"

echo -e "\n${CYN}━━━ Creating system group ━━━${RST}"
if ! getent group credman > /dev/null 2>&1; then
    sudo groupadd --system credman
    ok "Group 'credman' created"
else
    ok "Group 'credman' already exists"
fi

info "Adding ${INSTALL_USER} to 'credman' group"
sudo usermod -aG credman "$INSTALL_USER"
ok "${INSTALL_USER} added to credman group"
warn "Log out and back in for group membership to take effect"
warn "Or run: newgrp credman"

echo -e "\n${CYN}━━━ Installing binaries ━━━${RST}"
sudo cp target/release/credman        /usr/local/bin/credman
sudo cp target/release/credman-daemon /usr/local/sbin/credman-daemon

sudo chown root:root /usr/local/bin/credman
sudo chown root:root /usr/local/sbin/credman-daemon
sudo chmod 755 /usr/local/bin/credman
sudo chmod 700 /usr/local/sbin/credman-daemon   # root-only execution

ok "credman       → /usr/local/bin/credman"
ok "credman-daemon → /usr/local/sbin/credman-daemon"

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
    sudo install -m 0644 completions/credman.bash "$BASH_COMPDIR/credman"
    ok "bash completion → $BASH_COMPDIR/credman"
    info "Reload: source $BASH_COMPDIR/credman   (or open a new shell)"
else
    warn "bash-completion not detected — skipping completion install"
fi

echo -e "\n${CYN}━━━ Installing systemd service ━━━${RST}"
sudo cp systemd/credman.service /etc/systemd/system/credman.service
sudo systemctl daemon-reload
sudo systemctl enable credman.service
sudo systemctl restart credman.service
sleep 1

if sudo systemctl is-active --quiet credman.service; then
    ok "credman.service is running"
else
    echo "credman.service failed to start:"
    sudo journalctl -u credman.service -n 20 --no-pager
    exit 1
fi

echo -e "\n${CYN}━━━ Setup complete ━━━${RST}"
echo -e "
  ${GRN}credman is ready.${RST}

  First, reload your group membership:
    ${CYN}newgrp credman${RST}
    or log out and back in

  Then test:
    ${CYN}credman set TEST_KEY --generate${RST}
    ${CYN}credman get TEST_KEY${RST}
    ${CYN}credman list${RST}

  View audit log:
    ${CYN}journalctl -t credman-daemon -f${RST}

  Fix .agentrc (remove sudo):
    ${CYN}export OPENCLAW_GATEWAY_TOKEN=\"\$(credman get OPENCLAW_GATEWAY_TOKEN --quiet)\"${RST}
"
