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
cargo build --release -p kepr-gate
ok "Build complete"

SYSTEM_MODE=false
if [ "$(ps -p 1 -o comm= 2>/dev/null || true)" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
    SYSTEM_MODE=true
    echo -e "\n${CYN}━━━ Configuring optional system service ━━━${RST}"
    if ! getent group kepr > /dev/null 2>&1; then
        sudo groupadd --system kepr
        ok "Group 'kepr' created"
    fi
    sudo usermod -aG kepr "$INSTALL_USER"
    warn "Log out/in or run newgrp kepr for group membership"
else
    info "No systemd PID 1 detected; using self-contained user mode"
fi
echo -e "\n${CYN}━━━ Installing binaries ━━━${RST}"
sudo install -o root -g root -m 0755 target/release/kepr /usr/local/bin/kepr
sudo install -o root -g root -m 0755 target/release/kepr-daemon /usr/local/bin/kepr-daemon
sudo install -o root -g root -m 0755 target/release/docker-credential-kepr /usr/local/bin/docker-credential-kepr
sudo install -o root -g root -m 0755 target/release/git-credential-kepr /usr/local/bin/git-credential-kepr
sudo install -o root -g root -m 0755 target/release/kepr-gate /usr/local/bin/kepr-gate
ok "kepr                    → /usr/local/bin/kepr"
ok "kepr-daemon             → /usr/local/bin/kepr-daemon"
ok "docker-credential-kepr  → /usr/local/bin/docker-credential-kepr"
ok "git-credential-kepr     → /usr/local/bin/git-credential-kepr"
ok "kepr-gate               → /usr/local/bin/kepr-gate"


# Phase 2 ε: install the polkit action so creds set with
# `--requires-consent` can prompt the user via the desktop's
# polkit agent. Without this file, pkcheck denies the action
# unconditionally and every consent-flagged cred reads as
# "credential unavailable" (fail-closed).
if [ -d /usr/share/polkit-1/actions ]; then
    sudo cp systemd/polkit/io.kepr.policy /usr/share/polkit-1/actions/io.kepr.policy
    sudo chown root:root /usr/share/polkit-1/actions/io.kepr.policy
    sudo chmod 644 /usr/share/polkit-1/actions/io.kepr.policy
    ok "polkit action io.kepr.read-credential → /usr/share/polkit-1/actions/io.kepr.policy"
else
    warn "polkit not installed — --requires-consent flag will deny all reads"
    warn "install policykit-1 (or your distro's equivalent) and re-run install.sh"
fi

# Agent sandbox: Ubuntu 24.04+ restricts unprivileged user namespaces
# via AppArmor. The kepr profile grants `userns` to /usr/local/bin/kepr
# only, so `kepr agent run` can build its sandbox.
if [ -d /etc/apparmor.d ] && command -v apparmor_parser >/dev/null 2>&1; then
    sudo install -o root -g root -m 0644 packaging/apparmor/kepr /etc/apparmor.d/kepr
    if sudo apparmor_parser -r /etc/apparmor.d/kepr 2>/dev/null; then
        ok "AppArmor profile (agent sandbox) → /etc/apparmor.d/kepr"
    else
        warn "AppArmor profile installed but not loaded; run: sudo apparmor_parser -r /etc/apparmor.d/kepr"
    fi
fi

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

if $SYSTEM_MODE; then
    echo -e "\n${CYN}━━━ Installing systemd service ━━━${RST}"
    sudo cp systemd/kepr.service /etc/systemd/system/kepr.service
    # Agent sessions under the system daemon run in their own service
    # (unprivileged dynamic user with network access, no store access).
    sudo cp systemd/kepr-gate.service /etc/systemd/system/kepr-gate.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now kepr-gate.service || warn "kepr-gate.service did not start; agent sessions need it in system mode"
    # Scheduled rotations (T12.50): the system daemon never runs user
    # rotators, so each user's own timer runs `kepr rotate --due`.
    sudo install -d -m 0755 /usr/lib/systemd/user
    sudo install -m 0644 systemd/user/kepr-rotate.service systemd/user/kepr-rotate.timer /usr/lib/systemd/user/
    # Multi-device sync on a schedule: opt-in per user, like the rotation timer.
    sudo install -m 0644 systemd/user/kepr-sync.service systemd/user/kepr-sync.timer /usr/lib/systemd/user/
    sudo systemctl enable kepr.service
    sudo systemctl restart kepr.service
    sleep 1
    if sudo systemctl is-active --quiet kepr.service; then
        ok "kepr.service is running"
        # Point every login shell's kepr (and the credential helpers) at
        # the system daemon instead of auto-starting a per-user one.
        echo 'export KEPR_SYSTEM_MODE=1' | sudo tee /etc/profile.d/kepr.sh >/dev/null
        sudo chmod 0644 /etc/profile.d/kepr.sh
        ok "KEPR_SYSTEM_MODE=1 for login shells → /etc/profile.d/kepr.sh"
        info "Scheduled rotations (kepr rotate NAME --every DUR) need, per user: systemctl --user enable --now kepr-rotate.timer"
        info "Paired devices (kepr device, kepr sync remote add) stay in step with, per user: systemctl --user enable --now kepr-sync.timer"
    else
        echo "kepr.service failed to start:" >&2
        sudo journalctl -u kepr.service -n 20 --no-pager >&2
        exit 1
    fi
else
    info "User mode is ready; the CLI auto-starts kepr-daemon on first use"
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

  Give a command a secret without exporting it into your shell:
    ${CYN}kepr exec --env OPENCLAW_GATEWAY_TOKEN -- your-command${RST}

  Run an AI agent with sealed keys it never sees:
    ${CYN}kepr agent add ANTHROPIC_API_KEY && kepr agent run claude${RST}
"
