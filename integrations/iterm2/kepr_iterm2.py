#!/usr/bin/env python3
"""kepr status bar component for iTerm2 (Scripts > AutoLaunch).

Shows whether the kepr vault is locked, unlocked or unreachable, from
`kepr status --json`, polled every 10 seconds. Clicking it lists credential
names (never values) in the component's popover. Needs the iTerm2 Python
API (Scripts > Manage > Install Python Runtime).
"""

import asyncio
import os
import subprocess

import iterm2

import kepr_status

KEPR = os.environ.get("KEPR_BIN", "kepr")


def _run(args):
    return subprocess.run([KEPR, *args], capture_output=True, text=True, timeout=10).stdout


async def main(connection):
    component = iterm2.StatusBarComponent(
        short_description="kepr",
        detailed_description="Lock state of the kepr credential vault (never values)",
        knobs=[],
        exemplar="kepr: unlocked",
        update_cadence=10,
        identifier="io.kepr.status",
    )

    @iterm2.StatusBarRPC
    async def coro(knobs):
        try:
            text = await asyncio.get_running_loop().run_in_executor(None, _run, ["status", "--json"])
        except (OSError, subprocess.SubprocessError):
            return kepr_status.status_text("offline")
        state, _ = kepr_status.parse_status(text)
        return kepr_status.status_text(state)

    @iterm2.RPC
    async def click(session_id):
        try:
            text = await asyncio.get_running_loop().run_in_executor(None, _run, ["ls", "--json"])
            names = [c["name"] for c in kepr_status.parse_credentials(text)]
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            names = [str(e)]
        await component.async_open_popover(session_id, "\n".join(names) or "no credentials", iterm2.Size(320, 240))

    await component.async_register(connection, coro, onclick=click)


iterm2.run_forever(main)
