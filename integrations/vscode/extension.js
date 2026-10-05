'use strict';
// kepr for VS Code (plan T8.08): hover a kepr:// reference to see the
// credential's type, tags and expiry; "kepr: List credentials"; a status
// bar item with the vault's lock state. The extension only ever asks the
// daemon for metadata (list, status): it has no code path that reads a value.

const { referenceAt } = require('./src/notation');
const { hoverMarkdown, statusText, pickItems } = require('./src/view');
const { CredCache, newClient } = require('./src/creds');

const POLL_MS = 30000;

/**
 * VS Code calls `activate(context)`. Tests pass `deps` ({vscode, client,
 * pollMs}) instead of the editor's module and the daemon.
 */
function activate(context, deps = {}) {
  const vscode = deps.vscode || require('vscode');
  const socketPath = vscode.workspace.getConfiguration('kepr').get('socketPath');
  const client = deps.client || newClient(socketPath);
  const cache = new CredCache(client);
  const pollMs = deps.pollMs === undefined ? POLL_MS : deps.pollMs;

  const hover = vscode.languages.registerHoverProvider([{ scheme: 'file' }, { scheme: 'untitled' }], {
    async provideHover(document, position) {
      const ref = referenceAt(document.lineAt(position.line).text, position.character);
      if (!ref) return null;
      let text;
      try {
        text = hoverMarkdown(ref, await cache.info(ref.name));
      } catch (e) {
        text = `**kepr://${ref.name}**\n\nkepr daemon unreachable: ${e.message}`;
      }
      const range = new vscode.Range(position.line, ref.start, position.line, ref.end);
      return new vscode.Hover(new vscode.MarkdownString(text), range);
    },
  });

  const bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  bar.command = 'kepr.refreshStatus';
  async function refreshStatus() {
    let s;
    try {
      s = statusText(await client.status());
    } catch (e) {
      s = statusText(null, e);
    }
    bar.text = s.text;
    bar.tooltip = s.tooltip;
    bar.show();
  }

  const refresh = vscode.commands.registerCommand('kepr.refreshStatus', () => {
    cache.clear();
    return refreshStatus();
  });

  const list = vscode.commands.registerCommand('kepr.listCredentials', async () => {
    let creds;
    try {
      cache.clear();
      creds = await cache.all();
    } catch (e) {
      vscode.window.showErrorMessage(`kepr: ${e.message}`);
      return;
    }
    const pick = await vscode.window.showQuickPick(pickItems(creds), {
      placeHolder: 'kepr credentials (metadata only): pick one to insert its kepr:// reference',
    });
    if (!pick) return;
    const reference = `kepr://${pick.label}`;
    const editor = vscode.window.activeTextEditor;
    if (editor) {
      await editor.edit((b) => b.replace(editor.selection, reference));
    } else {
      await vscode.env.clipboard.writeText(reference);
      vscode.window.showInformationMessage(`Copied ${reference}`);
    }
  });

  const timer = pollMs > 0 ? setInterval(refreshStatus, pollMs) : null;
  const stop = { dispose: () => timer && clearInterval(timer) };
  context.subscriptions.push(hover, bar, refresh, list, stop);

  return {
    ready: refreshStatus(),
    dispose() {
      stop.dispose();
    },
  };
}

function deactivate() {}

module.exports = { activate, deactivate };
