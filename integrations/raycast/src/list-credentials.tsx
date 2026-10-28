import { Action, ActionPanel, Icon, List, Toast, showToast } from "@raycast/api";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { useEffect, useState } from "react";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { parseList, parseStatus, subtitle, copyable, validName } = require("./parse");

const run = promisify(execFile);
// Raycast does not inherit the login shell's PATH.
const KEPR = process.env.KEPR_BIN || "kepr";

type Cred = ReturnType<typeof parseList>[number];

export default function Command() {
  const [creds, setCreds] = useState<Cred[]>([]);
  const [state, setState] = useState<string>("checking");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const status = parseStatus((await run(KEPR, ["status", "--json"])).stdout);
        setState(status.state);
        if (status.state === "unlocked") {
          setCreds(parseList((await run(KEPR, ["ls", "--json"])).stdout));
        }
      } catch (e) {
        setState("offline");
        await showToast({ style: Toast.Style.Failure, title: "kepr", message: e instanceof Error ? e.message : "failed" });
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <List isLoading={loading} navigationTitle={`kepr (${state})`} searchBarPlaceholder="Search credentials">
      {creds.map((c) => (
        <List.Item
          key={c.name}
          title={c.name}
          subtitle={subtitle(c)}
          icon={c.sealed ? Icon.Lock : Icon.Key}
          actions={
            <ActionPanel>
              {copyable(c) && validName(c.name) && (
                <Action
                  title="Copy Value (Clears Later)"
                  onAction={async () => {
                    // kepr copy puts the value on the clipboard and clears it; this
                    // extension never reads or displays it.
                    try {
                      await run(KEPR, ["copy", c.name]);
                      await showToast({ style: Toast.Style.Success, title: `Copied ${c.name}` });
                    } catch {
                      await showToast({ style: Toast.Style.Failure, title: "Could not copy", message: "kepr refused or is locked" });
                    }
                  }}
                />
              )}
            </ActionPanel>
          }
        />
      ))}
      {!loading && creds.length === 0 && (
        <List.EmptyView title={state === "locked" ? "kepr is locked" : state === "offline" ? "kepr is not reachable" : "No credentials"} />
      )}
    </List>
  );
}
