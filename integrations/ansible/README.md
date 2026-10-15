# Ansible lookup plugin for kepr

`lookup('kepr', TERM)` reads credentials from the kepr daemon on the Ansible
controller, as the user running `ansible-playbook`. The daemon applies its
usual rules: per-user namespace, audit, consent prompts, and it never returns
sealed agent keys or SSH keys.

```yaml
- name: Call an API
  ansible.builtin.uri:
    url: https://api.example.com/v1/items
    headers:
      Authorization: "Bearer {{ lookup('kepr', 'API_TOKEN') }}"
  no_log: true

- name: One field of a typed record (kepr record add PROD_DB --type database)
  ansible.builtin.set_fact:
    db_password: "{{ lookup('kepr', 'kepr://PROD_DB/password') }}"
  no_log: true
```

Terms: `NAME`, `kepr://NAME`, or `kepr://NAME/field` (a string field of a
record). Options: `socket_path` (or `KEPR_SOCKET`; default as for the CLI)
and `timeout` (seconds, default 65 to cover a consent prompt).

## Install

```bash
pip install ./sdk/python                       # the kepr client, on the controller
mkdir -p ~/.ansible/plugins/lookup
cp integrations/ansible/lookup_plugins/kepr.py ~/.ansible/plugins/lookup/
```

Run from a kepr checkout, the plugin finds `sdk/python` on its own. Mark
tasks that receive values `no_log: true`; Ansible otherwise prints them in
verbose output.

Tests: `python3 -m unittest discover -s integrations/ansible/tests` (a fake
client and stub Ansible modules; `KEPR_SDK_LIVE=1` also runs a round trip
against a running daemon).
