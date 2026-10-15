# Podman secret driver for kepr

`kepr-podman-driver` lets Podman keep its secrets in kepr through Podman's
built-in `shell` secret driver. Containers read them the usual way
(`--secret NAME`, mounted at `/run/secrets/NAME` or set as an environment
variable); the values live in the kepr daemon, per user, audited, and never
in Podman's own `secrets.json`.

## Install

```bash
sudo install -m 0755 integrations/podman/kepr-podman-driver /usr/local/bin/
```

The user running `podman` must be able to use `kepr` (in the `kepr` group
for the system daemon, or running the user-mode daemon).

## Use it for one secret

```bash
D=/usr/local/bin/kepr-podman-driver
printf '%s' "$DB_PASSWORD" | podman secret create \
  --driver shell \
  --driver-opts "list=$D list,lookup=$D lookup,store=$D store,delete=$D delete" \
  db_password -

podman run --rm --secret db_password alpine cat /run/secrets/db_password
```

## Make it the default driver

In `~/.config/containers/containers.conf` (rootless) or
`/etc/containers/containers.conf`:

```toml
[secrets]
driver = "shell"

[secrets.opts]
list   = "/usr/local/bin/kepr-podman-driver list"
lookup = "/usr/local/bin/kepr-podman-driver lookup"
store  = "/usr/local/bin/kepr-podman-driver store"
delete = "/usr/local/bin/kepr-podman-driver delete"
```

Then plain `podman secret create NAME -` stores into kepr.

## How values are named

Podman gives every secret a hex id and runs the driver with `SECRET_ID` set.
The value is stored in kepr as `PODMAN_<ID>` (uppercased), so it shows up in
`kepr list`, `kepr history` and the audit log like any other credential.
Removing the secret (`podman secret rm`) deletes it from kepr.

## Point a Podman secret at an existing kepr credential

Store the reference `kepr://NAME` instead of a value:

```bash
printf 'kepr://DB_PASSWORD' | podman secret create db_password -
```

Each container start then reads the current value of `DB_PASSWORD`, so
`kepr rotate DB_PASSWORD` reaches the next container without re-creating
the secret. `podman secret rm` removes only the reference.

## Limits

- Values must be non-empty UTF-8 (kepr's rule for `kepr set --stdin`), and
  one trailing newline is dropped when storing.
- Sealed agent keys and SSH keys can't be read by `kepr get`, so they can't
  back a Podman secret.
- Credentials that ask for consent or a FIDO2 touch prompt on every
  container start.

## Tests

```bash
shellcheck integrations/podman/kepr-podman-driver integrations/podman/*.sh
bash integrations/podman/test_kepr_podman_driver.sh   # fake kepr, no Podman needed
```
