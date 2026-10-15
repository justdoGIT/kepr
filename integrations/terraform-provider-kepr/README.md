# terraform-provider-kepr

A Terraform provider for the local kepr daemon (plugin framework, protocol 6).
It talks to the same Unix socket as the `kepr` CLI through the Go SDK in
`sdk/go`, so the daemon applies its usual rules: Terraform can only reach the
credentials of the user running it, every access is audited, consent-gated
credentials prompt, and sealed agent keys and SSH keys are never returned.

```hcl
terraform {
  required_providers {
    kepr = { source = "justdogit/kepr" }
  }
}

provider "kepr" {}            # socket_path = "/run/kepr/kepr.sock" for a system daemon

# kepr generates the value; it never enters Terraform state.
resource "kepr_secret" "db" {
  name     = "PROD_DB_PASSWORD"
  generate = "words"
  ttl_secs = 2592000
}

# Read a value (or a typed record's fields) to pass to another resource.
data "kepr_secret" "github" {
  name = "GITHUB_TOKEN"
}

data "kepr_secret" "db_record" {
  name = "PROD_DB"            # made with `kepr record add PROD_DB --type database`
}

output "db_user" {
  value     = data.kepr_secret.db_record.fields["user"]
  sensitive = true
}
```

| `kepr_secret` resource | |
|---|---|
| `name` | required, forces replacement |
| `value` | optional, sensitive; omit it to generate |
| `generate` | `hex` (default), `base62`, `pass`, `uuid`, `words`; forces replacement |
| `ttl_secs`, `requires_consent` | optional, force replacement |
| `id`, `modified`, `expires_at` | computed |

Import: `terraform import kepr_secret.db PROD_DB_PASSWORD` (the value is not
imported). A credential deleted or expired outside Terraform is dropped from
state on the next refresh.

The `kepr_secret` data source returns `value`, `fields` (records),
`record_type`, `expires_at`, `modified` and `tags`. **Like every Terraform
data source, its values are written to state**: keep state encrypted, or use
`kepr exec -- terraform apply` with `TF_VAR_*` variables instead.

## Build and test

```bash
go build -o terraform-provider-kepr .
go vet ./... && go test ./...
KEPR_TF_LIVE=1 go test -run TestLiveDaemon ./internal/provider   # needs a running daemon
```

To use a local build, point a `dev_overrides` block in `~/.terraformrc` at the
directory holding the binary:

```hcl
provider_installation {
  dev_overrides { "justdogit/kepr" = "/path/to/dir" }
  direct {}
}
```
