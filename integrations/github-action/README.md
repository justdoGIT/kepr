# kepr GitHub Action

Installs kepr (cosign-verified release), logs in to your secret store with
the job's OIDC token, and pulls the secrets you list into a job-local kepr
vault. Every value is masked (`::add-mask::`, line by line) before anything
can print it. Values reach later steps only through `kepr exec` / `kepr get`,
or through `$GITHUB_ENV` when you set `export: true`.

```yaml
permissions:
  contents: read
  id-token: write          # the OIDC token for the cloud login

steps:
  - uses: justdoGIT/kepr/integrations/github-action@<sha> # pin a commit
    with:
      cloud: aws
      aws-role-arn: arn:aws:iam::123456789012:role/github-deploy
      aws-region: eu-west-1
      secrets: |
        DB_PASSWORD=aws-sm:prod/db/password
        API_TOKEN=aws-sm:prod/api/token
  - run: kepr exec --env DB_PASSWORD,API_TOKEN -- ./deploy.sh
```

| `cloud` | inputs | how it logs in |
|---|---|---|
| `aws` | `aws-role-arn`, `aws-region` | `AssumeRoleWithWebIdentity` (audience `sts.amazonaws.com`) |
| `gcp` | `gcp-workload-identity-provider`, optional `gcp-service-account` | STS token exchange, then impersonation |
| `vault` | `vault-addr`, `vault-role`, `vault-auth-path` (`jwt`) | JWT auth login |
| `none` | | uses credentials already in the environment (e.g. from `aws-actions/configure-aws-credentials`) |

`audience` overrides the token audience (for Vault, set it to the role's
`bound_audiences`). Cloud credentials stay inside the action's step; they
are masked and never written to `$GITHUB_ENV`.

`secrets` takes one `NAME=SCHEME:PATH` per line with the `kepr sync-pull`
schemes (`vault:`, `aws-sm:`, `gcp-sm:`); `#` starts a comment.

The steps live in `integrations/ci/kepr-ci.sh`, shared with the GitLab
template (`integrations/gitlab/kepr.gitlab-ci.yml`). Tests:
`bash integrations/ci/test_kepr_ci.sh`; CI also runs actionlint and
shellcheck. `.github/workflows/kepr-action-example.yml` is a manual example
against Vault.
