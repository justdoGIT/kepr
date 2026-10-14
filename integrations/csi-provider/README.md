# Secrets Store CSI provider for kepr

`kepr-csi-provider` plugs kepr into the
[Secrets Store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/):
pods mount credentials as files, fetched from
[`kepr-eso-provider`](../../crates/kepr-eso-provider)'s HTTP API when the
volume is mounted (and on every rotation poll).

It implements the driver's `v1alpha1.CSIDriverProvider` gRPC service on a
Unix socket in the driver's provider directory, and returns the files for
the driver to write (`-write-files` also writes them itself, for drivers
before v0.0.21). A mount gets every listed credential or fails; errors name
credentials, never values.

## Build

```bash
cd integrations/csi-provider
go build -o kepr-csi-provider .
go test ./...
```

## Run

Run it as a DaemonSet next to the driver, with the driver's provider
directory mounted (`/var/run/secrets-store-csi-providers` by default):

```
kepr-csi-provider \
  -endpoint /var/run/secrets-store-csi-providers/kepr.sock \
  -kepr-url http://kepr-eso-provider.kepr.svc:8080
```

## Use

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-secrets
spec:
  provider: kepr
  parameters:
    objects: |
      DB_URL
      API_KEY=api/key.txt
    fileMode: "0400"        # optional; else the volume's filePermission
    # url: http://kepr-eso-provider.kepr.svc:8080   # optional override
---
# in the pod spec
volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: app-secrets
      nodePublishSecretRef:
        name: kepr-eso-token    # a Secret with key "token"
```

`objects` lists `NAME` or `NAME=relative/path`, one per line or comma
separated (at most 100). The bearer token comes from the volume's
`nodePublishSecretRef` (key `token`), else from `-token-file`. Object
versions reported to the driver are a per-process HMAC, not a hash of the
value.
