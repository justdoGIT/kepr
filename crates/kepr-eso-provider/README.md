# kepr-eso-provider

Bridge between External Secrets Operator and kepr. ESO polls this HTTP
service via its webhook provider; the service translates each request
into a kepr daemon Get call over the Unix socket and returns the secret
as JSON.

### 1. Create the provider authentication secret

The provider refuses non-loopback listeners without a bearer token. Create the
token in the same namespace as the deployment before applying the manifests:

```bash
kubectl create secret generic kepr-eso-provider-auth \
  --from-literal=token="$(openssl rand -hex 32)"
```

### 2. Deploy the provider
kubectl apply -f deploy/deployment.yaml

The deployment listens on the pod network and requires
`Authorization: Bearer <token>` for all secret endpoints. The
`cluster-secret-store.yaml` configures ESO to read the same Kubernetes Secret
and send that header. `/health` remains unauthenticated for probes.
The deployment mounts /run/kepr/kepr.sock from the host via hostPath.

### 2. Configure the SecretStore
kubectl apply -f deploy/cluster-secret-store.yaml

### 3. Create an ExternalSecret
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: openai-key
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: kepr
    kind: ClusterSecretStore
  target:
    name: openai-api-key
  data:
    - secretKey: OPENAI_API_KEY
      remoteRef:
        key: OPENAI_API_KEY

## Endpoints

| Method | Path               | Description   |
|--------|--------------------|---------------|
| GET    | /health            | health check  |
| GET    | /v1/secrets/<NAME> | single secret |
| POST   | /v1/secrets        | batch secrets |

## Configuration

| Env variable               | Default          | Description |
|----------------------------|------------------|-------------|
| `KEPR_ESO_LISTEN`          | `127.0.0.1:8080` | Listen address:port. |
| `KEPR_ESO_AUTH_TOKEN`      | (none)           | Bearer token required on `/v1/secrets*`. **Required**, including on loopback: any local user can reach a loopback port. Compared in constant time. |
| `KEPR_ESO_INSECURE_NO_AUTH`| (unset)          | Set to `1` to run on loopback without a token, on a single-user host only. |

Sealed credentials (`kepr agent add`) are never served: the daemon
refuses `Get` for them.
