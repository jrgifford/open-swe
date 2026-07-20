# Local Kubernetes runtime (k3d)

The k3 runtime is a development-only, single-node installation. It runs the UI, FastAPI and all LangGraph graphs behind one localhost origin and provisions a persistent, isolated sandbox Pod for each agent thread.

## Prerequisites

- Linux or macOS on amd64 or arm64.
- A running Docker-compatible daemon supported by k3d.
- [mise](https://mise.jdx.dev/) on `PATH`.
- At least 8 GiB free disk space.
- An OpenAI API key and a GitHub App OAuth client ID and client secret.

The committed `mise.toml` and `mise.lock` install the supported Python, Node, pnpm, k3d, Kubernetes, and Helm versions. Docker and mise are deliberately not installed automatically.

## Start

```bash
make start-k3
```

On first start, the installer explains the GitHub App settings and prompts for missing credentials without echoing them. It writes credentials plus generated encryption keys atomically to the gitignored `.env` with mode `0600`. Non-interactive starts must provide all three required variables and otherwise fail before any cluster changes:

```bash
OPENAI_API_KEY=... \
GITHUB_APP_CLIENT_ID=... \
GITHUB_APP_CLIENT_SECRET=... \
make start-k3
```

Credential network validation can be bypassed, without supplying placeholders, in a constrained network or CI:

```bash
make start-k3 K3_FLAGS=--skip-credential-checks
```

The first install uses `http://localhost:3000`. If that port is occupied, the interactive first run asks for an alternative. The choice is persisted in `.open-swe/k3.json`; later runs never silently change it.

`start-k3` builds deterministic current-checkout images, creates or starts the cluster, imports the images, atomically reconciles the Helm release, and runs functional smoke gates. It exits after printing the URL. Re-running it preserves `.env`, graph state, thread PVCs, and application data.

## GitHub App

For the default port, configure:

- Homepage: `http://localhost:3000`
- OAuth callback: `http://localhost:3000/dashboard/api/auth/callback`
- Repository permissions: Contents read/write, Pull requests read/write, Issues read/write, Metadata read-only.
- Account permission: Email addresses read-only.

Install the App on repositories Open SWE may access. A webhook URL and webhook secret are intentionally unused because this milestone has no public tunnel. After opening the printed URL, sign in with GitHub; that OAuth exchange is the authoritative validation of the client secret.

## Lifecycle and diagnostics

```bash
make status-k3
make logs-k3
make stop-k3
make start-k3                 # resumes retained state
make destroy-k3               # requires typing "destroy"
make destroy-k3 K3_DESTROY_FLAGS=--yes
```

`stop-k3` retains the k3d Docker volumes. `destroy-k3` deletes the cluster and every in-cluster PVC, but retains `.env` and `.open-swe/k3.json`. Remove those files separately if desired.

A failed image build leaves the previous release running. Helm upgrades use `--atomic --wait`; failed reconciliation rolls back while retaining the cluster for `status-k3` and `logs-k3` inspection.

## Persistence and sandbox limits

The single `langgraph dev` control-plane replica stores `.langgraph_api` on a PVC. This is a local development runtime, not a supported production Agent Server or an HA durability claim.

Each thread has one PVC and, while active, one Pod. `/workspace` and `/root` persist; OS package changes elsewhere in the container are disposable. Idle Pods are removed after one hour and their PVCs after 30 days by default. Two Pods may be active; further provisioning waits for bounded capacity and then reports a timeout. Docker CLI is installed, but there is no daemon or socket, so nested containers are unsupported.

Sandbox Pods run as root for tool compatibility but drop all capabilities, disable privilege escalation and service-account tokens, use RuntimeDefault seccomp, and have no host namespaces, paths, or Docker socket. NetworkPolicy denies ingress and private-cluster egress while allowing DNS, the credential proxy, and public dependency traffic.

## Credential boundary

Sandbox Pods contain only `GH_TOKEN=dummy` and the non-secret proxy URL. The proxy binds credentials to the Pod source address observed on the connection, so no transferable proxy credential is mounted into a sandbox. Real GitHub credentials are encrypted with the shared control-plane/proxy admin key before crossing the policy-isolated admin channel and are held only in proxy memory. The proxy terminates GitHub TLS with its persisted private CA, injects authorization only for `github.com` and `api.github.com`, and enforces configured repository scope. Its CA certificate—not its private key—is mounted into sandboxes. Proxy restarts discard credentials; the normal control-plane reconnect path refreshes them without recreating a Pod.

The startup smoke sends a synthetic credential through the real CONNECT/TLS interception path, verifies source isolation, and scans full application/proxy/UI logs and Kubernetes events for configured secrets. Real `git` and `gh` access is exercised when the first authenticated agent sandbox is configured after GitHub login; startup does not spend model tokens, create a repository, or create a PR.

## Production delta

Production requires an explicit supported Agent Server/runtime decision, durable Postgres/Redis where required, external secret management, public TLS/webhooks, backup and migration procedures, HA and observability, quotas, and stronger multi-tenant/network boundaries. The local chart must not be presented as production-ready.
