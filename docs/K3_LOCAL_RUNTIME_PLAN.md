# K3 Local Runtime Plan

**Status:** Implemented; mandatory spikes passed on Linux amd64 (see `K3_SPIKE_RESULTS.md`)  
**Scope:** Local development / proof of concept  
**Primary command:** `make start-k3`

## Outcome

A developer with Docker and mise installed can run:

```bash
make start-k3
```

The command interactively collects missing credentials, creates or reuses a local k3d cluster, builds the current checkout, installs the complete Open SWE UI and backend, configures a Kubernetes-backed agent sandbox runtime, waits for a functional smoke test, prints one localhost URL, and exits successfully.

Repeated starts reconcile the installation without deleting cluster state, credentials, graph state, thread workspaces, or user data.

## Scope

### Included

- Linux and macOS on amd64 and arm64.
- A local k3d cluster managed by Make and a Python installer.
- The full user-facing stack:
  - TanStack Start UI.
  - FastAPI application and all graphs from `langgraph.json`.
  - The unlicensed local `langgraph dev` runtime.
  - A new `SANDBOX_TYPE=k3` provider.
- One sandbox Pod and PVC per LangGraph thread.
- A dedicated in-cluster GitHub credential proxy that keeps GitHub tokens out of sandbox Pods.
- A capability-driven first-run wizard, initially requiring OpenAI and GitHub App OAuth credentials.
- One browser-facing origin on a persisted localhost port.
- Idempotent Helm reconciliation, lifecycle commands, smoke tests, and support documentation.

### Explicitly excluded from milestone 1

- Production support, high availability, SLAs, backups, or multi-node operation.
- A licensed standalone LangGraph Agent Server, Postgres, or Redis.
- Public ingress and webhook tunnels.
- A separate remote sandbox cluster.
- Nested container workloads (`docker build`, `docker run`, or Compose) inside sandboxes.
- Full mutable-rootfs persistence for sandbox Pods.
- Istio.
- Automatic Docker or mise installation.
- Automatic destructive k3s upgrades.

## Accepted design

### 1. Host bootstrap and lifecycle

The host must already provide:

- A running Docker-compatible daemon supported by k3d.
- mise.

A committed `mise.toml` pins Python, k3d, kubectl, Helm, Node, pnpm/corepack requirements, and any other installer tools. Use explicit mise backends and commit a lockfile with resolved versions and checksums.

Make remains a thin interface:

```text
make start-k3       # preflight, prompt, build, reconcile, smoke, print URL
make status-k3      # concise cluster/release/workload status
make logs-k3        # useful application, proxy, and sandbox events
make stop-k3        # stop the k3d cluster without deleting state
make destroy-k3     # explicit destructive action with confirmation
```

`start-k3` exits after the smoke gate. It does not tail logs or open a browser.

The first run defaults to localhost port `3000`. If occupied, the wizard allows one alternate choice and persists it in gitignored local configuration. Later runs use the persisted value and fail with remediation rather than silently changing the port.

The cluster name, host port, enabled capabilities, and non-secret resource settings live in a gitignored local config file. Cluster creation uses a committed k3d config with a host-to-load-balancer port mapping.

### 2. Interactive installer

Implement a tested Python CLI invoked through mise by the Make targets.

The flow is:

1. Verify Docker, mise, supported OS/architecture, disk space, and selected port.
2. Install pinned project tools with mise.
3. Load the gitignored `.env` and non-secret local config.
4. Determine missing values for enabled capabilities.
5. In a TTY, prompt one missing value at a time with secret input hidden.
6. Without a TTY, fail once with the complete missing-variable list and make no cluster changes.
7. Validate selected credentials before deployment where technically possible.
8. Build current-checkout images and import them into k3d.
9. Create or reuse the cluster.
10. Reconcile Kubernetes Secrets and the Helm release.
11. Wait for rollout and run the functional smoke gate.
12. Print the UI URL, next login step, and lifecycle commands.

An explicit `--skip-credential-checks` escape hatch supports constrained networks and CI. It never supplies placeholder credentials.

#### Required user credentials

Milestone 1 requires:

- `OPENAI_API_KEY`.
- `GITHUB_APP_CLIENT_ID`.
- `GITHUB_APP_CLIENT_SECRET`.

The wizard recommends the existing default model, `openai:gpt-5.5`, and does not collect other model-provider keys initially.

GitHub setup is guided but manual. Before prompting, show the exact homepage and OAuth callback URL, required GitHub App permissions, installation step, and which webhook settings are intentionally unused in the localhost-only milestone.

The GitHub client secret cannot be fully validated before an OAuth code exchange. Validate its presence/shape during startup, then perform the real GitHub validation immediately after dashboard login and app installation.

#### Generated secrets

Generate strong values when absent and preserve them in `.env`, including at least:

- `DASHBOARD_JWT_SECRET`.
- `TOKEN_ENCRYPTION_KEY`.

Write `.env` atomically with mode `0600`, preserve comments and unknown values, never print secret values, and keep the existing gitignore protection. Reconcile the relevant values into a Kubernetes Secret without placing them in Helm command-line arguments or generated tracked files.

The `.env` file is the local source of truth for user credentials and stable application encryption keys. Kubernetes Secrets are the runtime copy.

### 3. Local application runtime

Use `langgraph dev` inside a single control-plane Pod:

```bash
langgraph dev \
  --host 0.0.0.0 \
  --port 2024 \
  --no-browser \
  --no-reload
```

Set:

```text
LANGSMITH_TRACING=false
LANGGRAPH_CLI_NO_ANALYTICS=1
SANDBOX_TYPE=k3
```

Mount a PVC at the working directory’s `.langgraph_api` path so local checkpoints, memory, assistants, threads, runs, crons, and store data survive Pod and cluster restarts.

This is a single-process development runtime. Do not scale it beyond one replica or claim production durability. A future production deployment must deliberately replace it with a supported persistent Agent Server shape and its required backing services/licensing.

### 4. Images

Build the current checkout, not published images.

Create three independently tagged images:

1. **Control plane:** project Python dependencies, source, and the LangGraph/FastAPI runtime.
2. **UI:** pinned Node/pnpm build followed by the documented Nitro Node runtime output.
3. **Sandbox:** the existing tool-rich sandbox image.

Use deterministic tags derived from source/build inputs and skip unchanged builds. Import images with `k3d image import` into the selected cluster. Never use `latest` as the deployed identity.

The UI image build must prove the exact Nitro output path and production start command against the lockfile. The current dependency on Nitro’s active-development Vite integration makes this a required packaging test.

The sandbox image may contain the Docker CLI, but no daemon or host socket is supplied. Attempts to run nested containers must fail clearly and are not supported in milestone 1.

### 5. Helm topology

Add a repo-local Helm chart that owns application reconciliation, not host cluster creation or `.env` editing.

Use:

```bash
helm upgrade --install --atomic --wait --timeout ...
```

The chart contains:

- `open-swe-system` and `open-swe-sandboxes` namespaces or equivalent explicitly managed namespace setup.
- Control-plane Deployment, Service, PVC, ConfigMap, Secret references, probes, and one replica.
- UI Deployment and Service.
- Traefik Ingress routes that expose one localhost origin.
- Dedicated credential-proxy Deployment, Service, configuration, CA/runtime Secrets, and network policy.
- Namespace-scoped RBAC for sandbox Pod/PVC lifecycle and `pods/exec`.
- Sandbox ingress/egress NetworkPolicies.
- Cleanup CronJob/controller and its narrow RBAC.
- Resource requests/limits and configurable storage sizes.

The k3d config exposes the embedded Traefik load balancer’s HTTP port to the persisted localhost port.

### 6. Single-origin routing

Deploy UI and backend separately but expose one browser origin.

At minimum, route backend-owned paths such as dashboard APIs, webhooks, graph APIs, streaming endpoints, health endpoints, and WebSocket upgrades to the control plane. Route UI/navigation paths to the Nitro server.

The same-origin design is required for cookies, GitHub OAuth redirects, streaming, and avoiding CORS configuration drift.

### 7. `k3` sandbox provider

Add `k3` to `SANDBOX_FACTORIES` and implement the existing `SandboxBackendProtocol` behind the current provider seam.

A sandbox ID identifies a stable thread workspace. For each thread:

- Create one Pod and one PVC in the sandbox namespace.
- Mount the PVC at `/workspace` and `/root` using stable subpaths or an equivalent layout.
- Persist the sandbox ID in existing LangGraph thread metadata.
- Reconnect by sandbox ID after control-plane restart.
- If the Pod is gone but its PVC remains, recreate the Pod and reattach the PVC.
- If both are gone, follow existing sandbox-recreation behavior and update metadata.
- Reapply Git identity, proxy trust/configuration, and baseline setup after every recreation.

System-level filesystem mutations, including `apt install`, are disposable. `/workspace` and `/root` persist; the rest of the container filesystem does not.

#### Security context

The sandbox process runs as root inside the container for toolchain compatibility, but the Pod must:

- Set `allowPrivilegeEscalation: false`.
- Drop all Linux capabilities.
- Use RuntimeDefault seccomp.
- Disable service-account token automounting.
- Avoid privileged mode, host networking, host PID/IPC, host paths, and Docker sockets.
- Receive no Kubernetes credentials and no real GitHub credentials.

#### Execution and file transport

Use the Kubernetes API’s Pod exec transport, not SSH or a custom per-Pod daemon. File upload/download uses binary-safe tar streams over exec.

This design is blocked on Spike A below.

#### Backpressure

Default to two active sandbox Pods.

- Serialize provisioning decisions in the single control-plane replica.
- Queue additional creation requests with visible state and a bounded configurable timeout.
- Never leave users with an unexplained Pending Pod or indefinite request.
- Make concurrency and per-sandbox CPU/memory configurable.
- Reconstruct capacity from Kubernetes state after control-plane restart.

### 8. Sandbox lifecycle

Track last use on every execute/upload/download/reconnect operation.

Defaults:

- Delete idle sandbox compute Pods after 1 hour when no operation lease is active.
- Retain the thread PVC for 30 days.
- Reconnecting during the retention window recreates the Pod on the existing PVC.
- Delete expired PVCs only after the thread-aligned retention window.

Cleanup must be race-safe with active operations. Both durations are configurable.

### 9. GitHub credential proxy

Real GitHub tokens remain in the trusted control plane/encrypted store and credential service. They must never appear in sandbox environment variables, files, process arguments, command output, or proxy responses.

Use a dedicated, namespace-isolated gateway rather than Istio. The intended shape is:

- A proxy-controlled CA trusted by sandbox Pods.
- Interception/termination for the exact GitHub hosts needed by `git` and `gh`.
- TLS origination from proxy to GitHub.
- Per-sandbox proxy identity that is not itself a GitHub credential.
- Server-side authorization injection.
- Repository/permission scope preservation where the upstream token type supports it.
- Token refresh without recreating the sandbox.
- No public proxy exposure.
- NetworkPolicy allowing sandbox Pods to reach only DNS, the proxy, and the public internet—not internal control-plane/store services.

The exact Envoy/custom credential-service protocol is blocked on Spike B below.

After dashboard OAuth login, onboarding must validate the real path by exercising authenticated GitHub access through a disposable sandbox. Startup itself tests proxy routing, identity isolation, and header injection against a local test upstream, avoiding a redundant PAT.

### 10. Network isolation

K3s’ network-policy controller must remain enabled. The installer smoke test must prove policy enforcement rather than assuming that creating `NetworkPolicy` objects is sufficient.

Sandbox policy:

- Default-deny ingress.
- Default-deny cluster egress.
- Explicit DNS egress.
- Explicit credential-proxy egress.
- Internet egress required for package managers and project dependencies.
- No direct access to Kubernetes API, control plane, UI, graph store, or other sandbox Pods.

Internet egress is not a data-loss-prevention boundary; arbitrary code can still send non-secret workspace data outward. The protected boundary is control-plane and reusable credential isolation.

## Mandatory pre-implementation spikes

### Spike A: Kubernetes exec transport

Prove the pinned Kubernetes Python client and k3s versions satisfy the sandbox protocol.

Acceptance:

- Correct stdout/stderr separation.
- Reliable exit status for success, non-zero exit, signal termination, and missing executable.
- Server-side timeout and cancellation without leaked processes or websocket sessions.
- Concurrent commands against one Pod and multiple Pods.
- Binary-safe upload/download, empty files, large files, directories, permissions, and traversal rejection.
- Reconnect after backend/control-plane restart.
- Clear normalization into existing `ExecuteResponse` and file response types.

If the protocol cannot be met reliably, stop and compare a small authenticated sidecar design before continuing.

### Spike B: GitHub credential proxy

Prove compatibility and secret isolation for both Git smart HTTP and GitHub CLI.

Acceptance:

- `git clone`, fetch, push, and credential failure behavior.
- `GH_TOKEN=dummy gh api`, repository reads, and a safe write against a disposable test repository.
- Correct operation for `github.com` and `api.github.com` without changing repository identity.
- Upstream authorization is injected only for approved hosts/routes.
- The real token is absent from sandbox env, filesystem, process table, packet-visible plaintext, logs, errors, and responses.
- Per-sandbox identity and repository/permission scope are enforced.
- Expired GitHub tokens refresh without Pod recreation.
- One sandbox cannot use another sandbox’s proxy identity.
- Proxy restart and control-plane restart recover safely.

If this fails, do not fall back silently to mounting a GitHub token. Re-open the security design.

## Functional smoke gates

`make start-k3` succeeds only after all of the following pass:

1. Expected Helm release and workloads are Ready.
2. UI returns expected content through the persisted localhost URL.
3. Backend `/ok` and graph metadata are available through the same origin.
4. Local graph state can be written, read, and observed after a control-plane Pod restart.
5. A sandbox can be created, command-executed, file-uploaded, file-downloaded, deleted, and reconnected to its PVC.
6. Capacity/backpressure reports a bounded queue rather than hanging.
7. Sandbox NetworkPolicy blocks control-plane and cross-sandbox access while allowing DNS, proxy, and internet egress.
8. Proxy infrastructure passes its local non-GitHub secret-injection/isolation test.
9. Logs and diagnostics contain no configured secrets.

A post-login onboarding gate then verifies:

1. GitHub OAuth/app installation access.
2. Authenticated GitHub operations through the sandbox proxy.
3. The configured OpenAI credential and selected default model.

No startup smoke test creates a PR or spends model tokens.

## Delivery plan

### Milestone 0: Retire architecture risks

1. Pin candidate k3s, k3d, Kubernetes Python client, Helm, and tool versions.
2. Complete Spike A.
3. Complete Spike B.
4. Record results and amend this plan before implementation if either spike changes an interface.

**Gate:** Both spikes pass; no real GitHub credential is observable in a sandbox.

### Milestone 1: Local cluster and application shell

1. Add mise configuration and lockfile.
2. Add the Python installer and Make lifecycle targets.
3. Add control-plane and UI container builds.
4. Add the Helm chart for UI, local LangGraph runtime, storage, ingress, probes, and secrets.
5. Implement `.env` prompting, generated secrets, strict non-interactive behavior, and credential checks.
6. Prove one-origin UI/API operation and persisted `.langgraph_api` state.

**Gate:** Fresh and repeated `make start-k3` runs pass without sandbox support and without state loss.

### Milestone 2: K3 sandbox runtime

1. Add the `k3` provider and startup validation.
2. Implement Pod/PVC creation, reconnect, exec, and file transfer.
3. Add hardened Pod specs, namespace RBAC, network policies, and policy enforcement tests.
4. Implement bounded queueing and resource configuration.
5. Implement idle Pod and PVC retention cleanup.
6. Extend startup smoke to cover sandbox lifecycle and persistence.

**Gate:** Core sandbox contract, recovery tests, policy tests, and real k3d integration tests pass.

### Milestone 3: Credential boundary and onboarding

1. Productize the accepted Spike B proxy design.
2. Integrate token provisioning/refresh with sandbox creation and existing user token resolution.
3. Install proxy CA/config without exposing the upstream token.
4. Add post-login GitHub validation and actionable UI failures.
5. Add cross-sandbox and secret-leak regression tests.

**Gate:** Git and `gh` workflows pass end to end; adversarial tests cannot recover the real credential.

### Milestone 4: End-to-end quality and documentation

1. Add the full non-interactive k3d smoke workflow for Linux amd64 CI.
2. Add unit/image-build checks on available Linux/macOS amd64/arm64 runners.
3. Record manual full-smoke evidence for unsupported CI matrix cells.
4. Add upgrade-drift detection; never auto-destroy an existing cluster.
5. Document first-run GitHub setup, supported limits, troubleshooting, logs, stop/destroy semantics, and data locations.
6. Document the future production delta: persistent supported Agent Server, Postgres/Redis, licensed or alternative runtime decision, external secret management, TLS/public ingress, backups, HA, observability, and optional dedicated sandbox cluster.

**Gate:** All functional smoke gates pass, lifecycle docs reproduce from a clean host, and support claims have recorded evidence.

## Test strategy

### Unit tests

- Installer preflight, prompt graph, `.env` merge, file permissions, redaction, non-TTY behavior, port persistence, command failure reporting, and version drift.
- Helm values generation without secret leakage.
- K3 resource naming, idempotency, status transitions, queue timeout, lifecycle annotations, and cleanup races.
- Sandbox response normalization and path safety.
- Credential-proxy routing, identity, scope, refresh, and redaction.

### Integration tests

- Real k3d cluster creation/reuse/stop with pinned versions.
- Helm fresh install, no-op reconcile, image update, failed atomic upgrade, and state-preserving restart.
- Pod exec/file transport contract.
- PVC reconnect after Pod and control-plane restart.
- Enforced network isolation.
- Proxy tests against a local upstream plus disposable GitHub resources where secrets are available.

### End-to-end tests

- Clean non-interactive install with fixture credentials and live credential checks explicitly skipped.
- Functional startup smoke.
- Idempotent second start.
- Dirty-source image rebuild and unchanged-source cache hit.
- Stop/start state preservation.
- Explicit destroy confirmation and expected state loss.

## Failure and upgrade behavior

- Preflight and credential failures happen before cluster mutation.
- Image-build failures leave the previous Helm release running.
- Helm uses atomic rollback and retains diagnostic output.
- Smoke failure returns non-zero, prints focused status/log commands, and keeps the cluster for inspection.
- `start-k3` never deletes a cluster, PVC, `.env`, or local config.
- Detect pinned k3s version drift. Continue only when declared compatible; otherwise stop with explicit export/destroy/recreate guidance.
- Destructive commands require explicit confirmation and state exactly what will be lost.

## Documentation validation record

### Confirmed

- k3d supports load-balancer port mappings and image import into a selected cluster:
  - https://k3d.io/stable/usage/exposing_services/
  - https://k3d.io/stable/usage/commands/k3d_image_import/
- mise’s registry includes k3d, kubectl, and Helm; explicit backends and a lockfile provide deterministic tool resolution:
  - https://mise.jdx.dev/registry.html
  - https://mise.jdx.dev/dev-tools/backends/aqua.html
- Helm `--atomic` implies waiting and rolls back/purges failed releases:
  - https://helm.sh/docs/helm/helm_upgrade
  - https://helm.sh/docs/helm/helm_install
- Kubernetes exec uses the stream transport, and tar-based copy requires `tar` in the container:
  - https://github.com/kubernetes-client/python/blob/master/examples/pod_exec.py
  - https://kubernetes.io/docs/reference/kubectl/generated/kubectl_cp/
- Kubernetes NetworkPolicies require an enforcing network plugin, and default-deny egress also requires an explicit DNS allowance:
  - https://kubernetes.io/docs/concepts/services-networking/network-policies/
- K3s includes an enabled network-policy controller by default:
  - https://docs.k3s.io/networking/networking-services
- TanStack Start supports a Nitro/Node deployment shape, while the Vite integration is still actively developed:
  - https://tanstack.com/start/latest/docs/framework/react/guide/hosting

### Corrected during grilling

The initial assumption that any fully local LangGraph runtime required `LANGGRAPH_CLOUD_LICENSE_KEY` was too broad.

- The production-ready standalone Agent Server does require a LangSmith API key, LangGraph license key, Postgres, Redis, and license egress:
  - https://docs.langchain.com/langsmith/deploy-standalone-server
- The local `langgraph dev` server persists state under `.langgraph_api`; with tracing and CLI analytics disabled, it can operate locally without sending application data to LangSmith:
  - https://docs.langchain.com/langsmith/data-storage-and-privacy#in-memory-development-server
  - https://docs.langchain.com/langsmith/local-dev-testing#langgraph-dev

The POC therefore uses `langgraph dev` and explicitly accepts its development-only limitations.

### Spike validation

Both mandatory spikes passed with the pinned local runtime. Kubernetes exec, cancellation, concurrency, file transport, and restart recovery are enforced by the functional startup gate. The credential proxy passed synthetic CONNECT/TLS isolation checks and live disposable-repository Git/`gh` validation without exposing the real token to sandbox-visible state. Evidence and the rejected shared-API-client transport are recorded in `K3_SPIKE_RESULTS.md`.

## Future production direction

Keep the Helm chart and provider boundaries reusable, but do not disguise the local POC as production-ready.

A production design must revisit:

- Supported persistent Agent Server and licensing/runtime choice.
- Managed or highly available Postgres/Redis where applicable.
- External secret manager and encrypted storage.
- Public TLS ingress, webhooks, and OAuth callback management.
- Backups, restores, migrations, and disaster recovery.
- Observability, audit logs, quotas, and SLOs.
- Dedicated sandbox nodes or a separate sandbox cluster.
- Stronger multi-tenant identity and policy enforcement.
- Rootless nested-container capability, if required.
- Generic Kubernetes provider naming versus the POC’s accepted `k3` provider name.
