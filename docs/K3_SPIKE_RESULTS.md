# K3 runtime spike results

**Validated:** 2026-07-20  
**Environment:** Linux amd64, k3d 5.8.3, k3s v1.32.3-k3s1, Kubernetes Python client 32.0.1

## Spike A — Kubernetes exec and file transport

The `make start-k3` functional gate ran against the pinned real k3d cluster and passed:

- independent stdout/stderr channels and reliable status for success, exit 7, missing executable (127), SIGTERM (143), and timeout (124);
- server-side timeout cleanup with no remaining marked process;
- concurrent commands against one Pod and two Pods;
- empty and 1 MiB binary uploads/downloads, directory handling, mode preservation, and traversal rejection;
- bounded capacity timeout;
- Pod deletion followed by PVC reattachment;
- backend/control-plane restart followed by the same sandbox ID and persisted-file read;
- protocol response normalization.

The implementation uses a fresh Kubernetes API client for each exec websocket. Sharing the API client caused a reproducible HTTP/websocket protocol race under concurrent exec and was rejected.

## Spike B — GitHub credential proxy

The startup gate passed the real proxy CONNECT/TLS path with a synthetic credential, source isolation, repository denial, public-host forwarding, internal-host denial, and log/event redaction.

A live disposable private repository test then passed with the host's authenticated GitHub OAuth token encrypted over the proxy admin channel:

- `GH_TOKEN=dummy gh api user`;
- repository-scoped REST read and denied out-of-scope repository read;
- HTTPS `git clone`, commit, and push;
- safe issue creation;
- a second unregistered sandbox denied access;
- credential replacement without Pod recreation;
- proxy restart failed closed, then recovered on trusted re-registration without Pod recreation;
- no real-token prefix in sandbox environment, process arguments, `/workspace`, `/root`, `/tmp`, or proxy logs.

The disposable repository was archived after validation: `jrgifford/open-swe-k3-proxy-spike-90fc3096`. The available OAuth token intentionally lacked GitHub's separate `delete_repo` scope, so permanent deletion remains a manual GitHub cleanup action.

## Runtime evidence

Fresh install, repeated `make start-k3`, and stop/start all passed. The persisted URL was loopback-only (`127.0.0.1:13000` in this validation run), Helm reported `deployed`, UI and all five graph assistants were reachable through the same origin, graph/thread state survived control-plane restarts, NetworkPolicy blocked control-plane and cross-sandbox access, and the cleanup CronJob completed with its restricted service account.
