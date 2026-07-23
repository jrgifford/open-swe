"""Kubernetes sandbox backend.

Runs each Open SWE task in a dedicated pod on your own cluster instead of a
managed cloud provider. Unlike the LangSmith/E2B/Daytona integrations there is
no `langchain_<provider>` wrapper class to lean on, so this extends
`BaseSandbox` from ``deepagents`` directly: it implements the shell-execution
primitive (`execute`) plus file transfer (`upload_files`/`download_files`) and
lets the base class derive `ls`/`read`/`write`/`edit`/`glob`/`grep` on top.

Configuration (all via environment variables):

    SANDBOX_TYPE="k8s"                      Select this backend.
    K8S_SANDBOX_IMAGE=<registry>/<image>    REQUIRED. Sandbox image, typically
                                            built from this repo's Dockerfile.
    K8S_SANDBOX_NAMESPACE="open-swe"        Namespace for sandbox pods.
    K8S_SANDBOX_RUNTIME_CLASS=""            Optional RuntimeClass (e.g. "kata"
                                            or "gvisor") for VM/sandboxed
                                            isolation of untrusted code.
    K8S_SANDBOX_CPU="4"                     CPU request/limit (cores).
    K8S_SANDBOX_MEMORY="8Gi"                Memory request/limit.
    K8S_SANDBOX_SERVICE_ACCOUNT=""          Optional pod serviceAccountName.
    K8S_SANDBOX_IMAGE_PULL_SECRET=""        Optional imagePullSecret name.
    K8S_SANDBOX_STARTUP_TIMEOUT="180"       Seconds to wait for pod Ready.
    K8S_SANDBOX_DEFAULT_EXEC_TIMEOUT="300"  Default per-command timeout (s).
    K8S_SANDBOX_WORKDIR="/workspace"        Working directory inside the pod.
    K8S_SANDBOX_ACTIVE_DEADLINE="3600"      Pod activeDeadlineSeconds — a hard
                                            wall-clock cap after which Kubernetes
                                            self-terminates the pod. Defence in
                                            depth against orphaned sandboxes; set
                                            to 0 to disable.
    K8S_SANDBOX_ENABLE_GH_PROXY="false"     Opt-in: run an egress-auth-proxy
                                            sidecar so git/gh authenticate via a
                                            MITM proxy and the GitHub token never
                                            enters the sandbox. See
                                            utils/k8s_github_proxy.py.
    K8S_SANDBOX_GH_PROXY_IMAGE=<img>        REQUIRED when the proxy is enabled:
                                            the egress-auth-proxy image.
    K8S_SANDBOX_GH_PROXY_CONTROL_API_KEY="" Shared key the agent server uses to
                                            PATCH the sidecar control plane; also
                                            injected into the sidecar. Empty ->
                                            sidecar runs with auth disabled.
    K8S_SANDBOX_GH_PROXY_DATA_PORT="8080"   Sidecar data-plane (proxy) port.
    K8S_SANDBOX_GH_PROXY_CONTROL_PORT="8081" Sidecar control-plane (config) port.

Auth resolves in-cluster config first (when the agent server itself runs as a
pod), then falls back to the local kubeconfig for development.
"""

from __future__ import annotations

import base64
import logging
import os
import uuid

from deepagents.backends.protocol import (
    ExecuteResponse,
    FileDownloadResponse,
    FileUploadResponse,
)
from deepagents.backends.sandbox import BaseSandbox
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL

logger = logging.getLogger(__name__)

_LABEL_APP = "open-swe-sandbox"
_LABEL_ID = "open-swe.langchain.com/sandbox-id"
_SANDBOX_CONTAINER = "sandbox"


def _env(name: str, default: str) -> str:
    value = os.getenv(name, default).strip()
    return value or default


def _load_kube_config() -> None:
    """Load in-cluster config when running as a pod, else local kubeconfig."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


class K8sSandbox(BaseSandbox):
    """A sandbox backed by a single long-lived Kubernetes pod.

    The pod runs ``sleep infinity`` as PID 1; every `execute` opens a fresh
    exec session against it. File transfer is done by piping base64 over an
    exec stdin/stdout stream, which avoids depending on the `kubectl` binary or
    a tar implementation being present in the agent server image.
    """

    # Base64 pipe + coreutils are stable on the Debian-derived sandbox image, so
    # opt into the base class's capture-at-source offload for large output.
    enable_capture_offload = True

    def __init__(self, api: client.CoreV1Api, namespace: str, pod_name: str):
        self._api = api
        self._namespace = namespace
        self._pod_name = pod_name
        self._default_timeout = int(_env("K8S_SANDBOX_DEFAULT_EXEC_TIMEOUT", "300"))

    @property
    def id(self) -> str:
        return self._pod_name

    # -- shell execution -----------------------------------------------------

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        effective_timeout = self._default_timeout if timeout is None else timeout
        # Merge stderr into stdout for a single combined stream (matches the
        # `output` contract), and enforce the budget in-pod with coreutils
        # `timeout` so a hung command can't wedge the exec session forever.
        # `timeout 0` disables the limit, mirroring the protocol's semantics.
        wrapped = f"{command} 2>&1"
        if effective_timeout and effective_timeout > 0:
            wrapped = f"timeout {effective_timeout}s /bin/sh -c {_shquote(wrapped)}"
        read_timeout = (
            (effective_timeout + 15) if effective_timeout and effective_timeout > 0 else None
        )
        output, exit_code = self._run(["/bin/sh", "-c", wrapped], read_timeout=read_timeout)
        return ExecuteResponse(output=output, exit_code=exit_code, truncated=False)

    def _run(self, argv: list[str], *, read_timeout: int | None = None) -> tuple[str, int | None]:
        """Open an exec session (no stdin), drive it to completion.

        Returns combined stdout+error-channel output and the numeric exit code.
        stdin is intentionally unused: the k8s ws client has no clean stdin-EOF
        frame, so any input a command needs is embedded in ``argv`` instead.
        """
        resp = stream(
            self._api.connect_get_namespaced_pod_exec,
            self._pod_name,
            self._namespace,
            # Explicit: with a dind sidecar the pod has >1 container, and the API
            # rejects an exec that doesn't name one. Always the sandbox container.
            container=_SANDBOX_CONTAINER,
            command=argv,
            stderr=True,
            stdout=True,
            stdin=False,
            tty=False,
            _preload_content=False,
        )
        chunks: list[str] = []
        resp.run_forever(
            timeout=read_timeout if read_timeout is not None else self._default_timeout + 15
        )
        while resp.peek_stdout():
            chunks.append(resp.read_stdout())
        while resp.peek_stderr():
            # stderr was merged via 2>&1, but drain the channel defensively.
            chunks.append(resp.read_stderr())
        exit_code = _exit_code_from_error_channel(resp)
        resp.close()
        return "".join(chunks), exit_code

    # -- file transfer -------------------------------------------------------

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        responses: list[FileUploadResponse] = []
        for path, content in files:
            try:
                parent = os.path.dirname(path) or "."
                encoded = base64.b64encode(content).decode("ascii")
                # Embed the payload in argv (piped through base64 -d) rather than
                # streaming over stdin, which the k8s ws client can't cleanly
                # half-close. Total argv is bounded by ARG_MAX (~2 MiB on Linux),
                # so base64 inflation caps single-file writes at ~1.5 MiB — ample
                # for source/config files. Chunked writes would lift this if a
                # workload ever needs to land larger blobs.
                cmd = (
                    f"mkdir -p {_shquote(parent)} && "
                    f"printf %s {_shquote(encoded)} | base64 -d > {_shquote(path)}"
                )
                _, exit_code = self._run(["/bin/sh", "-c", cmd])
                if exit_code not in (0, None):
                    responses.append(FileUploadResponse(path=path, error=f"exit_code={exit_code}"))
                else:
                    responses.append(FileUploadResponse(path=path, error=None))
            except Exception as exc:  # noqa: BLE001 - protocol requires per-file capture
                logger.warning("k8s sandbox upload failed for %s: %s", path, exc)
                responses.append(FileUploadResponse(path=path, error=str(exc)))
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        responses: list[FileDownloadResponse] = []
        for path in paths:
            try:
                # base64-encode in-pod so arbitrary binary survives the text
                # channel; a missing file yields non-zero exit and empty stdout.
                output, exit_code = self._run(["/bin/sh", "-c", f"base64 {_shquote(path)}"])
                if exit_code not in (0, None):
                    responses.append(
                        FileDownloadResponse(path=path, content=None, error="file_not_found")
                    )
                    continue
                content = base64.b64decode(output.encode("ascii"))
                responses.append(FileDownloadResponse(path=path, content=content, error=None))
            except Exception as exc:  # noqa: BLE001 - protocol requires per-file capture
                logger.warning("k8s sandbox download failed for %s: %s", path, exc)
                responses.append(FileDownloadResponse(path=path, content=None, error=str(exc)))
        return responses


def _shquote(s: str) -> str:
    """POSIX single-quote a string for safe embedding in `sh -c`."""
    return "'" + s.replace("'", "'\\''") + "'"


def _exit_code_from_error_channel(resp) -> int | None:
    """Parse the exec error channel (channel 3) into a numeric exit code.

    Kubernetes reports command status as a v1.Status object on the error
    channel: ``Success`` -> 0; a ``NonZeroExitCode`` cause carries the real
    code. Returns None when the status can't be parsed.
    """
    try:
        err = resp.read_channel(ERROR_CHANNEL)
    except Exception:  # noqa: BLE001
        return None
    if not err:
        return 0
    try:
        import json

        status = json.loads(err)
    except (ValueError, TypeError):
        return None
    if status.get("status") == "Success":
        return 0
    for cause in status.get("details", {}).get("causes", []):
        if cause.get("reason") == "ExitCode":
            try:
                return int(cause.get("message"))
            except (TypeError, ValueError):
                return 1
    # Non-success status with no explicit code -> generic failure.
    return 1


def _build_pod_manifest(pod_name: str) -> client.V1Pod:
    image = os.getenv("K8S_SANDBOX_IMAGE", "").strip()
    if not image:
        raise ValueError("K8S_SANDBOX_IMAGE environment variable is required for SANDBOX_TYPE=k8s")

    workdir = _env("K8S_SANDBOX_WORKDIR", "/workspace")
    cpu = _env("K8S_SANDBOX_CPU", "4")
    memory = _env("K8S_SANDBOX_MEMORY", "8Gi")
    runtime_class = os.getenv("K8S_SANDBOX_RUNTIME_CLASS", "").strip() or None
    service_account = os.getenv("K8S_SANDBOX_SERVICE_ACCOUNT", "").strip() or None
    pull_secret = os.getenv("K8S_SANDBOX_IMAGE_PULL_SECRET", "").strip() or None
    enable_dind = _env("K8S_SANDBOX_ENABLE_DIND", "false").lower() in ("1", "true", "yes")

    # Requests are what the scheduler reserves; limits are the burst ceiling.
    # A sandbox is mostly idle between execs, so reserve little (packs many
    # sandboxes on one node) while still allowing bursts up to CPU/MEMORY.
    resources = client.V1ResourceRequirements(
        requests={
            "cpu": _env("K8S_SANDBOX_CPU_REQUEST", "250m"),
            "memory": _env("K8S_SANDBOX_MEMORY_REQUEST", "512Mi"),
        },
        limits={"cpu": cpu, "memory": memory},
    )

    sandbox_env: list[client.V1EnvVar] = []
    sandbox_mounts: list[client.V1VolumeMount] = []
    volumes: list[client.V1Volume] = []
    sidecars: list[client.V1Container] = []
    init_containers: list[client.V1Container] = []
    # Keep PID 1 alive so the pod stays around for repeated exec sessions;
    # `wait` lets a TERM propagate for a clean shutdown. The GitHub-proxy path
    # below prepends a one-shot CA install to this.
    sandbox_command = ["/bin/sh", "-c", "trap 'exit 0' TERM INT; sleep infinity & wait"]

    if enable_dind:
        # Docker-in-Docker: a privileged sidecar runs dockerd; the sandbox's
        # docker CLI reaches it over the shared pod network (localhost:2375).
        # /workspace is a shared emptyDir so `docker build` context AND
        # `docker run -v` bind mounts of sandbox files resolve on the daemon side.
        # SECURITY: the dind sidecar is privileged (node-escape surface for
        # untrusted agent code). Pair with K8S_SANDBOX_RUNTIME_CLASS=kata/gvisor
        # to contain it. Opt-in via K8S_SANDBOX_ENABLE_DIND.
        volumes.append(client.V1Volume(name="workspace", empty_dir=client.V1EmptyDirVolumeSource()))
        dind_disk = _env("K8S_SANDBOX_DIND_DISK", "20Gi")
        # Backing store for the docker layer store. /var/lib/docker cannot be a
        # plain emptyDir here: under a microVM RuntimeClass (kata) an emptyDir is
        # shared into the guest via virtio-fs, and overlayfs cannot mount on
        # virtio-fs -> buildkit's overlay snapshotter dies with
        # "mount overlay ... invalid argument" and every `docker build` fails.
        # Instead we mount this emptyDir at /dind-img; the dind entrypoint (below)
        # puts a loop-backed ext4 on a file inside it and mounts THAT at
        # /var/lib/docker, giving overlay a real block-backed filesystem in the
        # guest (fast overlay2). The emptyDir sizeLimit bounds the backing file,
        # so a runaway build evicts this pod instead of filling the node.
        volumes.append(
            client.V1Volume(
                name="dind-img",
                empty_dir=client.V1EmptyDirVolumeSource(size_limit=dind_disk),
            )
        )
        sandbox_mounts.append(client.V1VolumeMount(name="workspace", mount_path=workdir))
        sandbox_env.append(client.V1EnvVar(name="DOCKER_HOST", value="tcp://127.0.0.1:2375"))
        dind_image = _env(
            "K8S_SANDBOX_DIND_IMAGE",
            "zot.tail48c2e7.ts.net/proxy-dockerio/library/docker:dind",
        )
        sidecars.append(
            client.V1Container(
                name="dind",
                image=dind_image,
                security_context=client.V1SecurityContext(privileged=True),
                env=[client.V1EnvVar(name="DOCKER_TLS_CERTDIR", value="")],
                command=["/bin/sh", "-c"],
                args=[
                    # Put a loop-backed ext4 on the /dind-img backing file and
                    # mount it at /var/lib/docker BEFORE starting dockerd. The
                    # kata guest kernel has the loop driver built in but no device
                    # nodes (privileged_without_host_devices strips host /dev/* in
                    # the microVM), so mknod them first. overlayfs can't mount on
                    # the virtio-fs a plain emptyDir provides, but works fine on
                    # this real block-backed ext4 -> fast overlay2 builds under
                    # kata. Then hand off to the normal dind entrypoint. Loopback-
                    # only binds keep the privileged docker API off the cluster
                    # network; --tls=false skips the ~15s non-loopback-TLS sleep.
                    "set -e; "
                    "[ -e /dev/loop-control ] || mknod /dev/loop-control c 10 237; "
                    "for i in $(seq 0 7); do [ -e /dev/loop$i ] || mknod /dev/loop$i b 7 $i; done; "
                    "if ! grep -q ' /var/lib/docker ' /proc/mounts; then "
                    f"truncate -s {dind_disk} /dind-img/docker.img; "
                    "losetup /dev/loop0 /dind-img/docker.img; "
                    "mkfs.ext4 -qF /dev/loop0; "
                    "mkdir -p /var/lib/docker; mount /dev/loop0 /var/lib/docker; "
                    "fi; "
                    "exec dockerd-entrypoint.sh dockerd "
                    "--host=unix:///var/run/docker.sock --host=tcp://127.0.0.1:2375 "
                    "--tls=false --storage-driver=overlay2"
                ],
                # Gate pod-Ready on dockerd actually serving. Must be an EXEC
                # probe (run inside the container): a TCP probe hits the pod IP,
                # which can't reach the loopback-bound daemon. Checks the exact
                # endpoint the sandbox uses.
                readiness_probe=client.V1Probe(
                    _exec=client.V1ExecAction(
                        command=["docker", "-H", "tcp://127.0.0.1:2375", "version"],
                    ),
                    period_seconds=2,
                    failure_threshold=45,
                ),
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "250m", "memory": "512Mi"},
                    limits={
                        "cpu": _env("K8S_SANDBOX_DIND_CPU", "2"),
                        "memory": _env("K8S_SANDBOX_DIND_MEMORY", "4Gi"),
                    },
                ),
                volume_mounts=[
                    client.V1VolumeMount(name="workspace", mount_path=workdir),
                    client.V1VolumeMount(name="dind-img", mount_path="/dind-img"),
                ],
            )
        )

    enable_gh_proxy = _env("K8S_SANDBOX_ENABLE_GH_PROXY", "false").lower() in ("1", "true", "yes")
    if enable_gh_proxy:
        # egress-auth-proxy sidecar (LangSmith-compatible): git/gh in the sandbox
        # make credential-free requests through a MITM proxy that injects the
        # GitHub token on the wire, so the token never lands in the sandbox
        # container's filesystem or env. The agent server configures per-run
        # github rules against the sidecar's control plane (see
        # utils/k8s_github_proxy.py). Opt-in via K8S_SANDBOX_ENABLE_GH_PROXY.
        proxy_image = os.getenv("K8S_SANDBOX_GH_PROXY_IMAGE", "").strip()
        if not proxy_image:
            raise ValueError(
                "K8S_SANDBOX_GH_PROXY_IMAGE is required when K8S_SANDBOX_ENABLE_GH_PROXY is set"
            )
        proxy_api_key = os.getenv("K8S_SANDBOX_GH_PROXY_CONTROL_API_KEY", "").strip()
        certs_dir = "/certs"
        ca_cert = f"{certs_dir}/mitmproxy-ca-cert.pem"
        data_port = _env("K8S_SANDBOX_GH_PROXY_DATA_PORT", "8080")
        control_port = _env("K8S_SANDBOX_GH_PROXY_CONTROL_PORT", "8081")

        volumes.append(
            client.V1Volume(name="gh-proxy-certs", empty_dir=client.V1EmptyDirVolumeSource())
        )
        certs_mount = client.V1VolumeMount(name="gh-proxy-certs", mount_path=certs_dir)

        # Init container: generate a per-pod, ephemeral MITM CA into the shared
        # volume using mitmproxy's own generator (guaranteed compatible with the
        # sidecar). Runs as root so the root-owned emptyDir is writable and the
        # CA key it writes stays readable by the root sidecar + sandbox.
        init_containers.append(
            client.V1Container(
                name="gh-proxy-ca-init",
                image=proxy_image,
                security_context=client.V1SecurityContext(run_as_user=0),
                command=["/bin/sh", "-c"],
                args=[
                    "mitmdump --set confdir=/certs --listen-host 127.0.0.1 "
                    "--listen-port 8080 >/dev/null 2>&1 & p=$!; "
                    "for _ in $(seq 1 100); do [ -f /certs/mitmproxy-ca-cert.pem ] && break; "
                    'sleep 0.1; done; kill "$p" 2>/dev/null; '
                    "test -f /certs/mitmproxy-ca-cert.pem"
                ],
                volume_mounts=[certs_mount],
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "50m", "memory": "96Mi"},
                    limits={"cpu": "500m", "memory": "256Mi"},
                ),
            )
        )

        proxy_env = [
            client.V1EnvVar(name="EAP_CONFDIR", value=certs_dir),
            client.V1EnvVar(name="EAP_DATA_HOST", value="127.0.0.1"),
            client.V1EnvVar(name="EAP_DATA_PORT", value=data_port),
            client.V1EnvVar(name="EAP_CONTROL_HOST", value="0.0.0.0"),
            client.V1EnvVar(name="EAP_CONTROL_PORT", value=control_port),
        ]
        if proxy_api_key:
            proxy_env.append(client.V1EnvVar(name="EAP_CONTROL_API_KEY", value=proxy_api_key))
        else:
            # No key configured (dev): let the sidecar still start.
            proxy_env.append(client.V1EnvVar(name="EAP_ALLOW_NO_AUTH", value="true"))
        # Sidecar: data plane on loopback (shared pod netns → only the sandbox
        # container can route through it); control plane on the pod IP so the
        # agent server can PATCH github rules. Runs as root to read the CA key.
        sidecars.append(
            client.V1Container(
                name="gh-proxy",
                image=proxy_image,
                security_context=client.V1SecurityContext(run_as_user=0),
                env=proxy_env,
                volume_mounts=[certs_mount],
                readiness_probe=client.V1Probe(
                    http_get=client.V1HTTPGetAction(path="/healthz", port=int(control_port)),
                    period_seconds=2,
                    failure_threshold=30,
                ),
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "50m", "memory": "128Mi"},
                    limits={"cpu": "1", "memory": "512Mi"},
                ),
            )
        )

        # Route sandbox egress through the proxy and trust its CA. The proxy
        # MITMs all TLS, so the sandbox only needs this CA; it is added
        # additively (system store + node/python/git bundles) alongside the
        # system roots rather than replacing them.
        proxy_url = f"http://127.0.0.1:{data_port}"
        no_proxy = "localhost,127.0.0.1,169.254.169.254,.svc,.cluster.local"
        for name, value in (
            ("HTTP_PROXY", proxy_url),
            ("HTTPS_PROXY", proxy_url),
            ("http_proxy", proxy_url),
            ("https_proxy", proxy_url),
            ("NO_PROXY", no_proxy),
            ("no_proxy", no_proxy),
            ("NODE_EXTRA_CA_CERTS", ca_cert),
            ("REQUESTS_CA_BUNDLE", ca_cert),
            ("GIT_SSL_CAINFO", ca_cert),
        ):
            sandbox_env.append(client.V1EnvVar(name=name, value=value))
        sandbox_mounts.append(
            client.V1VolumeMount(name="gh-proxy-certs", mount_path=certs_dir, read_only=True)
        )
        # Install the CA into the system trust store at startup (before any git).
        sandbox_command = [
            "/bin/sh",
            "-c",
            "if [ -f /certs/mitmproxy-ca-cert.pem ]; then "
            "cp /certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/egress-auth-proxy.crt && "
            "update-ca-certificates >/dev/null 2>&1 || true; fi; "
            "trap 'exit 0' TERM INT; sleep infinity & wait",
        ]

    container = client.V1Container(
        name=_SANDBOX_CONTAINER,
        image=image,
        command=sandbox_command,
        working_dir=workdir,
        resources=resources,
        env=sandbox_env or None,
        volume_mounts=sandbox_mounts or None,
    )
    # Hard wall-clock cap so a sandbox the server forgets to delete (e.g. the
    # langgraph dev in-memory runtime never drives thread-end cleanup) can't
    # linger forever holding CPU/memory. The out-of-band reaper CronJob is the
    # primary GC; this is defence in depth. 0 disables it.
    active_deadline = int(_env("K8S_SANDBOX_ACTIVE_DEADLINE", "3600"))
    spec = client.V1PodSpec(
        containers=[container, *sidecars],
        init_containers=init_containers or None,
        restart_policy="Never",
        runtime_class_name=runtime_class,
        service_account_name=service_account,
        image_pull_secrets=[client.V1LocalObjectReference(name=pull_secret)]
        if pull_secret
        else None,
        # Sandboxes are ephemeral; don't let them linger draining on delete.
        termination_grace_period_seconds=5,
        active_deadline_seconds=active_deadline if active_deadline > 0 else None,
        volumes=volumes or None,
    )
    return client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=pod_name,
            labels={"app": _LABEL_APP, _LABEL_ID: pod_name},
        ),
        spec=spec,
    )


def _wait_for_ready(api: client.CoreV1Api, namespace: str, pod_name: str, timeout: int) -> None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pod = api.read_namespaced_pod(name=pod_name, namespace=namespace)
        phase = pod.status.phase
        if phase == "Running":
            conditions = pod.status.conditions or []
            if any(c.type == "Ready" and c.status == "True" for c in conditions):
                return
        if phase in ("Failed", "Succeeded"):
            raise RuntimeError(
                f"sandbox pod {pod_name} entered terminal phase {phase} before becoming ready"
            )
        time.sleep(1.5)
    raise TimeoutError(f"sandbox pod {pod_name} not ready within {timeout}s")


def create_k8s_sandbox(sandbox_id: str | None = None):
    """Create or reconnect to a Kubernetes-backed sandbox.

    Args:
        sandbox_id: Existing pod name to reconnect to. If None, a new pod is
            created and awaited until Ready.

    Returns:
        A K8sSandbox implementing SandboxBackendProtocol.
    """
    _load_kube_config()
    api = client.CoreV1Api()
    namespace = _env("K8S_SANDBOX_NAMESPACE", "open-swe")

    if sandbox_id:
        try:
            api.read_namespaced_pod(name=sandbox_id, namespace=namespace)
        except ApiException as exc:
            raise RuntimeError(
                f"cannot reconnect to sandbox pod {sandbox_id}: {exc.reason}"
            ) from exc
        return K8sSandbox(api=api, namespace=namespace, pod_name=sandbox_id)

    pod_name = f"open-swe-sbx-{uuid.uuid4().hex[:10]}"
    manifest = _build_pod_manifest(pod_name)
    api.create_namespaced_pod(namespace=namespace, body=manifest)
    startup_timeout = int(_env("K8S_SANDBOX_STARTUP_TIMEOUT", "180"))
    try:
        _wait_for_ready(api, namespace, pod_name, startup_timeout)
    except BaseException:
        # Don't leak a half-started pod if readiness fails or is cancelled.
        try:
            api.delete_namespaced_pod(name=pod_name, namespace=namespace)
        except ApiException:
            logger.warning("failed to clean up sandbox pod %s after startup error", pod_name)
        raise
    return K8sSandbox(api=api, namespace=namespace, pod_name=pod_name)
