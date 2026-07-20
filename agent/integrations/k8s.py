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
        read_timeout = (effective_timeout + 15) if effective_timeout and effective_timeout > 0 else None
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
            command=argv,
            stderr=True,
            stdout=True,
            stdin=False,
            tty=False,
            _preload_content=False,
        )
        chunks: list[str] = []
        resp.run_forever(timeout=read_timeout if read_timeout is not None else self._default_timeout + 15)
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
                    responses.append(FileDownloadResponse(path=path, content=None, error="file_not_found"))
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

    resources = client.V1ResourceRequirements(
        requests={"cpu": cpu, "memory": memory},
        limits={"cpu": cpu, "memory": memory},
    )

    sandbox_env: list[client.V1EnvVar] = []
    sandbox_mounts: list[client.V1VolumeMount] = []
    volumes: list[client.V1Volume] = []
    sidecars: list[client.V1Container] = []

    if enable_dind:
        # Docker-in-Docker: a privileged sidecar runs dockerd; the sandbox's
        # docker CLI reaches it over the shared pod network (localhost:2375).
        # /workspace is a shared emptyDir so `docker build` context AND
        # `docker run -v` bind mounts of sandbox files resolve on the daemon side.
        # SECURITY: the dind sidecar is privileged (node-escape surface for
        # untrusted agent code). Pair with K8S_SANDBOX_RUNTIME_CLASS=kata/gvisor
        # to contain it. Opt-in via K8S_SANDBOX_ENABLE_DIND.
        volumes.append(
            client.V1Volume(name="workspace", empty_dir=client.V1EmptyDirVolumeSource())
        )
        volumes.append(
            client.V1Volume(name="dind-storage", empty_dir=client.V1EmptyDirVolumeSource())
        )
        sandbox_mounts.append(client.V1VolumeMount(name="workspace", mount_path=workdir))
        sandbox_env.append(client.V1EnvVar(name="DOCKER_HOST", value="tcp://localhost:2375"))
        dind_image = _env(
            "K8S_SANDBOX_DIND_IMAGE",
            "zot.tail48c2e7.ts.net/proxy-dockerio/library/docker:dind",
        )
        sidecars.append(
            client.V1Container(
                name="dind",
                image=dind_image,
                security_context=client.V1SecurityContext(privileged=True),
                # Empty cert dir => dockerd runs without TLS on plain tcp 2375.
                env=[client.V1EnvVar(name="DOCKER_TLS_CERTDIR", value="")],
                args=["--host=tcp://0.0.0.0:2375", "--host=unix:///var/run/docker.sock"],
                resources=client.V1ResourceRequirements(
                    requests={"cpu": "250m", "memory": "512Mi"},
                    limits={
                        "cpu": _env("K8S_SANDBOX_DIND_CPU", "2"),
                        "memory": _env("K8S_SANDBOX_DIND_MEMORY", "4Gi"),
                    },
                ),
                volume_mounts=[
                    client.V1VolumeMount(name="workspace", mount_path=workdir),
                    client.V1VolumeMount(name="dind-storage", mount_path="/var/lib/docker"),
                ],
            )
        )

    container = client.V1Container(
        name="sandbox",
        image=image,
        # Keep PID 1 alive so the pod stays around for repeated exec sessions;
        # `wait` lets a TERM propagate for a clean shutdown.
        command=["/bin/sh", "-c", "trap 'exit 0' TERM INT; sleep infinity & wait"],
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
        restart_policy="Never",
        runtime_class_name=runtime_class,
        service_account_name=service_account,
        image_pull_secrets=[client.V1LocalObjectReference(name=pull_secret)] if pull_secret else None,
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
            raise RuntimeError(f"sandbox pod {pod_name} entered terminal phase {phase} before becoming ready")
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
            raise RuntimeError(f"cannot reconnect to sandbox pod {sandbox_id}: {exc.reason}") from exc
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
