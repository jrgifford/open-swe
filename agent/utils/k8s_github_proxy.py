"""Configure a Kubernetes sandbox's egress-auth-proxy sidecar with GitHub auth.

The k8s backend runs each sandbox pod with an **egress-auth-proxy** sidecar
(a LangSmith-compatible MITM proxy). Instead of writing a token into the sandbox
filesystem, we PATCH github header-injection rules to the sidecar's control
plane; the sidecar then injects ``Authorization`` on the wire for
``github.com``/``api.github.com`` traffic. The token rides only the
proxy->GitHub leg and never enters the sandbox container.

The rule payload is identical to the LangSmith proxy-config contract, so we
reuse :func:`agent.integrations.langsmith._github_proxy_rules`. This is the k8s
analogue of ``_configure_github_proxy`` (which targets LangSmith's hosted
proxy-config API); here the target is the per-pod sidecar's control plane
(``http://<pod-ip>:<control-port>/v2/sandboxes/boxes/<name>``).

Best-effort: a failure is logged, not raised, so the run continues (git ops
would then fail with a clear auth error rather than crashing prep).
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx

from ..integrations.langsmith import _github_proxy_rules
from .sandbox_state import unwrap_sandbox_backend

logger = logging.getLogger(__name__)

_CONTROL_PORT = os.getenv("K8S_SANDBOX_GH_PROXY_CONTROL_PORT", "8081").strip() or "8081"
_TIMEOUT_SECONDS = 10.0
_MAX_ATTEMPTS = 3
_RETRY_DELAY_SECONDS = 1.5


def _gh_proxy_enabled() -> bool:
    return os.getenv("SANDBOX_TYPE", "langsmith") == "k8s" and os.getenv(
        "K8S_SANDBOX_ENABLE_GH_PROXY", "false"
    ).strip().lower() in ("1", "true", "yes")


def _control_api_key() -> str | None:
    return os.getenv("K8S_SANDBOX_GH_PROXY_CONTROL_API_KEY", "").strip() or None


def _read_pod_ip(backend) -> str | None:
    """Read the sandbox pod IP via the K8sSandbox's own API client (blocking)."""
    api = getattr(backend, "_api", None)
    namespace = getattr(backend, "_namespace", None)
    pod_name = getattr(backend, "_pod_name", None)
    if api is None or not namespace or not pod_name:
        return None
    pod = api.read_namespaced_pod(name=pod_name, namespace=namespace)
    return getattr(getattr(pod, "status", None), "pod_ip", None)


async def configure_k8s_github_proxy(sandbox_backend, github_token: str | None) -> None:
    """Push github header-injection rules to a k8s sandbox's proxy sidecar.

    No-op unless ``SANDBOX_TYPE=k8s`` and ``K8S_SANDBOX_ENABLE_GH_PROXY`` is set.
    """
    if not _gh_proxy_enabled() or not github_token:
        return
    api_key = _control_api_key()
    backend = unwrap_sandbox_backend(sandbox_backend)
    try:
        pod_ip = await asyncio.to_thread(_read_pod_ip, backend)
    except Exception:  # noqa: BLE001 - best-effort; fall through to warning
        pod_ip = None
    if not pod_ip:
        logger.warning(
            "Cannot configure GitHub proxy: sandbox %s has no resolvable pod IP",
            getattr(sandbox_backend, "id", "?"),
        )
        return

    url = f"http://{pod_ip}:{_CONTROL_PORT}/v2/sandboxes/boxes/{sandbox_backend.id}"
    payload = {"proxy_config": {"rules": _github_proxy_rules(github_token)}}
    headers = {"X-API-Key": api_key} if api_key else {}
    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
        for attempt in range(_MAX_ATTEMPTS):
            try:
                response = await client.patch(url, json=payload, headers=headers)
                response.raise_for_status()
                logger.info("Configured GitHub proxy sidecar for sandbox %s", sandbox_backend.id)
                return
            except Exception:  # noqa: BLE001 - best-effort credential setup
                if attempt == _MAX_ATTEMPTS - 1:
                    logger.warning(
                        "Failed to configure GitHub proxy sidecar for sandbox %s",
                        sandbox_backend.id,
                        exc_info=True,
                    )
                    return
                await asyncio.sleep(_RETRY_DELAY_SECONDS)
