"""Inject GitHub credentials into a Kubernetes sandbox (``SANDBOX_TYPE=k8s``).

open-swe normally authenticates git/gh inside the sandbox through the **LangSmith
sandbox proxy**: the agent prompt hardcodes ``GH_TOKEN=dummy gh ...`` and the
proxy swaps in the real installation token. The k8s backend has no such proxy, so
we configure credentials directly inside the pod instead:

- a **github.com-scoped git credential helper** that reads a root-only token
  file, so every ``git`` HTTPS operation (clone/fetch/push) authenticates without
  the token ever landing in ``~/.gitconfig``;
- a **``gh`` shim** earlier on ``PATH`` that swaps the prompt's ``GH_TOKEN=dummy``
  (or an empty value) for the real token, so ``gh ...`` works unchanged.

Both read ``/root/.openswe-gh-token``, so a token refresh only needs to rewrite
that file — no reconfiguration. Idempotent: safe to run on every prep.

The whole setup is a single ``;``-joined command (no heredocs / trailing
newline) so it survives the k8s backend wrapping it as ``<cmd> 2>&1`` inside
``timeout … sh -c '…'``. Multi-line files are written with ``printf '%s\\n' …``
(one quoted line per arg) to avoid escape/quoting pitfalls.
"""

from __future__ import annotations

import logging
import os
import shlex

logger = logging.getLogger(__name__)

_TOKEN_FILE = "/root/.openswe-gh-token"
_GIT_CRED_HELPER = "/root/.openswe-git-cred.sh"
_GH_SHIM = "/usr/local/bin/gh"


def _setup_command(token: str) -> str:
    tq = shlex.quote(token)
    # `&&`-joined so any step failing short-circuits and surfaces as a non-zero
    # exit code (rather than being masked by a later step's success).
    return " && ".join(
        [
            "umask 077",
            f"printf '%s' {tq} > {_TOKEN_FILE}",
            # github.com-scoped git credential helper reading the token file.
            "printf '%s\\n' "
            "'#!/bin/sh' "
            '\'[ "$1" = get ] || exit 0\' '
            "'echo username=x-access-token' "
            '\'echo "password=$(cat /root/.openswe-gh-token)"\' '
            f"> {_GIT_CRED_HELPER}",
            f"chmod +x {_GIT_CRED_HELPER}",
            f"git config --global credential.https://github.com.helper {_GIT_CRED_HELPER}",
            "mkdir -p /usr/local/bin",
            # gh shim: swap the prompt's GH_TOKEN=dummy for the real token.
            "printf '%s\\n' "
            "'#!/bin/sh' "
            "'if [ \"$GH_TOKEN\" = dummy ] || [ -z \"$GH_TOKEN\" ]; then GH_TOKEN=$(cat /root/.openswe-gh-token 2>/dev/null); fi' "
            "'export GH_TOKEN' "
            "'exec /usr/bin/gh \"$@\"' "
            f"> {_GH_SHIM}",
            f"chmod +x {_GH_SHIM}",
        ]
    )


async def configure_k8s_github_auth(sandbox_backend, github_token: str | None) -> None:
    """Inject git/gh credentials into a k8s sandbox. No-op for other backends.

    Best-effort: a failure is logged, not raised — the run continues (git ops
    would then fail with a clear auth error rather than crashing prep).
    """
    if os.getenv("SANDBOX_TYPE", "langsmith") != "k8s":
        return
    if not github_token:
        return
    try:
        resp = await sandbox_backend.aexecute(_setup_command(github_token))
    except Exception:  # noqa: BLE001 - best-effort credential setup
        logger.warning("Failed to configure GitHub auth in k8s sandbox", exc_info=True)
        return
    exit_code = getattr(resp, "exit_code", None)
    if exit_code not in (0, None):
        # resp.output never contains the token (the setup command emits nothing on
        # success and echoes no arg), so it is safe to log for diagnostics.
        logger.warning(
            "GitHub auth setup in k8s sandbox exited %s: %s",
            exit_code,
            (getattr(resp, "output", "") or "").strip()[:500],
        )
