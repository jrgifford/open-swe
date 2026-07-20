# open-swe dashboard (UI) image.
#
# Builds the TanStack Start SPA (package `open-swe-dashboard`) to static assets
# and serves them with nginx. The dashboard is a pure client: it calls
# `${VITE_DASHBOARD_API_BASE_URL}/dashboard/api/*` with credentials, and Vite
# inlines VITE_* env vars at BUILD time, so the backend origin is baked here as
# a build ARG. Base images come from the Zot docker.io pull-through proxy.

# --- build stage ---------------------------------------------------------
FROM zot.tail48c2e7.ts.net/proxy-dockerio/library/node:22-slim AS build

# Empty = same-origin: the client calls a relative `/dashboard/api/*`, which
# nginx reverse-proxies to the backend (see nginx.conf), keeping the UI, API, and
# OAuth callback on one origin (e.g. open-swe.jrg.dev) — no CORS, first-party
# cookie. Override with --build-arg for a split-origin deployment.
ARG VITE_DASHBOARD_API_BASE_URL=""
ENV VITE_DASHBOARD_API_BASE_URL=${VITE_DASHBOARD_API_BASE_URL}

# corepack ships with node:22; use it to run the pnpm version pinned by
# package.json's `packageManager` field. Disable the interactive download
# prompt so the build is non-interactive.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

WORKDIR /app

# Install deps against the frozen lockfile first for layer caching.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Build the static SPA (TanStack Start spa mode -> .output/public).
COPY . .
RUN pnpm run build

# --- runtime stage -------------------------------------------------------
FROM zot.tail48c2e7.ts.net/proxy-dockerio/library/nginx:1.27-alpine

# SPA-aware server config (fallback to the app shell for client routes).
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Drop nginx's stock welcome page so only the app's own files are served; the
# SPA build emits `_shell.html` (not index.html) as its entry.
RUN rm -f /usr/share/nginx/html/index.html

# Static build output.
COPY --from=build /app/.output/public /usr/share/nginx/html

EXPOSE 80
