# The one image for the API, the migration job, the database set-up job, the
# operator's command and, later, the worker (ADR-001): the same files, different start commands. Node
# 24 runs the TypeScript source itself (type stripping), so the server has no build
# step and the image holds exactly the files the repository holds, plus two
# things made beside them: DB-IP's place file and the console's build (below).
#
# Everything that goes in is pinned: the base image by digest (SEC-SC-02), pnpm
# by the sha512 in package.json (Corepack checks it), every dependency by the
# lockfile (frozen). One input is not: Debian's security updates as of the
# build, chosen over repeatable bytes (ADR-001 Amendment S77). Only production
# dependencies of the apps are installed; test helpers and test files never
# ship (.dockerignore).

FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS dependencies

# Corepack must not read a .corepack.env file, which could turn off its
# signature checks or point it at another registry (the same rule as CI).
ENV COREPACK_ENV_FILE=0
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/
COPY apps/migrate/package.json apps/migrate/
COPY apps/db-setup/package.json apps/db-setup/
COPY apps/operator/package.json apps/operator/
COPY packages/core/package.json packages/core/
COPY packages/platform/package.json packages/platform/

# The apps and what they depend on inside the workspace (the `...` suffix), production dependencies only.
RUN corepack enable pnpm \
  && pnpm install --frozen-lockfile --prod --filter "@agentx/api..." --filter "@agentx/migrate..." --filter "@agentx/db-setup..." --filter "@agentx/operator..."

# The console (Phase 6 6A1): built here from its sources and the lockfile, its
# build tools (Vite) installed in this stage alone. Only the built files, the
# page and its hashed assets, reach the image (console-files.ts serves them).
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS console

ENV COREPACK_ENV_FILE=0
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/console/package.json apps/console/
RUN corepack enable pnpm && pnpm install --frozen-lockfile --filter "@agentx/console"
COPY apps/console apps/console
RUN pnpm --filter "@agentx/console" run build

# The activity log's place file (Phase 3 L4, client-clues.ts): DB-IP's IP to
# City Lite, October 2026, unchanged. IP Geolocation by DB-IP
# (https://db-ip.com), licensed under CC BY 4.0. DB-IP keeps only its latest
# two months, so this is our copy of theirs, published as a data release of
# this repository; the build takes it only with the SHA-256 of DB-IP's own
# file. The monthly refresh (.github/workflows/places-refresh.yml) checks each
# new month's file and opens a PR moving this pin (tooling/places/pin.ts).
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS places

ADD --checksum=sha256:c839d407f85a1e0bddba354cef16b2c398182d1c34ed8d985555dce134b36b14 \
  https://github.com/shahbaz242630/agent-x/releases/download/geoip-dbip-city-lite-2026-10/dbip-city-lite-2026-10.mmdb.gz \
  /places/dbip-city-lite.mmdb.gz
# Read-only to all: a download is root's alone (0600), and the API runs as node.
RUN gzip --decompress /places/dbip-city-lite.mmdb.gz && chmod 0444 /places/dbip-city-lite.mmdb

FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea

ARG AGENTX_RELEASE=local
LABEL org.opencontainers.image.source="https://github.com/shahbaz242630/agent-x" \
  org.opencontainers.image.revision="${AGENTX_RELEASE}" \
  org.opencontainers.image.description="Agent X: the API, the migration job, the database set-up job, the operator's command and the worker"

# The base image's Debian packages brought to their security updates (the
# image scan found OpenSSL and PCRE2 fixes newer than the base image), and
# npm, npx, Corepack and Yarn removed: nothing here runs them, and their own
# bundled packages carried known vulnerabilities (Security-Handoff §13b).
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get upgrade --yes --no-install-recommends -o Dpkg::Options::=--force-confold \
  && rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

WORKDIR /app
COPY --from=dependencies /app /app
COPY apps/api apps/api
COPY apps/migrate apps/migrate
COPY apps/db-setup apps/db-setup
COPY apps/operator apps/operator
COPY packages/core packages/core
COPY packages/platform packages/platform
COPY db db
# The file keeps its mode; COPY's --chmod would set the new geo folder's too, and nothing could open it.
COPY --from=places /places/dbip-city-lite.mmdb geo/dbip-city-lite.mmdb
COPY --from=console /app/apps/console/dist apps/console/dist

# Every AGENTX_ setting but the release comes from the deployment (compose,
# Azure): each job refuses the others' settings, so the image sets none.
ENV AGENTX_RELEASE=${AGENTX_RELEASE}

# The image's unprivileged user (uid 1000). The files stay owned by root and
# read-only to it: the app writes nothing to disk.
USER node
EXPOSE 8080

CMD ["node", "apps/api/src/main.ts"]
