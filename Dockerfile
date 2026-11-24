# The one image for the API, the migration job, the database set-up job, the
# operator's command and, later, the worker (ADR-001): the same files, different start commands. Node
# 26 runs the TypeScript source itself (type stripping), so the server has no build
# step and the image holds exactly the files the repository holds, plus two
# things made beside them: DB-IP's place file and the console's build (below).
#
# Everything that goes in is pinned: the base image by digest (SEC-SC-02), pnpm
# by the sha512 in package.json (Corepack, itself pinned by SHA-256, checks
# it), every dependency by the lockfile (frozen). One input is not: Debian's
# security updates as of the
# build, chosen over repeatable bytes (ADR-001 Amendment S77). Only production
# dependencies of the apps are installed; test helpers and test files never
# ship (.dockerignore).

FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS dependencies

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
# Node 26 ships no Corepack: the pinned release, by its SHA-256 (tooling/corepack/install.sh).
ADD --checksum=sha256:9128cfe26aee0c99f4fc68c15c6b8b12309a68be0de2c012cdfea2a463cb722f \
  https://registry.npmjs.org/corepack/-/corepack-0.36.0.tgz /tmp/corepack.tgz
RUN npm install --global --ignore-scripts --no-audit --no-fund /tmp/corepack.tgz && rm /tmp/corepack.tgz \
  && corepack enable pnpm \
  && pnpm install --frozen-lockfile --prod --filter "@agentx/api..." --filter "@agentx/migrate..." --filter "@agentx/db-setup..." --filter "@agentx/operator..."

# The console (Phase 6 6A1): built here from its sources and the lockfile, its
# build tools (Vite) installed in this stage alone. Only the built files, the
# page and its hashed assets, reach the image (console-files.ts serves them).
FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS console

ENV COREPACK_ENV_FILE=0
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/console/package.json apps/console/
ADD --checksum=sha256:9128cfe26aee0c99f4fc68c15c6b8b12309a68be0de2c012cdfea2a463cb722f \
  https://registry.npmjs.org/corepack/-/corepack-0.36.0.tgz /tmp/corepack.tgz
RUN npm install --global --ignore-scripts --no-audit --no-fund /tmp/corepack.tgz && rm /tmp/corepack.tgz \
  && corepack enable pnpm && pnpm install --frozen-lockfile --filter "@agentx/console"
COPY apps/console apps/console
RUN pnpm --filter "@agentx/console" run build

# The activity log's place file (Phase 3 L4, client-clues.ts): DB-IP's IP to
# City Lite, November 2026, unchanged. IP Geolocation by DB-IP
# (https://db-ip.com), licensed under CC BY 4.0. DB-IP keeps only its latest
# two months, so this is our copy of theirs, published as a data release of
# this repository; the build takes it only with the SHA-256 of DB-IP's own
# file. The monthly refresh (.github/workflows/places-refresh.yml) checks each
# new month's file and opens a PR moving this pin (tooling/places/pin.ts).
FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS places

ADD --checksum=sha256:b69c625515f636ac92112b71df26bb92a5748f648c79bad124ecd9ba1c97bf4a \
  https://github.com/shahbaz242630/agent-x/releases/download/geoip-dbip-city-lite-2026-11/dbip-city-lite-2026-11.mmdb.gz \
  /places/dbip-city-lite.mmdb.gz
# Read-only to all: a download is root's alone (0600), and the API runs as node.
RUN gzip --decompress /places/dbip-city-lite.mmdb.gz && chmod 0444 /places/dbip-city-lite.mmdb

FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc

ARG AGENTX_RELEASE=local
LABEL org.opencontainers.image.source="https://github.com/shahbaz242630/agent-x" \
  org.opencontainers.image.revision="${AGENTX_RELEASE}" \
  org.opencontainers.image.description="Agent X: the API, the migration job, the database set-up job, the operator's command and the worker"

# The base image's Debian packages brought to their security updates (the
# image scan found OpenSSL and PCRE2 fixes newer than the base image), and
# npm and npx removed (Corepack and Yarn too, should a base bring them back):
# nothing here runs them, and their own bundled packages carried known
# vulnerabilities (Security-Handoff §13b).
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
