# The one image for the API, the migration job, the database set-up job, the
# operator's command and, later, the worker (ADR-001): the same files, different start commands. Node
# 24 runs the TypeScript source itself (type stripping), so there is no build
# step and the image holds exactly the files the repository holds.
#
# Everything that goes in is pinned: the base image by digest (SEC-SC-02), pnpm
# by the sha512 in package.json (Corepack checks it), every dependency by the
# lockfile (frozen). One input is not: Debian's security updates as of the
# build, chosen over repeatable bytes (ADR-001 Amendment S77). Only production
# dependencies of the apps are installed; test helpers and test files never
# ship (.dockerignore).

FROM node:24.21.0-trixie-slim@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe AS dependencies

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

FROM node:24.21.0-trixie-slim@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe

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

# Every AGENTX_ setting but the release comes from the deployment (compose,
# Azure): each job refuses the others' settings, so the image sets none.
ENV AGENTX_RELEASE=${AGENTX_RELEASE}

# The image's unprivileged user (uid 1000). The files stay owned by root and
# read-only to it: the app writes nothing to disk.
USER node
EXPOSE 8080

CMD ["node", "apps/api/src/main.ts"]
