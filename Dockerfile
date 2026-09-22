# The one image for the API, the migration job, the database set-up job, the
# operator's command and, later, the worker (ADR-001): the same files, different start commands. Node
# 24 runs the TypeScript source itself (type stripping), so there is no build
# step and the image holds exactly the files the repository holds.
#
# Everything that goes in is pinned: the base image by digest (SEC-SC-02), pnpm
# by the sha512 in package.json (Corepack checks it), every dependency by the
# lockfile (frozen). Only production dependencies of the apps are
# installed; test helpers and test files never ship (.dockerignore).

FROM node:24.21.0-trixie-slim@sha256:db3ae80f5d8df06e04dabdf7b44cbf008d32de168205fa0294444aabbc08c590 AS dependencies

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

FROM node:24.21.0-trixie-slim@sha256:db3ae80f5d8df06e04dabdf7b44cbf008d32de168205fa0294444aabbc08c590

ARG AGENTX_RELEASE=local
LABEL org.opencontainers.image.source="https://github.com/shahbaz242630/agent-x" \
  org.opencontainers.image.revision="${AGENTX_RELEASE}" \
  org.opencontainers.image.description="Agent X: the API, the migration job, the database set-up job, the operator's command and the worker"

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
