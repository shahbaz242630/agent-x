# The load test's image (Phase 4 D2c, PL-38): the seed, the checks, the
# clean-up and k6, for the two jobs that run the load test inside staging's
# network. Built from the repository's root, never by the release:
#
#   docker build --file tooling/load/Dockerfile .
#
# only when a load run is near, by the Load image workflow from main
# (.github/workflows/load-image.yml, partner S153), which signs it as the app
# image is signed; the deploy check (deploy/image/verify.ts) accepts it only
# with that workflow's signature at the commit it names. It is not the app's
# image and never runs as the API: it holds the test helpers the seed builds
# its world with (mandate-world.helper.test.ts, @agentx/testing), which the
# app's image never ships. Pinned as the app's image is (SEC-SC-02): the
# same Node base by digest, pnpm by its sha512, the lockfile frozen, and k6
# the same pinned image the laptop's run uses (compose.load.yaml).

FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS dependencies

ENV COREPACK_ENV_FILE=0
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/
COPY packages/core/package.json packages/core/
COPY packages/platform/package.json packages/platform/
COPY packages/testing/package.json packages/testing/

# Not --prod: the seed's world reaches @agentx/testing, a development
# dependency of the API. The filter keeps the root's tools (Vitest, lint) out.
# Node 26 ships no Corepack: the pinned release, by its SHA-256 (tooling/corepack/install.sh).
ADD --checksum=sha256:9128cfe26aee0c99f4fc68c15c6b8b12309a68be0de2c012cdfea2a463cb722f \
  https://registry.npmjs.org/corepack/-/corepack-0.36.0.tgz /tmp/corepack.tgz
RUN npm install --global --ignore-scripts --no-audit --no-fund /tmp/corepack.tgz && rm /tmp/corepack.tgz \
  && corepack enable pnpm \
  && pnpm install --frozen-lockfile --filter "@agentx/api..." --filter "@agentx/testing..."

# k6 is one static binary; only it is taken from its image.
FROM grafana/k6:2.4.0@sha256:d41bb79cd8de5a7ad619b53570e3712633e8bff0937010a5c6c57a4747e7a276 AS k6

FROM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc

ARG AGENTX_RELEASE=local
LABEL org.opencontainers.image.source="https://github.com/shahbaz242630/agent-x" \
  org.opencontainers.image.revision="${AGENTX_RELEASE}" \
  org.opencontainers.image.description="Agent X: the load test's jobs (seed, k6, checks, clean-up), staging only"

# As the app's image: Debian's security updates, and no package manager.
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get upgrade --yes --no-install-recommends -o Dpkg::Options::=--force-confold \
  && rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

WORKDIR /app
COPY --from=dependencies /app /app
COPY apps/api apps/api
COPY packages/core packages/core
COPY packages/platform packages/platform
COPY packages/testing packages/testing
COPY deploy/compose/prepare.ts deploy/compose/prepare.ts
COPY tooling/load tooling/load
COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6

ENV AGENTX_RELEASE=${AGENTX_RELEASE}

# Each job names its own command (deploy/azure/apps.bicep); the image runs none by itself.
USER node
