#!/bin/sh
# Corepack for Node 26, which no longer ships it (Node 25 dropped it). Corepack
# is what runs pnpm at the version and sha512 package.json pins, so it is
# pinned the same way: this release of npm's corepack package (the one Node
# 24.22.3 bundled), checked by its SHA-256 before anything installs it, with no
# install scripts. CI runs this before `corepack enable pnpm`; on a laptop, run
# it once under each new Node 26 (Git Bash on Windows). The Dockerfiles take
# the same file with ADD --checksum; tooling/checks/supply-chain.test.ts holds
# all three to this version and digest.
set -eu
version=0.36.0
sha256=9128cfe26aee0c99f4fc68c15c6b8b12309a68be0de2c012cdfea2a463cb722f
# A folder of its own (mktemp): no other user can swap the file between the check and the install.
dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/corepack.XXXXXX")
file="${dir}/corepack-${version}.tgz"
curl --fail --silent --show-error --location --output "$file" "https://registry.npmjs.org/corepack/-/corepack-${version}.tgz"
# A mismatch stops here with an error, whether or not `set -e` is in force: nothing is installed.
echo "${sha256}  ${file}" | sha256sum --check --strict - || { rm -f "$file"; rmdir "$dir"; exit 1; }
npm install --global --ignore-scripts --no-audit --no-fund "$file"
rm -f "$file"
rmdir "$dir"
