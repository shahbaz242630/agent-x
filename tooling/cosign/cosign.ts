// cosign, which checks an image's signature and SBOM before a deploy
// (`deploy/image/verify.ts`, ADR-002 Amendment E2): the version CI installs
// (ci.yml, cosign-installer), for an operator's own machine. The SHA-256 pins
// here are GitHub's digests of the release files, reviewed in the repository;
// a download that doesn't match is refused before it is installed, and the
// installed binary is checked against its pin every time it is used.
// Installed under .tools/ (git-ignored) by `corepack pnpm tools:cosign`, which
// CI never runs: its image jobs install cosign their own way, and the release
// file for Windows is 200 MB.
import { existsSync } from 'node:fs';
import path from 'node:path';

import { downloadPinnedTo, sha256OfFile, type StreamingFetch, TOOLS_DIR } from '../pinned-download.ts';

/** The version ci.yml's cosign-installer is given (`cosign-release`); a test holds the two equal. */
export const COSIGN_VERSION = '3.1.3';

export interface PinnedBinary {
  readonly file: string;
  readonly sha256: string;
}

/** The release file for each platform we work on. cosign publishes no Windows build for Arm. */
export const BINARIES: Readonly<Record<string, PinnedBinary>> = {
  'win32-x64': {
    file: 'cosign-windows-amd64.exe',
    sha256: '9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be',
  },
  'linux-x64': {
    file: 'cosign-linux-amd64',
    sha256: '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71',
  },
  'linux-arm64': {
    file: 'cosign-linux-arm64',
    sha256: 'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a',
  },
  'darwin-x64': {
    file: 'cosign-darwin-amd64',
    sha256: '2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c',
  },
  'darwin-arm64': {
    file: 'cosign-darwin-arm64',
    sha256: '5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76',
  },
};

/** Where the binary lives once installed. */
export function cosignPath(platform: NodeJS.Platform = process.platform, toolsDir = TOOLS_DIR): string {
  return path.join(toolsDir, 'cosign', COSIGN_VERSION, platform === 'win32' ? 'cosign.exe' : 'cosign');
}

/** The pinned binary for this machine, or an error naming what is missing. */
export function binaryFor(platform: string, arch: string, binaries = BINARIES): PinnedBinary {
  const binary = binaries[`${platform}-${arch}`];
  if (binary === undefined) throw new Error(`No cosign binary is pinned for ${platform}-${arch}.`);
  return binary;
}

export const downloadUrl = (file: string): string =>
  `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/${file}`;

export interface CosignOptions {
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly toolsDir?: string;
  /** The pins to check against; tests give their own, everything else uses BINARIES. */
  readonly binaries?: Readonly<Record<string, PinnedBinary>>;
}

const MISSING = 'run corepack pnpm tools:cosign to install it';

/** The installed binary's path, once it matches its pin. Downloads nothing. */
export function installedCosign(options: CosignOptions = {}): string {
  const platform = options.platform ?? process.platform;
  const pinned = binaryFor(platform, options.arch ?? process.arch, options.binaries);
  const target = cosignPath(platform, options.toolsDir);
  const actual = sha256OfFile(target);
  if (actual === undefined) throw new Error(`cosign ${COSIGN_VERSION} isn't installed at ${target}: ${MISSING}.`);
  if (actual !== pinned.sha256) {
    throw new Error(`${target} does not match its pinned SHA-256: delete the .tools/cosign folder and ${MISSING}.`);
  }
  return target;
}

/**
 * Installs the pinned binary if it isn't there, and returns its path. An
 * installed binary that doesn't match is refused, never replaced silently.
 */
export async function ensureCosign(options: CosignOptions & { readonly fetch?: StreamingFetch } = {}): Promise<string> {
  const platform = options.platform ?? process.platform;
  const pinned = binaryFor(platform, options.arch ?? process.arch, options.binaries);
  const target = cosignPath(platform, options.toolsDir);
  if (!existsSync(target)) {
    await downloadPinnedTo(downloadUrl(pinned.file), pinned.file, pinned.sha256, target, options.fetch);
  }
  return installedCosign(options);
}
