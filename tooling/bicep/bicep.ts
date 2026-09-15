// The Bicep compiler that builds, lints and snapshots deploy/azure: one version
// for every machine and for CI, downloaded from the Bicep release. The release
// publishes no signatures, so the SHA-256 pins here, reviewed in the
// repository, are what we trust: GitHub's digest of each release file, checked
// against a download. A download that doesn't match is refused before it is
// written, and the installed binary is checked against its pin every time it is
// used, so a file swapped in under .tools/ is refused too. Installed under
// .tools/ (git-ignored) by `corepack pnpm tools`.
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BICEP_VERSION = '0.47.16';

export interface PinnedBinary {
  readonly file: string;
  readonly sha256: string;
}

/** The release file for each platform we work on. */
export const BINARIES: Readonly<Record<string, PinnedBinary>> = {
  'win32-x64': {
    file: 'bicep-win-x64.exe',
    sha256: '3f343ab1ce41feac156464adee3dc499cb6c197366fc731aed276192011d867c',
  },
  'win32-arm64': {
    file: 'bicep-win-arm64.exe',
    sha256: '657e6aacc4e44d73674874f802d98396bf5e2e23530d160f275fbf9d67b7fde7',
  },
  'linux-x64': {
    file: 'bicep-linux-x64',
    sha256: '64c345a58e0c3e48b1bc98a4e62d6b3adb1d238281297de3400aeafb2697aa5a',
  },
  'linux-arm64': {
    file: 'bicep-linux-arm64',
    sha256: '4406214cc274cfac7c821552aec2178b80aec637d91ed8b244282964c1cf24e3',
  },
  'darwin-x64': {
    file: 'bicep-osx-x64',
    sha256: '8ba5771b5261413d88583829f2ea24509eb65b06d899620c17283ecb60d5ca73',
  },
  'darwin-arm64': {
    file: 'bicep-osx-arm64',
    sha256: '68046a084c88503cf6bd11dacf2a1c4ffcb7e3ac9c6b310d295e024af21bbea4',
  },
};

const TOOLS_DIR = fileURLToPath(new URL('../../.tools/', import.meta.url));

/** Where the binary lives once installed. */
export function bicepPath(platform: NodeJS.Platform = process.platform, toolsDir = TOOLS_DIR): string {
  return path.join(toolsDir, 'bicep', BICEP_VERSION, platform === 'win32' ? 'bicep.exe' : 'bicep');
}

/** The pinned binary for this machine, or an error naming what is missing. */
export function binaryFor(platform: string, arch: string, binaries = BINARIES): PinnedBinary {
  const binary = binaries[`${platform}-${arch}`];
  if (binary === undefined) throw new Error(`No Bicep binary is pinned for ${platform}-${arch}.`);
  return binary;
}

export const downloadUrl = (file: string): string =>
  `https://github.com/Azure/bicep/releases/download/v${BICEP_VERSION}/${file}`;

export const sha256Of = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

export type Fetch = (url: string) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface BicepOptions {
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly toolsDir?: string;
  /** The pins to check against; tests give their own, everything else uses BINARIES. */
  readonly binaries?: Readonly<Record<string, PinnedBinary>>;
}

const MISSING = 'run corepack pnpm tools to install it';

/**
 * The installed binary's path, once it matches its pin. Downloads nothing: a
 * test or a check that finds it missing says how to install it.
 */
export function installedBicep(options: BicepOptions = {}): string {
  const platform = options.platform ?? process.platform;
  const pinned = binaryFor(platform, options.arch ?? process.arch, options.binaries);
  const target = bicepPath(platform, options.toolsDir);
  if (!existsSync(target)) throw new Error(`Bicep ${BICEP_VERSION} isn't installed at ${target}: ${MISSING}.`);
  if (sha256Of(readFileSync(target)) !== pinned.sha256) {
    throw new Error(`${target} does not match its pinned SHA-256: delete the .tools folder and ${MISSING}.`);
  }
  return target;
}

/**
 * Installs the pinned binary if it isn't there, and returns its path. An
 * installed binary that doesn't match is refused, never replaced silently.
 */
export async function ensureBicep(options: BicepOptions & { readonly fetch?: Fetch } = {}): Promise<string> {
  const platform = options.platform ?? process.platform;
  const pinned = binaryFor(platform, options.arch ?? process.arch, options.binaries);
  const target = bicepPath(platform, options.toolsDir);
  if (existsSync(target)) return installedBicep(options);

  const response = await (options.fetch ?? fetch)(downloadUrl(pinned.file));
  if (!response.ok) throw new Error(`Downloading ${pinned.file} failed: HTTP ${String(response.status)}.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = sha256Of(bytes);
  if (actual !== pinned.sha256) {
    throw new Error(`${pinned.file} does not match its pinned SHA-256 (got ${actual}); nothing was installed.`);
  }

  // Written beside the target, then renamed into place: a half-written file never carries the final name.
  mkdirSync(path.dirname(target), { recursive: true });
  const partial = `${target}.partial`;
  try {
    writeFileSync(partial, bytes);
    chmodSync(partial, 0o755);
    renameSync(partial, target);
  } finally {
    rmSync(partial, { force: true });
  }
  return installedBicep(options);
}
