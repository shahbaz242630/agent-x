// The gitleaks binary for the pre-push hook: the same version CI runs (a
// check keeps them equal), downloaded from the gitleaks release. gitleaks
// publishes no signatures, so the SHA-256 pins here, reviewed in the
// repository, are what we trust: the archive's is from the release's
// checksums file, the binary's from unpacking that archive. A download that
// doesn't match is refused before it is unpacked, and the installed binary is
// checked against its pin every time the hook runs it, so a file swapped in
// under .tools/ is refused too. Installed under .tools/ (git-ignored).
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { downloadPinned, type Fetch, sha256Of, TOOLS_DIR } from '../pinned-download.ts';

export const GITLEAKS_VERSION = '8.30.1';

export interface PinnedArchive {
  readonly file: string;
  /** The archive, as the release's checksums file gives it. */
  readonly sha256: string;
  /** The binary inside it. */
  readonly binarySha256: string;
}

/** The release archive for each platform we work on. */
export const ARCHIVES: Readonly<Record<string, PinnedArchive>> = {
  'win32-x64': {
    file: `gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`,
    sha256: 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e',
    binarySha256: '17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c',
  },
  'linux-x64': {
    file: `gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`,
    sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
    binarySha256: '88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509',
  },
  'linux-arm64': {
    file: `gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`,
    sha256: 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080',
    binarySha256: '00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b',
  },
  'darwin-x64': {
    file: `gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`,
    sha256: 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709',
    binarySha256: 'cee01fea7173f1b779dff188e1c26ecbcb4027d394acc573b23aaf0be260e291',
  },
  'darwin-arm64': {
    file: `gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`,
    sha256: 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
    binarySha256: 'ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f',
  },
};

/** Where the binary lives once installed. */
export function gitleaksPath(platform: NodeJS.Platform = process.platform, toolsDir = TOOLS_DIR): string {
  return path.join(toolsDir, 'gitleaks', GITLEAKS_VERSION, platform === 'win32' ? 'gitleaks.exe' : 'gitleaks');
}

/** The pinned archive for this machine, or an error naming what is missing. */
export function archiveFor(platform: string, arch: string, archives = ARCHIVES): PinnedArchive {
  const archive = archives[`${platform}-${arch}`];
  if (archive === undefined) throw new Error(`No gitleaks archive is pinned for ${platform}-${arch}.`);
  return archive;
}

export const downloadUrl = (file: string): string =>
  `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${file}`;

export interface InstallOptions {
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly toolsDir?: string;
  readonly fetch?: Fetch;
  /** The pins to check against; tests give their own, the hook always uses ARCHIVES. */
  readonly archives?: Readonly<Record<string, PinnedArchive>>;
}

/** Unpacks the one binary from the archive with the system's tar (Windows' own tar.exe reads zip files). */
function unpack(archive: string, into: string, binary: string, platform: NodeJS.Platform): void {
  const tar = platform === 'win32' ? path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  const flags = archive.endsWith('.zip') ? '-xf' : '-xzf';
  const run = spawnSync(tar, [flags, archive, '-C', into, binary], { encoding: 'utf8', windowsHide: true });
  if (run.error !== undefined || run.status !== 0) {
    throw new Error(`Could not unpack ${path.basename(archive)}: ${run.error?.message ?? run.stderr.trim()}`);
  }
}

/**
 * The installed binary's path, once it matches its pin: downloaded, checked
 * and unpacked first if it isn't installed. An installed binary that doesn't
 * match is refused, never replaced silently.
 */
export async function ensureGitleaks(options: InstallOptions = {}): Promise<string> {
  const platform = options.platform ?? process.platform;
  const pinned = archiveFor(platform, options.arch ?? process.arch, options.archives);
  const target = gitleaksPath(platform, options.toolsDir);
  const matchesPin = (): boolean => sha256Of(readFileSync(target)) === pinned.binarySha256;

  if (existsSync(target)) {
    if (!matchesPin()) {
      throw new Error(
        `${target} does not match its pinned SHA-256: delete the .tools folder and run corepack pnpm hooks.`,
      );
    }
    return target;
  }

  const bytes = await downloadPinned(downloadUrl(pinned.file), pinned.file, pinned.sha256, options.fetch);

  const work = mkdtempSync(path.join(tmpdir(), 'agentx-gitleaks-'));
  try {
    const archive = path.join(work, pinned.file);
    writeFileSync(archive, bytes);
    const binary = path.basename(target);
    unpack(archive, work, binary, platform);
    mkdirSync(path.dirname(target), { recursive: true });
    // Copied, not moved: the temporary folder may sit on another file system.
    copyFileSync(path.join(work, binary), target);
    chmodSync(target, 0o755);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  if (!matchesPin()) {
    rmSync(target, { force: true });
    throw new Error(`The unpacked gitleaks does not match its pinned SHA-256; removed it.`);
  }
  return target;
}
