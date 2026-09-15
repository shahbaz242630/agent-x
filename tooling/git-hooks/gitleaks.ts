// The gitleaks binary for the pre-push hook: the same version CI runs (a
// check keeps them equal), downloaded from the gitleaks release and refused
// unless its archive matches the SHA-256 pinned here. gitleaks publishes no
// signatures, so this pin, reviewed in the repository, is what we trust.
// Installed under .tools/ (git-ignored), never on the system PATH.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const GITLEAKS_VERSION = '8.30.1';

/** The release archive for each platform we work on, with its SHA-256 from the release's checksums file. */
export const ARCHIVES: Readonly<Record<string, { readonly file: string; readonly sha256: string }>> = {
  'win32-x64': {
    file: `gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`,
    sha256: 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e',
  },
  'linux-x64': {
    file: `gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`,
    sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
  },
  'linux-arm64': {
    file: `gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`,
    sha256: 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080',
  },
  'darwin-x64': {
    file: `gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`,
    sha256: 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709',
  },
  'darwin-arm64': {
    file: `gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`,
    sha256: 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5',
  },
};

const TOOLS_DIR = fileURLToPath(new URL('../../.tools/', import.meta.url));

/** Where the binary lives once installed. */
export function gitleaksPath(platform: NodeJS.Platform = process.platform, toolsDir = TOOLS_DIR): string {
  return path.join(toolsDir, 'gitleaks', GITLEAKS_VERSION, platform === 'win32' ? 'gitleaks.exe' : 'gitleaks');
}

/** The pinned archive for this machine, or an error naming what is missing. */
export function archiveFor(platform: string, arch: string): { readonly file: string; readonly sha256: string } {
  const archive = ARCHIVES[`${platform}-${arch}`];
  if (archive === undefined) throw new Error(`No gitleaks archive is pinned for ${platform}-${arch}.`);
  return archive;
}

export const downloadUrl = (file: string): string =>
  `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${file}`;

export const sha256Of = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

export type Fetch = (url: string) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface InstallOptions {
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly toolsDir?: string;
  readonly fetch?: Fetch;
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
 * The installed binary's path, downloading and checking it first if needed.
 * A download whose hash differs from the pin is refused before it is unpacked.
 */
export async function ensureGitleaks(options: InstallOptions = {}): Promise<string> {
  const platform = options.platform ?? process.platform;
  const target = gitleaksPath(platform, options.toolsDir);
  if (existsSync(target)) return target;

  const { file, sha256 } = archiveFor(platform, options.arch ?? process.arch);
  const response = await (options.fetch ?? fetch)(downloadUrl(file));
  if (!response.ok) throw new Error(`Downloading ${file} failed: HTTP ${String(response.status)}.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = sha256Of(bytes);
  if (actual !== sha256) {
    throw new Error(`${file} does not match its pinned SHA-256 (got ${actual}); nothing was installed.`);
  }

  const work = mkdtempSync(path.join(tmpdir(), 'agentx-gitleaks-'));
  try {
    const archive = path.join(work, file);
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

  const version = spawnSync(target, ['version'], { encoding: 'utf8', windowsHide: true });
  if (version.error !== undefined || !version.stdout.includes(GITLEAKS_VERSION)) {
    rmSync(target, { force: true });
    throw new Error(`The unpacked gitleaks does not report version ${GITLEAKS_VERSION}; removed it.`);
  }
  return target;
}
