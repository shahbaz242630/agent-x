import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import {
  ARCHIVES,
  archiveFor,
  downloadUrl,
  ensureGitleaks,
  type Fetch,
  GITLEAKS_VERSION,
  gitleaksPath,
  sha256Of,
} from './gitleaks.ts';

const tools = mkdtempSync(path.join(tmpdir(), 'agentx-tools-'));
afterAll(() => {
  rmSync(tools, { recursive: true, force: true });
});

/** A fetch that must not be called. */
const noFetch: Fetch = () => Promise.reject(new Error('no download expected'));
const serve =
  (bytes: Uint8Array, status = 200): Fetch =>
  () =>
    Promise.resolve({ ok: status === 200, status, arrayBuffer: () => Promise.resolve(bytes.slice().buffer) });

describe('the pinned gitleaks', () => {
  it('is the version CI runs, in every workflow that runs it', () => {
    const versions = ['.github/workflows/ci.yml', '.github/workflows/security-weekly.yml'].flatMap((file) => {
      const workflow = parse(readFileSync(file, 'utf8')) as {
        jobs: Record<string, { steps?: { uses?: string; env?: Record<string, string> }[] }>;
      };
      return Object.values(workflow.jobs).flatMap((job) =>
        (job.steps ?? [])
          .filter((step) => step.uses?.startsWith('gitleaks/gitleaks-action@') === true)
          .map((step) => step.env?.GITLEAKS_VERSION),
      );
    });
    expect(versions).toHaveLength(2);
    expect(new Set(versions)).toEqual(new Set([GITLEAKS_VERSION]));
  });

  it('pins one archive of that version per platform, each with a SHA-256', () => {
    expect(Object.keys(ARCHIVES).sort()).toEqual([
      'darwin-arm64',
      'darwin-x64',
      'linux-arm64',
      'linux-x64',
      'win32-x64',
    ]);
    for (const { file, sha256, binarySha256 } of Object.values(ARCHIVES)) {
      expect(file).toMatch(
        new RegExp(
          `^gitleaks_${GITLEAKS_VERSION.replaceAll('.', '[.]')}_(windows|linux|darwin)_(x64|arm64)[.](zip|tar[.]gz)$`,
        ),
      );
      expect(sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(binarySha256).toMatch(/^[0-9a-f]{64}$/);
    }
    const pins = Object.values(ARCHIVES).flatMap((archive) => [archive.sha256, archive.binarySha256]);
    expect(new Set(pins).size).toBe(10);
  });

  it("downloads from gitleaks' own release, and names what isn't pinned", () => {
    expect(downloadUrl(archiveFor('linux', 'x64').file)).toBe(
      `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`,
    );
    expect(() => archiveFor('freebsd', 'x64')).toThrow('No gitleaks archive is pinned for freebsd-x64.');
  });

  it('installs under the tools folder, one folder per version', () => {
    expect(gitleaksPath('win32', tools)).toBe(path.join(tools, 'gitleaks', GITLEAKS_VERSION, 'gitleaks.exe'));
    expect(gitleaksPath('linux', tools)).toBe(path.join(tools, 'gitleaks', GITLEAKS_VERSION, 'gitleaks'));
  });
});

describe('installing it', () => {
  /** A binary already in place under a fresh tools folder, and pins that name it. */
  const installed = (content: string): { dir: string; binary: string; archives: typeof ARCHIVES } => {
    const dir = mkdtempSync(path.join(tools, 'installed-'));
    const binary = gitleaksPath('linux', dir);
    mkdirSync(path.dirname(binary), { recursive: true });
    writeFileSync(binary, content);
    const pinned = {
      file: 'test.tar.gz',
      sha256: '0'.repeat(64),
      binarySha256: sha256Of(Buffer.from('the pinned binary')),
    };
    return { dir, binary, archives: { 'linux-x64': pinned } };
  };

  it('uses an installed binary that matches its pin, without downloading anything', async () => {
    const { dir, binary, archives } = installed('the pinned binary');
    expect(await ensureGitleaks({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: noFetch, archives })).toBe(
      binary,
    );
  });

  it('refuses an installed binary that does not match its pin (a file swapped in under .tools)', async () => {
    const { dir, binary, archives } = installed('something else');
    await expect(
      ensureGitleaks({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: noFetch, archives }),
    ).rejects.toThrow(
      `${binary} does not match its pinned SHA-256: delete the .tools folder and run corepack pnpm hooks.`,
    );
  });

  it('checks against the real pins unless told otherwise', async () => {
    const { dir } = installed('the pinned binary');
    await expect(ensureGitleaks({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: noFetch })).rejects.toThrow(
      'does not match its pinned SHA-256',
    );
  });

  it('refuses a download that does not match its pin, and installs nothing', async () => {
    const dir = mkdtempSync(path.join(tools, 'tampered-'));
    const tampered = new TextEncoder().encode('not the release');
    await expect(
      ensureGitleaks({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: serve(tampered) }),
    ).rejects.toThrow(
      `gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz does not match its pinned SHA-256 (got ${sha256Of(tampered)}); nothing was installed.`,
    );
    expect(readdirSync(dir)).toEqual([]);
  });

  it('refuses a failed download', async () => {
    const dir = mkdtempSync(path.join(tools, 'missing-'));
    await expect(
      ensureGitleaks({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: serve(new Uint8Array(0), 404) }),
    ).rejects.toThrow(`Downloading gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz failed: HTTP 404.`);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('hashes bytes as SHA-256 in hex', () => {
    expect(sha256Of(new Uint8Array(0))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});
