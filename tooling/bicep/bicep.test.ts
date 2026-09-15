import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { type Fetch, sha256Of } from '../pinned-download.ts';
import { BICEP_VERSION, bicepPath, BINARIES, binaryFor, downloadUrl, ensureBicep, installedBicep } from './bicep.ts';

const tools = mkdtempSync(path.join(tmpdir(), 'agentx-bicep-'));
afterAll(() => {
  rmSync(tools, { recursive: true, force: true });
});

/** A fetch that must not be called. */
const noFetch: Fetch = () => Promise.reject(new Error('no download expected'));
const serve =
  (bytes: Uint8Array, status = 200): Fetch =>
  () =>
    Promise.resolve({ ok: status === 200, status, arrayBuffer: () => Promise.resolve(bytes.slice().buffer) });

describe('the pinned Bicep compiler', () => {
  it('pins one binary of the release per platform, each with its own SHA-256', () => {
    expect(Object.keys(BINARIES).sort()).toEqual([
      'darwin-arm64',
      'darwin-x64',
      'linux-arm64',
      'linux-x64',
      'win32-arm64',
      'win32-x64',
    ]);
    for (const { file, sha256 } of Object.values(BINARIES)) {
      expect(file).toMatch(/^bicep-(win|linux|osx)-(x64|arm64)(\.exe)?$/);
      expect(sha256).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(new Set(Object.values(BINARIES).map(({ sha256 }) => sha256)).size).toBe(6);
  });

  it("downloads from Bicep's own release, and names what isn't pinned", () => {
    expect(downloadUrl(binaryFor('linux', 'x64').file)).toBe(
      `https://github.com/Azure/bicep/releases/download/v${BICEP_VERSION}/bicep-linux-x64`,
    );
    expect(() => binaryFor('freebsd', 'x64')).toThrow('No Bicep binary is pinned for freebsd-x64.');
  });

  it('installs under the tools folder, one folder per version', () => {
    expect(bicepPath('win32', tools)).toBe(path.join(tools, 'bicep', BICEP_VERSION, 'bicep.exe'));
    expect(bicepPath('linux', tools)).toBe(path.join(tools, 'bicep', BICEP_VERSION, 'bicep'));
  });

  it('is installed by CI before the tests, through the same installer', () => {
    const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as {
      jobs: Record<string, { steps?: { name?: string; run?: string }[] }>;
    };
    const steps = workflow.jobs.verify?.steps ?? [];
    const install = steps.findIndex((step) => step.run === 'pnpm tools');
    const tests = steps.findIndex((step) => step.run === 'pnpm test:coverage');
    expect(install).toBeGreaterThan(-1);
    expect(install).toBeLessThan(tests);
    const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts;
    expect(scripts.tools).toBe('node tooling/bicep/install.ts');
  });
});

describe('installing it', () => {
  const pins = { 'linux-x64': { file: 'bicep-test', sha256: sha256Of(Buffer.from('the pinned binary')) } };

  /** A binary already in place under a fresh tools folder. */
  const installed = (content: string): { dir: string; binary: string } => {
    const dir = mkdtempSync(path.join(tools, 'installed-'));
    const binary = bicepPath('linux', dir);
    mkdirSync(path.dirname(binary), { recursive: true });
    writeFileSync(binary, content);
    return { dir, binary };
  };

  it('uses an installed binary that matches its pin, without downloading anything', async () => {
    const { dir, binary } = installed('the pinned binary');
    const options = { platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins } as const;
    expect(await ensureBicep({ ...options, fetch: noFetch })).toBe(binary);
    expect(installedBicep(options)).toBe(binary);
  });

  it('refuses an installed binary that does not match its pin (a file swapped in under .tools)', async () => {
    const { dir, binary } = installed('something else');
    const options = { platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins } as const;
    const message = `${binary} does not match its pinned SHA-256: delete the .tools folder and run corepack pnpm tools to install it.`;
    await expect(ensureBicep({ ...options, fetch: noFetch })).rejects.toThrow(message);
    expect(() => installedBicep(options)).toThrow(message);
    expect(readFileSync(binary, 'utf8')).toBe('something else');
  });

  it('checks a binary again once its size or modified time changes after a check', () => {
    const { dir, binary } = installed('the pinned binary');
    const options = { platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins } as const;
    expect(installedBicep(options)).toBe(binary);
    writeFileSync(binary, 'swapped in afterwards');
    expect(() => installedBicep(options)).toThrow('does not match its pinned SHA-256');
  });

  it('gives every download a deadline, so a stalled one fails instead of hanging', async () => {
    const dir = mkdtempSync(path.join(tools, 'deadline-'));
    const signals: unknown[] = [];
    const recording: Fetch = (_url, init) => {
      signals.push(init?.signal);
      return serve(new TextEncoder().encode('the pinned binary'))('');
    };
    await ensureBicep({ platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins, fetch: recording });
    expect(signals).toHaveLength(1);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
  });

  it('checks against the real pins unless told otherwise', () => {
    const { dir } = installed('the pinned binary');
    expect(() => installedBicep({ platform: 'linux', arch: 'x64', toolsDir: dir })).toThrow(
      'does not match its pinned SHA-256',
    );
  });

  it('says how to install it when it is missing, and never downloads it for a check', () => {
    const dir = mkdtempSync(path.join(tools, 'absent-'));
    expect(() => installedBicep({ platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins })).toThrow(
      `Bicep ${BICEP_VERSION} isn't installed at ${bicepPath('linux', dir)}: run corepack pnpm tools to install it.`,
    );
  });

  it('installs a download that matches its pin, runnable', async () => {
    const dir = mkdtempSync(path.join(tools, 'fresh-'));
    const options = { platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins } as const;
    const binary = await ensureBicep({ ...options, fetch: serve(new TextEncoder().encode('the pinned binary')) });
    expect(binary).toBe(bicepPath('linux', dir));
    expect(readFileSync(binary, 'utf8')).toBe('the pinned binary');
    expect(readdirSync(path.dirname(binary))).toEqual(['bicep']);
  });

  it('refuses a download that does not match its pin, and installs nothing', async () => {
    const dir = mkdtempSync(path.join(tools, 'tampered-'));
    const tampered = new TextEncoder().encode('not the release');
    await expect(
      ensureBicep({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: serve(tampered) }),
    ).rejects.toThrow(
      `bicep-linux-x64 does not match its pinned SHA-256 (got ${sha256Of(tampered)}); nothing was installed.`,
    );
    expect(readdirSync(dir)).toEqual([]);
  });

  it('refuses a failed download', async () => {
    const dir = mkdtempSync(path.join(tools, 'missing-'));
    await expect(
      ensureBicep({ platform: 'linux', arch: 'x64', toolsDir: dir, fetch: serve(new Uint8Array(0), 404) }),
    ).rejects.toThrow('Downloading bicep-linux-x64 failed: HTTP 404.');
    expect(readdirSync(dir)).toEqual([]);
  });

  it('hashes bytes as SHA-256 in hex', () => {
    expect(sha256Of(new Uint8Array(0))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});
