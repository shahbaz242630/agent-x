// SEC-SC-02: the cosign an operator's machine checks an image with before a
// deploy is the version CI signs with, pinned by digest, and checked on every use.
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { sha256Of, type StreamingFetch } from '../pinned-download.ts';
import {
  BINARIES,
  binaryFor,
  COSIGN_VERSION,
  cosignPath,
  downloadUrl,
  ensureCosign,
  installedCosign,
} from './cosign.ts';

const tools = mkdtempSync(path.join(tmpdir(), 'agentx-cosign-'));
afterAll(() => {
  rmSync(tools, { recursive: true, force: true });
});

const noFetch: StreamingFetch = () => Promise.reject(new Error('no download expected'));
const serve =
  (text: string): StreamingFetch =>
  () =>
    Promise.resolve({
      ok: true,
      status: 200,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(text));
          controller.close();
        },
      }),
    });

interface Workflow {
  jobs: Record<string, { steps?: { uses?: string; with?: Record<string, unknown> }[] }>;
}

describe('the pinned cosign', () => {
  it('pins one binary of the release per platform, each with its own SHA-256', () => {
    expect(Object.keys(BINARIES).sort()).toEqual([
      'darwin-arm64',
      'darwin-x64',
      'linux-arm64',
      'linux-x64',
      'win32-x64',
    ]);
    for (const { file, sha256 } of Object.values(BINARIES)) {
      expect(file).toMatch(/^cosign-(windows|linux|darwin)-(amd64|arm64)(\.exe)?$/);
      expect(sha256).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(new Set(Object.values(BINARIES).map(({ sha256 }) => sha256)).size).toBe(5);
  });

  it('is the version CI installs wherever it signs or checks an image', () => {
    const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8')) as Workflow;
    const releases = Object.values(workflow.jobs)
      .flatMap((job) => job.steps ?? [])
      .filter((step) => step.uses?.startsWith('sigstore/cosign-installer@') === true)
      .map((step) => step.with?.['cosign-release']);
    expect(releases.length).toBeGreaterThan(0);
    expect(new Set(releases)).toEqual(new Set([`v${COSIGN_VERSION}`]));
  });

  it("downloads from cosign's own release, installs under the tools folder, and names what isn't pinned", () => {
    expect(downloadUrl(binaryFor('win32', 'x64').file)).toBe(
      `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-windows-amd64.exe`,
    );
    expect(cosignPath('win32', tools)).toBe(path.join(tools, 'cosign', COSIGN_VERSION, 'cosign.exe'));
    expect(cosignPath('linux', tools)).toBe(path.join(tools, 'cosign', COSIGN_VERSION, 'cosign'));
    expect(() => binaryFor('win32', 'arm64')).toThrow('No cosign binary is pinned for win32-arm64.');
  });

  it('is installed by its own command, which CI never runs', () => {
    const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts;
    expect(scripts['tools:cosign']).toBe('node tooling/cosign/install.ts');
    expect(readFileSync('.github/workflows/ci.yml', 'utf8')).not.toContain('tools:cosign');
  });
});

describe('installing it', () => {
  const pins = { 'linux-x64': { file: 'cosign-test', sha256: sha256Of(Buffer.from('the pinned binary')) } };
  const options = (dir: string) => ({ platform: 'linux', arch: 'x64', toolsDir: dir, binaries: pins }) as const;

  /** A binary already in place under a fresh tools folder. */
  const installed = (content: string): { dir: string; binary: string } => {
    const dir = mkdtempSync(path.join(tools, 'installed-'));
    const binary = cosignPath('linux', dir);
    mkdirSync(path.dirname(binary), { recursive: true });
    writeFileSync(binary, content);
    return { dir, binary };
  };

  it('uses an installed binary that matches its pin, without downloading anything', async () => {
    const { dir, binary } = installed('the pinned binary');
    await expect(ensureCosign({ ...options(dir), fetch: noFetch })).resolves.toBe(binary);
    expect(installedCosign(options(dir))).toBe(binary);
  });

  it('refuses one that does not match, on every use, and never replaces it silently', async () => {
    const { dir, binary } = installed('something else');
    const message = `${binary} does not match its pinned SHA-256: delete the .tools/cosign folder and run corepack pnpm tools:cosign to install it.`;
    await expect(ensureCosign({ ...options(dir), fetch: noFetch })).rejects.toThrow(message);
    expect(() => installedCosign(options(dir))).toThrow(message);
    expect(readFileSync(binary, 'utf8')).toBe('something else');
    const swapped = installed('the pinned binary');
    expect(installedCosign(options(swapped.dir))).toBe(swapped.binary);
    writeFileSync(swapped.binary, 'swapped in afterwards');
    expect(() => installedCosign(options(swapped.dir))).toThrow('does not match its pinned SHA-256');
  });

  it('says how to install it when it is missing, and never downloads it for a check', () => {
    const dir = mkdtempSync(path.join(tools, 'absent-'));
    expect(() => installedCosign(options(dir))).toThrow(
      `cosign ${COSIGN_VERSION} isn't installed at ${cosignPath('linux', dir)}: run corepack pnpm tools:cosign to install it.`,
    );
  });

  it('installs a download that matches its pin, and refuses one that does not', async () => {
    const fresh = mkdtempSync(path.join(tools, 'fresh-'));
    const binary = await ensureCosign({ ...options(fresh), fetch: serve('the pinned binary') });
    expect(readFileSync(binary, 'utf8')).toBe('the pinned binary');
    expect(readdirSync(path.dirname(binary))).toEqual(['cosign']);
    const tampered = mkdtempSync(path.join(tools, 'tampered-'));
    await expect(ensureCosign({ ...options(tampered), fetch: serve('not the release') })).rejects.toThrow(
      'cosign-test does not match its pinned SHA-256',
    );
    expect(readdirSync(path.dirname(cosignPath('linux', tampered)))).toEqual([]);
  });

  it('checks against the real pins unless told otherwise', () => {
    const { dir } = installed('the pinned binary');
    expect(() => installedCosign({ platform: 'linux', arch: 'x64', toolsDir: dir })).toThrow(
      'does not match its pinned SHA-256',
    );
  });
});
