// 6A1: the console's files, served by the layer in front of Fastify, through a
// real server listening (the layer is the server's own handler, so Fastify's
// inject never reaches it). A page and an asset answer with the security
// headers; an API address, a write, a dot or a query on an asset go on to
// Fastify's JSON 404. Requests go through the outbound client, allowed this
// one local origin, as all of our HTTP does (SEC-WEB-05).
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import type { Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createOutboundFetch } from '@agentx/platform/outbound';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { type ConsoleFiles, loadConsoleFiles, putConsoleInFront, readConsoleFiles } from './console-files.ts';
import { SECURITY_HEADERS } from './security-headers.ts';
import { buildServer } from './server.ts';

const PAGE = '<!doctype html><title>Agent X</title><script type="module" src="/assets/index-Ab12_c.js"></script>';
const SCRIPT = 'console.log("console")';

let directory: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'agentx-console-'));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

/** A build in a folder of its own: the page, and the assets named. */
async function build(name: string, assets: Readonly<Record<string, string>>): Promise<string> {
  const dir = join(directory, name);
  await mkdir(join(dir, 'assets'), { recursive: true });
  await writeFile(join(dir, 'index.html'), PAGE, { mode: 0o600 });
  for (const [file, text] of Object.entries(assets)) {
    await writeFile(join(dir, 'assets', file), text, { mode: 0o600 });
  }
  return dir;
}

const logged = () => {
  const capture = new LogCapture();
  const config = {
    environment: 'test' as const,
    release: 'r-1',
    log: { level: 'info' as const, eventCapPerMinute: 100 },
  };
  return { capture, logger: createLogger({ service: 'api', config, destination: capture }) };
};

const servers: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** The API with the console's files, listening on a port of its own; its address. */
async function listening(files: ConsoleFiles) {
  const { logger } = logged();
  const app = await buildServer({
    config: {
      http: {
        host: '127.0.0.1',
        port: 0,
        publicOrigin: 'https://app.agentx.example',
        trustedProxies: [],
        rateLimitPerMinute: 1000,
        rateLimitPerUserPerMinute: 1000,
        rateLimitPerAgentPerMinute: 1000,
      },
      log: { level: 'info', eventCapPerMinute: 10_000 },
    },
    logger,
    ids: new SequentialIds(),
    healthChecks: [],
    consoleFiles: files,
  });
  servers.push(app);
  await app.listen({ host: '127.0.0.1', port: 0 });
  const [address] = app.addresses();
  const base = `http://127.0.0.1:${String(address?.port)}`;
  const fetch = createOutboundFetch([base]);
  return { base, app, fetch };
}

describe('the console’s files (6A1)', () => {
  it('serves the page at the root and at any console path, never kept, with the security headers', async () => {
    const { base, fetch } = await listening(
      await readConsoleFiles(await build('pages', { 'index-Ab12_c.js': SCRIPT })),
    );
    for (const path of [
      '/',
      '/approvals',
      '/approvals/0199a0f0-0000-7000-8000-00000000abcd',
      '/payments?status=unknown',
    ]) {
      const answer = await fetch(base + path);
      expect(answer.status, path).toBe(200);
      expect(await answer.text()).toBe(PAGE);
      expect(answer.headers.get('content-type')).toBe('text/html; charset=utf-8');
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(answer.headers.get(name), name).toBe(value);
    }
  });

  it('serves an asset by its exact path, kept for a year, and a HEAD with no body', async () => {
    const { base, fetch } = await listening(
      await readConsoleFiles(await build('assets', { 'index-Ab12_c.js': SCRIPT })),
    );
    const answer = await fetch(`${base}/assets/index-Ab12_c.js`);
    expect(answer.status).toBe(200);
    expect(await answer.text()).toBe(SCRIPT);
    expect(answer.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
    expect(answer.headers.get('cache-control')).toBe('public, max-age=31536000, immutable');
    expect(answer.headers.get('content-security-policy')).toBe(SECURITY_HEADERS['content-security-policy']);
    const head = await fetch(`${base}/assets/index-Ab12_c.js`, { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBe(String(SCRIPT.length));
    expect(await head.text()).toBe('');
  });

  it('leaves everything else to Fastify: API addresses, writes, unknown assets, dots, capitals and odd queries', async () => {
    const { base, fetch } = await listening(
      await readConsoleFiles(await build('others', { 'index-Ab12_c.js': SCRIPT })),
    );
    const notOurs: [string, RequestInit?][] = [
      ['/v1'],
      ['/v1/agents'],
      ['/health/deep'],
      ['/assets/missing-1.js'],
      ['/assets/index-Ab12_c.js?v=1'],
      ['/favicon.ico'],
      ['/Approvals'],
      ['/approvals/../v1/agents'],
      ['/approvals?a=|b'],
      ['/approvals?a=1?b=2'],
      ['/approvals', { method: 'POST', headers: { origin: 'https://app.agentx.example' } }],
    ];
    for (const [path, init] of notOurs) {
      const answer = await fetch(base + path, init);
      expect(answer.headers.get('content-type'), path).toMatch(/^application\/json/);
      expect([404, 401], path).toContain(answer.status);
    }
  });

  it('keeps Fastify’s own server and its timeouts', async () => {
    const { app } = await listening(await readConsoleFiles(await build('timeouts', {})));
    expect(app.server.requestTimeout).toBe(30_000);
    expect(app.server.listeners('request')).toHaveLength(1);
  });

  it('refuses a server without exactly one request listener to stand in front of', () => {
    const files = { page: Buffer.from(PAGE), assets: new Map() };
    const bare = new EventEmitter() as unknown as Server;
    expect(() => {
      putConsoleInFront(bare, files);
    }).toThrow("Fastify's one request listener on its server, not 0");
    bare.on('request', () => undefined);
    bare.on('request', () => undefined);
    expect(() => {
      putConsoleInFront(bare, files);
    }).toThrow('not 2');
  });

  it('refuses a build holding a file it can’t serve, or one named unlike a hashed asset', async () => {
    await expect(readConsoleFiles(await build('unknown-kind', { 'notes.txt': 'x' }))).rejects.toThrow(
      'assets/notes.txt',
    );
    await expect(readConsoleFiles(await build('two-dots', { 'a.b.js': 'x' }))).rejects.toThrow('assets/a.b.js');
  });

  it('serves a page alone when the build has no assets folder', async () => {
    const dir = join(directory, 'page-only');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'index.html'), PAGE, { mode: 0o600 });
    const files = await readConsoleFiles(dir);
    expect(files.assets.size).toBe(0);
    expect(files.page.toString()).toBe(PAGE);
  });
});

describe('loading the console’s build at start (6A1)', () => {
  it('loads a build there, and logs how many assets', async () => {
    const { capture, logger } = logged();
    const files = await loadConsoleFiles('staging', logger, await build('loaded', { 'index-Ab12_c.js': SCRIPT }));
    expect(files?.assets.size).toBe(1);
    expect(capture.lines()).toEqual([expect.objectContaining({ event: 'console.loaded', assets: 1 })]);
  });

  it('serves the API alone locally when there is no build', async () => {
    const { capture, logger } = logged();
    expect(await loadConsoleFiles('development', logger, join(directory, 'none'))).toBeUndefined();
    expect(capture.lines()).toEqual([expect.objectContaining({ event: 'console.off', reason: 'no console build' })]);
  });

  it('stops a deployed API starting without its console, and any environment on a build it can’t read', async () => {
    const { logger } = logged();
    await expect(loadConsoleFiles('staging', logger, join(directory, 'none'))).rejects.toThrow(/ENOENT/);
    await expect(loadConsoleFiles('test', logger, await build('bad', { 'x.txt': 'x' }))).rejects.toThrow(
      'assets/x.txt',
    );
  });
});
