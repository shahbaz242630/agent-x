// The console's files (Phase 6 6A1, ADR-001: the API serves the console, one
// origin, no CORS). They are served by a layer in front of Fastify, so the
// API's contract stays whole: every route Fastify serves is a JSON route its
// OpenAPI document holds (contract.ts, SEC-WEB-06), and none of them is here.
//
// The layer answers only what the console's build made, read into memory once
// at start: `index.html` and the files under `assets/` (Vite's hashed names).
// - A GET or HEAD of an asset by its exact path answers it, kept for a year
//   (its name changes whenever its bytes do).
// - A GET or HEAD of a console page (a plain path of lower-case letters,
//   digits and hyphens, outside /v1 and /health, with at most a plain query
//   for the page's filters) answers index.html, never kept, so a release
//   reaches every browser at its next page load.
// - Anything else goes on to Fastify, which answers it as it always has (a
//   dot, an upper-case letter, an asset with a query, a write: its JSON 404
//   or route).
// Each answer carries the security headers every API answer does: the CSP
// (`default-src 'self'; script-src 'self'`) holds the console to its own
// files, so the build inlines nothing (vite.config.ts).
import { readdir, readFile } from 'node:fs/promises';
import type { IncomingMessage, RequestListener, Server, ServerResponse } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type Environment, LOCAL_ONLY } from '@agentx/platform/config';
import type { Logger } from '@agentx/platform/observability';

import { SECURITY_HEADERS } from './security-headers.ts';

/** Where the image keeps the console's build (Dockerfile), beside the API's own files. */
const CONSOLE_DIR = fileURLToPath(new URL('../../console/dist', import.meta.url));

/** The kinds of file the build may hold, by extension. Any other file in it stops the API starting. */
const TYPES: Readonly<Record<string, string>> = {
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

/** An asset's published name, as Vite writes it: letters, digits, `-` and `_`, one dot, a known extension. */
const ASSET_NAME = /^[A-Za-z0-9_-]+\.[a-z0-9]+$/;

/** A console page's path: `/`, or segments of lower-case letters, digits and hyphens. The path part, never a dot. */
const PAGE_PATH = /^\/(?:[a-z0-9-]+(?:\/[a-z0-9-]+)*)?$/;

/** The first segments that are the API's own, never a console page. */
const API_SEGMENTS: ReadonlySet<string> = new Set(['v1', 'health']);

/** Hashed assets: their name changes with their bytes, so a browser may keep them. */
const KEPT = 'public, max-age=31536000, immutable';

interface ConsoleFile {
  readonly body: Buffer;
  readonly type: string;
}

/** The console's build, in memory: the page and its assets by published path. */
export interface ConsoleFiles {
  readonly page: Buffer;
  readonly assets: ReadonlyMap<string, ConsoleFile>;
}

function notThere(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}

/** Reads the console's build from `dir`: its page and every asset, each of a kind TYPES names. */
export async function readConsoleFiles(dir: string): Promise<ConsoleFiles> {
  const page = await readFile(join(dir, 'index.html'));
  const assets = new Map<string, ConsoleFile>();
  const entries = await readdir(join(dir, 'assets'), { withFileTypes: true }).catch((error: unknown) => {
    // A build with no assets at all is a page alone; anything else is a failure to read it.
    if (notThere(error)) return [];
    throw error;
  });
  for (const entry of entries) {
    const type = TYPES[extname(entry.name)];
    if (!entry.isFile() || type === undefined || !ASSET_NAME.test(entry.name)) {
      throw new Error(`The console's build holds a file it can't serve: assets/${entry.name}`);
    }
    assets.set(`/assets/${entry.name}`, { body: await readFile(join(dir, 'assets', entry.name)), type });
  }
  return { page, assets };
}

/**
 * The console's build, or undefined where it isn't there and needn't be: a
 * local run or a test, which serve the API alone. A deployed environment
 * without it stops starting, as a release that lost its console must not go
 * live as an API alone unseen.
 */
export async function loadConsoleFiles(
  environment: Environment,
  logger: Logger,
  dir: string = CONSOLE_DIR,
): Promise<ConsoleFiles | undefined> {
  try {
    const files = await readConsoleFiles(dir);
    logger.info('console.loaded', { assets: files.assets.size });
    return files;
  } catch (error) {
    if (!notThere(error) || !LOCAL_ONLY.includes(environment)) throw error;
    logger.info('console.off', { reason: 'no console build' });
    return undefined;
  }
}

/** A page's query: the filters a console page keeps in its address, in the characters a URL needs no escaping for. */
const PAGE_QUERY = /^[A-Za-z0-9\-._~%=&+]{0,512}$/;

/** Whether a path, with no query, names a console page, not an API address (browser-errors.ts checks reports by it). */
export function isPagePath(path: string): boolean {
  return PAGE_PATH.test(path) && !API_SEGMENTS.has(path.split('/')[1] ?? '');
}

/** Whether an address names a console page, not an API address: its path, and its query if any. */
function isPage(url: string): boolean {
  const [path = '', query, ...rest] = url.split('?');
  if (rest.length > 0 || (query !== undefined && !PAGE_QUERY.test(query))) return false;
  return isPagePath(path);
}

function send(response: ServerResponse, file: ConsoleFile, cacheControl?: string): void {
  response.writeHead(200, {
    ...SECURITY_HEADERS,
    ...(cacheControl !== undefined && { 'cache-control': cacheControl }),
    'content-type': file.type,
    'content-length': file.body.length,
  });
  // Node itself sends no body on an answer to a HEAD (the mutation pass, S149), only these headers.
  response.end(file.body);
}

/**
 * Answers a request for the console's files and says true, or leaves it
 * untouched and says false, for Fastify to answer.
 */
function answerConsoleFile(files: ConsoleFiles, request: IncomingMessage, response: ServerResponse): boolean {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  const url = request.url ?? '';
  const asset = files.assets.get(url);
  if (asset !== undefined) {
    send(response, asset, KEPT);
    return true;
  }
  if (!isPage(url)) return false;
  send(response, { body: files.page, type: 'text/html; charset=utf-8' });
  return true;
}

/**
 * Puts the console's layer in front of Fastify on the server Fastify made: its
 * one request listener (lib/server.js) is answered only for what the layer
 * leaves. Fastify's own server keeps its own timeouts, and no network module
 * is imported here (SEC-WEB-05's boundary rule). A host naming several
 * addresses (`localhost`) gets Fastify's extra servers without the layer: a
 * local run only, as a deployed API binds one address.
 */
export function putConsoleInFront(server: Server, files: ConsoleFiles): void {
  const listeners = server.listeners('request') as RequestListener[];
  const [fastify] = listeners;
  if (listeners.length !== 1 || fastify === undefined) {
    throw new Error(
      `The console expects Fastify's one request listener on its server, not ${String(listeners.length)}`,
    );
  }
  server.removeListener('request', fastify);
  server.on('request', (request: IncomingMessage, response: ServerResponse) => {
    if (!answerConsoleFile(files, request, response)) fastify(request, response);
  });
}
