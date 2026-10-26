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
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type Environment, LOCAL_ONLY } from '@agentx/platform/config';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyServerFactory } from 'fastify';

import { SECURITY_HEADERS } from './security-headers.ts';

/** Where the image keeps the console's build (Dockerfile), beside the API's own files. */
export const CONSOLE_DIR = fileURLToPath(new URL('../../console/dist', import.meta.url));

/** The kinds of file the build may hold, by extension. Any other file in it stops the API starting. */
const TYPES: Readonly<Record<string, string>> = {
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.woff2': 'font/woff2',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

/** An asset's published name, as Vite writes it: letters, digits, `-` and `_`, one dot, a known extension. */
const ASSET_NAME = /^[A-Za-z0-9_-]+\.[a-z0-9]+$/;

/** A console page's path: `/`, or segments of lower-case letters, digits and hyphens. No dot, no query. */
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

const notThere = (error: unknown): boolean => error instanceof Error && 'code' in error && error.code === 'ENOENT';

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

/** Whether an address names a console page, not an API address: its path, and its query if any. */
function isPage(url: string): boolean {
  const [path = '', query, ...rest] = url.split('?');
  if (rest.length > 0 || (query !== undefined && !PAGE_QUERY.test(query))) return false;
  if (!PAGE_PATH.test(path)) return false;
  const first = path.split('/')[1] ?? '';
  return !API_SEGMENTS.has(first);
}

function send(request: IncomingMessage, response: ServerResponse, file: ConsoleFile, keep: boolean): void {
  response.writeHead(200, {
    ...SECURITY_HEADERS,
    ...(keep ? { 'cache-control': KEPT } : {}),
    'content-type': file.type,
    'content-length': file.body.length,
  });
  response.end(request.method === 'HEAD' ? undefined : file.body);
}

/**
 * Answers a request for the console's files and says true, or leaves it
 * untouched and says false, for Fastify to answer.
 */
export function answerConsoleFile(files: ConsoleFiles, request: IncomingMessage, response: ServerResponse): boolean {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  const url = request.url ?? '';
  const asset = files.assets.get(url);
  if (asset !== undefined) {
    send(request, response, asset, true);
    return true;
  }
  if (!isPage(url)) return false;
  send(request, response, { body: files.page, type: 'text/html; charset=utf-8' }, false);
  return true;
}

/** Fastify's settings for the server it makes, each filled in by Fastify with its default when not given. */
const TIMEOUTS = ['keepAliveTimeout', 'requestTimeout', 'connectionTimeout', 'maxRequestsPerSocket'] as const;

/** The settings, each a number: Fastify fills every one in, so a missing one is a Fastify we don't know. */
function timeoutsOf(options: object): Record<(typeof TIMEOUTS)[number], number> {
  const read = (name: (typeof TIMEOUTS)[number]): number => {
    const value: unknown = (options as Record<string, unknown>)[name];
    if (typeof value !== 'number') throw new Error(`Fastify gave the server factory no ${name}`);
    return value;
  };
  return {
    keepAliveTimeout: read('keepAliveTimeout'),
    requestTimeout: read('requestTimeout'),
    connectionTimeout: read('connectionTimeout'),
    maxRequestsPerSocket: read('maxRequestsPerSocket'),
  };
}

/**
 * Fastify's server factory with the console's layer in front. Fastify sets its
 * timeouts only on a server it makes itself (lib/server.js), so this sets the
 * same ones from the options it is given: a slow client is cut off here as on
 * any other server of ours.
 */
export function consoleServer(files: ConsoleFiles): FastifyServerFactory {
  return (handler, options): Server => {
    const timeouts = timeoutsOf(options);
    const server = createServer((request, response) => {
      if (!answerConsoleFile(files, request, response)) handler(request, response);
    });
    server.keepAliveTimeout = timeouts.keepAliveTimeout;
    server.requestTimeout = timeouts.requestTimeout;
    server.setTimeout(timeouts.connectionTimeout);
    // Fastify's zero is Node's default, no limit (lib/server.js).
    if (timeouts.maxRequestsPerSocket > 0) server.maxRequestsPerSocket = timeouts.maxRequestsPerSocket;
    return server;
  };
}
