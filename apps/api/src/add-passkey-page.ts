// The add-a-passkey page (SA6), served on its own host just below the login service's (AGENTX_ADD_PASSKEY_ORIGIN,
// addkey.auth.<site>): a passkey made there is the login service's own, for its host, and works at its sign-in
// (S220's probe of the pinned Zitadel and its login pages). A host of its own, not a path on the login service's:
// the login service's session cookies are its host's alone, so none reaches this page, and nothing here can call
// the login service's pages as their own origin.
//
// One page, one script, one stylesheet, nothing else on the host (server.ts's host gate): served ahead of Fastify, as
// the console's files are (console-files.ts), on the page's host alone; every other request there goes on to Fastify,
// which answers the page's two calls (passkey-additions.ts) and a plain 404 for anything else. The page reads
// the one-time ticket from its address's fragment, which no request carries, and drops it from the address at once.
// Its policy lets it run only its own script, which the page also names by its SHA-256 (subresource integrity), talk
// only to its own host, and be framed by nothing; nothing is cached. The script writes only text, never markup.

import { createHash } from 'node:crypto';
import type { IncomingMessage, RequestListener, Server, ServerResponse } from 'node:http';

import { SECURITY_HEADERS } from './security-headers.ts';

/** The page's path on its host; the console opens it with `#<ticket>`. */
export const ADD_PASSKEY_PATH = '/add-passkey';
export const ADD_PASSKEY_SCRIPT_PATH = '/add-passkey.js';
export const ADD_PASSKEY_STYLE_PATH = '/add-passkey.css';

/** The page's own script: plain browser JavaScript, served as it stands. */
export const ADD_PASSKEY_SCRIPT = `'use strict';
(() => {
  const TICKET = /^[A-Za-z0-9_-]{43}$/;
  const ticket = window.location.hash.slice(1);
  window.history.replaceState(null, '', window.location.pathname);
  const status = document.getElementById('status');
  const button = document.getElementById('make');
  const say = (text) => {
    status.textContent = text;
  };
  const fromBase64 = (text) => {
    const plain = text.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(plain.padEnd(Math.ceil(plain.length / 4) * 4, '=')), (c) => c.charCodeAt(0));
  };
  const toBase64 = (buffer) =>
    btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const post = async (path, body) => {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
    });
    return { ok: response.ok, body: await response.json().catch(() => ({})) };
  };
  const startAgain = ' Go back to Agent X and start adding the passkey again.';
  if (typeof window.PublicKeyCredential !== 'function') {
    say("This browser can't make passkeys. Open Agent X in another browser and start again there.");
    return;
  }
  if (!TICKET.test(ticket)) {
    say('This page only works from the link Agent X opens.' + startAgain);
    return;
  }
  button.hidden = false;
  say("Press the button, then follow your device's prompt to make your new passkey.");
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      say('Getting ready...');
      const asked = await post('/v1/passkey-additions/options', { ticket });
      if (!asked.ok) {
        say('This link has run out, or was used already.' + startAgain);
        return;
      }
      const publicKey = asked.body.options.publicKey;
      publicKey.challenge = fromBase64(publicKey.challenge);
      publicKey.user = { ...publicKey.user, id: fromBase64(publicKey.user.id) };
      publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map((each) => ({
        ...each,
        id: fromBase64(each.id),
      }));
      say("Follow your device's prompt...");
      let made;
      try {
        made = await navigator.credentials.create({ publicKey });
      } catch {
        say('No passkey was made.' + startAgain);
        return;
      }
      say('Saving your new passkey...');
      const sent = await post('/v1/passkey-additions/confirm', {
        ticket,
        credential: {
          id: made.id,
          rawId: toBase64(made.rawId),
          type: made.type,
          response: {
            attestationObject: toBase64(made.response.attestationObject),
            clientDataJSON: toBase64(made.response.clientDataJSON),
          },
        },
      });
      say(
        sent.ok
          ? 'Your new passkey is added. You can close this tab and go back to Agent X.'
          : 'Your new passkey was not added.' + startAgain,
      );
    } catch {
      say('Something went wrong, and no passkey was added.' + startAgain);
    }
  });
})();
`;

/** The page's own stylesheet: the console's Calm Ledger colours, light and dark. */
export const ADD_PASSKEY_STYLE = `:root { color-scheme: light dark; --bg: #f5f4f1; --fg: #1b1a18; --accent: #0e5c57; }
@media (prefers-color-scheme: dark) { :root { --bg: #121211; --fg: #edebe6; --accent: #5cc0b3; } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 32rem; margin: 4rem auto; padding: 0 16px; }
button { font: inherit; padding: 0.6rem 1.2rem; border: 0; border-radius: 6px; background: var(--accent); color: var(--bg); cursor: pointer; }
button:disabled { opacity: 0.6; cursor: default; }
`;

/** The integrity attribute's value for a file: its SHA-256, base64. */
const integrityOf = (text: string): string => `sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}`;

export const ADD_PASSKEY_SCRIPT_INTEGRITY = integrityOf(ADD_PASSKEY_SCRIPT);
const STYLE_INTEGRITY = integrityOf(ADD_PASSKEY_STYLE);

/** The page: no inline script or style, its script and stylesheet named by their hashes. */
export const ADD_PASSKEY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Add a passkey - Agent X</title>
<link rel="stylesheet" href="${ADD_PASSKEY_STYLE_PATH}" integrity="${STYLE_INTEGRITY}">
<script src="${ADD_PASSKEY_SCRIPT_PATH}" integrity="${ADD_PASSKEY_SCRIPT_INTEGRITY}" defer></script>
</head>
<body>
<main>
<h1>Add a passkey to Agent X</h1>
<p id="status" role="status" aria-live="polite">Loading...</p>
<button id="make" type="button" hidden>Make my new passkey</button>
</main>
</body>
</html>
`;

/**
 * The page's own policy: its own host's script and stylesheet only, calls to its own host only, no frames, forms,
 * images or plugins, framed by nothing, and only text written by script (Trusted Types).
 */
export const ADD_PASSKEY_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  'trusted-types',
].join('; ');

/** The page's files by path, each with its type. */
const FILES: ReadonlyMap<string, { readonly type: string; readonly body: Buffer }> = new Map([
  [ADD_PASSKEY_PATH, { type: 'text/html; charset=utf-8', body: Buffer.from(ADD_PASSKEY_HTML) }],
  [ADD_PASSKEY_SCRIPT_PATH, { type: 'text/javascript; charset=utf-8', body: Buffer.from(ADD_PASSKEY_SCRIPT) }],
  [ADD_PASSKEY_STYLE_PATH, { type: 'text/css; charset=utf-8', body: Buffer.from(ADD_PASSKEY_STYLE) }],
]);

/**
 * Puts the page's files in front of Fastify on its server, for requests `onPageHost` picks: a GET or HEAD of one of
 * them is answered with the page's own policy and the security headers, never kept; anything else goes on to Fastify.
 * Expects the server's one request listener (Fastify's, or the console's layer in front of it).
 */
export function putAddPasskeyPageInFront(server: Server, onPageHost: (host: string | undefined) => boolean): void {
  const listeners = server.listeners('request') as RequestListener[];
  const [next] = listeners;
  if (listeners.length !== 1 || next === undefined) {
    throw new Error(
      `The add-a-passkey page expects one request listener on its server, not ${String(listeners.length)}`,
    );
  }
  server.removeListener('request', next);
  server.on('request', (request: IncomingMessage, response: ServerResponse) => {
    const file = FILES.get(request.url ?? '');
    if (
      file === undefined ||
      (request.method !== 'GET' && request.method !== 'HEAD') ||
      !onPageHost(request.headers.host)
    ) {
      next(request, response);
      return;
    }
    response.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-security-policy': ADD_PASSKEY_CSP,
      'content-type': file.type,
      'content-length': file.body.length,
    });
    response.end(file.body);
  });
}
