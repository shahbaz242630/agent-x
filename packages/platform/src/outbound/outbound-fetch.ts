// SEC-WEB-05: the app calls only origins on the config allowlist. Every
// outbound HTTP request made by our code goes through here; lint and the
// boundary rules keep fetch and the network modules out of the rest of the
// product.
// - Redirects are never followed: one from an allowed origin could point anywhere.
// - Only a fixed set of fetch options is accepted: Node's fetch also takes a
//   `dispatcher`, which could send the request to any host.
// - TLS certificate checks are confirmed on before every request (SEC-PTR-07).
import { tlsChecksOff } from '../config/index.ts';

/** A fetch that refuses every URL whose origin is not on the allowlist. */
export type OutboundFetch = (url: string | URL, init?: RequestInit) => Promise<Response>;

export class OutboundRefused extends Error {
  constructor(reason: string) {
    super(`Outbound request refused: ${reason}`);
    this.name = 'OutboundRefused';
  }
}

type Send = (url: URL, init: RequestInit) => Promise<Response>;

/** The fetch options a caller may set. `duplex` is needed to stream a request body. */
const ALLOWED_OPTIONS = new Set(['method', 'headers', 'body', 'signal', 'duplex', 'redirect']);

/** The statuses fetch treats as redirects (the Fetch standard's redirect statuses). */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * `allowedOrigins` comes from the checked config (`config.outbound`). `send`
 * is the network call itself; tests replace it.
 */
export function createOutboundFetch(
  allowedOrigins: readonly string[],
  send: Send = (url, init) => fetch(url, init),
): OutboundFetch {
  const allowed = new Set(allowedOrigins);

  return async (url, init = {}) => {
    if (tlsChecksOff()) {
      throw new OutboundRefused('TLS certificate checks are off (NODE_TLS_REJECT_UNAUTHORIZED), so nothing is sent');
    }
    const target = parseAbsolute(url);
    // Only the origin is ever named in an error: a path or query can carry tokens.
    if (target.username !== '' || target.password !== '') {
      throw new OutboundRefused(`${target.origin} has a user name or password in the URL`);
    }
    if (!allowed.has(target.origin)) {
      throw new OutboundRefused(`${target.origin} is not on the outbound allowlist`);
    }
    const unsupported = Object.keys(init).filter((option) => !ALLOWED_OPTIONS.has(option));
    if (unsupported.length > 0) {
      throw new OutboundRefused(`the fetch option ${unsupported.join(', ')} is not allowed`);
    }
    if (init.redirect !== undefined && init.redirect !== 'error') {
      throw new OutboundRefused('redirects are never followed');
    }

    // 'manual' hands a redirect back instead of following it, so it's refused with a clear error.
    const response = await send(target, { ...init, redirect: 'manual' });
    if (REDIRECT_STATUSES.has(response.status)) {
      await response.body?.cancel();
      throw new OutboundRefused(`${target.origin} answered with a redirect, and redirects are never followed`);
    }
    return response;
  };
}

function parseAbsolute(url: string | URL): URL {
  const text = String(url);
  if (!URL.canParse(text)) throw new OutboundRefused('the URL is not absolute');
  return new URL(text);
}
