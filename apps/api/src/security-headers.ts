// ADR-011 §6, SEC-WEB-02: the headers every response carries. The console and
// the API share one origin, so there's no CORS. The first request hook sets
// them, so refusals, errors and 404s carry them. Two answers are written before
// any hook runs, so they set them too: a malformed address (server.ts) and a
// request Node can't parse at all (client-errors.ts).
export const SECURITY_HEADERS = {
  // ADR-011 §6 as written: no inline scripts, no plugins, and nothing may frame the app.
  'content-security-policy':
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  // Once a browser has seen this over https, it uses only https for a year.
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  // Responses can hold account data, so no browser or proxy keeps a copy.
  'cache-control': 'no-store',
  // frame-ancestors, for browsers that don't read it.
  'x-frame-options': 'DENY',
  // A response is read only as the type it declares.
  'x-content-type-options': 'nosniff',
  // Not `no-referrer`: under it, a browser sends `Origin: null` on the console's
  // own form posts, which the Origin check (SEC-WEB-01) would refuse. Other
  // sites still get no referrer.
  'referrer-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
} as const;
