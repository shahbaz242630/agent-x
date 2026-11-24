// ADR-011 §6, SEC-WEB-02: the headers every response carries. The console and
// the API share one origin, so there's no CORS. The first request hook sets
// them, so refusals, errors and 404s carry them. Two answers are written before
// any hook runs, so they set them too: a malformed address (server.ts) and a
// request Node can't parse at all (client-errors.ts).
export const SECURITY_HEADERS = {
  // ADR-011 §6 as written: no inline scripts, no plugins, and nothing may frame the app.
  // form-action doesn't fall back to default-src (ZAP 10055), so it is set: a form sends only to us. Chrome also
  // holds a form's redirects to it, but no page here sends a form natively: every form's submit is prevented and
  // posted by fetch, and the OAuth consent, deny and device pages reach the app's redirect address by script
  // (goTo, after the API's JSON answer), which form-action doesn't govern. A native form ending in a 302 to a
  // redirect address would be blocked: keep it that way (oauth-requests.test.ts).
  'content-security-policy':
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
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
  // Before launch (partner S216: no one sees the pilot unless we decide): no search engine lists any page or follows
  // a link from it. A page's own <meta name="robots"> says the same for a crawler that reads only the HTML.
  'x-robots-tag': 'noindex, nofollow',
} as const;
