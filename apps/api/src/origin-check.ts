// SEC-WEB-01 (threat WEB-2, cross-site request forgery): a request that can
// change something must come from the app's own origin. Browsers send `Origin`
// on such requests and a page elsewhere can't forge it, so a missing or
// foreign one is refused, before the body is read. GET and HEAD only read, so
// they pass.
//
// C2-1: agents call the API with their keys and send no Origin. A request
// carrying an Authorization header, to a route naming agents, is let past
// this rule: the access hook then judges it as an agent's alone, by its key,
// never by a cookie, so there is no session a forged request could ride on.
// And a page elsewhere can't send one: Authorization isn't a header a browser
// sends across sites without a CORS preflight, which the API never grants.
const READ_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD']);

/** True when a request that can change something didn't come from `publicOrigin`. */
export function isForeignWrite(method: string, origin: string | undefined, publicOrigin: string): boolean {
  return !READ_METHODS.has(method) && origin !== publicOrigin;
}

/** True when a request is an agent's, to be judged by its key alone: it carries one, to a route naming agents. */
export function isAgentsRequest(authorization: string | undefined, access: readonly string[]): boolean {
  return authorization !== undefined && access.includes('agent');
}
