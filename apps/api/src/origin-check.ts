// SEC-WEB-01 (threat WEB-2, cross-site request forgery): a request that can
// change something must come from the app's own origin. Browsers send `Origin`
// on such requests and a page elsewhere can't forge it, so a missing or
// foreign one is refused, before the body is read. GET and HEAD only read, so
// they pass. Agents calling the API with their keys (Phase 1) send no Origin;
// a browser never attaches an agent key by itself, so a request that carries
// one will need its own rule here.
const READ_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD']);

/** True when a request that can change something didn't come from `publicOrigin`. */
export function isForeignWrite(method: string, origin: string | undefined, publicOrigin: string): boolean {
  return !READ_METHODS.has(method) && origin !== publicOrigin;
}
