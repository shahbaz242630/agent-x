// Where an authorization code may be sent (OAuth 2.1 §2.3.1, RFC 8252 §7.3;
// SEC-OAUTH-03, -11): only to an address the client registered, matched
// exactly. A code sent anywhere else is a code given away, and an address
// matched loosely is an open redirect.
//
// - Registered: https, or http to the machine's own loopback (127.0.0.1,
//   [::1] or localhost: a native app on the person's own computer); no
//   fragment, no wildcard, no user or password, at most 512 characters.
// - Matched: the very text registered; for a loopback address any port (a
//   native app takes whichever is free, RFC 8252 §7.3), its scheme, host,
//   path and query exactly as registered.
const MOST_CHARACTERS = 512;

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', '[::1]', 'localhost']);

/** The address parsed, or undefined for text that is no absolute URL. */
const parsed = (text: string): URL | undefined => {
  try {
    return new URL(text);
  } catch {
    return undefined;
  }
};

/** Whether the address is plain http to this machine's own loopback. */
export function isLoopback(text: string): boolean {
  const url = parsed(text);
  return url?.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
}

/** Why the client can't register this address, if it can't. */
export function redirectProblems(text: string): string[] {
  if (text.length === 0 || text.length > MOST_CHARACTERS) {
    return [`a redirect address is 1 to ${String(MOST_CHARACTERS)} characters`];
  }
  const url = parsed(text);
  if (url === undefined) return ['a redirect address is an absolute URL'];
  const problems: string[] = [];
  if (text.includes('#')) problems.push('a redirect address has no fragment');
  if (text.includes('*')) problems.push('a redirect address has no wildcard');
  if (url.username !== '' || url.password !== '') problems.push('a redirect address names no user or password');
  if (url.protocol !== 'https:' && !isLoopback(text)) {
    problems.push("a redirect address is https, or http to the machine's own loopback");
  }
  return problems;
}

/** Whether `given` is an address the client registered as `registered`: exactly, or a loopback's on another port. */
export function redirectMatches(registered: string, given: string): boolean {
  if (given === registered) return true;
  if (!isLoopback(registered) || !isLoopback(given) || given.includes('#')) return false;
  const [one, other] = [parsed(registered), parsed(given)];
  if (one === undefined || other === undefined) return false;
  // The text after the port, as sent: the parser's own tidying of a path is never taken for the registered one. A host
  // not written as the parser prints it (capitals, a default port) is no match: none is ever needed.
  const afterPort = (text: string, url: URL): string | undefined => {
    const at = text.indexOf(`//${url.host}`);
    return at === -1 ? undefined : text.slice(at + 2 + url.host.length);
  };
  const path = afterPort(given, other);
  return (
    one.hostname === other.hostname &&
    other.username === '' &&
    other.password === '' &&
    path !== undefined &&
    afterPort(registered, one) === path &&
    // A port, if given, is digits alone: what the parser read as the port is what was sent.
    /^http:\/\/[^/?#]+(?::\d{1,5})?(?:[/?]|$)/.test(given)
  );
}

/** Whether `given` is one of the client's registered addresses. */
export const isRegisteredRedirect = (registered: readonly string[], given: string): boolean =>
  registered.some((one) => redirectMatches(one, given));
