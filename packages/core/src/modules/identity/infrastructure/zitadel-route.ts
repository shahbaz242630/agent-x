// Where a call to the login service goes (B2-6). Azure's apps can't call their
// own public door, so with an internal origin every call to the issuer's
// origin goes there instead, carrying the issuer's host in Zitadel's
// `x-zitadel-instance-host` and `x-zitadel-public-host` headers, as the login
// pages do: Zitadel then answers as the issuer. Without one, the call goes to
// the URL itself. The OIDC client (B2-2) and the address book (B5-3) share it.

/** The URL and options a call to `url`, on the issuer's own origin, is sent with. */
export function routedToIssuer(
  issuer: string,
  internalOrigin: string | undefined,
  url: string,
  init: RequestInit,
): [string, RequestInit] {
  if (internalOrigin === undefined) return [url, init];
  const target = new URL(url);
  const headers = new Headers(init.headers);
  const { host } = new URL(issuer);
  headers.set('x-zitadel-instance-host', host);
  headers.set('x-zitadel-public-host', host);
  return [`${internalOrigin}${target.pathname}${target.search}`, { ...init, headers }];
}
