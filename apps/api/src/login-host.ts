// SA1: the login service's public host is a door the API stands behind too.
// The auth door (deploy/azure/apps.bicep) sends every path it doesn't let
// through to Zitadel to the API, for its 404. But the API answers far more
// than 404s: the console's pages, sign-in, health and every /v1 route. Served
// on the login host, our console would share a browser origin with Zitadel's
// own console and the administrator tokens it keeps. So any request whose Host names the login
// service's public host (the OIDC issuer's) gets the API's plain 404, whatever
// its path or method, before the console's files or any route. Every other
// host (the app host, the internal one) is left alone.

/** A Host header's host name, lower case, without a trailing dot, and its port ('' for none); undefined if it isn't one. */
function hostOf(host: string): { readonly name: string; readonly port: string } | undefined {
  try {
    const url = new URL(`http://${host}`);
    // `new URL` keeps a path, user, query or fragment it finds, so a Host holding one isn't a plain host.
    if (url.pathname !== '/' || url.username !== '' || url.search !== '' || url.hash !== '') return undefined;
    return { name: url.hostname.replace(/\.$/, ''), port: url.port };
  } catch {
    return undefined;
  }
}

/**
 * Whether a request's Host names the login service's public host, given its
 * origin (the OIDC issuer); never, without one. The host name in any case,
 * on any port where the issuer names none: Azure's edge may match the door's
 * host whatever port a client wrote, so `auth.host:8443` is the login host
 * too. A port only where the issuer names one, so a local run's login service
 * on another port of localhost (http://localhost:8081) leaves the API's own
 * (localhost:8080) alone.
 */
export function loginHostCheck(issuer: string | undefined): (host: string | undefined) => boolean {
  if (issuer === undefined) return () => false;
  const login = new URL(issuer);
  const name = login.hostname.replace(/\.$/, '');
  return (host) => {
    const found = host === undefined ? undefined : hostOf(host);
    if (found?.name !== name) return false;
    return login.port === '' || found.port === login.port;
  };
}
