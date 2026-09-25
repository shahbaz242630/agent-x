// The login service's break-glass admin (B4-6c): the person Zitadel makes when
// it is first set up, who administers the login service itself and is never an
// Agent X person. Its verified email can be anyone's (on staging, the
// partner's own, which their everyday login shares), so it is known by its
// login name instead: the username `admin` in the first organisation, `Agent
// X`, whose domain Zitadel makes from the name under the issuer's host, as in
// `admin@agent-x.auth.example.com`. Zitadel names a login that way, or by the
// username alone where an instance doesn't suffix login names with their
// organisation's domain. apps.bicep and the compose stack set up Zitadel with
// this username and organisation (the deploy policy's tests hold them to it).

/** The username Zitadel's first admin is set up with (`ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME`). */
export const BREAK_GLASS_USERNAME = 'admin';

/** The organisation Zitadel is first set up with (`ZITADEL_FIRSTINSTANCE_ORG_NAME`). */
export const FIRST_ORGANIZATION = 'Agent X';

/** The organisation's domain under the login service's host, as Zitadel makes it from the name. */
const FIRST_ORGANIZATION_LABEL = FIRST_ORGANIZATION.toLowerCase().replaceAll(' ', '-');

/**
 * Whether a login name (OIDC's `preferred_username`) is the break-glass
 * admin's at this issuer: the username alone, or with the first
 * organisation's domain, in any case. Anything that isn't text is not.
 */
export function isBreakGlassLogin(loginName: unknown, issuer: string): boolean {
  if (typeof loginName !== 'string') return false;
  // A URL's host comes out in lower case.
  const host = new URL(issuer).hostname;
  const name = loginName.toLowerCase();
  return name === BREAK_GLASS_USERNAME || name === `${BREAK_GLASS_USERNAME}@${FIRST_ORGANIZATION_LABEL}.${host}`;
}
