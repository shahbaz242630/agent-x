// A test fixture: the auth door staging held before PL-26, for the tests that read it.
/**
 * The auth door as every apps deploy sent it before PL-26 (apps.bicep at 904eb1f9, rule for rule): staging's live
 * door until the first apps deploy after it.
 */
export const LEGACY_DOOR = (
  [
    ["Zitadel's debug pages on the auth host get the API's 404", '/debug', true, 'api'],
    ['The login pages on the auth host go to the login app', '/ui/v2/login', false, 'login'],
    ["Zitadel's OpenID discovery on the auth host", '/.well-known/', false, 'zitadel'],
    ["Zitadel's OAuth endpoints on the auth host", '/oauth/v2/', false, 'zitadel'],
    ["Zitadel's OpenID Connect endpoints on the auth host", '/oidc/v1/', false, 'zitadel'],
    ["Zitadel's console on the auth host", '/ui/console', false, 'zitadel'],
    ["Zitadel's hosted login on the auth host", '/ui/login', false, 'zitadel'],
    ["Zitadel's branding assets on the auth host", '/assets/v1/', false, 'zitadel'],
    ["The console's AdminService (v1) on the auth host", '/zitadel.admin.v1.AdminService/', false, 'zitadel'],
    [
      "The console's ManagementService (v1) on the auth host",
      '/zitadel.management.v1.ManagementService/',
      false,
      'zitadel',
    ],
    ["The console's AuthService (v1) on the auth host", '/zitadel.auth.v1.AuthService/', false, 'zitadel'],
    ["The console's UserService (v2) on the auth host", '/zitadel.user.v2.UserService/', false, 'zitadel'],
    ["The console's SessionService (v2) on the auth host", '/zitadel.session.v2.SessionService/', false, 'zitadel'],
    ["The console's FeatureService (v2) on the auth host", '/zitadel.feature.v2.FeatureService/', false, 'zitadel'],
    ["The console's ActionService (v2) on the auth host", '/zitadel.action.v2.ActionService/', false, 'zitadel'],
    ["The console's WebKeyService (v2) on the auth host", '/zitadel.webkey.v2.WebKeyService/', false, 'zitadel'],
    [
      "The console's OrganizationService (v2) on the auth host",
      '/zitadel.org.v2.OrganizationService/',
      false,
      'zitadel',
    ],
    [
      "The console's AuthorizationService (v2) on the auth host",
      '/zitadel.authorization.v2.AuthorizationService/',
      false,
      'zitadel',
    ],
    [
      "The console's ApplicationService (v2) on the auth host",
      '/zitadel.application.v2.ApplicationService/',
      false,
      'zitadel',
    ],
    ['Every other path on the auth host goes to the API, which answers 404 on this host', '/', false, 'api'],
  ] as const
).map(([description, prefix, anyCase, reaches]) => ({
  description,
  routes: [{ match: { prefix, caseSensitive: !anyCase } }],
  targets: [{ containerApp: `ca-agentx-stg-${reaches}` }],
}));
