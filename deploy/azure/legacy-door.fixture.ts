// A test fixture: the auth door staging held before PL-26, for the tests that read it.
/**
 * Staging's live auth door before PL-26's first apps deploy, verbatim as Azure gave it back (a read-only GET of
 * httpRouteConfigs/rtagentxstgauth, api-version 2026-01-01, `properties.rules`, S206): Azure writes each match's
 * fields in its own order (caseSensitive before prefix), which the shape comparison must not mind.
 */
export const LEGACY_DOOR: unknown[] = [
  {
    description: "Zitadel's debug pages on the auth host get the API's 404",
    routes: [
      {
        match: {
          caseSensitive: false,
          prefix: '/debug',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-api',
      },
    ],
  },
  {
    description: 'The login pages on the auth host go to the login app',
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/ui/v2/login',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-login',
      },
    ],
  },
  {
    description: "Zitadel's OpenID discovery on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/.well-known/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "Zitadel's OAuth endpoints on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/oauth/v2/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "Zitadel's OpenID Connect endpoints on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/oidc/v1/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "Zitadel's console on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/ui/console',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "Zitadel's hosted login on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/ui/login',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "Zitadel's branding assets on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/assets/v1/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's AdminService (v1) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.admin.v1.AdminService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's ManagementService (v1) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.management.v1.ManagementService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's AuthService (v1) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.auth.v1.AuthService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's UserService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.user.v2.UserService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's SessionService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.session.v2.SessionService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's FeatureService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.feature.v2.FeatureService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's ActionService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.action.v2.ActionService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's WebKeyService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.webkey.v2.WebKeyService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's OrganizationService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.org.v2.OrganizationService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's AuthorizationService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.authorization.v2.AuthorizationService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: "The console's ApplicationService (v2) on the auth host",
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/zitadel.application.v2.ApplicationService/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-zitadel',
      },
    ],
  },
  {
    description: 'Every other path on the auth host goes to the API, which answers 404 on this host',
    routes: [
      {
        match: {
          caseSensitive: true,
          prefix: '/',
        },
      },
    ],
    targets: [
      {
        containerApp: 'ca-agentx-stg-api',
      },
    ],
  },
];
