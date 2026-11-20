import { beforeAll, describe, expect, it } from 'vitest';

import { authRoutes, authRules, consolePatch, consoleStateOf, readAuthDoor } from './auth-door.ts';
import { stagingApp } from './deploy.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

/** The auth door as staging's apps deployment sends it, from the pinned Bicep's own snapshot. */
let deployedRules: unknown;

beforeAll(() => {
  const staging = inCopy((dir) => environmentSnapshot(dir, 'staging')).together;
  const door = staging.predictedResources.find((resource) => resource.name.endsWith('/rtagentxstgauth'));
  deployedRules = (door?.properties as { rules?: unknown } | undefined)?.rules;
});

const door = readAuthDoor();

/** One item of a list, or a failure: the list is the test's own. */
function nth<T>(items: readonly T[], index: number): T {
  const item = items.at(index);
  if (item === undefined) throw new Error(`no item ${String(index)}`);
  return item;
}
const prefixes = (state: 'closed' | 'open'): string[] => authRoutes(state).map((route) => route.prefix);

describe('auth-door.json (PL-26)', () => {
  it('keeps every route a browser needs to sign in open, and the console and its services out of the closed door', () => {
    expect(prefixes('closed')).toEqual([
      '/debug',
      '/ui/v2/login',
      '/.well-known/',
      '/oauth/v2/',
      '/oidc/v1/',
      '/assets/v1/',
      '/',
    ]);
    // No gRPC service at all: the login app calls Zitadel from its server alone.
    expect(prefixes('closed').filter((prefix) => prefix.startsWith('/zitadel.'))).toEqual([]);
    expect(prefixes('closed')).not.toContain('/ui/console');
  });

  it('opens the console, its hosted login and its eleven services between the browser routes and the API', () => {
    const open = prefixes('open');
    expect(open.slice(0, 6)).toEqual(prefixes('closed').slice(0, 6));
    expect(open.at(-1)).toBe('/');
    expect(open.slice(6, -1)).toEqual([
      '/ui/console',
      '/ui/login',
      '/zitadel.admin.v1.AdminService/',
      '/zitadel.management.v1.ManagementService/',
      '/zitadel.auth.v1.AuthService/',
      '/zitadel.user.v2.UserService/',
      '/zitadel.session.v2.SessionService/',
      '/zitadel.feature.v2.FeatureService/',
      '/zitadel.action.v2.ActionService/',
      '/zitadel.webkey.v2.WebKeyService/',
      '/zitadel.org.v2.OrganizationService/',
      '/zitadel.authorization.v2.AuthorizationService/',
      '/zitadel.application.v2.ApplicationService/',
    ]);
    // Never Zitadel's system API or an instance service, and every service matched with its slash and its case.
    for (const route of door.console) {
      expect(route.prefix).not.toMatch(/zitadel\.(?:system|instance)\./);
      expect(route.anyCase).toBe(false);
      expect(route.reaches).toBe('zitadel');
    }
  });

  it('is what apps.bicep sends: the closed shape, rule for rule, so a door just deployed reads closed', () => {
    expect(deployedRules).toEqual(authRules('closed', stagingApp));
    expect(consoleStateOf(deployedRules, stagingApp)).toBe('closed');
  });
});

describe('consoleStateOf', () => {
  const closed = authRules('closed', stagingApp);
  const open = authRules('open', stagingApp);

  it('reads each shape, and fields Azure gives back as null as unset', () => {
    expect(consoleStateOf(closed, stagingApp)).toBe('closed');
    expect(consoleStateOf(open, stagingApp)).toBe('open');
    const echoed = structuredClone(open).map((rule) => ({
      ...rule,
      routes: rule.routes.map((route) => ({ ...route, action: null })),
      targets: rule.targets.map((target) => ({ ...target, revision: null, label: null })),
    }));
    expect(consoleStateOf(echoed, stagingApp)).toBe('open');
  });

  it('reads anything else as neither shape', () => {
    const changed = (change: (rules: ReturnType<typeof authRules>) => void): unknown => {
      const rules = structuredClone(closed);
      change(rules);
      return rules;
    };
    for (const rules of [
      undefined,
      null,
      [],
      'closed',
      closed.slice(1),
      [...closed].reverse(),
      // One console service let through on its own.
      [...closed.slice(0, -1), ...open.slice(8, 9), ...closed.slice(-1)],
      // The open shape a service short.
      open.filter((_rule, index) => index !== 9),
      changed((rules) => (nth(nth(rules, 2).routes, 0).match.caseSensitive = false)),
      changed((rules) => (nth(nth(rules, 2).routes, 0).match.prefix = '/')),
      changed((rules) => (nth(nth(rules, 6).targets, 0).containerApp = 'ca-agentx-stg-zitadel')),
      changed(
        (rules) => ((nth(nth(rules, 0).targets, 0) as Record<string, unknown>).revision = 'ca-agentx-stg-api--1'),
      ),
      changed((rules) => ((nth(nth(rules, 0).routes, 0) as Record<string, unknown>).action = { prefixRewrite: '/x' })),
      changed((rules) => (nth(rules, 3).description = 'something else')),
      // A rule after `/`, or a field Azure holds on the last rule: still a change, wherever it sits.
      [...closed, ...open.slice(8, 9)],
      [...open, ...closed.slice(0, 1)],
      changed((rules) => ((nth(rules, -1) as Record<string, unknown>).extra = 'x')),
    ]) {
      expect(consoleStateOf(rules, stagingApp)).toBeUndefined();
    }
  });

  it('names each app by the workload it reaches', () => {
    expect(authRules('closed', (workload) => `app-${workload}`).map((rule) => rule.targets[0]?.containerApp)).toEqual([
      'app-api',
      'app-login',
      'app-zitadel',
      'app-zitadel',
      'app-zitadel',
      'app-zitadel',
      'app-api',
    ]);
  });
});

describe('consolePatch', () => {
  it('sends the rules of the shape asked for, and the host exactly as read, nothing else', () => {
    const hosts = [{ name: 'auth.example.invalid', bindingType: 'Auto', certificateId: 'managed' }];
    expect(JSON.parse(consolePatch('open', hosts, stagingApp))).toEqual({
      properties: { customDomains: hosts, rules: authRules('open', stagingApp) },
    });
    expect(JSON.parse(consolePatch('closed', hosts, stagingApp))).toEqual({
      properties: { customDomains: hosts, rules: authRules('closed', stagingApp) },
    });
  });
});
