/**
 * The auth host's public door (SA1, PL-26), read from auth-door.json, the one place its routes are listed: apps.bicep
 * compiles the same file. The door has two shapes, and only two:
 * - closed, the normal one: `browser` then `fallback`. A browser can sign in; Zitadel's console and the admin and
 *   management services its browser code calls are reachable from nowhere outside
 * - open, for a piece of work in Zitadel's console: `browser`, `console`, then `fallback`
 * Every apps deploy sends it closed; `deploy.ts console --open` / `--close` moves it between the two with a PATCH of
 * its rules alone. Anything else is a door nobody decided on: the policy, the console step and the infrastructure plan
 * each refuse it.
 *
 * Kept free of deploy.ts and policy.ts (both import this), so no module loads half-made.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

/** One route as auth-door.json writes it, and as apps.bicep sends it. */
export interface DoorRoute {
  readonly description: string;
  readonly prefix: string;
  /** Whether the match ignores case: only where another case would find nothing anyway (the API's 404). */
  readonly anyCase: boolean;
  /** The workload it reaches, as names.bicep `appName` takes it. */
  readonly reaches: string;
}

interface DoorFile {
  readonly browser: readonly DoorRoute[];
  readonly console: readonly DoorRoute[];
  readonly fallback: readonly DoorRoute[];
}

const DOOR_FILE = path.join(import.meta.dirname, 'auth-door.json');

export const readAuthDoor = (): DoorFile => JSON.parse(readFileSync(DOOR_FILE, 'utf8')) as DoorFile;

export type ConsoleState = 'closed' | 'open';

/**
 * A shape a live door may be found in: one of the two, or `legacy`, the door every apps deploy sent before PL-26
 * (the console open, its pages before the branding assets). Never sent again; read so the first plan after PL-26
 * plans the apps deploy that closes it, rather than stopping red on a door it knows.
 */
export type DoorShape = ConsoleState | 'legacy';

/** The door's routes in order, in the shape asked for. */
export function authRoutes(state: DoorShape, door: DoorFile = readAuthDoor()): readonly DoorRoute[] {
  if (state === 'closed') return [...door.browser, ...door.fallback];
  if (state === 'open') return [...door.browser, ...door.console, ...door.fallback];
  // Before PL-26 the console's page and hosted login sat after the OpenID routes and before the branding assets.
  const assets = door.browser.findIndex((route) => route.prefix === '/assets/v1/');
  return [
    ...door.browser.slice(0, assets),
    ...door.console.slice(0, 2),
    ...door.browser.slice(assets),
    ...door.console.slice(2),
    ...door.fallback,
  ];
}

/**
 * The rules Azure takes for a shape, exactly as apps.bicep writes them (its `publicDoors` map): one route and one
 * target each, case as the file says, nothing rewritten, nothing pinned. `appOf` names a workload's app.
 */
export function authRules(state: DoorShape, appOf: (workload: string) => string, door: DoorFile = readAuthDoor()) {
  return authRoutes(state, door).map((route) => ({
    description: route.description,
    routes: [{ match: { prefix: route.prefix, caseSensitive: !route.anyCase } }],
    targets: [{ containerApp: appOf(route.reaches) }],
  }));
}

/**
 * A value read back from Azure in one canonical form: each object's fields in name order, since Azure writes them in
 * its own (a match comes back caseSensitive before prefix, S206: the first plan after PL-26 read staging's door as
 * neither shape for that alone), and without the fields it fills with null (an unset rewrite or pin may come back so).
 * Any field with a value is kept, so a rewrite, a pin or anything else Azure holds reads as a change; arrays keep
 * their order, which is the order Azure tries the rules in.
 */
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (typeof value !== 'object' || value === null) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, each]) => each !== null)
      .toSorted(([one], [other]) => (one < other ? -1 : Number(one > other)))
      .map(([field, each]) => [field, canonical(each)]),
  );
}

const asText = (rules: unknown): string => JSON.stringify(canonical(rules ?? null));

/**
 * Which shape a door's rules, as Azure gives them back, are in: closed, open, legacy, or neither (undefined).
 * Compared whole, field for field and in order, so a route added, dropped, moved, widened or pointed elsewhere is
 * neither.
 */
export function consoleStateOf(
  rules: unknown,
  appOf: (workload: string) => string,
  door: DoorFile = readAuthDoor(),
): DoorShape | undefined {
  const live = asText(rules);
  return (['closed', 'open', 'legacy'] as const).find((state) => asText(authRules(state, appOf, door)) === live);
}

/** The PATCH body that moves the door to a shape: its rules alone, and its host sent back exactly as read. */
export function consolePatch(
  state: ConsoleState,
  customDomains: unknown,
  appOf: (workload: string) => string,
  door: DoorFile = readAuthDoor(),
): string {
  return JSON.stringify({ properties: { customDomains, rules: authRules(state, appOf, door) } });
}
