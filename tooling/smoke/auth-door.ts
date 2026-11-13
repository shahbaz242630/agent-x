// SA1 on every release: the auth host's door (deploy/azure/apps.bicep) lets
// through only what a browser needs from Zitadel, and the API answers every
// other request on that host with its plain 404 (apps/api/src/login-host.ts).
// So staging's auth host must still serve Zitadel's sign-in discovery, and
// must answer its root, the API's health and Zitadel's system API with the
// API's JSON 404, never our console's page. The host is the app host's
// sibling (`app.` becomes `auth.`, as security-weekly.yml's certificate check
// finds it), so no domain is written here; each line names a path, never the
// host. Node builtins only.
import { askAwake, REAL, type Ways } from './ask.ts';

/** The auth host's origin beside the app host's: `https://app.<domain>` gives `https://auth.<domain>`. */
export function authOriginOf(appOrigin: string): string {
  const url = new URL(appOrigin);
  if (!url.hostname.startsWith('app.')) {
    throw new Error('AGENTX_SMOKE_ORIGIN must be the app host (app.<domain>), whose sibling auth.<domain> is checked');
  }
  url.hostname = `auth.${url.hostname.slice('app.'.length)}`;
  return url.origin;
}

interface Check {
  /** What the line names: the method and path, never the host. */
  readonly name: string;
  readonly path: string;
  readonly init: { readonly method?: string; readonly headers: Record<string, string>; readonly body?: string };
  /** What's wrong with the final answer, said in plain words (what happened, what broke, what next), or nothing. */
  readonly problem: (status: number, type: string, text: string, authOrigin: string) => string | undefined;
}

const NEXT_404 =
  'check the API has AGENTX_OIDC_ISSUER set to the auth origin and the auth door still ends with "/" to the API (deploy/azure/apps.bicep, SA1)';

/** Whether a body is the API's own JSON 404. */
function isApi404(type: string, text: string): boolean {
  if (!type.startsWith('application/json')) return false;
  try {
    const body = JSON.parse(text) as { error?: { code?: unknown } } | null;
    return body?.error?.code === 'NOT_FOUND';
  } catch {
    return false;
  }
}

/** A path the API must answer with its plain 404, never a page, a route or Zitadel. */
const api404 =
  (what: string) =>
  (status: number, type: string, text: string): string | undefined => {
    if (status === 404 && isApi404(type, text) && !/<!doctype html/i.test(text)) return undefined;
    const said = /<!doctype html/i.test(text) ? 'a page' : type === '' ? 'no content type' : type;
    return `answered ${String(status)} with ${said}, not the API's JSON 404: ${what} is reachable on the auth host; ${NEXT_404}`;
  };

/** Zitadel's discovery, through the allow-list: a JSON object naming the auth origin as its issuer. */
function discovery(status: number, type: string, text: string, authOrigin: string): string | undefined {
  const next = 'check the auth door still sends /.well-known/ to Zitadel and Zitadel is up (Incident playbook)';
  if (status !== 200) return `answered ${String(status)}, not Zitadel's sign-in discovery: nobody can sign in; ${next}`;
  let issuer: unknown;
  try {
    issuer = (JSON.parse(text) as { issuer?: unknown } | null)?.issuer;
  } catch {
    issuer = undefined;
  }
  if (issuer === authOrigin) return undefined;
  return `answered 200 (${type}), but not with Zitadel's discovery for the auth origin: sign-in may go to the wrong place; ${next} and its external domain`;
}

/** The checks, in order: Zitadel reached first, so a sleeping Zitadel wakes before the 404s are judged. */
export const CHECKS: readonly Check[] = [
  {
    name: 'GET /.well-known/openid-configuration',
    path: '/.well-known/openid-configuration',
    init: { headers: { accept: 'application/json' } },
    problem: discovery,
  },
  {
    name: 'GET /',
    path: '/',
    init: { headers: { accept: 'text/html' } },
    problem: api404("our console's page"),
  },
  {
    name: 'GET /health',
    path: '/health',
    init: { headers: { accept: 'application/json' } },
    problem: api404("the API's health"),
  },
  {
    name: 'POST /zitadel.system.v1.SystemService/ListInstances',
    path: '/zitadel.system.v1.SystemService/ListInstances',
    init: { method: 'POST', headers: { 'content-type': 'application/grpc-web+proto' }, body: '' },
    problem: api404("Zitadel's system API"),
  },
];

/** Every check's line, said as soon as known, and whether all passed: `<name>: ok`, or what was wrong. */
export async function checkAuthDoor(
  authOrigin: string,
  ways: Partial<Ways> = {},
  say: (line: string) => void = () => undefined,
): Promise<{ readonly lines: string[]; readonly passed: boolean }> {
  const all = { ...REAL, ...ways };
  const lines: string[] = [];
  let passed = true;
  for (const check of CHECKS) {
    const asked = await askAwake(`${authOrigin}${check.path}`, check.init, all);
    let problem: string | undefined;
    if ('waited' in asked) {
      problem = `answered ${asked.waited}: the auth host did not answer; check the auth door and its apps are running (Incident playbook)`;
    } else {
      const { answer } = asked;
      problem = check.problem(answer.status, answer.headers.get('content-type') ?? '', await answer.text(), authOrigin);
    }
    const line = `auth host ${check.name}: ${problem ?? 'ok'}`;
    if (problem !== undefined) passed = false;
    say(line);
    lines.push(line);
  }
  return { lines, passed };
}
