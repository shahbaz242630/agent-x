// B4-6d-1 end to end: a new organisation's first admin, as the partner makes
// one on staging (B4-6b). The operator's command, run from a request file as
// its job runs on Azure, creates an organisation and invites its first admin
// with a token's hash (the token itself made here, where the link would be
// shown); the invited person signs in through the API in a real Chrome, with
// their password and code, and accepts with the token: they join at once as
// its admin, since no one else is there, and a second first-admin invitation
// is then refused. Neither run writes the address, the token or its hash.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { type Browser, type BrowserContext, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { uuidV7Ids } from '../../packages/core/src/shared-kernel/ids.ts';
import { API_ORIGIN, type Run, runOperator, SECRETS_DIR } from './compose.ts';
import { loginDriver, where } from './login-pages.ts';

const { password, users } = inject('e2e');
const user = users.firstAdmin;
/** The address Zitadel holds for the user, verified (zitadel.ts's createHumanUser). */
const email = `${user.loginName}@agentx.localhost`;

/** Where the person goes once signed in: any path on the API's origin. */
const RETURN_TO = '/v1/after-first-admin';

const { drive } = loginDriver({
  password,
  callback: new RegExp(`^${`${API_ORIGIN}${RETURN_TO}`.replaceAll('.', '[.]')}$`),
});

/** Where the suite writes a request, and where the operator's container reads it (compose.yaml). */
const REQUESTS = path.join(SECRETS_DIR, 'operator-requests');
const MOUNTED = '/mnt/requests';

/** Writes a request file, a JSON list of the command's words, and gives its path in the container. */
function request(words: readonly string[]): string {
  mkdirSync(REQUESTS, { recursive: true });
  const name = `${randomUUID()}.json`;
  // Readable by the container's own user; nothing in it outlives the stack's secrets folder.
  writeFileSync(path.join(REQUESTS, name), JSON.stringify(words), { mode: 0o644 });
  return `${MOUNTED}/${name}`;
}

/** The events of a run's log lines, in order. */
const eventsOf = (run: Run): string[] =>
  run.stdout
    .split(String.fromCharCode(10))
    .filter((line) => line.startsWith('{'))
    .map((line) => String((JSON.parse(line) as { event?: unknown }).event));

/** A token as the partner's tool makes one: 32 random bytes in base64url, and its SHA-256 in hex. */
function newToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: createHash('sha256').update(token, 'ascii').digest('hex') };
}

const orgId = uuidV7Ids.next();
const first = newToken();
const runs: Run[] = [];

let browser: Browser;
let context: BrowserContext;
let page: Page;

beforeAll(async () => {
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  context = await browser.newContext();
  page = await context.newPage();
});

afterAll(async () => {
  await context.close();
  await browser.close();
});

/** A request to the API from the signed-in page, as the console will make it: same origin, the cookie sent by the browser. */
async function call(
  method: 'GET' | 'POST',
  route: string,
  { organization, body }: { organization?: string; body?: unknown } = {},
): Promise<{ status: number; json: unknown }> {
  return page.evaluate(
    async ({ method, route, organization, body, key }) => {
      const headers: Record<string, string> = { accept: 'application/json' };
      if (organization !== undefined) headers['agentx-organization'] = organization;
      if (body !== undefined) {
        headers['content-type'] = 'application/json';
        headers['idempotency-key'] = key;
      }
      const response = await fetch(route, {
        method,
        headers,
        ...(body !== undefined && { body: JSON.stringify(body) }),
      });
      return { status: response.status, json: await response.json() };
    },
    { method, route, organization, body, key: randomUUID() },
  );
}

describe('B4-6d-1 the operator invites a new organisation’s first admin, who accepts in a real browser', () => {
  it('creates the organisation from a request file, as its job does', async () => {
    const run = await runOperator([
      '--request',
      request(['create-organization', '--name', 'End-to-end Org', '--id', orgId]),
    ]);
    runs.push(run);

    expect(run.code, run.stderr).toBe(0);
    expect(eventsOf(run)).toContain('operator.organization_created');
  });

  it('invites its first admin with the token’s hash alone', async () => {
    const run = await runOperator([
      '--request',
      request([
        'invite-first-admin',
        '--org',
        orgId,
        '--email',
        email,
        '--id',
        uuidV7Ids.next(),
        '--token-hash',
        first.hash,
      ]),
    ]);
    runs.push(run);

    expect(run.code, run.stderr).toBe(0);
    expect(eventsOf(run)).toContain('operator.first_admin_invited');
  });

  it('signs the invited person in through the API with their password and code; they are no member yet', async () => {
    await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${encodeURIComponent(RETURN_TO)}`);
    const { stoppedAt, shown } = await drive(page, user, []);
    expect(stoppedAt, where(page)).toBe('callback');
    expect(shown).toEqual(['loginName', 'password', 'otp', 'callback']);

    expect((await call('GET', '/v1/members', { organization: orgId })).status).toBe(403);
  });

  it('SEC-HA-08 accepts with the token and joins at once as the admin, as no one else is there', async () => {
    const accepted = await call('POST', '/v1/invitations/accept', { body: { token: first.token } });

    expect(accepted.status).toBe(200);
    expect(accepted.json).toMatchObject({
      organizationId: orgId,
      invitation: { role: 'admin', status: 'ACCEPTED' },
    });
  });

  it('lists them in the organisation, the one active admin', async () => {
    const listed = await call('GET', '/v1/members', { organization: orgId });

    expect(listed.status).toBe(200);
    const { members } = listed.json as { members: { role: string; status: string }[] };
    expect(members.map(({ role, status }) => [role, status])).toEqual([['admin', 'ACTIVE']]);
  });

  it('refuses a second first-admin invitation now that someone is there, changing nothing', async () => {
    const run = await runOperator([
      '--request',
      request([
        'invite-first-admin',
        '--org',
        orgId,
        '--email',
        email,
        '--id',
        uuidV7Ids.next(),
        '--token-hash',
        newToken().hash,
      ]),
    ]);
    runs.push(run);

    expect(run.code).toBe(1);
    expect(eventsOf(run)).toContain('operator.refused');
    const listed = await call('GET', '/v1/members', { organization: orgId });
    expect((listed.json as { members: unknown[] }).members).toHaveLength(1);
  });

  it('writes neither the address, the token nor its hash in any run', () => {
    const written = runs.map((run) => run.stdout + run.stderr).join(String.fromCharCode(10));

    expect(runs).toHaveLength(3);
    for (const secret of [email, first.token, first.hash]) expect(written).not.toContain(secret);
  });
});
