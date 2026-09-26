// B4-6d-1 end to end: a new organisation's first admin, as the partner makes
// one on staging (B4-6b). The operator's command, run from a request file as
// its job runs on Azure, creates an organisation and invites its first admin
// with a token's hash (the token itself made here, where the link would be
// shown); the invited person signs in through the API in a real Chrome, with
// their password and a security key registered at that first sign-in (an
// admin needs a passkey, B3+-1), and accepts with the token: they join at
// once as its admin, since no one else is there, and a second first-admin
// invitation is then refused. Neither run writes the address, the token or
// its hash.
//
// B4-6d-2 goes on from there, the journey an organisation's people take: the
// admin invites a second person as a developer, signing in again (step-up)
// before the link is made; that person, in their own browser, accepts and
// joins; the admin then makes them an admin and deactivates them, each change
// with a step-up by security key, and each ends every session the person held
// (SEC-HA-10). Signed in with their app code, the new admin may still read the
// members, and is refused an admin's change for want of a passkey (SEC-HA-12).
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
  // Chrome's own authenticator, through the DevTools protocol: the WebAuthn ceremony runs for real with no hardware.
  const devtools = await context.newCDPSession(page);
  await devtools.send('WebAuthn.enable');
  await devtools.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
});

afterAll(async () => {
  await context.close();
  await browser.close();
});

/** A request to the API from the signed-in page, as the console will make it: same origin, the cookie sent by the browser. */
async function call(
  method: 'GET' | 'POST',
  route: string,
  { organization, body, on = page }: { organization?: string; body?: unknown; on?: Page } = {},
): Promise<{ status: number; json: unknown }> {
  return on.evaluate(
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

  it('signs the invited person in through the API, registering a security key as the login asks for a second factor; they are no member yet', async () => {
    await page.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${encodeURIComponent(RETURN_TO)}`);
    const { stoppedAt } = await drive(page, user, ['factorSetup']);
    expect(stoppedAt, where(page)).toBe('factorSetup');
    await page.locator('a[href*="/ui/v2/login/u2f/set"]').click();
    await page.waitForURL(/\/ui\/v2\/login\/u2f\/set/);
    const deviceName = page.locator('input[name=name]');
    if ((await deviceName.count()) > 0) await deviceName.fill('end-to-end key');
    await page.getByTestId('submit-button').click();
    await page.waitForURL((url) => url.href.startsWith(`${API_ORIGIN}${RETURN_TO}`), { timeout: 60_000 });

    const session = await call('GET', '/v1/auth/session');
    expect((session.json as { methods: string[] }).methods).toContain('user');

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

describe('B4-6d-2 the admin invites a second person, then changes their role and deactivates them', () => {
  const member = users.member;
  const memberEmail = `${member.loginName}@agentx.localhost`;
  let memberContext: BrowserContext;
  let memberPage: Page;
  /** The second person's membership, once they have joined. */
  let membershipId: string;

  beforeAll(async () => {
    memberContext = await browser.newContext();
    memberPage = await memberContext.newPage();
  });

  afterAll(async () => {
    await memberContext.close();
  });

  // The person's own driver: each driver waits for a code its last one hasn't
  // used, so the admin's driver never gives the admin a code twice.
  const memberLogin = loginDriver({
    password,
    callback: new RegExp(`^${`${API_ORIGIN}${RETURN_TO}`.replaceAll('.', '[.]')}$`),
  });

  /** Signs the second person in through the API, however much the login still knows of them. */
  async function signIn(): Promise<void> {
    await memberPage.goto(`${API_ORIGIN}/v1/auth/sign-in?returnTo=${encodeURIComponent(RETURN_TO)}`);
    const { stoppedAt } = await memberLogin.drive(memberPage, member, []);
    expect(stoppedAt, where(memberPage)).toBe('callback');
  }

  /** The admin signs in again for a challenge (ADR-003 §9): the password and security key are asked again. */
  async function stepUp(challengeId: string): Promise<void> {
    await page.goto(`${API_ORIGIN}/v1/auth/step-up?challenge=${challengeId}&returnTo=${encodeURIComponent(RETURN_TO)}`);
    const { stoppedAt, shown } = await drive(page, user, []);
    expect(stoppedAt, where(page)).toBe('callback');
    expect(shown).toEqual(expect.arrayContaining(['password', 'u2f', 'callback']));
  }

  /** The organisation's members, as the admin sees them, by membership. */
  async function members(): Promise<Map<string, { role: string; status: string }>> {
    const listed = await call('GET', '/v1/members', { organization: orgId });
    expect(listed.status).toBe(200);
    const { members: found } = listed.json as { members: { id: string; role: string; status: string }[] };
    return new Map(found.map(({ id, role, status }) => [id, { role, status }]));
  }

  /** Whether the person's page still holds a live session. */
  const signedIn = async (on: Page): Promise<number> =>
    on.evaluate(async () => (await fetch('/v1/auth/session')).status);

  it('asks to invite them as a developer: a draft, and a step-up to sign in again for', async () => {
    const asked = await call('POST', '/v1/members/invitations', {
      organization: orgId,
      body: { email: memberEmail, role: 'developer' },
    });
    expect(asked.status).toBe(202);
    const { invitation, stepUpChallengeId } = asked.json as {
      invitation: { id: string; status: string };
      stepUpChallengeId: string;
    };
    expect(invitation.status).toBe('DRAFT');

    // Not before the admin has signed in again for it.
    const early = await call('POST', `/v1/members/invitations/${invitation.id}/confirm`, {
      organization: orgId,
      body: {},
    });
    expect(early.status).toBe(403);
    expect(early.json).toMatchObject({ error: { code: 'STEP_UP_FAILED' } });

    await stepUp(stepUpChallengeId);
    const confirmed = await call('POST', `/v1/members/invitations/${invitation.id}/confirm`, {
      organization: orgId,
      body: {},
    });
    expect(confirmed.status).toBe(200);
    const { link } = confirmed.json as { link: string };
    expect(link.startsWith(`${API_ORIGIN}/invitations/accept#token=`)).toBe(true);

    await signIn();
    const token = link.slice(link.indexOf('#token=') + '#token='.length);
    const accepted = await call('POST', '/v1/invitations/accept', { on: memberPage, body: { token } });
    expect(accepted.status).toBe(200);
    expect(accepted.json).toMatchObject({
      organizationId: orgId,
      invitation: { role: 'developer', status: 'ACCEPTED' },
    });
  });

  it('lists them beside the admin, and lets them read the list as a developer', async () => {
    const listed = await members();
    const joined = [...listed].filter(([, { role }]) => role === 'developer');
    expect(joined).toHaveLength(1);
    membershipId = joined[0]?.[0] ?? '';
    expect(listed.size).toBe(2);

    expect((await call('GET', '/v1/members', { organization: orgId, on: memberPage })).status).toBe(200);
  });

  it('SEC-HA-10 makes them an admin with a step-up, and ends every session they held', async () => {
    expect(await signedIn(memberPage)).toBe(200);
    const asked = await call('POST', `/v1/members/${membershipId}/role`, {
      organization: orgId,
      body: { role: 'admin' },
    });
    expect(asked.status).toBe(202);
    const { stepUpChallengeId } = asked.json as { stepUpChallengeId: string };
    await stepUp(stepUpChallengeId);

    const changed = await call('POST', `/v1/members/${membershipId}/role/confirm`, {
      organization: orgId,
      body: { role: 'admin', stepUpChallengeId },
    });
    expect(changed.status).toBe(200);
    expect(changed.json).toMatchObject({ member: { id: membershipId, role: 'admin', status: 'ACTIVE' } });
    expect(await signedIn(memberPage)).toBe(401);
  });

  it('SEC-HA-12 lets the new admin, signed in with an app code, read the members, and refuses them an admin’s change', async () => {
    await signIn();
    expect((await call('GET', '/v1/members', { organization: orgId, on: memberPage })).status).toBe(200);

    const refused = await call('POST', '/v1/members/invitations', {
      organization: orgId,
      on: memberPage,
      body: { email: 'someone-else@agentx.localhost', role: 'viewer' },
    });
    expect(refused.status).toBe(403);
    expect(refused.json).toMatchObject({ error: { code: 'PASSKEY_REQUIRED' } });
  });

  it('SEC-HA-10 deactivates them with a step-up: every session ends, and they reach the organisation no more', async () => {
    const asked = await call('POST', `/v1/members/${membershipId}/deactivate`, { organization: orgId, body: {} });
    expect(asked.status).toBe(202);
    const { stepUpChallengeId } = asked.json as { stepUpChallengeId: string };
    await stepUp(stepUpChallengeId);

    const changed = await call('POST', `/v1/members/${membershipId}/deactivate/confirm`, {
      organization: orgId,
      body: { stepUpChallengeId },
    });
    expect(changed.status).toBe(200);
    expect(changed.json).toMatchObject({ member: { id: membershipId, status: 'DEACTIVATED' } });
    expect(await signedIn(memberPage)).toBe(401);
    expect((await members()).get(membershipId)).toMatchObject({ status: 'DEACTIVATED' });

    // They can still sign in to Agent X, and are refused the organisation.
    await signIn();
    expect((await call('GET', '/v1/members', { organization: orgId, on: memberPage })).status).toBe(403);
  });
});
