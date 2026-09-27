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
//
// B6-2c ends it: the admin's security key is removed in the login service
// itself, behind Agent X's back, as someone with rights in Zitadel's console
// could. At the API's next run of the events copier (made to come at once by
// restarting it, as a revision restarts) the change is on the organisation's
// audit chain and the platform chain, and the admin is told by email, through
// the stack's stand-in for ACS (SEC-OPS-02). On the way it pins down the event
// feed's span as the copier relies on it: an event at `since` itself is left
// out, and one a millisecond after is read.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { type Browser, type BrowserContext, chromium, type Page } from 'playwright';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

import { uuidV7Ids } from '../../packages/core/src/shared-kernel/ids.ts';
import { apiAnswers } from './api-sign-in.ts';
import {
  adminQuery,
  API_ORIGIN,
  LOGIN_ORIGIN,
  readAutomationToken,
  restartInPlace,
  type Run,
  runOperator,
  SECRETS_DIR,
  serviceLogs,
} from './compose.ts';
import { loginDriver, where } from './login-pages.ts';
import { eventsBetween, removeSecurityKey, securityKeysOf, zitadelClient } from './zitadel.ts';

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

describe('B6-2c a security key removed in the login service is copied into the audit trail and told', () => {
  /** Zitadel's own type for it, one the copier watches (idp-event.ts). */
  const REMOVED = 'user.human.mfa.u2f.token.removed';
  /** How long after its time the copier first reads an event (idp-copier.ts's SETTLE_MS), and a second more. */
  const SETTLED_MS = 61_000;
  /** The removal as Zitadel recorded it: its name as the copier writes it, and its time exactly as the feed gives it. */
  let removal: { key: string; creationDate: string };

  /** Zitadel's user IDs are digits; checked before one goes into a query. */
  const subject = (): string => {
    if (!/^[0-9]{1,32}$/.test(user.userId)) throw new Error('the test user ID is not the digits Zitadel issues');
    return user.userId;
  };

  /** A query's rows, one a line. */
  const rowsOf = async (query: string): Promise<string[]> =>
    (await adminQuery(query)).split(String.fromCharCode(10)).filter((row) => row !== '');

  /** Waits for a value, asking again every two seconds until the deadline. */
  async function eventually<T>(ask: () => Promise<T | undefined>, timeoutMs: number, what: string): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = await ask();
      if (found !== undefined) return found;
      if (Date.now() > deadline) throw new Error(`${what} after ${String(timeoutMs)} ms`);
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
  }

  it('removes the admin’s one security key as Zitadel’s console would, and finds the event in the feed', async () => {
    const zitadel = zitadelClient(LOGIN_ORIGIN, await readAutomationToken());
    const keys = await securityKeysOf(zitadel, subject());
    expect(keys).toHaveLength(1);
    const before = new Date(Date.now() - 5_000).toISOString();
    await removeSecurityKey(zitadel, subject(), keys[0] ?? '');

    const event = await eventually(
      async () =>
        (await eventsBetween(zitadel, [REMOVED], before, new Date(Date.now() + 5_000).toISOString())).find(
          ({ aggregate }) => aggregate.id === subject(),
        ),
      30_000,
      'the removal is still not in the feed',
    );
    removal = { key: `user:${subject()}:${String(event.sequence)}`, creationDate: event.creationDate };
  });

  it('reads the feed’s span as the copier relies on: `since` itself left out, a millisecond before it read', async () => {
    const zitadel = zitadelClient(LOGIN_ORIGIN, await readAutomationToken());
    const at = new Date(removal.creationDate);
    const until = new Date(at.getTime() + 5_000).toISOString();
    const found = async (since: string): Promise<boolean> =>
      (await eventsBetween(zitadel, [REMOVED], since, until)).some(({ aggregate }) => aggregate.id === subject());

    expect(await found(removal.creationDate)).toBe(false);
    expect(await found(new Date(at.getTime() - 1).toISOString())).toBe(true);
  });

  it(
    'SEC-OPS-02 copies it at the next run into the organisation’s chain and the platform chain',
    { timeout: 240_000 },
    async () => {
      // The copier reads only events a minute old, and its next run is five minutes off; a start runs it at once.
      const wait = new Date(removal.creationDate).getTime() + SETTLED_MS - Date.now();
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
      await restartInPlace('api');
      await apiAnswers();

      const onOrgChain = await eventually(
        async () => {
          const found = (
            await rowsOf(
              `SELECT subject_type || '|' || details FROM audit.events WHERE org_id = '${orgId}' ` +
                "AND action = 'person.sign_in_changed' ORDER BY seq",
            )
          )
            .map((row) => ({
              subjectType: row.slice(0, row.indexOf('|')),
              details: JSON.parse(row.slice(row.indexOf('|') + 1)) as Record<string, unknown>,
            }))
            .filter(({ details }) => details.event === removal.key);
          return found.length === 0 ? undefined : found;
        },
        60_000,
        'the removal is still not on the organisation’s chain',
      );
      expect(onOrgChain).toEqual([
        {
          subjectType: 'person',
          details: {
            event: removal.key,
            type: REMOVED,
            at: new Date(removal.creationDate).toISOString(),
            by: 'other',
          },
        },
      ]);

      const onPlatform = (
        await rowsOf("SELECT details FROM platform_controls.audit_events WHERE action = 'idp.event_copied'")
      )
        .map((row) => JSON.parse(row) as Record<string, unknown>)
        .filter((details) => details.event === removal.key);
      expect(onPlatform).toHaveLength(1);
      expect(onPlatform[0]).toMatchObject({ org: orgId, type: REMOVED, by: 'other' });
    },
  );

  it(
    'tells the admin once by email, as the person it is about, through the stand-in for ACS',
    { timeout: 180_000 },
    async () => {
      // Two notices: to the person, and to the admins but them (B6-2a review), which the sender
      // turns into none, as they are its one admin. The sender runs each minute; none given up.
      const toPerson = await eventually(
        async () => {
          const rows = (
            await rowsOf(
              "SELECT id || '|' || (recipient_user_id IS NULL) || '|' || (sent_at IS NOT NULL) || '|' || (given_up_at IS NOT NULL) " +
                `FROM notifications.outbox WHERE org_id = '${orgId}' AND kind = 'second_factor_removed'`,
            )
          ).map((row) => row.split('|'));
          if (rows.some(([, , , givenUp]) => givenUp === 'true')) throw new Error('a notice was given up');
          if (rows.length !== 2 || !rows.every(([, , sent]) => sent === 'true')) return undefined;
          expect(rows.filter(([, toGroup]) => toGroup === 'true')).toHaveLength(1);
          return rows.find(([, toGroup]) => toGroup === 'false')?.[0];
        },
        150_000,
        'the notices are still not sent',
      );

      const received = (await serviceLogs('mail'))
        .split(String.fromCharCode(10))
        .filter((line) => line.startsWith('{'))
        .map((line) => JSON.parse(line) as { event: string; to?: string[]; operationId?: string });
      expect(received.filter(({ event }) => event === 'mail.refused')).toEqual([]);
      expect(received.filter(({ operationId }) => operationId === toPerson)).toEqual([
        { event: 'mail.received', to: [email], subject: expect.any(String) as string, operationId: toPerson },
      ]);
    },
  );
});
