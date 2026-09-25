// B4-3a: invitations and their tokens' directory entries (0016), on the real
// migrated schema, as the app role. What the owner can do past the app is
// invitations-tamper.db.test.ts.
import { createHash } from 'node:crypto';

import { createTestDatabase, FixedClock, LogCapture, SequentialIds, type TestDatabase } from '@agentx/testing';
import { createDatabase, type Database, TenantContextError, withTenant } from '@agentx/platform/db';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';

import { type AuditTables, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedInvite, registerInvite } from '../../directory/index.ts';
import { createOrganization, type OrganizationsTables } from '../../organizations/index.ts';
import { INVITATION_HOURS } from '../domain/invitation.ts';
import type { Role } from '../domain/membership.ts';
import {
  acceptInvitation,
  draftInvitation,
  invitationChange,
  invitationRecord,
  invitationToAccept,
  invitationToOpen,
  inviteTokenHash,
  openInvitation,
} from './invitations.ts';
import { addMembership } from './memberships.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

type Tables = IdentityTables & OrganizationsTables & DirectoryTables & AuditTables;

const server = inject('postgres');
let database: TestDatabase;
let app: Database<Tables>;

/** Stand-in keys, one per purpose. */
const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
// Each ID has a hex letter in it, so looking one up in upper case is another string.
const ids = new SequentialIds(0xb000_0000_0000);
const clock = new FixedClock(new Date('2026-09-25T09:00:00Z'));

let capture: LogCapture;
const services = () => ({
  keys,
  ids,
  logger: createLogger({
    service: 'test',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  }),
});

const OPERATOR = { type: 'system' as const, id: 'test-operator' };
const alarms = () => capture.lines().filter((line) => line.event === 'audit.integrity_failed');
const HOUR = 3_600_000;
const EVIDENCE = { stepUpChallengeId: '0199a0f0-0000-7000-8000-00000000c0de', methods: 'pwd,otp,mfa' };

let subjects = 0;
/** A new organisation with an admin in it, as the operator's command and B4-6 make them. */
async function organization(): Promise<{ org: string; admin: string; adminUser: string }> {
  const org = ids.next();
  subjects += 1;
  const adminUser = await userForSubject(
    app,
    { issuer: 'https://auth.example.test', subject: `inviter-${String(subjects)}` },
    { ids, clock },
  );
  const admin = ids.next();
  await withSignedStates(app, org, services(), async (tx, states) => {
    await createOrganization(tx, states, { id: org, name: 'Acme Trading LLC', actor: OPERATOR });
    await addMembership(tx, states, {
      orgId: org,
      id: admin,
      userId: adminUser,
      role: 'admin',
      joinedAt: clock.now(),
      actor: OPERATOR,
    });
  });
  return { org, admin, adminUser };
}

/** Asks for an invitation as the admin, a DRAFT, with the challenge's ID given. */
async function draft(
  { org, admin, adminUser }: { org: string; admin: string; adminUser: string },
  {
    email = 'Sara.Khan@Example.test',
    role = 'developer',
    inside = org,
    invitedBy = admin,
  }: { email?: string; role?: Role; inside?: string; invitedBy?: string } = {},
) {
  const id = ids.next();
  const stepUpChallengeId = ids.next();
  const { change, changeHash } = invitationChange({
    orgId: org,
    id,
    email,
    role,
    invitedBy,
    createdAt: clock.now(),
  });
  const recorded = await withSignedStates(app, inside, services(), (tx, states) =>
    draftInvitation(tx, states, keys, change, {
      stepUpChallengeId,
      createdAt: clock.now(),
      actor: { type: 'user', id: adminUser },
    }),
  );
  return { id, stepUpChallengeId, change, changeHash, recorded };
}

const toOpen = (org: string, id: string, now = clock.now()) =>
  withSignedStates(app, org, services(), (tx, states) => invitationToOpen(tx, states, keys, { orgId: org, id, now }));

const record = (org: string, id: string) =>
  withSignedStates(app, org, services(), (tx, states) => invitationRecord(tx, states, org, id));

/** Reads the draft for the change and opens it, as the confirm route does once the step-up is consumed. */
const open = (org: string, id: string, adminUser: string) =>
  withSignedStates(app, org, services(), async (tx, states) => {
    const read = await invitationToOpen(tx, states, keys, { orgId: org, id, now: clock.now() });
    if (read.outcome !== 'draft') return read;
    const token = await openInvitation(tx, states, {
      orgId: org,
      id,
      actor: { type: 'user', id: adminUser },
      details: EVIDENCE,
    });
    return { outcome: 'opened' as const, token };
  });

/** The directory's entries for the organisation. */
const invitesOf = (org: string) =>
  withTenant(app, org, (tx) => tx.selectFrom('directory.invites').selectAll().where('org_id', '=', org).execute());

const sha256 = (text: string): Buffer => createHash('sha256').update(text, 'ascii').digest();

beforeAll(async () => {
  database = await createTestDatabase(server, { schema: 'migrated' });
  app = createDatabase<Tables>(
    { ...database.connection('app'), maxConnections: 4 },
    createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: new LogCapture(),
    }),
  );
});

afterAll(async () => {
  await app.destroy();
  await database.drop();
});

beforeEach(() => {
  capture = new LogCapture();
});

describe(`asking for an invitation (B4-3a, Postgres ${server.version})`, () => {
  it('keeps it as a DRAFT with its role, the admin, its end and the challenge, signed, the address encrypted', async () => {
    const who = await organization();

    const { id, stepUpChallengeId, recorded } = await draft(who, { role: 'approver' });

    expect(recorded).toMatchObject({ version: 1, seq: 4n });
    expect(await record(who.org, id)).toEqual({
      outcome: 'found',
      invitation: {
        id,
        role: 'approver',
        status: 'DRAFT',
        expiresAt: new Date(clock.now().getTime() + INVITATION_HOURS * HOUR),
        stepUpChallengeId,
        byOperator: false,
        acceptedBy: null,
      },
    });
    const { row, event } = await withTenant(app, who.org, async (tx) => ({
      row: await tx.selectFrom('identity.invitations').selectAll().executeTakeFirstOrThrow(),
      event: await tx
        .selectFrom('audit.events')
        .select(['actor_type', 'actor_id', 'action', 'subject_type', 'subject_id', 'subject_version', 'details'])
        .where('seq', '=', 4n)
        .executeTakeFirstOrThrow(),
    }));
    expect(row).toMatchObject({
      org_id: who.org,
      id,
      role: 'approver',
      status: 'DRAFT',
      invited_by: who.admin,
      created_at: clock.now(),
      email_key_version: 1,
      step_up_challenge_id: stepUpChallengeId,
      state_version: 1,
      state_event_id: recorded.eventId.toLowerCase(),
    });
    // Encrypted: nothing of the address is in the row, in either case.
    expect(row.email_ciphertext.toString('latin1').toLowerCase()).not.toContain('sara');
    expect(row.email_ciphertext.length).toBe(12 + 16 + 'sara.khan@example.test'.length);
    expect(event).toMatchObject({
      actor_type: 'user',
      actor_id: who.adminUser,
      action: 'invitation.drafted',
      subject_type: 'invitation',
      subject_id: id,
      subject_version: 1,
    });
    expect(JSON.parse(event.details)).toMatchObject({ role: 'approver' });
    expect(event.details.toLowerCase()).not.toContain('sara');
    expect(alarms()).toEqual([]);
  });

  it('gives the same change and hash back for the draft as it was asked with, the address in lower case', async () => {
    const who = await organization();
    const { id, change, changeHash } = await draft(who);

    const read = await toOpen(who.org, id);

    expect(change.email).toBe('sara.khan@example.test');
    expect(read).toMatchObject({ outcome: 'draft', change, changeHash });
    if (read.outcome !== 'draft') throw new Error('not a draft');
    expect(read.changeHash.equals(changeHash)).toBe(true);
  });

  it('finds the draft whatever case its ID is given in', async () => {
    const who = await organization();
    const { id, changeHash } = await draft(who);

    expect(await record(who.org, id.toUpperCase())).toMatchObject({ outcome: 'found', invitation: { id } });
    expect(await toOpen(who.org, id.toUpperCase())).toMatchObject({ outcome: 'draft', changeHash, invitation: { id } });
  });

  it('refuses an admin who is a membership of another organisation, by the key to the memberships', async () => {
    const who = await organization();
    const elsewhere = await organization();

    await expect(draft(who, { invitedBy: elsewhere.admin })).rejects.toMatchObject({
      code: '23503',
      constraint: 'asked_by_a_member',
    });
  });

  it("refuses a transaction that isn't withTenant's for the organisation", async () => {
    const who = await organization();
    const other = await organization();

    // The tenant policy refuses the row before any signed state is written.
    await expect(draft(who, { inside: other.org })).rejects.toMatchObject({ code: '42501' });
  });

  it('is not found from another organisation', async () => {
    const who = await organization();
    const other = await organization();
    const { id } = await draft(who);

    expect(await record(other.org, id)).toEqual({ outcome: 'missing' });
    expect(await toOpen(other.org, id)).toEqual({ outcome: 'missing' });
  });

  it("won't let the app change the address, or delete the invitation", async () => {
    const who = await organization();
    const { id } = await draft(who);

    await expect(
      withTenant(app, who.org, (tx) =>
        tx
          .updateTable('identity.invitations')
          .set({ email_ciphertext: Buffer.alloc(40) })
          .where('id', '=', id)
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '42501' });
    await expect(
      withTenant(app, who.org, (tx) => tx.deleteFrom('identity.invitations').where('id', '=', id).execute()),
    ).rejects.toMatchObject({ code: '42501' });
  });
});

describe(`the table's own checks, past the module (B4-3a, Postgres ${server.version})`, () => {
  /** Writes a row past the module, in a transaction rolled back if nothing refuses it. */
  const written = (org: string, admin: string, changes: Record<string, unknown>) =>
    withTenant(app, org, async (tx) => {
      await tx
        .insertInto('identity.invitations')
        .values({
          org_id: org,
          id: ids.next(),
          role: 'viewer',
          status: 'DRAFT',
          invited_by: admin,
          expires_at: new Date(clock.now().getTime() + HOUR),
          created_at: clock.now(),
          email_ciphertext: Buffer.alloc(29),
          email_key_version: 1,
          step_up_challenge_id: ids.next(),
          ...changes,
        })
        .execute();
      throw new Error('rolled back');
    });

  it('takes a row within every check, so each refusal below is its own', async () => {
    const who = await organization();

    await expect(written(who.org, who.admin, {})).rejects.toThrow('rolled back');
  });

  it.each([
    ['a role that isn’t one of the four', { role: 'owner' }, 'invitations_role_check'],
    ['a role in another case', { role: 'Admin' }, 'invitations_role_check'],
    ['a status that isn’t one', { status: 'ACCEPTED' }, 'status_guard'],
    [
      'an end no later than its start',
      { expires_at: new Date('2026-09-25T09:00:00Z') },
      'invitation_ends_after_it_begins',
    ],
    ['an address too short to be sealed', { email_ciphertext: Buffer.alloc(28) }, 'invitations_email_ciphertext_check'],
    ['an address too long', { email_ciphertext: Buffer.alloc(1025) }, 'invitations_email_ciphertext_check'],
    ['a key version below 1', { email_key_version: 0 }, 'invitations_email_key_version_check'],
    ['a new row OPEN', { status: 'OPEN' }, 'status_guard'],
  ])('refuses %s', async (_what, changes, constraint) => {
    const who = await organization();

    await expect(written(who.org, who.admin, changes)).rejects.toMatchObject({ code: '23514', constraint });
  });

  it('keeps an address of up to 1,024 sealed bytes', async () => {
    const who = await organization();

    await expect(written(who.org, who.admin, { email_ciphertext: Buffer.alloc(1024) })).rejects.toThrow('rolled back');
  });

  it('refuses a token’s entry that isn’t a SHA-256', async () => {
    const who = await organization();

    for (const length of [31, 33]) {
      await expect(
        withTenant(app, who.org, (tx) =>
          tx
            .insertInto('directory.invites')
            .values({ token_hash: Buffer.alloc(length), org_id: who.org, invitation_id: ids.next() })
            .execute(),
        ),
      ).rejects.toMatchObject({ code: '23514', constraint: 'invites_token_hash_check' });
    }
  });

  it('the backup role reads both tables, as a logical backup must', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await open(who.org, id, who.adminUser);
    const backup = database.as('backup');

    expect(await backup.query('select id from identity.invitations where id = $1', [id])).toEqual([{ id }]);
    expect(await backup.query('select invitation_id from directory.invites where invitation_id = $1', [id])).toEqual([
      { invitation_id: id },
    ]);
  });
});

describe(`opening an invitation (B4-3a, Postgres ${server.version})`, () => {
  it('lists the token by its SHA-256, moves it to OPEN and signs the step-up’s evidence on the event', async () => {
    const who = await organization();
    const { id, stepUpChallengeId } = await draft(who, { role: 'admin' });

    const opened = await open(who.org, id, who.adminUser);

    if (opened.outcome !== 'opened') throw new Error(`not opened: ${opened.outcome}`);
    expect(opened.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await record(who.org, id)).toMatchObject({
      outcome: 'found',
      invitation: { id, role: 'admin', status: 'OPEN', stepUpChallengeId },
    });
    const { entries, event } = await withTenant(app, who.org, async (tx) => ({
      entries: await tx.selectFrom('directory.invites').selectAll().where('org_id', '=', who.org).execute(),
      event: await tx
        .selectFrom('audit.events')
        .select(['actor_id', 'action', 'subject_id', 'subject_version', 'details'])
        .where('action', '=', 'invitation.opened')
        .executeTakeFirstOrThrow(),
    }));
    expect(entries).toEqual([{ token_hash: sha256(opened.token), org_id: who.org, invitation_id: id }]);
    expect(event).toMatchObject({ actor_id: who.adminUser, subject_id: id, subject_version: 2 });
    expect(JSON.parse(event.details)).toMatchObject({ ...EVIDENCE, statusFrom: 'DRAFT', statusTo: 'OPEN' });
    // The token is kept nowhere: not in the event, not in the directory.
    expect(event.details).not.toContain(opened.token);
    expect(alarms()).toEqual([]);
  });

  it('makes a new token each time', async () => {
    const who = await organization();
    const first = await open(who.org, (await draft(who)).id, who.adminUser);
    const second = await open(who.org, (await draft(who)).id, who.adminUser);

    expect(first).toMatchObject({ outcome: 'opened' });
    expect(second).toMatchObject({ outcome: 'opened' });
    if (first.outcome !== 'opened' || second.outcome !== 'opened') throw new Error('not opened');
    expect(first.token).not.toBe(second.token);
  });

  it('reads an open invitation as no longer a draft, and opens it only once', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await open(who.org, id, who.adminUser);

    expect(await toOpen(who.org, id)).toEqual({ outcome: 'not_draft' });
    expect(await open(who.org, id, who.adminUser)).toEqual({ outcome: 'not_draft' });
  });

  it('refuses a second token for the same invitation, by the directory’s key, rolling back the move', async () => {
    const who = await organization();
    const { id } = await draft(who);
    await withTenant(app, who.org, (tx) =>
      tx
        .insertInto('directory.invites')
        .values({ token_hash: sha256('an earlier token'), org_id: who.org, invitation_id: id })
        .execute(),
    );

    await expect(open(who.org, id, who.adminUser)).rejects.toMatchObject({
      code: '23505',
      constraint: 'one_token_per_invitation',
    });

    expect(await record(who.org, id)).toMatchObject({ invitation: { status: 'DRAFT' } });
  });

  it('reads a draft as ended at its end, and as a draft a moment before', async () => {
    const who = await organization();
    const { id } = await draft(who);
    const ends = clock.now().getTime() + INVITATION_HOURS * HOUR;

    expect(await toOpen(who.org, id, new Date(ends - 1))).toMatchObject({ outcome: 'draft' });
    expect(await toOpen(who.org, id, new Date(ends))).toEqual({ outcome: 'ended' });
  });

  it('opens nothing for an invitation that doesn’t exist', async () => {
    const who = await organization();

    expect(await toOpen(who.org, ids.next())).toEqual({ outcome: 'missing' });
    const id = ids.next();
    await expect(
      withSignedStates(app, who.org, services(), (tx, states) =>
        openInvitation(tx, states, { orgId: who.org, id, actor: OPERATOR, details: {} }),
      ),
    ).rejects.toMatchObject({ name: 'InvitationNotOpened', outcome: 'missing' });
    // Its directory entry rolled back with the rest: no token listed for it.
    expect(await invitesOf(who.org)).toEqual([]);
  });

  it('refuses to open one open already, called past its read, listing no second token', async () => {
    const who = await organization();
    const { id } = await draft(who);
    const opened = await open(who.org, id, who.adminUser);
    const before = await invitesOf(who.org);

    await expect(
      withSignedStates(app, who.org, services(), (tx, states) =>
        openInvitation(tx, states, { orgId: who.org, id, actor: OPERATOR, details: {} }),
      ),
    ).rejects.toMatchObject({ code: '23505', constraint: 'one_token_per_invitation' });
    expect(opened).toMatchObject({ outcome: 'opened' });
    expect(await invitesOf(who.org)).toEqual(before);
  });

  it('keeps the directory’s token to an organisation it lists', async () => {
    await expect(
      withTenant(app, ids.next(), (tx) =>
        tx
          .insertInto('directory.invites')
          .values({ token_hash: sha256('a token'), org_id: ids.next(), invitation_id: ids.next() })
          .execute(),
      ),
    ).rejects.toMatchObject({ code: '23503' });
  });

  it('lists a token only in its own organisation’s transaction, by the directory’s own check', async () => {
    const who = await organization();
    const other = await organization();

    await expect(
      withTenant(app, other.org, (tx) =>
        registerInvite(tx, { orgId: who.org, invitationId: ids.next(), tokenHash: sha256('a token') }),
      ),
    ).rejects.toBeInstanceOf(TenantContextError);
    expect(await invitesOf(who.org)).toEqual([]);
  });

  it('refuses the directory’s entry from another organisation’s transaction', async () => {
    const who = await organization();
    const other = await organization();
    const { id } = await draft(who);

    await expect(
      withSignedStates(app, other.org, services(), (tx, states) =>
        openInvitation(tx, states, { orgId: who.org, id, actor: OPERATOR, details: {} }),
      ),
    ).rejects.toBeInstanceOf(TenantContextError);
  });
});

describe(`accepting an invitation (B4-4b, Postgres ${server.version})`, () => {
  let invitees = 0;
  /** A person who has signed in, to accept. */
  const invitee = (): Promise<string> => {
    invitees += 1;
    return userForSubject(
      app,
      { issuer: 'https://auth.example.test', subject: `invitee-${String(invitees)}` },
      { ids, clock },
    );
  };

  /** An open invitation for this role, and its token. */
  async function opened(who: Awaited<ReturnType<typeof organization>>, role: Role = 'developer') {
    const { id } = await draft(who, { role });
    const result = await open(who.org, id, who.adminUser);
    if (result.outcome !== 'opened') throw new Error('not opened');
    return { id, token: result.token };
  }

  const toAccept = (org: string, id: string, now = clock.now()) =>
    withSignedStates(app, org, services(), (tx, states) =>
      invitationToAccept(tx, states, keys, { orgId: org, id, now }),
    );

  const accept = (org: string, id: string, userId: string) =>
    withSignedStates(app, org, services(), (tx, states) =>
      acceptInvitation(tx, states, { orgId: org, id, userId, actor: { type: 'user', id: userId } }),
    );

  it('finds an open invitation by its token, through the directory', async () => {
    const who = await organization();
    const { id, token } = await opened(who);

    expect(await listedInvite(app, inviteTokenHash(token))).toEqual({ orgId: who.org, invitationId: id });
    expect(await listedInvite(app, inviteTokenHash(`${token}x`))).toBeUndefined();
    expect(inviteTokenHash(token)).toEqual(sha256(token));
  });

  it('reads an open invitation for its acceptance, with the invited address decrypted', async () => {
    const who = await organization();
    const { id } = await opened(who, 'viewer');

    expect(await toAccept(who.org, id.toUpperCase())).toMatchObject({
      outcome: 'open',
      invitation: { id, role: 'viewer', status: 'OPEN', acceptedBy: null },
      email: 'sara.khan@example.test',
    });
  });

  it('reads a draft, one past its end, and one accepted already as closed, and another organisation’s as missing', async () => {
    const who = await organization();
    const other = await organization();
    const { id: drafted } = await draft(who);
    const { id } = await opened(who);
    const ends = clock.now().getTime() + INVITATION_HOURS * HOUR;

    expect(await toAccept(who.org, drafted)).toEqual({ outcome: 'closed' });
    expect(await toAccept(who.org, id, new Date(ends - 1))).toMatchObject({ outcome: 'open' });
    expect(await toAccept(who.org, id, new Date(ends))).toEqual({ outcome: 'closed' });
    expect(await toAccept(other.org, id)).toEqual({ outcome: 'missing' });
    await accept(who.org, id, await invitee());
    expect(await toAccept(who.org, id)).toEqual({ outcome: 'closed' });
  });

  it.each([
    ['developer', 'ACCEPTED', 'accepted', 'invitation.accepted'],
    ['viewer', 'ACCEPTED', 'accepted', 'invitation.accepted'],
    ['admin', 'AWAITING_CONFIRMATION', 'awaiting_confirmation', 'invitation.awaiting_confirmation'],
    ['approver', 'AWAITING_CONFIRMATION', 'awaiting_confirmation', 'invitation.awaiting_confirmation'],
  ] as const)(
    'accepts a %s’s invitation: %s, who accepted sealed, on two events',
    async (role, status, outcome, action) => {
      const who = await organization();
      const { id } = await opened(who, role);
      const person = await invitee();

      expect(await accept(who.org, id, person)).toEqual({ outcome, role });

      expect(await record(who.org, id)).toMatchObject({ outcome: 'found', invitation: { status, acceptedBy: person } });
      const events = await withTenant(app, who.org, (tx) =>
        tx
          .selectFrom('audit.events')
          .select(['action', 'actor_id', 'subject_version', 'details'])
          .where('subject_id', '=', id)
          .orderBy('seq')
          .execute(),
      );
      expect(
        events.slice(2).map(({ action, actor_id, subject_version }) => [action, actor_id, subject_version]),
      ).toEqual([
        ['invitation.acceptance_recorded', person, 3],
        [action, person, 4],
      ]);
      expect(JSON.parse(events[3]?.details ?? '{}')).toMatchObject({ role, statusFrom: 'OPEN', statusTo: status });
      expect(alarms()).toEqual([]);
    },
  );

  it('refuses to accept a draft, or one missing, keeping nothing', async () => {
    const who = await organization();
    const { id } = await draft(who);
    const person = await invitee();

    await expect(accept(who.org, id, person)).rejects.toMatchObject({
      name: 'InvitationNotAccepted',
      outcome: 'DRAFT',
    });
    await expect(accept(who.org, ids.next(), person)).rejects.toMatchObject({
      name: 'InvitationNotAccepted',
      outcome: 'missing',
    });
    expect(await record(who.org, id)).toMatchObject({ invitation: { status: 'DRAFT', acceptedBy: null } });
  });

  it('reads and accepts in one transaction, as accepting does: the row locked once, for the change', async () => {
    const who = await organization();
    const { id } = await opened(who, 'viewer');
    const person = await invitee();

    const accepted = await withSignedStates(app, who.org, services(), async (tx, states) => {
      const read = await invitationToAccept(tx, states, keys, { orgId: who.org, id, now: clock.now() });
      if (read.outcome !== 'open') throw new Error('not open');
      return acceptInvitation(tx, states, { orgId: who.org, id, userId: person, actor: { type: 'user', id: person } });
    });

    expect(accepted).toEqual({ outcome: 'accepted', role: 'viewer' });
    expect(alarms()).toEqual([]);
  });

  it('refuses to accept one waiting for an admin’s confirmation, keeping who accepted first', async () => {
    const who = await organization();
    const { id } = await opened(who, 'approver');
    const first = await invitee();
    await accept(who.org, id, first);

    await expect(accept(who.org, id, await invitee())).rejects.toMatchObject({ outcome: 'AWAITING_CONFIRMATION' });
    expect(await record(who.org, id)).toMatchObject({
      invitation: { status: 'AWAITING_CONFIRMATION', acceptedBy: first },
    });
  });

  it('refuses to accept one accepted already, keeping who accepted first', async () => {
    const who = await organization();
    const { id } = await opened(who);
    const first = await invitee();
    await accept(who.org, id, first);

    await expect(accept(who.org, id, await invitee())).rejects.toMatchObject({ outcome: 'ACCEPTED' });
    expect(await record(who.org, id)).toMatchObject({ invitation: { acceptedBy: first } });
  });

  it('holds who accepted to a person who has signed in, by the key to the people', async () => {
    const who = await organization();
    const { id } = await opened(who);

    await expect(accept(who.org, id, ids.next())).rejects.toMatchObject({ code: '23503' });
  });

  it('holds every move to the machine’s, past the module too', async () => {
    const who = await organization();
    const { id } = await opened(who, 'admin');
    const moved = (status: string) =>
      withTenant(app, who.org, (tx) =>
        tx.updateTable('identity.invitations').set({ status }).where('id', '=', id).execute(),
      );

    for (const status of ['DECLINED', 'DRAFT']) {
      await expect(moved(status)).rejects.toMatchObject({ code: '23514', constraint: 'status_guard' });
    }
    await expect(moved('WITHDRAWN')).rejects.toMatchObject({ code: '23514' });
    await accept(who.org, id, await invitee());
    for (const status of ['OPEN', 'DRAFT']) {
      await expect(moved(status)).rejects.toMatchObject({ code: '23514', constraint: 'status_guard' });
    }
  });
});
