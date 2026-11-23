// SEC-HA-02 (S208): every step-up action walked, so none is left without its
// proof. The actions come from the API's own document (contract.test.ts keeps
// openapi.json equal to what the server builds): every operation answering 202
// with a step-up to sign in again for. WALK below must name exactly those, so a
// new step-up action fails here until it is added with its proof.
//
// Each action is proved in two places:
// - here, over HTTP on the real server with a stand-in for every use case: its
//   confirm, sent everything else it needs, is refused 400 at the edge without
//   the step-up, or with one that is not an ID, before any use case runs; with
//   one, the use case is handed exactly that step-up, and its STEP_UP_FAILED is
//   answered 403. Three confirm a draft whose step-up the server holds (the
//   path's ID, nothing sent): those have no step-up field to leave out.
// - in its use case's own database test, named in WALK and tagged SEC-HA-02:
//   a step-up not signed in again for, signed in with an app code where a
//   passkey is needed, or asked for another change, is refused STEP_UP_FAILED;
//   the same file's confirms show one signed in again for being taken. The
//   challenge store every one of them passes is SEC-HA-02's own test too
//   (step-up-challenges.db.test.ts), with SEC-HA-03 to 06.
import { readFileSync } from 'node:fs';
import type { MembershipCheck } from '@agentx/core/modules/identity';
import { systemClock } from '@agentx/core/shared-kernel';
import { afterEach, describe, expect, it } from 'vitest';

import { ORGANIZATION_HEADER } from './access.ts';
import { liveSession, PASSKEY } from './live-session.helper.test.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import type { ServerOptions } from './server.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { worded } from './statement-words.helper.test.ts';

afterEach(closeServers);

const API = 'apps/api/src/';
const IDENTITY = 'packages/core/src/modules/identity/infrastructure/';
const UUID = '0199a0f0-0000-7000-8000-0000000000d1';
const STEP_UP = '0199a0f0-0000-7000-8000-0000000000e1';

/**
 * How a step-up action's confirm names its step-up: `body` (`stepUpChallengeId`, beside the rest of the body
 * given), or `draft` (the draft in the path holds it, so nothing is sent).
 */
type Confirmed = { readonly body: Readonly<Record<string, unknown>> } | { readonly draft: true };

/** A step-up action: how its confirm names the step-up, and the database test proving its refusals. */
interface Walked {
  readonly confirmed: Confirmed;
  readonly proof: readonly [file: string, title: string];
}

const NOTHING = { body: {} } as const;
const DRAFT = { draft: true } as const;

/** Every step-up action, by its ask's operation. */
const WALK: Readonly<Record<string, Walked>> = {
  'members.role': {
    confirmed: { body: { role: 'developer' } },
    proof: [
      `${IDENTITY}membership-changes.db.test.ts`,
      'SEC-HA-02 refuses before the admin signs in again, changing nothing and ending no session; the same key changes after',
    ],
  },
  'members.deactivate': {
    confirmed: NOTHING,
    proof: [
      `${IDENTITY}membership-changes.db.test.ts`,
      'SEC-HA-02 refuses another change than the one signed in again for: another role, deactivating, or another member',
    ],
  },
  'members.invite': {
    confirmed: DRAFT,
    proof: [
      `${IDENTITY}inviting.db.test.ts`,
      'SEC-HA-02 refuses before the admin signs in again, leaving the draft, and confirms with the same key after',
    ],
  },
  'members.approve': {
    confirmed: NOTHING,
    proof: [
      `${IDENTITY}confirming.db.test.ts`,
      'SEC-HA-02 refuses before the admin signs in again, leaving the person waiting; the same key confirms after',
    ],
  },
  'resets.ask': {
    confirmed: DRAFT,
    proof: [
      `${IDENTITY}reset-changes.db.test.ts`,
      'SEC-HA-02 refuses without the step-up, with an app code rather than a passkey (SEC-HA-12), or from another admin',
    ],
  },
  'contacts.add': {
    confirmed: DRAFT,
    proof: [
      `${IDENTITY}contact-changes.db.test.ts`,
      'SEC-HA-02 refuses to confirm without the step-up, or with an app code rather than a passkey (SEC-HA-12), changing nothing',
    ],
  },
  'contacts.remove': {
    confirmed: NOTHING,
    proof: [
      `${IDENTITY}contact-changes.db.test.ts`,
      'SEC-HA-02 refuses a removal stepped up for another contact, or not stepped up, or with an app code',
    ],
  },
  'integrity-hold.clear': {
    confirmed: { body: { investigationId: UUID } },
    proof: [
      `${IDENTITY}hold-clearing.db.test.ts`,
      'SEC-HA-02 refuses to confirm before the admin has signed in again, as STEP_UP_FAILED, leaving it HELD',
    ],
  },
  'organization.unfreeze': {
    confirmed: { body: { reason: 'All clear', pendingRequests: 'pause' } },
    proof: [
      `${API}brake-voids.db.test.ts`,
      'SEC-HA-02 refuses a step-up signed in with an app code: STEP_UP_FAILED (a passkey, SEC-HA-12)',
    ],
  },
  'spend-requests.approve': {
    confirmed: NOTHING,
    proof: [
      `${API}spend-request-approvals.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another request, or for a reject: STEP_UP_FAILED',
    ],
  },
  'spend-requests.reject': {
    confirmed: { body: { reason: 'Not this one' } },
    proof: [
      `${API}spend-request-rejects.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another request, or for another reason: STEP_UP_FAILED',
    ],
  },
  'payments.failure-proposal': {
    confirmed: { body: { evidenceRef: 'BANK-NACK-12345', confirmed: 'invoice_can_be_paid_again' } },
    proof: [
      `${API}mark-failed.db.test.ts`,
      'SEC-HA-02, SEC-DP-11 a step-up asked for another payment or another reference: STEP_UP_FAILED',
    ],
  },
  'payments.failure-proposal.approve': {
    confirmed: { body: { confirmed: 'invoice_can_be_paid_again' } },
    proof: [
      `${API}mark-failed.db.test.ts`,
      'SEC-HA-02, SEC-DP-11 a step-up signed in with an app code: STEP_UP_FAILED, to propose and to confirm',
    ],
  },
  'payments.failure-proposal.withdraw': {
    confirmed: NOTHING,
    proof: [
      `${API}mark-failed.db.test.ts`,
      'SEC-HA-02 a withdrawal confirmed before signing in again, or with an app code: STEP_UP_FAILED, still open; the same step-up, signed in again with a passkey, withdraws it',
    ],
  },
  'agents.register': {
    confirmed: { body: { name: 'Buyer', scopes: ['requests:read'] } },
    proof: [
      `${API}agent-registering.db.test.ts`,
      'SEC-HA-02 a confirm before the member signed in again, or from another session: STEP_UP_FAILED',
    ],
  },
  'agents.reactivate': {
    confirmed: NOTHING,
    proof: [
      `${API}agent-changes.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another agent, or before the admin signed in again: STEP_UP_FAILED',
    ],
  },
  'agents.owner': {
    confirmed: { body: { owner: UUID } },
    proof: [
      `${API}agent-changes.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another new owner, another agent, or a reactivation: STEP_UP_FAILED',
    ],
  },
  'agents.keys.rotate': {
    confirmed: { body: { oldKey: 'overlap' } },
    proof: [
      `${API}agent-key-changes.db.test.ts`,
      'SEC-HA-02 binds the step-up to the key as it was asked, and to rotating: another key’s, or a revocation’s, fails',
    ],
  },
  'agents.keys.revoke': {
    confirmed: NOTHING,
    proof: [
      `${API}agent-key-changes.db.test.ts`,
      'SEC-HA-02 binds the step-up to the key as it was asked: a revocation asked before a rotation fails after it',
    ],
  },
  'connections.make': {
    confirmed: { body: { agentId: UUID, scopes: ['requests:read'] } },
    proof: [
      `${API}oauth-connections.db.test.ts`,
      'SEC-HA-02 refuses a developer another member’s agent, an admin without a passkey, a scope not asked, and a suspended agent',
    ],
  },
  'connections.revoke': {
    confirmed: NOTHING,
    proof: [
      `${API}oauth-connections.db.test.ts`,
      'SEC-HA-02 M08: a step-up for one connection’s revocation can’t revoke another',
    ],
  },
  'funding-sources.reactivate': {
    confirmed: { body: { pendingRequests: 'pause' } },
    proof: [
      `${API}funding-source-suspension.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another source, or before the admin signed in again',
    ],
  },
  'suppliers.reactivate': {
    confirmed: { body: { pendingRequests: 'pause' } },
    proof: [
      `${API}supplier-changes.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another supplier, in another session, or before the admin signed in again',
    ],
  },
  'suppliers.details': {
    confirmed: {
      body: {
        displayName: 'Gulf Supplies',
        phone: '+971500000000',
        source: { kind: 'registry', ref: 'DED-123456' },
        pendingRequests: 'pause',
      },
    },
    proof: [
      `${API}supplier-details.db.test.ts`,
      'SEC-HA-02, SEC-HA-12 refuses a step-up with an app code, and binds it to the details asked for',
    ],
  },
  'suppliers.remittance-email': {
    confirmed: { body: { remittanceEmail: 'on' } },
    proof: [
      `${API}supplier-remittance.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked for another supplier, or from where the setting no longer stands',
    ],
  },
  'suppliers.payee.approve': {
    confirmed: NOTHING,
    proof: [
      `${API}supplier-payee-changes.db.test.ts`,
      'SEC-HA-02, SEC-HA-12 refuses a step-up made with an app code, changing nothing and telling no one',
    ],
  },
  'suppliers.verify': {
    confirmed: { body: { calledBack: true } },
    proof: [
      `${API}supplier-verifications.db.test.ts`,
      'SEC-HA-02 binds the step-up to the note asked with: another note at the confirm verifies nothing',
    ],
  },
  'mandates.accept': {
    confirmed: NOTHING,
    proof: [`${API}mandate-acceptance.db.test.ts`, 'SEC-HA-02 refuses a step-up never signed in again for, or run out'],
  },
  'mandates.suspend': {
    confirmed: { body: { pendingRequests: 'pause' } },
    proof: [
      `${API}mandate-moves.db.test.ts`,
      'SEC-HA-02 refuses a step-up signed in with an app code: STEP_UP_FAILED, nothing moved',
    ],
  },
  'mandates.resume': {
    confirmed: NOTHING,
    proof: [
      `${API}mandate-moves.db.test.ts`,
      'SEC-HA-02 refuses a resume confirmed before signing in again, or with an app code: still suspended; the same step-up, signed in again with a passkey, resumes it',
    ],
  },
  'mandates.revoke': {
    confirmed: NOTHING,
    proof: [
      `${API}mandate-moves.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked before the mandate changed: STEP_UP_FAILED, for the mandate as it stood',
    ],
  },
  'mandates.over-limit': {
    confirmed: { body: { overLimit: 'refuse' } },
    proof: [
      `${API}mandate-moves.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked with the other choice, or before the mandate changed: STEP_UP_FAILED, nothing chosen',
    ],
  },
  'policies.organization.change': {
    confirmed: { body: { currency: 'AED', monthlyCapMinor: null, monthlyCapChoice: 'none', approvalWaitHours: 72 } },
    proof: [
      `${API}policy-changes.db.test.ts`,
      'SEC-HA-02 refuses a step-up asked before the policy changed: STEP_UP_FAILED, for the policy as it stood',
    ],
  },
  'policies.mandate.change': {
    confirmed: { body: { currency: 'AED', monthlyCapMinor: 1000 } },
    proof: [
      `${API}policy-changes.db.test.ts`,
      'SEC-HA-02 refuses one confirmed before signing in again, or with an app code: none set; the same step-up, signed in again with a passkey, sets it',
    ],
  },
};

interface Operation {
  readonly id: string;
  readonly method: string;
  readonly path: string;
  readonly access: readonly string[];
  readonly body: Schema | undefined;
  readonly asks: boolean;
}

interface Schema {
  readonly $ref?: string;
  readonly properties?: Readonly<Record<string, Schema>>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
  readonly format?: string;
}

interface Document {
  readonly paths: Record<string, Record<string, Record<string, unknown>>>;
  readonly components: { readonly schemas: Record<string, Schema> };
}

const DOCUMENT = JSON.parse(readFileSync(new URL('../openapi.json', import.meta.url), 'utf8')) as Document;

/** A schema with its `$ref`s followed. */
const resolved = (schema: Schema | undefined): Schema | undefined => {
  let at = schema;
  while (at?.$ref !== undefined) at = DOCUMENT.components.schemas[at.$ref.split('/').at(-1) ?? ''];
  return at;
};

const jsonOf = (part: unknown): Schema | undefined =>
  resolved(
    (part as { content?: Record<string, { schema?: Schema }> } | undefined)?.content?.['application/json']?.schema,
  );

const OPERATIONS: readonly Operation[] = Object.entries(DOCUMENT.paths).flatMap(([path, item]) =>
  Object.entries(item).flatMap(([method, operation]) => {
    const id = operation.operationId;
    if (typeof id !== 'string') return [];
    const answered = jsonOf((operation.responses as Record<string, unknown> | undefined)?.['202']);
    return [
      {
        id,
        method: method.toUpperCase(),
        path,
        access: operation['x-access'] as string[],
        body: jsonOf(operation.requestBody),
        asks: answered?.properties?.stepUpChallengeId !== undefined,
      },
    ];
  }),
);

const operation = (id: string): Operation => {
  const found = OPERATIONS.find((each) => each.id === id);
  if (found === undefined) throw new Error(`no operation ${id}`);
  return found;
};

/** Each step-up action's confirm, as the walk sends it. */
const CONFIRMS = Object.entries(WALK).map(([ask, { confirmed }]) => ({
  ask,
  confirm: operation(`${ask}.confirm`),
  confirmed,
}));
const SENT = CONFIRMS.flatMap(({ confirm, confirmed }) =>
  'body' in confirmed ? [{ confirm, body: confirmed.body }] : [],
);

/** Every call a stand-in use case was sent, as its arguments. */
const calls: unknown[][] = [];

/**
 * A stand-in for any use case (`never`, so it stands for each): each method records what it was sent and refuses it
 * STEP_UP_FAILED.
 */
const STAND_IN = new Proxy(
  {},
  {
    get: (_target, name) =>
      // Not a promise itself (`then`), and nothing a symbol asks for.
      typeof name === 'symbol' || name === 'then'
        ? undefined
        : (...sent: unknown[]) => {
            calls.push(sent);
            return Promise.resolve({ outcome: 'refused', status: 403, code: 'STEP_UP_FAILED' });
          },
  },
) as never;

/** Every use case a step-up action's confirm runs, a stand-in. */
const USE_CASES: Partial<ServerOptions> = {
  membershipChanges: STAND_IN,
  acceptanceConfirmations: STAND_IN,
  holdClearings: STAND_IN,
  organizationChanges: STAND_IN,
  contactChanges: STAND_IN,
  spendRequestApprovals: STAND_IN,
  spendRequestRejects: STAND_IN,
  paymentMarks: STAND_IN,
  agentRegistrations: STAND_IN,
  agentChanges: STAND_IN,
  agentKeyChanges: STAND_IN,
  connectionChanges: STAND_IN,
  fundingSourceChanges: STAND_IN,
  supplierChanges: STAND_IN,
  supplierDetailsChanges: STAND_IN,
  supplierRemittance: STAND_IN,
  supplierPayeeChanges: STAND_IN,
  supplierVerifications: STAND_IN,
  mandateAcceptance: STAND_IN,
  mandateMoves: STAND_IN,
  policyChanges: STAND_IN,
  oauth: {
    authorizing: STAND_IN,
    grants: STAND_IN,
    consents: STAND_IN,
    device: STAND_IN,
    clock: systemClock,
  },
};

const ADMIN = {
  outcome: 'active',
  id: '0199a0f0-0000-7000-8000-000000000033',
  role: 'admin',
} as const satisfies MembershipCheck;

/** The confirm sent by an admin signed in with a passkey, every path parameter an ID. */
async function send(confirm: Operation, body: Readonly<Record<string, unknown>>) {
  const app = await routeServer({
    live: liveSession('2026-09-24T09:00:00.000Z', { amr: PASSKEY }),
    member: ADMIN,
    oauthOn: true,
    ...USE_CASES,
  });
  const url = confirm.path.replaceAll(/\{\w+\}/g, UUID);
  calls.length = 0;
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `${SESSION_COOKIE}=${COOKIE}`,
      [ORGANIZATION_HEADER]: ORG,
      origin: PUBLIC_ORIGIN,
      'idempotency-key': 'walk-1',
    },
    payload: worded(url, body) as Record<string, unknown>,
  });
}

/**
 * The source of the test named `title` in `text`, from its title to the next
 * test or block that starts after it; undefined when no test, or more than one,
 * carries that title. Read as text, so the proof's file is never run here.
 */
function testBodyOf(text: string, title: string): string | undefined {
  const quoted = `'${title}'`;
  const at = text.indexOf(quoted);
  if (at === -1 || text.lastIndexOf(quoted) !== at) return undefined;
  const rest = text.slice(at + quoted.length);
  const next = rest.search(/\n\s*(?:it|test|describe)(?:\.\w+)*\(/);
  return next === -1 ? rest : rest.slice(0, next);
}

/**
 * Whether a test's body asserts a refusal STEP_UP_FAILED: one statement, its
 * comments left out, with an `expect` and either the code as a quoted string or
 * a constant the body declared holding it (`const refused = { ...,
 * code: 'STEP_UP_FAILED' }`). A test that only mentions the code, or asserts
 * something else, doesn't count.
 */
function assertsStepUpRefused(body: string): boolean {
  const statements = body
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n')
    .split(';');
  const holding = statements.flatMap((statement) => {
    const declared = /\bconst (\w+) =/.exec(statement);
    return declared?.[1] !== undefined && statement.includes("'STEP_UP_FAILED'") ? [declared[1]] : [];
  });
  return statements.some(
    (statement) =>
      statement.includes('expect') &&
      (statement.includes("'STEP_UP_FAILED'") || holding.some((name) => new RegExp(`\\b${name}\\b`).test(statement))),
  );
}

describe('SEC-HA-02 every step-up action, walked', () => {
  it('walks exactly the step-up actions the API’s document holds: a new one fails here until it is added', () => {
    expect(
      OPERATIONS.filter(({ asks }) => asks)
        .map(({ id }) => id)
        .toSorted(),
    ).toEqual(Object.keys(WALK).toSorted());
  });

  it('confirms each by its own POST, open to exactly the ask’s callers, never to an agent', () => {
    for (const { ask, confirm } of CONFIRMS) {
      expect(confirm.method, confirm.id).toBe('POST');
      expect(confirm.access, confirm.id).toEqual(operation(ask).access);
      expect(confirm.access, confirm.id).not.toContain('agent');
    }
  });

  it('takes each step-up a confirm sends as a required ID, nothing more; a draft’s confirm sends none', () => {
    for (const { confirm, confirmed } of CONFIRMS) {
      const stepUp = resolved(confirm.body?.properties?.stepUpChallengeId);
      if ('draft' in confirmed) {
        expect(stepUp, confirm.id).toBeUndefined();
        expect(confirm.path, confirm.id).toMatch(/\/\{id\}\/confirm$/);
      } else {
        expect(stepUp?.format, confirm.id).toBe('uuid');
        expect(confirm.body?.required, confirm.id).toContain('stepUpChallengeId');
        expect(confirm.body?.additionalProperties, confirm.id).toBe(false);
      }
    }
  });

  it('names for each the database test proving its refusals, tagged SEC-HA-02, whose own body asserts the refusal', () => {
    const missing = Object.entries(WALK)
      .filter(
        ([
          ,
          {
            proof: [file, title],
          },
        ]) => {
          const text = readFileSync(new URL(`../../../${file}`, import.meta.url), 'utf8');
          const body = testBodyOf(text, title);
          return !title.startsWith('SEC-HA-02') || body === undefined || !assertsStepUpRefused(body);
        },
      )
      .map(([ask]) => ask);
    expect(missing).toEqual([]);
  });

  it('finds a named test’s own body, and refuses an empty one, one named twice, or one asserting nothing', () => {
    const file = [
      "describe('d', () => {",
      "  it('SEC-HA-02 proves it', async () => {",
      "    expect(await confirm()).toEqual(refused(403, 'STEP_UP_FAILED'));",
      '  });',
      "  it('SEC-HA-02 empty', async () => {});",
      "  it('SEC-HA-02 says it only', async () => {",
      '    // STEP_UP_FAILED, in words alone, then expect( nothing about it',
      '    expect(1).toBe(1);',
      '  });',
      "  it('SEC-HA-02 by its constant', async () => {",
      "    const refused = { outcome: 'refused', code: 'STEP_UP_FAILED' };",
      '    expect(await confirm()).toEqual(refused);',
      '  });',
      "  it('SEC-HA-02 its constant unused', async () => {",
      "    const refused = { outcome: 'refused', code: 'STEP_UP_FAILED' };",
      "    expect(await confirm()).toEqual({ outcome: 'written' });",
      '  });',
      "  it('SEC-HA-02 named twice', () => {});",
      "  it('SEC-HA-02 named twice', () => { expect(x).toBe('STEP_UP_FAILED'); });",
      "  it('after', () => { expect(y).toBe('STEP_UP_FAILED'); });",
      '});',
    ].join('\n');
    const proves = (title: string) => {
      const body = testBodyOf(file, title);
      return body !== undefined && assertsStepUpRefused(body);
    };

    expect(proves('SEC-HA-02 proves it')).toBe(true);
    expect(proves('SEC-HA-02 by its constant')).toBe(true);
    expect(proves('SEC-HA-02 its constant unused')).toBe(false);
    // The next test's assertion never counts for an empty one before it.
    expect(proves('SEC-HA-02 empty')).toBe(false);
    expect(proves('SEC-HA-02 says it only')).toBe(false);
    expect(proves('SEC-HA-02 named twice')).toBe(false);
    expect(proves('SEC-HA-02 not there')).toBe(false);
  });

  it.each(SENT.map(({ confirm, body }) => [confirm.id, confirm, body] as const))(
    '%s: refused 400 without the step-up, or with one not an ID, before any use case runs',
    async (_id, confirm, body) => {
      for (const stepUp of [undefined, 'not-a-step-up', 42]) {
        const response = await send(confirm, stepUp === undefined ? body : { ...body, stepUpChallengeId: stepUp });
        expect(response.statusCode, response.body).toBe(400);
        expect(calls).toEqual([]);
      }
    },
  );

  it.each(SENT.map(({ confirm, body }) => [confirm.id, confirm, body] as const))(
    '%s: hands its use case exactly the step-up sent, and answers its STEP_UP_FAILED 403',
    async (_id, confirm, body) => {
      const response = await send(confirm, { ...body, stepUpChallengeId: STEP_UP });

      expect(response.statusCode, response.body).toBe(403);
      expect(response.json()).toMatchObject({ error: { code: 'STEP_UP_FAILED' } });
      // An amount reaches its use case as a bigint, which JSON can't write as it is.
      const written = (sent: unknown[]) =>
        JSON.stringify(sent, (_key, value: unknown) => (typeof value === 'bigint' ? String(value) : value));
      expect(calls.filter((sent) => written(sent).includes(STEP_UP))).toHaveLength(1);
    },
  );
});
