// 6A2: GET /v1/statements serves the words each change is confirmed with,
// from the constants the use cases state and version, for a signed-in person
// alone; and every such constant in the API is imported into statements.ts
// (whose types then hold it in SERVED_STATEMENTS, or lint refuses the unused
// import), so a new choice's words can't be left off the console's confirm.
// CO3: every change confirmed with a set sends back the version it was shown,
// and one the API no longer confirms with, or none, is refused 409
// STATEMENT_CHANGED before the use case runs; each set's words are pinned by
// their hash beside their version, so new words can't keep an old version.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import type { MembershipCheck } from '@agentx/core/modules/identity';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ORGANIZATION_HEADER } from './access.ts';
import { liveSession, ONE_TIME_CODE, PASSKEY } from './live-session.helper.test.ts';
import { MARK_FAILED_STATEMENT, MARK_FAILED_STATEMENT_VERSION } from './payment-marks.ts';
import { closeServers, COOKIE, ORG, PUBLIC_ORIGIN, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { CONFIRMS, confirmedBody, versionNow } from './statement-words.helper.test.ts';
import {
  isStale,
  SERVED_STATEMENTS,
  type StatementConfirmed,
  type StatementId,
  statementProblems,
  versionWithChoice,
} from './statements.ts';
import { FREEZE_STATEMENT_VERSION, FREEZE_STATEMENTS } from './suspensions.ts';

const LIVE = liveSession('2026-09-24T09:00:00.000Z', { amr: ONE_TIME_CODE });

afterEach(closeServers);

interface Served {
  readonly statements: readonly { id: string; version: number; words: { choice: string; text: string }[] }[];
}

describe('GET /v1/statements', () => {
  it('answers a signed-in person with every set, its version and its words', async () => {
    const app = await routeServer({ live: LIVE });

    const response = await app.inject({
      method: 'GET',
      url: '/v1/statements',
      headers: { cookie: `${SESSION_COOKIE}=${COOKIE}` },
    });

    expect(response.statusCode).toBe(200);
    const { statements } = response.json<Served>();
    expect(statements.map(({ id }) => id)).toEqual(SERVED_STATEMENTS.map(({ id }) => id));
    expect(statements.find(({ id }) => id === 'freeze')).toEqual({
      id: 'freeze',
      version: FREEZE_STATEMENT_VERSION,
      words: [
        { choice: 'cancel', text: FREEZE_STATEMENTS.cancel },
        { choice: 'pause', text: FREEZE_STATEMENTS.pause },
      ],
    });
    expect(statements.find(({ id }) => id === 'mark_failed')).toEqual({
      id: 'mark_failed',
      version: MARK_FAILED_STATEMENT_VERSION,
      words: [{ choice: 'confirm', text: MARK_FAILED_STATEMENT }],
    });
  });

  it('refuses anyone not signed in', async () => {
    const app = await routeServer({ live: LIVE });

    const response = await app.inject({ method: 'GET', url: '/v1/statements' });

    expect(response.statusCode).toBe(401);
  });

  it('names each set once', () => {
    const ids = SERVED_STATEMENTS.map(({ id }) => id);

    expect(new Set(ids).size).toBe(ids.length);
  });
});

/** Every `const …_STATEMENT(S) =` in the API's own code, by the file holding it. */
function statementConstants(): readonly { file: string; name: string }[] {
  const directory = new URL('.', import.meta.url);
  return (
    readdirSync(directory)
      // statements.ts serves them (its own SERVED_STATEMENTS): every other file states them.
      .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && file !== 'statements.ts')
      .flatMap((file) =>
        [...readFileSync(new URL(file, directory), 'utf8').matchAll(/^(?:export )?const (\w*STATEMENTS?) =/gm)].map(
          (match) => ({ file, name: match[1] ?? '' }),
        ),
      )
  );
}

describe('every statement the API confirms a change with is served', () => {
  const constants = statementConstants();

  const served = readFileSync(new URL('statements.ts', import.meta.url), 'utf8');

  it('finds the constants it checks', () => {
    expect(constants).toHaveLength(SERVED_STATEMENTS.length);
  });

  it.each(constants)('$file: $name', ({ file, name }) => {
    const imports = [...served.matchAll(/^import \{([^}]*)\} from '\.\/([\w-]+\.ts)';$/gm)];

    // Each imported name, before any `as`: `STATEMENTS as SUSPEND_STATEMENTS` imports STATEMENTS.
    const namesOf = (list: string) => list.split(',').map((entry) => entry.trim().split(' ')[0]);
    const imported = imports.some(([, names = '', from]) => from === file && namesOf(names).includes(name));
    expect(imported, `statements.ts imports ${name} from ./${file}`).toBe(true);
  });
});

/** Each set's words as served, hashed: what its version stands for. */
const wordsHash = (words: Readonly<Record<string, string>>): string =>
  createHash('sha256')
    .update(JSON.stringify(Object.entries(words)))
    .digest('hex')
    .slice(0, 16);

describe('each set of words keeps its version (CO3)', () => {
  // A change to a set's words changes its hash here: raise its version with it, then pin the new pair.
  const PINNED: Readonly<Record<StatementId, readonly [version: number, hash: string]>> = {
    suspend: [4, 'cb8ec543f7589ec5'],
    reactivate: [3, 'e80551f61530572b'],
    freeze: [3, 'e8ba90c94a99e318'],
    unfreeze: [2, 'd1a925047af7cbfa'],
    payee: [3, 'c46ec74995255d33'],
    supplier_details: [2, '52c4aa926f704008'],
    consent_expiry: [1, '54d5ef0d4458adbb'],
    old_key: [1, 'c2707e20fcf29743'],
    supersede: [2, '897b3fe414a361ba'],
    monthly_cap: [1, '2663db9dac21f125'],
    over_limit: [1, 'a5556efada5072e6'],
    waiting_requests: [4, '4b5b9afd8c6d850b'],
    approval_wait: [1, '62c671b52d873756'],
    mark_failed: [1, '7f947dd28d848c5a'],
    recheck: [1, 'ef3c83ef959d39a4'],
  };

  it.each(SERVED_STATEMENTS.map((statement) => [statement.id, statement] as const))(
    '%s: its words are those its version names',
    (id, { version, words }) => {
      expect([version, wordsHash(words)], `${id}: new words need a new version`).toEqual(PINNED[id]);
    },
  );
});

const ID = '0199a0f0-0000-7000-8000-000000000071';
const KEY_ID = '0199a0f0-0000-7000-8000-000000000072';

const ADMIN = {
  outcome: 'active',
  id: '0199a0f0-0000-7000-8000-000000000033',
  role: 'admin',
} as const satisfies MembershipCheck;

const urlOf = (path: string): string => path.replace('{keyId}', KEY_ID).replace(/\{\w+\}/, ID);

async function sendConfirm(path: string, body: Readonly<Record<string, unknown>>) {
  const app = await routeServer({ live: liveSession('2026-09-24T09:00:00.000Z', { amr: PASSKEY }), member: ADMIN });
  return app.inject({
    method: 'POST',
    url: urlOf(path),
    headers: {
      cookie: `${SESSION_COOKIE}=${COOKIE}`,
      [ORGANIZATION_HEADER]: ORG,
      origin: PUBLIC_ORIGIN,
      'idempotency-key': 'k-1',
    },
    payload: body,
  });
}

/** The version fields each operation's body takes, as the contract documents them. */
function documentedVersionFields(): readonly string[] {
  const document = JSON.parse(readFileSync(new URL('../openapi.json', import.meta.url), 'utf8')) as {
    paths: Record<string, Record<string, { requestBody?: { content: Record<string, { schema?: unknown }> } }>>;
  };
  return Object.entries(document.paths).flatMap(([path, item]) =>
    Object.values(item).flatMap(({ requestBody }) => {
      const schema = requestBody?.content['application/json']?.schema as { properties?: object } | undefined;
      return Object.keys(schema?.properties ?? {})
        .filter((field) => /^statementVersion$|StatementVersion$/.test(field))
        .map((field) => `${path} ${field}`);
    }),
  );
}

describe('every confirm sends back the version of the words it was shown (CO3)', () => {
  const cases = CONFIRMS.flatMap(([path, named]) =>
    named.map(([field, id]) => ({ path, named, field, id, label: `${path} ${field}` })),
  );

  it('names every route whose body takes a version, as the contract documents them', () => {
    expect(documentedVersionFields().toSorted()).toEqual(cases.map(({ label }) => label).toSorted());
  });

  it.each(cases)('$label: an older version is refused 409 STATEMENT_CHANGED', async ({ path, named, field, id }) => {
    const response = await sendConfirm(path, { ...confirmedBody(named), [field]: versionNow(id) - 1 });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'STATEMENT_CHANGED' } });
  });

  it.each(cases)(
    '$label: a newer one, or one not a number, is refused the same',
    async ({ path, named, field, id }) => {
      for (const sent of [versionNow(id) + 1, String(versionNow(id))]) {
        const response = await sendConfirm(path, { ...confirmedBody(named), [field]: sent });
        expect(response.statusCode).toBe(409);
        expect(response.json()).toMatchObject({ error: { code: 'STATEMENT_CHANGED' } });
      }
    },
  );

  it.each(cases)('$label: none is refused the same', async ({ path, named, field }) => {
    const body = Object.fromEntries(Object.entries(confirmedBody(named)).filter(([name]) => name !== field));

    const response = await sendConfirm(path, body);

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ error: { code: 'STATEMENT_CHANGED' } });
  });

  it.each(cases)('$label: the version now goes on to the route', async ({ path, named }) => {
    const response = await sendConfirm(path, confirmedBody(named));

    // No use case is given here, so the route answers otherwise (each route's own tests have its 200).
    expect(response.json()).not.toMatchObject({ error: { code: 'STATEMENT_CHANGED' } });
  });
});

describe('a version named with an optional choice (CO3)', () => {
  const WAITING: StatementConfirmed = {
    id: 'waiting_requests',
    field: 'waitingStatementVersion',
    with: 'waitingRequests',
  };
  const now = versionNow('waiting_requests');

  it.each([
    ['no choice and no version', {}, false],
    ['the choice and the version now', { waitingRequests: 'reject', waitingStatementVersion: now }, false],
    ['the choice and an older version', { waitingRequests: 'reject', waitingStatementVersion: now - 1 }, true],
    ['the choice alone', { waitingRequests: 'reject' }, true],
    ['an older version alone', { waitingStatementVersion: now - 1 }, true],
    ['the version now alone', { waitingStatementVersion: now }, false],
  ])('%s: stale %s', (_case, body, stale) => {
    expect(isStale([WAITING], body)).toBe(stale);
  });

  it.each([null, 'text', 7])('reads %j, no object, as sending none', (body) => {
    expect(isStale([WAITING], body)).toBe(false);
    expect(isStale([{ id: 'freeze', field: 'statementVersion' }], body)).toBe(true);
  });

  it('refuses a version sent without its choice, or the choice without it, as the schema checks it', () => {
    const schema = z
      .strictObject({ waitingRequests: z.string().optional(), waitingStatementVersion: z.int().optional() })
      .superRefine(versionWithChoice('waitingRequests', 'waitingStatementVersion'));

    expect(schema.safeParse({}).success).toBe(true);
    expect(schema.safeParse({ waitingRequests: 'leave', waitingStatementVersion: now }).success).toBe(true);
    expect(schema.safeParse({ waitingRequests: 'leave' }).success).toBe(false);
    expect(schema.safeParse({ waitingStatementVersion: now }).success).toBe(false);
  });
});

describe('a route naming words names fields its body holds, and every version field is named (CO3)', () => {
  const body = z.strictObject({ pendingRequests: z.string(), statementVersion: z.int() });
  const named: readonly StatementConfirmed[] = [{ id: 'freeze', field: 'statementVersion', with: 'pendingRequests' }];

  it('takes a body holding each field named, a transformed one too', () => {
    expect(statementProblems({ url: '/x', schema: { body }, config: { statements: named } })).toEqual([]);
    expect(
      statementProblems({ url: '/x', schema: { body: body.transform((x) => x) }, config: { statements: named } }),
    ).toEqual([]);
  });

  it('refuses a field named its body does not hold, or no body to hold it', () => {
    const elsewhere: readonly StatementConfirmed[] = [{ id: 'freeze', field: 'otherVersion', with: 'choice' }];

    expect(statementProblems({ url: '/x', schema: { body }, config: { statements: elsewhere } })).toEqual([
      "/x: its statements name otherVersion, which its body doesn't hold",
      "/x: its statements name choice, which its body doesn't hold",
      "/x: its body's statementVersion names no set of words (config.statements), so it goes unchecked",
    ]);
    expect(statementProblems({ url: '/y', config: { statements: named } })).toHaveLength(2);
  });

  it('refuses a version field no set names: it would go unchecked', () => {
    const policy = z.strictObject({ monthlyCapStatementVersion: z.int() });

    expect(statementProblems({ url: '/x', schema: { body: policy } })).toEqual([
      "/x: its body's monthlyCapStatementVersion names no set of words (config.statements), so it goes unchecked",
    ]);
  });
});
