// 6A2: GET /v1/statements serves the words each change is confirmed with,
// from the constants the use cases state and version, for a signed-in person
// alone; and every such constant in the API is imported into statements.ts
// (whose types then hold it in SERVED_STATEMENTS, or lint refuses the unused
// import), so a new choice's words can't be left off the console's confirm.
import { readdirSync, readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';

import { liveSession, ONE_TIME_CODE } from './live-session.helper.test.ts';
import { MARK_FAILED_STATEMENT, MARK_FAILED_STATEMENT_VERSION } from './payment-marks.ts';
import { closeServers, COOKIE, routeServer } from './route-server.helper.test.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { SERVED_STATEMENTS } from './statements.ts';
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
  return readdirSync(directory)
    .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts'))
    .flatMap((file) =>
      [...readFileSync(new URL(file, directory), 'utf8').matchAll(/^(?:export )?const (\w*STATEMENTS?) =/gm)].map(
        (match) => ({ file, name: match[1] ?? '' }),
      ),
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
