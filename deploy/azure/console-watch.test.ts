import { describe, expect, it } from 'vitest';

import { authRules, type ConsoleState } from './auth-door.ts';
import { checkConsoleDoor } from './console-watch.ts';
import { LEGACY_DOOR } from './legacy-door.fixture.ts';
import {
  type Az,
  type AzResult,
  Cancelled,
  CONSOLE_SAID,
  deploy,
  parseArguments,
  stagingApp,
  type Steps,
  USAGE,
  UsageError,
} from './deploy.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-000000000000';
const DOOR_URL = `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/managedEnvironments/cae-agentx-staging/httpRouteConfigs/rtagentxstgauth?api-version=2026-01-01`;
const HOSTS = [{ name: 'auth.example.invalid', bindingType: 'Auto', certificateId: 'managed-certificate' }];

const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/**
 * Azure as the console step meets it: the auth door in a shape (or rules of its own), a PATCH that moves it to what
 * was sent unless refused or `sticks` says it stays, and every call kept.
 */
class DoorAz implements Az {
  readonly calls: (readonly string[])[] = [];
  rules: unknown;
  readonly patch: 'moves' | 'refused' | 'sticks';

  constructor(start: ConsoleState | unknown[], patch: 'moves' | 'refused' | 'sticks' = 'moves') {
    this.rules = Array.isArray(start) ? start : authRules(start, stagingApp);
    this.patch = patch;
  }

  interactive(): number {
    throw new Error('never interactive');
  }

  run(args: readonly string[]): AzResult {
    this.calls.push(args);
    if (args.join(' ') === 'account show --output json') return json({ name: 'Staging', id: SUBSCRIPTION });
    if (args[0] !== 'rest' || args[4] !== DOOR_URL) throw new Error(`unexpected az ${args.join(' ')}`);
    if (args[2] === 'get')
      return json({ name: 'rtagentxstgauth', properties: { customDomains: HOSTS, rules: this.rules } });
    if (args[2] !== 'patch') throw new Error(`unexpected az ${args.join(' ')}`);
    if (this.patch === 'refused') return { status: 1, stdout: '', stderr: 'ERROR: (AuthorizationFailed) no\nmore' };
    if (this.patch === 'moves')
      this.rules = (JSON.parse(args[6] ?? '') as { properties: { rules: unknown } }).properties.rules;
    return json({});
  }

  get patches(): unknown[] {
    return this.calls.filter((args) => args[2] === 'patch').map((args) => JSON.parse(args[6] ?? '') as unknown);
  }
}

async function console_(argv: readonly string[], az: DoorAz, answers: readonly string[] = []) {
  const said: string[] = [];
  const asked: string[] = [];
  const queue = [...answers];
  const terminal = {
    say: (line: string) => said.push(line),
    ask: (question: string) => {
      asked.push(question);
      return Promise.resolve(queue.shift() ?? '');
    },
  };
  const outcome = await deploy(parseArguments(argv), { terminal, az } as unknown as Steps).then(
    (status) => ({ status, error: undefined as unknown }),
    (error: unknown) => ({ status: undefined, error }),
  );
  return { ...outcome, said, asked };
}

describe('deploy.ts console (PL-26)', () => {
  it('takes one of --open, --close or --status', () => {
    expect(parseArguments(['console', '--open'])).toEqual({ command: 'console', mode: 'open' });
    expect(parseArguments(['console', '--close'])).toEqual({ command: 'console', mode: 'close' });
    expect(parseArguments(['console', '--status'])).toEqual({ command: 'console', mode: 'status' });
    for (const options of [[], ['--open', '--close'], ['--opened'], ['open']]) {
      expect(() => parseArguments(['console', ...options])).toThrow(
        new UsageError('console takes one of --open, --close or --status, and nothing else'),
      );
    }
  });

  it('writes the partner’s routine in its help: open, do the work, close', () => {
    expect(USAGE).toContain('node deploy/azure/deploy.ts console --open | --close | --status');
    const routine = USAGE.slice(USAGE.indexOf("Zitadel's console (PL-26)"));
    expect(routine.indexOf('console --open')).toBeLessThan(routine.indexOf('/ui/console and do the work'));
    expect(routine.indexOf('/ui/console and do the work')).toBeLessThan(routine.indexOf('console --close'));
  });

  it('opens a closed door with a PATCH of its rules alone, the host sent back as read, then reads it open', async () => {
    const az = new DoorAz('closed');
    const done = await console_(['console', '--open'], az, ['y']);
    expect(done.error).toBeUndefined();
    expect(done.status).toBe(0);
    expect(done.asked).toEqual(["Open Zitadel's console on staging's auth host? [y/N] "]);
    expect(az.calls.map((args) => args.slice(0, 3).join(' '))).toEqual([
      'account show --output',
      'rest --method get',
      'rest --method patch',
      'rest --method get',
    ]);
    // A PATCH to the door itself: no revision suffix, nothing of az containerapp.
    expect(az.calls[2]?.slice(0, 6)).toEqual(['rest', '--method', 'patch', '--url', DOOR_URL, '--body']);
    expect(az.patches).toEqual([{ properties: { customDomains: HOSTS, rules: authRules('open', stagingApp) } }]);
    expect(done.said).toContain(CONSOLE_SAID.open);
    expect(done.said.at(-1)).toMatch(/close it in this same sitting/);
  });

  it('closes an open door the same way, and reads it closed', async () => {
    const az = new DoorAz('open');
    const done = await console_(['console', '--close'], az, ['yes']);
    expect(done.status).toBe(0);
    expect(done.asked).toEqual(["Close Zitadel's console on staging's auth host? [y/N] "]);
    expect(az.patches).toEqual([{ properties: { customDomains: HOSTS, rules: authRules('closed', stagingApp) } }]);
    expect(done.said.at(-1)).toBe(CONSOLE_SAID.closed);
  });

  it('only says the shape for --status, or when the door is already as asked', async () => {
    for (const [argv, start] of [
      [['console', '--status'], 'open'],
      [['console', '--status'], 'closed'],
      [['console', '--open'], 'open'],
      [['console', '--close'], 'closed'],
    ] as const) {
      const az = new DoorAz(start);
      const done = await console_(argv, az);
      expect(done.status).toBe(0);
      expect(done.asked).toEqual([]);
      expect(az.patches).toEqual([]);
      expect(done.said.at(-1)).toBe(CONSOLE_SAID[start]);
    }
  });

  it('changes nothing on a door in neither shape, whatever was asked', async () => {
    const stray = [...authRules('closed', stagingApp).slice(0, -1), authRules('open', stagingApp)[8]];
    for (const mode of ['--open', '--close', '--status']) {
      const az = new DoorAz(stray);
      const done = await console_(['console', mode], az, ['y']);
      expect(done.error).toMatchObject({ message: `${CONSOLE_SAID.neither} Nothing was changed.` });
      expect(az.patches).toEqual([]);
    }
  });

  it('says the pre-PL-26 door for --status, and closes it like an open one', async () => {
    const status = await console_(['console', '--status'], new DoorAz(LEGACY_DOOR));
    expect(status.said.at(-1)).toBe(CONSOLE_SAID.legacy);
    const az = new DoorAz(LEGACY_DOOR);
    const done = await console_(['console', '--close'], az, ['y']);
    expect(done.status).toBe(0);
    expect(az.patches).toEqual([{ properties: { customDomains: HOSTS, rules: authRules('closed', stagingApp) } }]);
    expect(done.said.at(-1)).toBe(CONSOLE_SAID.closed);
  });

  it('sends nothing unless the operator answers yes', async () => {
    const az = new DoorAz('closed');
    const done = await console_(['console', '--open'], az, ['n']);
    expect(done.error).toBeInstanceOf(Cancelled);
    expect(az.patches).toEqual([]);
  });

  it('says a refused PATCH by its first line, and a door that did not move, with what next', async () => {
    const refused = await console_(['console', '--open'], new DoorAz('closed', 'refused'), ['y']);
    expect(refused.error).toMatchObject({
      message:
        "Azure refused the change to the auth host's door (ERROR: (AuthorizationFailed) no), so the console stays closed.",
    });
    const stuck = await console_(['console', '--close'], new DoorAz('open', 'sticks'), ['y']);
    expect(stuck.error).toMatchObject({
      message:
        "Azure took the change, but the auth host's door now reads open, not closed. Run console --status in a minute; if it still isn't closed, run apps, which puts the door back closed.",
    });
  });
});

describe('checkConsoleDoor', () => {
  const check = (start: ConsoleState | unknown[], openIsRed: boolean) => {
    const said: string[] = [];
    const { status, shape } = checkConsoleDoor(new DoorAz(start), SUBSCRIPTION, (line) => said.push(line), openIsRed);
    return { status, shape, said };
  };

  it('passes a closed door, and fails an open or pre-PL-26 one only for the watch, saying so either way', () => {
    expect(check('closed', true)).toEqual({ status: 0, shape: 'closed', said: [CONSOLE_SAID.closed] });
    expect(check('open', true)).toEqual({ status: 1, shape: 'open', said: [CONSOLE_SAID.open] });
    expect(check('open', false)).toEqual({ status: 0, shape: 'open', said: [CONSOLE_SAID.open] });
    expect(check(LEGACY_DOOR, true)).toEqual({ status: 1, shape: 'legacy', said: [CONSOLE_SAID.legacy] });
    expect(check(LEGACY_DOOR, false)).toEqual({ status: 0, shape: 'legacy', said: [CONSOLE_SAID.legacy] });
    expect(CONSOLE_SAID.legacy).toMatch(/an apps deploy closes it/);
  });

  it('fails a door in neither shape for the watch and the plan alike', () => {
    expect(check([], true)).toEqual({ status: 1, shape: undefined, said: [CONSOLE_SAID.neither] });
    expect(check([], false)).toEqual({ status: 1, shape: undefined, said: [CONSOLE_SAID.neither] });
  });
});
