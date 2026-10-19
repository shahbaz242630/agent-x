// Naming the audit log's actors (decision 25): the login service first, the
// kept copy where it can't answer or no longer has the person, agents and
// Agent X's own parts by their names, and a namer that stops asking a login
// service that failed, logging why and never a name.
import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import type { AuditActor } from '../../audit/index.ts';
import { type DirectoryNames, DirectoryUnavailable, type KeptPerson } from '../../identity/index.ts';

import { type ActorsHeld, createActorNamer } from './actor-names.ts';

const ISSUER = 'https://auth.example.test';
const SARA = '0199a0f0-0000-7000-8000-00000000a001';
const OMAR = '0199a0f0-0000-7000-8000-00000000a002';
const AGENT = '0199a0f0-0000-7000-8000-00000000a003';

const person = (subject: string, kept: Partial<KeptPerson> = {}): KeptPerson => ({
  issuer: ISSUER,
  subject,
  name: undefined,
  email: undefined,
  unreadable: false,
  ...kept,
});

const held = (people: Record<string, KeptPerson>, agents: Record<string, string> = {}): ActorsHeld => ({
  people: new Map(Object.entries(people)),
  agents: new Map(Object.entries(agents)),
});

/** A login service that has these people, counting each time it is asked. */
const directoryOf = (entries: Record<string, { name?: string; email?: string }>) => {
  const asked: string[][] = [];
  const directory: DirectoryNames = {
    issuer: ISSUER,
    entriesOf: (subjects) => {
      asked.push([...subjects]);
      return Promise.resolve(
        new Map(
          subjects
            .filter((subject) => subject in entries)
            .map((subject) => [subject, { name: entries[subject]?.name, email: entries[subject]?.email }]),
        ),
      );
    },
  };
  return { directory, asked };
};

describe('the audit log’s actors, by name (decision 25)', () => {
  it('names a person from the login service, filling only what it lacks from the kept copy', async () => {
    const { directory, asked } = directoryOf({ '101': { name: 'Sara Khan' } });
    const namer = createActorNamer({ directory, logger: testLogger() });
    const actors: AuditActor[] = [
      { type: 'user', id: SARA },
      { type: 'user', id: SARA },
    ];

    const names = await namer.namesOf(
      actors,
      held({ [SARA]: person('101', { name: 'Old', email: 's@example.test' }) }),
    );

    expect(names.get(`user:${SARA}`)).toEqual({
      name: 'Sara Khan',
      email: 's@example.test',
      shownFrom: 'login_service',
    });
    expect(asked).toEqual([['101']]);
  });

  it('asks about each person once a namer, however many batches name them', async () => {
    const { directory, asked } = directoryOf({ '101': { name: 'Sara Khan' } });
    const namer = createActorNamer({ directory, logger: testLogger() });
    const page = held({ [SARA]: person('101'), [OMAR]: person('102') });

    await namer.namesOf([{ type: 'user', id: SARA }], held({ [SARA]: person('101') }));
    const names = await namer.namesOf(
      [
        { type: 'user', id: SARA },
        { type: 'user', id: OMAR },
      ],
      page,
    );

    expect(names.get(`user:${SARA}`)).toMatchObject({ name: 'Sara Khan', shownFrom: 'login_service' });
    expect(asked).toEqual([['101'], ['102']]);
  });

  it('names from the kept copy one the login service no longer has, and the ID alone with neither', async () => {
    const { directory } = directoryOf({});
    const namer = createActorNamer({ directory, logger: testLogger() });
    const actors: AuditActor[] = [
      { type: 'user', id: SARA },
      { type: 'user', id: OMAR },
    ];

    const names = await namer.namesOf(
      actors,
      held({ [SARA]: person('101', { name: 'Sara Khan', email: 's@example.test' }), [OMAR]: person('102') }),
    );

    expect(names.get(`user:${SARA}`)).toEqual({ name: 'Sara Khan', email: 's@example.test', shownFrom: 'kept_copy' });
    expect(names.get(`user:${OMAR}`)).toEqual({ name: null, email: null, shownFrom: null });
  });

  it('asks the login service only about its own people: another issuer’s alike subject isn’t theirs', async () => {
    const { directory, asked } = directoryOf({ '101': { name: 'Mallory' } });
    const namer = createActorNamer({ directory, logger: testLogger() });

    const names = await namer.namesOf(
      [{ type: 'user', id: SARA }],
      held({ [SARA]: person('101', { issuer: 'https://other.example.test', name: 'Sara Khan' }) }),
    );

    expect(names.get(`user:${SARA}`)).toMatchObject({ name: 'Sara Khan', shownFrom: 'kept_copy' });
    expect(asked).toEqual([]);
  });

  it('falls back to the kept copy when the login service fails, then stops asking it, logging why', async () => {
    const capture = new LogCapture();
    let calls = 0;
    const directory: DirectoryNames = {
      issuer: ISSUER,
      entriesOf: () => {
        calls += 1;
        return Promise.reject(new DirectoryUnavailable('the call failed'));
      },
    };
    const namer = createActorNamer({ directory, logger: testLogger(capture) });
    const page = held({ [SARA]: person('101', { name: 'Sara Khan' }) });

    expect((await namer.namesOf([{ type: 'user', id: SARA }], page)).get(`user:${SARA}`)).toMatchObject({
      name: 'Sara Khan',
      shownFrom: 'kept_copy',
    });
    await namer.namesOf([{ type: 'user', id: SARA }], page);

    expect(calls).toBe(1);
    expect(capture.lines()).toEqual([expect.objectContaining({ event: 'audit_log.names_unavailable' })]);
    expect(JSON.stringify(capture.lines())).not.toContain('Sara');
  });

  it('names from the kept copy alone when no login service is set up, logging a copy that won’t open', async () => {
    const capture = new LogCapture();
    const namer = createActorNamer({ directory: undefined, logger: testLogger(capture) });

    const names = await namer.namesOf(
      [
        { type: 'user', id: SARA },
        { type: 'user', id: OMAR },
      ],
      held({ [SARA]: person('101', { email: 's@example.test' }), [OMAR]: person('102', { unreadable: true }) }),
    );

    expect(names.get(`user:${SARA}`)).toEqual({ name: null, email: 's@example.test', shownFrom: 'kept_copy' });
    expect(names.get(`user:${OMAR}`)).toEqual({ name: null, email: null, shownFrom: null });
    expect(capture.lines()).toEqual([expect.objectContaining({ event: 'audit_log.kept_names_unreadable', count: 1 })]);
  });

  it('names an agent by its own name, and Agent X’s parts by theirs', async () => {
    const namer = createActorNamer({ directory: undefined, logger: testLogger() });

    const names = await namer.namesOf(
      [
        { type: 'agent', id: AGENT },
        { type: 'agent', id: OMAR },
        { type: 'system', id: 'api' },
        { type: 'system', id: 'operator' },
        { type: 'system', id: 'integrity-hold' },
        { type: 'system', id: 'anchor-check' },
      ],
      held({}, { [AGENT]: 'Invoice bot' }),
    );

    expect(Object.fromEntries(names)).toEqual({
      [`agent:${AGENT}`]: { name: 'Invoice bot', email: null, shownFrom: 'agent' },
      [`agent:${OMAR}`]: { name: null, email: null, shownFrom: null },
      'system:api': { name: 'Agent X', email: null, shownFrom: 'agent_x' },
      'system:operator': { name: 'Agent X operations', email: null, shownFrom: 'agent_x' },
      'system:integrity-hold': { name: 'Agent X integrity hold', email: null, shownFrom: 'agent_x' },
      'system:anchor-check': { name: 'Agent X (anchor-check)', email: null, shownFrom: 'agent_x' },
    });
  });
});
