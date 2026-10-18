// Who each actor of the audit log is, by name (partner's catch S121, decision
// 25: "the whole idea of the log is to know who did what"): shown beside
// their Agent X ID on a page and in a download, never sealed into an event.
//
// - A person: their name and verified email as the login service has them
//   now, asked once for everyone on the page (directory-names.ts), after the
//   organisation's transaction, so a slow login service holds no
//   connection. Where it can't answer, or no longer has them, the copy
//   Agent X kept at their latest sign-in (user-contacts.ts); `shownFrom` says
//   which. Neither: null, the ID alone.
// - An agent: its name, believed only as its signed state verifies it
//   (agentsNamed); one that can't be is INTEGRITY_FAILED, as for the event.
// - Agent X's own parts: a name for each.
// - Once the login service fails, a namer stops asking it (a download's
//   twenty batches don't each wait), and logs why, never a name.
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { agentsNamed, type AgentsTables } from '../../agents/index.ts';
import type { AuditActor, AuditTables, LogEvent, SignedStates } from '../../audit/index.ts';
import type { DirectoryTables } from '../../directory/index.ts';
import {
  type DirectoryEntry,
  type DirectoryNames,
  type IdentityTables,
  type KeptPerson,
  keptPeopleOf,
} from '../../identity/index.ts';

type NamesTx = DatabaseTransaction<IdentityTables & DirectoryTables & AuditTables & AgentsTables>;

/** Where a name was found: the login service, Agent X's kept copy, the agent's own record, or Agent X itself. */
export const SHOWN_FROM = ['login_service', 'kept_copy', 'agent', 'agent_x'] as const;

/** An actor as the log names them; nulls where nothing names them. */
export interface ActorName {
  readonly name: string | null;
  readonly email: string | null;
  readonly shownFrom: (typeof SHOWN_FROM)[number] | null;
}

/** Agent X's own parts that act in an organisation's log, by name. */
const SYSTEM_NAMES: Readonly<Record<string, string>> = {
  api: 'Agent X',
  operator: 'Agent X operations',
  'integrity-hold': 'Agent X integrity hold',
};

const NO_NAME: ActorName = { name: null, email: null, shownFrom: null };

/** An actor's key in a namer's answer. */
const actorKey = (actor: AuditActor): string => `${actor.type}:${actor.id}`;

/** An actor's name in a namer's answer; nulls for one it doesn't name. */
export const nameOf = (names: ReadonlyMap<string, ActorName>, actor: AuditActor): ActorName =>
  names.get(actorKey(actor)) ?? NO_NAME;

/** What Agent X itself holds for a page's actors, read in the organisation's transaction. */
export interface ActorsHeld {
  readonly people: ReadonlyMap<string, KeptPerson>;
  readonly agents: ReadonlyMap<string, string>;
}

/** The page's actors as Agent X holds them, in two statements; `tampered` for an agent that can't be believed. */
export async function actorsHeld(
  tx: NamesTx,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  events: readonly LogEvent[],
): Promise<ActorsHeld | 'tampered'> {
  const idsOf = (type: AuditActor['type']) => [
    ...new Set(events.filter(({ event }) => event.actor.type === type).map(({ event }) => event.actor.id)),
  ];
  const agentIds = idsOf('agent');
  const agents = agentIds.length === 0 ? undefined : await agentsNamed(tx, states, orgId, agentIds);
  if (agents?.outcome === 'tampered') return 'tampered';
  return {
    people: await keptPeopleOf(tx, keys, idsOf('user')),
    agents: new Map([...(agents?.agents.values() ?? [])].map((agent) => [agent.id, agent.name])),
  };
}

export interface ActorNamer {
  /** Each actor of `events` by name, the login service asked once for all the people. */
  namesOf(events: readonly LogEvent[], held: ActorsHeld): Promise<ReadonlyMap<string, ActorName>>;
}

/** A namer for one page or download. Without `directory` (no login service set up), people are named from the kept copy. */
export function createActorNamer({
  directory,
  logger,
}: {
  readonly directory: DirectoryNames | undefined;
  readonly logger: Logger;
}): ActorNamer {
  let asking = directory !== undefined;
  /** Each person the login service already answered for, by Agent X ID: a download's later batches don't ask again. */
  const answered = new Map<string, DirectoryEntry | undefined>();

  /**
   * The login service's entries for these people, by their Agent X ID, or none
   * once it has failed. Only its own people are asked about: another issuer's
   * alike subject isn't theirs.
   */
  const fromDirectory = async (
    people: ReadonlyMap<string, KeptPerson>,
  ): Promise<ReadonlyMap<string, DirectoryEntry>> => {
    const theirs = [...people].filter(
      ([userId, person]) => person.issuer === directory?.issuer && !answered.has(userId),
    );
    if (asking && directory !== undefined && theirs.length > 0) {
      try {
        const entries = await directory.entriesOf(theirs.map(([, person]) => person.subject));
        for (const [userId, person] of theirs) answered.set(userId, entries.get(person.subject));
      } catch (error) {
        asking = false;
        logger.warn('audit_log.names_unavailable', { err: error });
      }
    }
    return new Map(
      [...people.keys()].flatMap((userId) => {
        const entry = answered.get(userId);
        return entry === undefined ? [] : [[userId, entry] as const];
      }),
    );
  };

  const personShown = (person: KeptPerson | undefined, now: DirectoryEntry | undefined): ActorName => {
    const name = now?.name ?? person?.name;
    const email = now?.email ?? person?.email;
    if (name === undefined && email === undefined) return NO_NAME;
    // The login service when it gave either; the kept copy only fills what it didn't.
    const shownFrom = now?.name !== undefined || now?.email !== undefined ? 'login_service' : 'kept_copy';
    return { name: name ?? null, email: email ?? null, shownFrom };
  };

  return {
    async namesOf(events, held) {
      const unreadable = [...held.people.values()].filter((person) => person.unreadable).length;
      if (unreadable > 0) logger.warn('audit_log.kept_names_unreadable', { count: unreadable });
      const now = await fromDirectory(held.people);
      const names = new Map<string, ActorName>();
      for (const { event } of events) {
        const { actor } = event;
        const key = actorKey(actor);
        if (names.has(key)) continue;
        if (actor.type === 'user') {
          names.set(key, personShown(held.people.get(actor.id), now.get(actor.id)));
        } else if (actor.type === 'agent') {
          const name = held.agents.get(actor.id);
          names.set(key, name === undefined ? NO_NAME : { name, email: null, shownFrom: 'agent' });
        } else {
          names.set(key, {
            name: SYSTEM_NAMES[actor.id] ?? `Agent X (${actor.id})`,
            email: null,
            shownFrom: 'agent_x',
          });
        }
      }
      return names;
    },
  };
}
