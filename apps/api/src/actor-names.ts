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
import { agentsNamed, type AgentsTables } from '@agentx/core/modules/agents';
import type { AuditActor, AuditTables, LogEvent, SignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  type DirectoryEntry,
  type DirectoryNames,
  type IdentityTables,
  type KeptPerson,
  keptPeopleOf,
} from '@agentx/core/modules/identity';
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

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
export const actorKey = (actor: AuditActor): string => `${actor.type}:${actor.id}`;

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

  /** The login service's entries for these people, or none once it has failed. */
  const fromDirectory = async (people: readonly KeptPerson[]): Promise<ReadonlyMap<string, DirectoryEntry>> => {
    const subjects = people.filter((person) => person.issuer === directory?.issuer).map((person) => person.subject);
    if (!asking || directory === undefined || subjects.length === 0) return new Map();
    try {
      return await directory.entriesOf(subjects);
    } catch (error) {
      asking = false;
      logger.warn('audit_log.names_unavailable', { err: error });
      return new Map();
    }
  };

  const personName = (person: KeptPerson | undefined, now: DirectoryEntry | undefined): ActorName => {
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
      const now = await fromDirectory([...held.people.values()]);
      const names = new Map<string, ActorName>();
      for (const { event } of events) {
        const { actor } = event;
        const key = actorKey(actor);
        if (names.has(key)) continue;
        if (actor.type === 'user') {
          const person = held.people.get(actor.id);
          // Only the login service's own subjects were asked about: another issuer's alike subject isn't theirs.
          const current = person?.issuer === directory?.issuer ? now.get(person?.subject ?? '') : undefined;
          names.set(key, personName(person, current));
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
