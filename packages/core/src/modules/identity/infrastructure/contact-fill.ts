// Filling the kept names of people who signed in before Agent X kept them
// (decision 25, E10d-4): each person of the login service this API signs in
// with who has no kept copy yet is looked up there, a hundred at a time, and
// their name and verified address kept as a sign-in keeps them
// (keepUserContact). So the audit log can name them even once the login
// service no longer has them.
//
// - It runs at the API's start and hourly after: a person the login service
//   no longer has stays without a copy, and is asked about again on the next
//   run only, at most a hundred a call; with none to fill, a run is one read.
// - Each person is kept by one statement of their own that only adds a copy:
//   a sign-in meanwhile keeps its own, newer values, and two runs at once add
//   one row.
// - A login service that fails ends the run, logged by its step, never a name,
//   and the next run tries again. It logs how many were kept, never who.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import type { Clock } from '../../../shared-kernel/index.ts';
import { MOST_A_CALL, type DirectoryNames } from './directory-names.ts';
import type { IdentityTables } from './tables.ts';
import { keepUserContact } from './user-contacts.ts';

export interface ContactFill {
  run(signal?: AbortSignal): Promise<void>;
}

export function createContactFill({
  db,
  keys,
  directory,
  clock,
  logger,
}: {
  readonly db: Kysely<IdentityTables>;
  readonly keys: KeyProvider;
  readonly directory: DirectoryNames;
  readonly clock: Clock;
  readonly logger: Logger;
}): ContactFill {
  /** The next hundred of the login service's people with no kept copy, after `afterId`, in ID order. */
  const unkept = (afterId: string) =>
    db
      .selectFrom('identity.users as u')
      .leftJoin('identity.user_contacts as c', 'c.user_id', 'u.id')
      .select(['u.id', 'u.subject'])
      .where('c.user_id', 'is', null)
      .where('u.issuer', '=', directory.issuer)
      .where('u.id', '>', afterId)
      .orderBy('u.id')
      .limit(MOST_A_CALL)
      .execute();

  /** Keeps a copy for each of these people the login service names; how many it added. */
  const keepPage = async (people: readonly { readonly id: string; readonly subject: string }[]) => {
    const entries = await directory.entriesOf(people.map((person) => person.subject));
    let added = 0;
    for (const person of people) {
      const entry = entries.get(person.subject);
      if (entry === undefined) continue;
      const given = { name: entry.name, verifiedEmail: entry.email };
      if (await keepUserContact(db, keys, person.id, given, clock.now(), { onlyIfMissing: true })) added += 1;
    }
    return added;
  };

  return {
    async run(signal) {
      let kept = 0;
      let afterId = '00000000-0000-0000-0000-000000000000';
      try {
        for (;;) {
          if (signal?.aborted === true) break;
          const people = await unkept(afterId);
          const last = people.at(-1);
          if (last === undefined) break;
          kept += await keepPage(people);
          afterId = last.id;
          if (people.length < MOST_A_CALL) break;
        }
      } catch (error) {
        logger.warn('identity.contact_fill_failed', { kept, err: error });
        return;
      }
      logger.info('identity.contact_fill_done', { kept });
    },
  };
}
