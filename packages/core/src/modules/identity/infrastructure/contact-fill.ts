// Filling the kept names of people who signed in before Agent X kept them
// (decision 25, E10d-4): each person of the login service this API signs in
// with who has no kept copy yet is looked up there, a hundred at a time, and
// their name and verified address kept as a sign-in keeps them
// (keepUserContact). So the audit log can name them even once the login
// service no longer has them.
//
// - It runs at the API's start and once a day after: a person the login
//   service no longer has stays without a copy, and is asked about again on
//   the next run only, at most a hundred a call.
// - Each person is kept by one statement of their own: two runs at once, or a
//   sign-in meanwhile, refresh the same row (its upsert) and lose nothing.
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

  return {
    async run(signal) {
      let kept = 0;
      let afterId = '00000000-0000-0000-0000-000000000000';
      try {
        for (;;) {
          if (signal?.aborted === true) break;
          const people = await unkept(afterId);
          if (people.length === 0) break;
          const entries = await directory.entriesOf(people.map((person) => person.subject));
          for (const person of people) {
            const entry = entries.get(person.subject);
            if (entry === undefined || (entry.name === undefined && entry.email === undefined)) continue;
            await keepUserContact(db, keys, person.id, { name: entry.name, verifiedEmail: entry.email }, clock.now());
            kept += 1;
          }
          afterId = people.at(-1)?.id ?? afterId;
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
