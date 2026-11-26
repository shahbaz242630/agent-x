// A passkey added inside Agent X (SA6; ADR-012 §8, SEC-OPS-04, B6-3d), from the step-up's return to the key
// confirmed (passkey-addition.ts tells the whole flow; 0121 keeps each addition under way):
//
// - `begin`, for the console, with an idempotency key (kept under the person's own keys, as their downloads are): a
//   step-up challenge of the session for PASSKEY_ADD_ACTION.
// - `steppedUp`, in the step-up's own transaction once its checks passed (a passkey among them): the person's access
//   token, sealed with the addition's ID, person and session, so it opens for this addition alone.
// - `ticket`, for the console, in the same session, with an idempotency key: the one-time ticket for the add-a-key
//   page, kept only as its SHA-256, TICKET_SECONDS to redeem; the step-up's challenge goes, used. A retry of the same
//   request can't be given the ticket again, which is kept nowhere: it is told PASSKEY_TICKET_ALREADY_ISSUED.
// - `status`, for the console, in the same session: where its addition got to, until the key is confirmed.
// - `options`, for the page: the ticket redeemed, once (`redeemed`); the login service asked for a passkey as the
//   person; the passkey's ID then recorded on the platform chain as the person's own addition, with the addition
//   moved to `registering`, in one transaction, its head outside the database (TR-1), and only then the options
//   handed out. A record that fails hands out nothing: the copier finds no record, and a key made anyway restricts.
//   On any failure there (the login service, the record), or the person's token refused (PASSKEY_REFUSED, never a
//   LoginTokenRefused, which pages: only our own service tokens should), the token is taken back and the row deleted
//   with it: a token carrying the login service's API audience never outlives the addition it was kept for.
// - `confirm`, for the page: the ticket's addition taken, once (`confirming`, its token out of the row), the key sent
//   to the login service as the person, and the token taken back there; `confirmed` for the console to read, or the
//   row gone when the login service refused the key.
// - sweepPasskeyAdditions: additions past their time deleted (the API's sweep, hourly), and each token still in one
//   (left at `stepped_up`, `ticketed`, `redeemed` or `registering`) taken back at the login service first. A token
//   the login service won't take back is deleted all the same, and said (`identity.passkey_token_kept`).
//
// The ticket is the page's only credential: the add-a-key page is on a host of its own, which the console's session
// cookie never reaches. It goes from the console to the page in the address's fragment, which no request carries.
// Nothing here logs a token, a ticket, or a passkey's ID.
import { createHash, randomBytes } from 'node:crypto';

import { createIdempotentWrites, type IdempotentRequest, limitStatements, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely, Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { nowChainsOf, waitWitnessed } from '../../audit/index.ts';
import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import {
  OWN_PASSKEY_REGISTERED,
  OWN_KEY_WINDOW_MS,
  PASSKEY_ADD_ACTION,
  REGISTERING_SECONDS,
  STEPPED_UP_SECONDS,
  TICKET_SECONDS,
} from '../domain/passkey-addition.ts';
import type { OwnPasskeys } from './idp-passkeys.ts';
import { LoginTokenRefused } from './zitadel-call.ts';
import type { RowMacs } from './row-macs.ts';
import { openField } from './sealed-fields.ts';
import type { StepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { subjectOfUser } from './users.ts';

type Tables = IdentityTables & PlatformControlsTables;
type Handle = Kysely<Tables> | Transaction<Tables>;

/** A ticket as this module makes them: 32 random bytes in base64url. */
const TICKET = /^[A-Za-z0-9_-]{43}$/;

/** Who records: the API, for the person. */
const ACTOR = { type: 'system', id: 'api' } as const;

/** Why an addition step was refused, for its answer: none of them says whose, or why beyond this. */
export type AdditionRefusal =
  /** The session ended as the step-up was asked for. */
  | 'UNAUTHENTICATED'
  /** No addition of this session waits for its ticket: not signed in again for, one already ticketed, or past its time. */
  | 'STEP_UP_FAILED'
  /** A retry of the ticket's own request: the ticket is kept nowhere, so it can't be given again. */
  | 'PASSKEY_TICKET_ALREADY_ISSUED'
  /** The ticket redeems nothing: never issued, used already, or past its time. */
  | 'PASSKEY_TICKET_INVALID'
  /** The login service took no key: the key isn't one made for this passkey, or the person's token ran out. */
  | 'PASSKEY_REFUSED';

/** A step's answer: done, its idempotency key's own answer, or refused. */
export type AdditionAnswer<T> =
  | ({ readonly outcome: 'done' } & T)
  | { readonly outcome: 'conflict' | 'busy' }
  | { readonly outcome: 'refused'; readonly code: AdditionRefusal };

/** Where the session's addition got to, for the console. */
export type AdditionStatus = 'STEPPED_UP' | 'WAITING_FOR_KEY' | 'ADDED' | 'GONE';

export interface PasskeyAdditions {
  /** Opens the session's step-up for adding a passkey, under `idempotent`: its challenge, the same for a retry. */
  begin(
    sessionId: string,
    userId: string,
    idempotent: IdempotentRequest,
  ): Promise<AdditionAnswer<{ readonly challengeId: string }>>;
  /**
   * In the step-up's own transaction, its checks passed: the person's access token, sealed, for the addition named by
   * the step-up's challenge.
   */
  steppedUp(
    tx: Transaction<IdentityTables>,
    addition: {
      readonly challengeId: string;
      readonly sessionId: string;
      readonly userId: string;
      readonly accessToken: string;
    },
  ): Promise<void>;
  /** The page's one-time ticket, for the session's addition stepped up for `challengeId`, under `idempotent`. */
  ticket(
    sessionId: string,
    challengeId: string,
    idempotent: IdempotentRequest,
  ): Promise<AdditionAnswer<{ readonly ticket: string; readonly endsAt: Date }>>;
  /** Where the session's addition for `challengeId` got to. */
  status(sessionId: string, challengeId: string): Promise<AdditionStatus>;
  /** What the page makes the key with, for a ticket redeemed once; recorded first. Throws when the login service fails. */
  options(ticket: string): Promise<AdditionAnswer<{ readonly options: Readonly<Record<string, unknown>> }>>;
  /** The key the page made, sent to the login service as the person, once. Throws when the login service fails. */
  confirm(ticket: string, credential: unknown): Promise<AdditionAnswer<object>>;
}

/** The token's associated data: its addition, its person and its session, so it opens for this addition alone. */
const tokenData = (id: string, userId: string, sessionId: string) =>
  ['identity.passkey_additions', id.toLowerCase(), userId.toLowerCase(), sessionId.toLowerCase()] as const;

const hashOf = (ticket: string): Buffer => createHash('sha256').update(ticket, 'ascii').digest();

/** A sealed token that won't open: changed, or copied from another addition. */
export class AdditionTokenUnreadable extends Error {
  override readonly name = 'AdditionTokenUnreadable';
  constructor(options: ErrorOptions) {
    super("A passkey addition's token can't be opened", options);
  }
}

/** A step refused inside its idempotent transaction, which so rolls back and keeps no key. */
class Refused extends Error {
  override readonly name = 'Refused';
  readonly code: AdditionRefusal;
  constructor(code: AdditionRefusal) {
    super(code);
    this.code = code;
  }
}

/** A row's sealed token, as far as opening it needs. */
interface SealedRow {
  readonly id: string;
  readonly user_id: string;
  readonly session_id: string;
  readonly token_ciphertext: Buffer | null;
  readonly token_key_version: number | null;
}

export function createPasskeyAdditions({
  database,
  challenges,
  passkeys,
  revoke,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly challenges: StepUpChallenges;
  readonly passkeys: OwnPasskeys;
  /** Takes an access token back at the login service (the OIDC client's); never throws. */
  readonly revoke: (accessToken: string) => Promise<boolean>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): PasskeyAdditions {
  const platform = createPlatformChain({ keys, ids });
  const macs: RowMacs = { keys, logger };
  const refused = (code: AdditionRefusal) => ({ outcome: 'refused', code }) as const;
  const later = (ms: number) => new Date(clock.now().getTime() + ms);

  /** The work in a transaction of its own, each statement limited to 10 seconds; once committed, its heads witnessed. */
  const inTransaction = async <T>(work: (tx: Transaction<Tables>) => Promise<T>): Promise<T> => {
    const opened: { tx?: object } = {};
    const result = await database.transaction().execute(async (tx) => {
      opened.tx = tx;
      await limitStatements(tx);
      return work(tx);
    });
    if (opened.tx !== undefined) await waitWitnessed(nowChainsOf(opened.tx));
    return result;
  };

  /**
   * The work under the request's idempotency key, in the person's own keys' transaction: `done` with what it made, the
   * key's own answer, `refused` for a Refused it threw; `replayed` names what an earlier request made.
   */
  const keyed = async <T>(
    idempotent: IdempotentRequest,
    work: (
      tx: Transaction<Tables>,
    ) => Promise<{ readonly status: number; readonly resourceId: string; readonly made: T }>,
  ): Promise<
    | { readonly outcome: 'done'; readonly made: T }
    | { readonly outcome: 'replayed'; readonly resourceId: string }
    | { readonly outcome: 'conflict' | 'busy' }
    | { readonly outcome: 'refused'; readonly code: AdditionRefusal }
  > => {
    const idempotency = createIdempotentWrites({ keys, logger });
    const kept: { made?: T } = {};
    try {
      const written = await withTenant(database, idempotent.orgId, (tx) =>
        idempotency.run(tx, idempotent, async () => {
          const { status, resourceId, made } = await work(tx);
          kept.made = made;
          return { status, resourceId };
        }),
      );
      if (written.outcome === 'conflict' || written.outcome === 'busy') return { outcome: written.outcome };
      if (written.outcome === 'replayed' || !('made' in kept)) {
        return { outcome: 'replayed', resourceId: written.result.resourceId };
      }
      return { outcome: 'done', made: kept.made };
    } catch (error) {
      if (error instanceof Refused) return refused(error.code);
      throw error;
    }
  };

  /** The token of a row, opened; a row without one throws, as does one that won't open. */
  const tokenOf = (row: SealedRow): string => {
    if (row.token_ciphertext === null || row.token_key_version === null) {
      throw new AdditionTokenUnreadable({ cause: 'the addition holds no token' });
    }
    return openField(
      keys,
      { keyVersion: row.token_key_version, ciphertext: row.token_ciphertext },
      tokenData(row.id, row.user_id, row.session_id),
      (cause) => new AdditionTokenUnreadable({ cause }),
    );
  };

  /** The addition the ticket names, locked, in `state` and still in time; undefined for any other. */
  const byTicket = (tx: Handle, ticket: string, state: 'ticketed' | 'registering') =>
    tx
      .selectFrom('identity.passkey_additions')
      .selectAll()
      .where('ticket_hash', '=', hashOf(ticket))
      .where('state', '=', state)
      .where('ends_at', '>', clock.now())
      .forUpdate()
      .executeTakeFirst();

  const takeBack = (token: string): Promise<void> => takenBack(revoke, token, logger);

  /**
   * An addition that won't reach its key confirmed: its token taken back at the login service, and its row, token and
   * all, deleted, while it is still between its ticket redeemed and its key sent.
   */
  const dropAddition = async (id: string, token: string): Promise<void> => {
    await takeBack(token);
    await database
      .deleteFrom('identity.passkey_additions')
      .where('id', '=', id)
      .where('state', 'in', ['redeemed', 'registering'])
      .execute();
  };

  return {
    async begin(sessionId, userId, idempotent) {
      const opened = await keyed(idempotent, async (tx) => {
        const challenge = await challenges.open(tx, {
          sessionId,
          action: PASSKEY_ADD_ACTION,
          changeHash: createHash('sha256').update(`${PASSKEY_ADD_ACTION}:${userId.toLowerCase()}`).digest(),
        });
        if (challenge === undefined) throw new Refused('UNAUTHENTICATED');
        return { status: 202, resourceId: challenge.challengeId, made: challenge.challengeId };
      });
      if (opened.outcome === 'done') return { outcome: 'done', challengeId: opened.made };
      if (opened.outcome === 'replayed') return { outcome: 'done', challengeId: opened.resourceId };
      return opened;
    },

    async steppedUp(tx, { challengeId, sessionId, userId, accessToken }) {
      const sealed = keys.encrypt(
        'field-encryption',
        Buffer.from(accessToken, 'utf8'),
        tokenData(challengeId, userId, sessionId),
      );
      const now = clock.now();
      await tx
        .insertInto('identity.passkey_additions')
        .values({
          id: challengeId,
          session_id: sessionId,
          user_id: userId,
          state: 'stepped_up',
          token_ciphertext: sealed.ciphertext,
          token_key_version: sealed.keyVersion,
          ticket_hash: null,
          passkey_id: null,
          created_at: now,
          ends_at: new Date(now.getTime() + STEPPED_UP_SECONDS * 1000),
        })
        .execute();
    },

    async ticket(sessionId, challengeId, idempotent) {
      const ticket = randomBytes(32).toString('base64url');
      const endsAt = later(TICKET_SECONDS * 1000);
      const issued = await keyed(idempotent, async (tx) => {
        const moved = await tx
          .updateTable('identity.passkey_additions')
          .set({ state: 'ticketed', ticket_hash: hashOf(ticket), ends_at: endsAt })
          .where('id', '=', challengeId)
          .where('session_id', '=', sessionId)
          .where('state', '=', 'stepped_up')
          .where('ends_at', '>', clock.now())
          .executeTakeFirst();
        if (moved.numUpdatedRows !== 1n) throw new Refused('STEP_UP_FAILED');
        // The step-up is used: its challenge goes, so nothing else can be confirmed with it.
        await tx
          .deleteFrom('identity.step_up_challenges')
          .where('id', '=', challengeId)
          .where('session_id', '=', sessionId)
          .execute();
        return { status: 201, resourceId: challengeId, made: undefined };
      });
      if (issued.outcome === 'done') return { outcome: 'done', ticket, endsAt };
      if (issued.outcome === 'replayed') return refused('PASSKEY_TICKET_ALREADY_ISSUED');
      return issued;
    },

    async status(sessionId, challengeId) {
      const row = await database
        .selectFrom('identity.passkey_additions')
        .select('state')
        .where('id', '=', challengeId)
        .where('session_id', '=', sessionId)
        .where('ends_at', '>', clock.now())
        .executeTakeFirst();
      if (row === undefined) return 'GONE';
      if (row.state === 'stepped_up') return 'STEPPED_UP';
      return row.state === 'confirmed' ? 'ADDED' : 'WAITING_FOR_KEY';
    },

    async options(ticket) {
      if (!TICKET.test(ticket)) return refused('PASSKEY_TICKET_INVALID');
      const redeemed = await inTransaction(async (tx) => {
        const row = await byTicket(tx, ticket, 'ticketed');
        if (row === undefined) return undefined;
        await tx
          .updateTable('identity.passkey_additions')
          .set({ state: 'redeemed' })
          .where('id', '=', row.id)
          .execute();
        const subject = await subjectOfUser(tx, row.user_id, macs);
        return subject === undefined ? undefined : { row, subject: subject.subject };
      });
      if (redeemed === undefined) return refused('PASSKEY_TICKET_INVALID');
      const { row, subject } = redeemed;
      const token = tokenOf(row);
      try {
        const asked = await passkeys.register(token, subject);
        // The person's own addition on the record before anything to make the key with leaves this process.
        await inTransaction(async (tx) => {
          await tx
            .updateTable('identity.passkey_additions')
            .set({ state: 'registering', passkey_id: asked.passkeyId, ends_at: later(REGISTERING_SECONDS * 1000) })
            .where('id', '=', row.id)
            .where('state', '=', 'redeemed')
            .execute();
          await platform.record(tx, {
            actor: ACTOR,
            action: OWN_PASSKEY_REGISTERED,
            details: { person: row.user_id, subject, passkey: asked.passkeyId, at: clock.now().toISOString() },
          });
        });
        return { outcome: 'done', options: asked.options };
      } catch (error) {
        // Nothing to make the key with went out: the token is of no more use, so it goes, whatever failed.
        await dropAddition(row.id, token);
        // The person's token refused (run out, or taken back): theirs to start again, never our service token's alarm.
        if (error instanceof LoginTokenRefused) return refused('PASSKEY_REFUSED');
        throw error;
      }
    },

    async confirm(ticket, credential) {
      if (!TICKET.test(ticket)) return refused('PASSKEY_TICKET_INVALID');
      const taken = await inTransaction(async (tx) => {
        const row = await byTicket(tx, ticket, 'registering');
        if (row?.passkey_id === null || row === undefined) return undefined;
        const token = tokenOf(row);
        await tx
          .updateTable('identity.passkey_additions')
          .set({ state: 'confirming', token_ciphertext: null, token_key_version: null })
          .where('id', '=', row.id)
          .execute();
        const subject = await subjectOfUser(tx, row.user_id, macs);
        return subject === undefined
          ? undefined
          : { id: row.id, token, passkeyId: row.passkey_id, subject: subject.subject };
      });
      if (taken === undefined) return refused('PASSKEY_TICKET_INVALID');
      let confirmed: 'confirmed' | 'refused';
      try {
        confirmed = await passkeys.confirm(taken.token, taken.subject, taken.passkeyId, credential);
      } finally {
        await takeBack(taken.token);
      }
      if (confirmed === 'confirmed') {
        // Kept only for the console to read the key added, as long as the copier's window.
        await database
          .updateTable('identity.passkey_additions')
          .set({ state: 'confirmed', ends_at: later(OWN_KEY_WINDOW_MS) })
          .where('id', '=', taken.id)
          .where('state', '=', 'confirming')
          .execute();
        return { outcome: 'done' };
      }
      await database
        .deleteFrom('identity.passkey_additions')
        .where('id', '=', taken.id)
        .where('state', '=', 'confirming')
        .execute();
      return refused('PASSKEY_REFUSED');
    },
  };
}

/** Takes a token back at the login service; one it won't take back is said (never the token), never thrown. */
async function takenBack(
  revoke: ((accessToken: string) => Promise<boolean>) | undefined,
  token: string,
  logger: Logger,
): Promise<void> {
  if (revoke === undefined || !(await revoke(token))) logger.warn('identity.passkey_token_kept');
}

/**
 * Deletes up to `most` additions past their time; each token still in one taken back at the login service first, by
 * `revoke` (none where sign-in is off: said, and deleted all the same). How many went.
 */
export async function sweepPasskeyAdditions(
  {
    database,
    keys,
    revoke,
    clock,
    logger,
  }: {
    readonly database: Kysely<IdentityTables>;
    readonly keys: KeyProvider;
    readonly revoke: ((accessToken: string) => Promise<boolean>) | undefined;
    readonly clock: Clock;
    readonly logger: Logger;
  },
  most: number,
): Promise<number> {
  const gone = await database.transaction().execute(async (tx) => {
    await limitStatements(tx);
    return tx
      .deleteFrom('identity.passkey_additions')
      .where(
        'id',
        'in',
        tx
          .selectFrom('identity.passkey_additions')
          .select('id')
          .where('ends_at', '<=', clock.now())
          .orderBy('ends_at')
          .limit(most),
      )
      .returning(['id', 'user_id', 'session_id', 'token_ciphertext', 'token_key_version'])
      .execute();
  });
  for (const row of gone) {
    if (row.token_ciphertext === null || row.token_key_version === null) continue;
    let token: string;
    try {
      token = openField(
        keys,
        { keyVersion: row.token_key_version, ciphertext: row.token_ciphertext },
        tokenData(row.id, row.user_id, row.session_id),
        (cause) => new AdditionTokenUnreadable({ cause }),
      );
    } catch {
      // Sealed for another row, or changed: deleted, and the alarm, as no token of ours would be.
      logger.error('audit.integrity_failed', { check: 'passkey_addition', reason: 'token', rowId: row.id });
      continue;
    }
    await takenBack(revoke, token, logger);
  }
  return gone.length;
}
