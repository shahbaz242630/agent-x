// Removing a person's second factors at the login service (ADR-003 §4,
// ADR-012 §8; SEC-OPS-04; B6-3c): what a reset a registered contact confirmed
// does once its cooling-off has passed. Zitadel's user API (v2), asked with
// the token of a service user of its own holding the organisation's Org User
// Manager role (partner, S57: no built-in role removes factors without being
// able to delete users; this token is used for nothing else).
//
// - Every second factor the person has, ready or not: app codes (TOTP), SMS
//   and email codes, security keys (U2F) and passkeys, each by its own call,
//   and recovery codes when the person's methods list them. The password, and
//   a link to another login, are not second factors, and stay.
// - Then read again, a few times while the login service catches up:
//   anything still left but those two throws, so a reset is completed only
//   once the login service shows none left (a call that said yes and did
//   nothing can't pass).
// - A factor already gone (404) is taken as removed: a run that stopped
//   part-way is run again from the start.
// - The token goes only to the issuer's origin, through the same route as
//   sign-in (`routedToIssuer`), and the outbound fetch's allowlist. Each
//   answer is read strictly and bounded; anything else throws
//   IdpFactorsUnavailable, naming the step, never the answer.
import { createZitadelCall, type ZitadelCallOptions } from './zitadel-call.ts';

/** How long one call to the login service may take. */
const CALL_TIMEOUT_MS = 10_000;

/** The most one answer may hold. */
const MOST_ANSWER_BYTES = 256 * 1024;

/**
 * How many times the factors are read after their removal, and how long to
 * wait between reads: Zitadel's searches read a projection that can trail a
 * removal by a moment (the e2e flake of S67 and S70), so one left only that
 * long isn't one left. A factor still there after the last read throws.
 */
const READS_AFTER_REMOVAL = 5;
const PAUSE_BETWEEN_READS_MS = 400;

const sleep = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

/** The most factors, or passkeys, one person may have that a removal reads. */
const MOST_FACTORS = 100;

/** A subject, and a factor's ID, as Zitadel makes them: digits. */
const ZITADEL_ID = /^[0-9]{1,32}$/;

/** The methods that aren't second factors, which a removal leaves. */
const NOT_SECOND_FACTORS: ReadonlySet<string> = new Set([
  'AUTHENTICATION_METHOD_TYPE_PASSWORD',
  'AUTHENTICATION_METHOD_TYPE_IDP',
]);

/** Every method Zitadel names (user/v2 AuthenticationMethodType): one outside it is an answer we can't judge. */
const METHODS: ReadonlySet<string> = new Set([
  ...NOT_SECOND_FACTORS,
  'AUTHENTICATION_METHOD_TYPE_PASSKEY',
  'AUTHENTICATION_METHOD_TYPE_TOTP',
  'AUTHENTICATION_METHOD_TYPE_U2F',
  'AUTHENTICATION_METHOD_TYPE_OTP_SMS',
  'AUTHENTICATION_METHOD_TYPE_OTP_EMAIL',
  'AUTHENTICATION_METHOD_TYPE_RECOVERY_CODE',
]);

/** A factor's or passkey's states; a removed one is gone. */
const STATES: ReadonlySet<string> = new Set([
  'AUTH_FACTOR_STATE_UNSPECIFIED',
  'AUTH_FACTOR_STATE_NOT_READY',
  'AUTH_FACTOR_STATE_READY',
  'AUTH_FACTOR_STATE_REMOVED',
]);
const REMOVED = 'AUTH_FACTOR_STATE_REMOVED';
const READY = 'AUTH_FACTOR_STATE_READY';

export class IdpFactorsUnavailable extends Error {
  override readonly name = 'IdpFactorsUnavailable';
  constructor(step: string) {
    super(`the login service's second factors couldn't be removed: ${step}`);
  }
}

/** How many second factors a person holds at the login service (the S68 audit; F1's first-passkey rule). */
export interface SecondFactorsHeld {
  /**
   * The second factors of the login service's user `subject` that are ready
   * to use, of every kind: app codes, SMS and email codes, security keys,
   * passkeys, and recovery codes (one, however many codes). Throws
   * IdpFactorsUnavailable for an answer it can't judge.
   */
  secondFactorsHeld(subject: string): Promise<number>;
}

export interface SecondFactorRemover {
  /**
   * Removes every second factor of the login service's user `subject`, and
   * says how many calls removed one. Throws IdpFactorsUnavailable, and then
   * some may have been removed: running it again finishes the job.
   */
  removeAll(subject: string): Promise<number>;
}

type Answer = Readonly<Record<string, unknown>>;

const field = (value: unknown, name: string): unknown =>
  typeof value === 'object' && value !== null ? (value as Answer)[name] : undefined;

/** An answer's list, empty when Zitadel leaves it out (as it does an empty one); anything else throws. */
function listIn(answer: unknown, name: string, step: string): readonly unknown[] {
  const list = field(answer, name) ?? [];
  if (!Array.isArray(list) || list.length > MOST_FACTORS) {
    throw new IdpFactorsUnavailable(`${step}: the answer holds no list of at most ${String(MOST_FACTORS)}`);
  }
  return list;
}

/** A factor's or passkey's state, read strictly; Zitadel leaves an unspecified one out. */
function stateOf(raw: unknown, what: string): string {
  const state = field(raw, 'state') ?? 'AUTH_FACTOR_STATE_UNSPECIFIED';
  if (typeof state !== 'string' || !STATES.has(state)) throw new IdpFactorsUnavailable(`${what} has no state we know`);
  return state;
}

/** Where a factor is removed, below the user's own path; a factor of a kind we don't know throws. */
function removalOf(factor: unknown): string {
  const kinds = ['otp', 'otpSms', 'otpEmail', 'u2f'].filter((kind) => field(factor, kind) !== undefined);
  const [kind] = kinds;
  if (kinds.length !== 1) throw new IdpFactorsUnavailable('a factor is not as the login service writes them');
  if (kind === 'otp') return '/totp';
  if (kind === 'otpSms') return '/otp_sms';
  if (kind === 'otpEmail') return '/otp_email';
  const id = field(field(factor, 'u2f'), 'id');
  if (typeof id !== 'string' || !ZITADEL_ID.test(id)) throw new IdpFactorsUnavailable("a security key's ID is not one");
  return `/u2f/${id}`;
}

/** Where a passkey is removed. */
function passkeyRemovalOf(passkey: unknown): string {
  const id = field(passkey, 'id');
  if (typeof id !== 'string' || !ZITADEL_ID.test(id)) throw new IdpFactorsUnavailable("a passkey's ID is not one");
  return `/passkeys/${id}`;
}

export function createSecondFactorRemover({
  pause = sleep,
  ...login
}: ZitadelCallOptions & {
  /** Waits between the reads after a removal; a test's is instant. */
  readonly pause?: (ms: number) => Promise<void>;
}): SecondFactorRemover & SecondFactorsHeld {
  const zitadel = createZitadelCall(login, { timeoutMs: CALL_TIMEOUT_MS, mostAnswerBytes: MOST_ANSWER_BYTES });

  /** Calls the user's path; its answer's status and body (parsed for a 200 alone). */
  const call = (subject: string, path: string, method: 'GET' | 'POST' | 'DELETE', body: unknown, step: string) =>
    zitadel(
      { path: `/v2/users/${subject}${path}`, method, body },
      (how) => new IdpFactorsUnavailable(`${step}: ${how}`),
    );

  /** A read's answer; anything but 200 throws. */
  const read = async (subject: string, path: string, method: 'GET' | 'POST', body: unknown, step: string) => {
    const { status, answer } = await call(subject, path, method, body, step);
    if (status !== 200) throw new IdpFactorsUnavailable(`${step}: it answered ${String(status)}`);
    return answer;
  };

  /** The person's factors in `states`, passkeys and methods, each list read strictly. */
  const listsOf = async (subject: string, states: readonly string[]) => {
    const factors = listIn(
      await read(subject, '/authentication_factors/_search', 'POST', { states }, 'reading the factors'),
      'result',
      'reading the factors',
    );
    const passkeys = listIn(
      await read(subject, '/passkeys/_search', 'POST', {}, 'reading the passkeys'),
      'result',
      'reading the passkeys',
    );
    const methods = listIn(
      await read(subject, '/authentication_methods', 'GET', undefined, 'reading the methods'),
      'authMethodTypes',
      'reading the methods',
    );
    if (!methods.every((method) => typeof method === 'string' && METHODS.has(method))) {
      throw new IdpFactorsUnavailable('a method is not one the login service names');
    }
    return { factors, passkeys, methods };
  };

  /** Every second factor the person has now, as the paths that remove them; and any method left otherwise. */
  const secondFactorsOf = async (subject: string): Promise<{ removals: string[]; otherMethods: string[] }> => {
    const { factors, passkeys, methods } = await listsOf(subject, ['AUTH_FACTOR_STATE_NOT_READY', READY]);
    const removals = [
      ...factors.filter((factor) => stateOf(factor, 'a factor') !== REMOVED).map(removalOf),
      ...passkeys.filter((passkey) => stateOf(passkey, 'a passkey') !== REMOVED).map(passkeyRemovalOf),
      ...(methods.includes('AUTHENTICATION_METHOD_TYPE_RECOVERY_CODE') ? ['/recovery_codes'] : []),
    ];
    const listed = new Set(['AUTHENTICATION_METHOD_TYPE_RECOVERY_CODE', ...NOT_SECOND_FACTORS]);
    return { removals, otherMethods: methods.filter((method) => !listed.has(method as string)) as string[] };
  };

  return {
    async secondFactorsHeld(subject) {
      if (!ZITADEL_ID.test(subject)) throw new RangeError("the subject must be the login service's user ID");
      const { factors, passkeys, methods } = await listsOf(subject, [READY]);
      // removalOf judges each factor's kind: one we don't know throws, never a count.
      const ready = factors.filter((factor) => stateOf(factor, 'a factor') === READY).map(removalOf);
      const readyPasskeys = passkeys.filter((passkey) => stateOf(passkey, 'a passkey') === READY);
      const recoveryCodes = methods.includes('AUTHENTICATION_METHOD_TYPE_RECOVERY_CODE') ? 1 : 0;
      return ready.length + readyPasskeys.length + recoveryCodes;
    },

    async removeAll(subject) {
      if (!ZITADEL_ID.test(subject)) throw new RangeError("the subject must be the login service's user ID");
      const { removals } = await secondFactorsOf(subject);
      let removed = 0;
      for (const path of removals) {
        const { status } = await call(subject, path, 'DELETE', undefined, 'removing a factor');
        // Gone already: removed by a run that stopped part-way, or by someone at the login service.
        if (status === 404) continue;
        if (status !== 200) throw new IdpFactorsUnavailable(`removing a factor: it answered ${String(status)}`);
        removed += 1;
      }
      for (let read = 1; ; read += 1) {
        const left = await secondFactorsOf(subject);
        if (left.removals.length === 0 && left.otherMethods.length === 0) return removed;
        if (read === READS_AFTER_REMOVAL) {
          throw new IdpFactorsUnavailable('a second factor is still there after its removal');
        }
        await pause(PAUSE_BETWEEN_READS_MS);
      }
    },
  };
}
