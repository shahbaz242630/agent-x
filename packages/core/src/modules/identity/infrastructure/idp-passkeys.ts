// A passkey registered at the login service as the person themselves (SA6): Zitadel's user API (v2), asked with
// the person's own access token, which a step-up done with a passkey they already hold gave (passkey-additions.ts).
// No service user of ours holds a right to register a key for anyone (S220's probe: the Org User Manager role
// can't, and the roles that can would let a stolen token add a key to any account); a person may for themselves.
//
// - `register` asks for a new passkey on the login service's own name (its host, the relying party its sign-in
//   pages use): the passkey's ID, known before the key exists, and what the browser makes it with, passed on as
//   the login service gave it.
// - `confirm` sends the key the browser made back, under that ID.
// - The token goes only to the issuer's origin, through the same route as sign-in (`routedToIssuer`), and the
//   outbound fetch's allowlist; never logged. Each answer is read strictly and bounded; anything else throws
//   OwnPasskeysUnavailable, naming the step, never the answer.
import { field, ZITADEL_ID } from './zitadel-answer.ts';
import { createZitadelCall, LoginTokenRefused, type ZitadelCallOptions } from './zitadel-call.ts';

/** How long one call to the login service may take: one waking from idle takes most of it. */
const CALL_TIMEOUT_MS = 30_000;

/** The most one answer may hold: a passkey's creation options. */
const MOST_ANSWER_BYTES = 64 * 1024;

/** The name the new passkey is given at the login service, where the person sees their keys. */
export const OWN_PASSKEY_NAME = 'Added in Agent X';

export class OwnPasskeysUnavailable extends Error {
  override readonly name = 'OwnPasskeysUnavailable';
  constructor(step: string) {
    super(`the login service couldn't register the passkey: ${step}`);
  }
}

/** A passkey asked for: its ID, and the options the browser makes it with (WebAuthn's, as JSON). */
interface PasskeyAsked {
  readonly passkeyId: string;
  readonly options: Readonly<Record<string, unknown>>;
}

export interface OwnPasskeys {
  /** A new passkey for the person `subject`, as the person (`token`). Throws OwnPasskeysUnavailable. */
  register(token: string, subject: string): Promise<PasskeyAsked>;
  /**
   * Confirms the passkey with the key the browser made: `confirmed`, or `refused` when the login service won't take
   * it (a key not made for these options, or a token past its time). Throws OwnPasskeysUnavailable otherwise.
   */
  confirm(token: string, subject: string, passkeyId: string, credential: unknown): Promise<'confirmed' | 'refused'>;
}

/** The answer's object, or undefined for anything that isn't a plain JSON object. */
const objectIn = (value: unknown): Readonly<Record<string, unknown>> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : undefined;

export function createOwnPasskeys({ issuer, internalOrigin, fetch }: Omit<ZitadelCallOptions, 'token'>): OwnPasskeys {
  /** The relying party the login service's own sign-in pages use: its host (S220's probe of the pinned login image). */
  const domain = new URL(issuer).hostname;
  const unavailable = (step: string) => (how: string) => new OwnPasskeysUnavailable(`${step}: ${how}`);
  const caller = (token: string) =>
    createZitadelCall(
      { issuer, internalOrigin, token, fetch },
      { timeoutMs: CALL_TIMEOUT_MS, mostAnswerBytes: MOST_ANSWER_BYTES },
    );
  const checkedSubject = (subject: string) => {
    if (!ZITADEL_ID.test(subject)) throw new RangeError("the subject must be the login service's user ID");
  };

  return {
    async register(token, subject) {
      checkedSubject(subject);
      const step = 'asking for a passkey';
      const { status, answer } = await caller(token)(
        { path: `/v2/users/${subject}/passkeys`, method: 'POST', body: { domain } },
        unavailable(step),
      );
      if (status !== 200) throw new OwnPasskeysUnavailable(`${step}: it answered ${String(status)}`);
      const passkeyId = field(answer, 'passkeyId');
      const options = objectIn(field(answer, 'publicKeyCredentialCreationOptions'));
      if (typeof passkeyId !== 'string' || !ZITADEL_ID.test(passkeyId)) {
        throw new OwnPasskeysUnavailable(`${step}: the answer names no passkey`);
      }
      if (options === undefined || objectIn(options.publicKey) === undefined) {
        throw new OwnPasskeysUnavailable(`${step}: the answer holds no options to make the key with`);
      }
      return { passkeyId, options };
    },

    async confirm(token, subject, passkeyId, credential) {
      checkedSubject(subject);
      if (!ZITADEL_ID.test(passkeyId)) throw new RangeError("the passkey must be the login service's ID");
      const step = 'confirming the passkey';
      let status: number;
      try {
        ({ status } = await caller(token)(
          {
            path: `/v2/users/${subject}/passkeys/${passkeyId}`,
            method: 'POST',
            body: { publicKeyCredential: credential, passkeyName: OWN_PASSKEY_NAME },
          },
          unavailable(step),
        ));
      } catch (error) {
        // The person's token past its time, or taken back: the key can't be confirmed as them.
        if (error instanceof LoginTokenRefused) return 'refused';
        throw error;
      }
      if (status === 200) return 'confirmed';
      // A key that isn't one made for these options, or a passkey already confirmed or gone.
      if (status === 400 || status === 404 || status === 412) return 'refused';
      throw new OwnPasskeysUnavailable(`${step}: it answered ${String(status)}`);
    },
  };
}
