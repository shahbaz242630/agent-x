// The step-up's checks on the way back from the login service (ADR-003 §9,
// step 4; B3-2). The OIDC client has already checked the ID token itself,
// its nonce against the challenge's own among them; these check that the
// fresh sign-in stands for this challenge:
// - the same person as the session's (the subject's user is the challenge's);
// - authenticated at or after the challenge was made (SEC-HA-05): `auth_time`
//   is in whole seconds, so it is held to the challenge's time rounded down to
//   its second. A login service that signed the person straight back in
//   without asking (`max_age=0` alone, S10) leaves `auth_time` as it was, and
//   is refused here;
// - with a second factor, `mfa` in `amr` (SEC-HA-06);
// - with a passkey (a security key, `user` in `amr`) where the change asks
//   for one: admins and finance approvers (ADR-012 §7, SEC-HA-12). A code
//   from an authenticator app (`otp`) alone won't do there. Who needs one is
//   decided by roles, from B4.
// Each refusal names the check, never a value.
import type { SignInEvidence } from './sign-in.ts';

/** Why a fresh sign-in doesn't stand for the challenge. */
export type StepUpRefusal = 'other_person' | 'stale_authentication' | 'no_second_factor' | 'no_passkey';

/** What the checks need of the challenge. */
export interface ChallengeFacts {
  readonly userId: string;
  readonly createdAt: Date;
}

/** What the checks need of the fresh sign-in: its person, as a user, and what it proved. */
export interface FreshSignIn {
  readonly userId: string;
  readonly evidence: Pick<SignInEvidence, 'authTime' | 'amr'>;
}

/** The `amr` value every second factor carries at Zitadel (S10: security key and authenticator app alike). */
const SECOND_FACTOR = 'mfa';
/** The `amr` value a security key (WebAuthn) carries at Zitadel, and an authenticator app doesn't (S10). */
const PASSKEY = 'user';

/** The first reason the fresh sign-in doesn't stand for the challenge, or undefined when it does. */
export function stepUpRefusal(
  challenge: ChallengeFacts,
  signIn: FreshSignIn,
  { passkeyRequired }: { readonly passkeyRequired: boolean },
): StepUpRefusal | undefined {
  if (signIn.userId.toLowerCase() !== challenge.userId.toLowerCase()) return 'other_person';
  const challengeSecond = Math.floor(challenge.createdAt.getTime() / 1000) * 1000;
  const authTime = signIn.evidence.authTime.getTime();
  if (Number.isNaN(authTime) || authTime < challengeSecond) return 'stale_authentication';
  const { amr } = signIn.evidence;
  if (!amr.includes(SECOND_FACTOR)) return 'no_second_factor';
  if (passkeyRequired && !amr.includes(PASSKEY)) return 'no_passkey';
  return undefined;
}
