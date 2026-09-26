// The step-up's checks on the way back from the login service (ADR-003 §9,
// step 4; B3-2). The OIDC client has already checked the ID token itself,
// its nonce against the challenge's own among them; these check that the
// fresh sign-in stands for this challenge:
// - the same person as the session's (the subject's user is the challenge's);
// - authenticated at or after the challenge was made (SEC-HA-05): `auth_time`
//   is in whole seconds and stamped by the login service's clock, so it is
//   held to the challenge's time rounded down to its second, less 5 seconds
//   for the two clocks to differ (review, B3-2). A login service that signed
//   the person straight back in without asking (`max_age=0` alone, S10) leaves
//   `auth_time` as it was, the session's own sign-in minutes or hours before,
//   and is refused here. The ID token must also carry the challenge's own
//   nonce, which exists only from the challenge on;
// - with a second factor, `mfa` in `amr` (SEC-HA-06);
// - with a passkey (a security key, `user` in `amr`) where the change asks
//   for one: admins and finance approvers (ADR-012 §7, SEC-HA-12). A code
//   from an authenticator app (`otp`) alone won't do there. Who needs one is
//   decided by the role the change is made in, so the change's own
//   transaction asks for it as it consumes the challenge (B3+-1,
//   step-up-challenges.ts); the way back from the login service doesn't know
//   the organisation yet. A passwordless sign-in's `amr` is unproven: it is
//   refused unless it carries `mfa`.
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

/** How far behind ours the login service's clock may be: both keep time from Azure's, so seconds at most. */
export const AUTH_TIME_TOLERANCE_SECONDS = 5;

/** The `amr` value every second factor carries at Zitadel (S10: security key and authenticator app alike). */
const SECOND_FACTOR = 'mfa';
/** The `amr` value a security key (WebAuthn) carries at Zitadel, and an authenticator app doesn't (S10). */
export const PASSKEY_METHOD = 'user';

/** The first reason the fresh sign-in doesn't stand for the challenge, or undefined when it does. */
export function stepUpRefusal(
  challenge: ChallengeFacts,
  signIn: FreshSignIn,
  { passkeyRequired }: { readonly passkeyRequired: boolean },
): StepUpRefusal | undefined {
  if (signIn.userId.toLowerCase() !== challenge.userId.toLowerCase()) return 'other_person';
  const earliest = Math.floor(challenge.createdAt.getTime() / 1000) * 1000 - AUTH_TIME_TOLERANCE_SECONDS * 1000;
  const authTime = signIn.evidence.authTime.getTime();
  if (Number.isNaN(authTime) || authTime < earliest) return 'stale_authentication';
  const { amr } = signIn.evidence;
  if (!amr.includes(SECOND_FACTOR)) return 'no_second_factor';
  if (passkeyRequired && !amr.includes(PASSKEY_METHOD)) return 'no_passkey';
  return undefined;
}
