// The login service's own admin events we copy into our audit trail
// (ADR-003 §4: "Zitadel's admin events (MFA reset, user and role changes) are
// copied into our audit trail. The affected user and their organisation's
// admins are notified"; SEC-OPS-02; B6-2b). Each event type Zitadel v4.17.3
// records (read from its source, S56) is sorted into what it means for us:
//
// - a change to a person's sign-in, told to them and their organisations'
//   admins: a second factor removed (an authenticator app, a security key, a
//   passkey, recovery codes) or added (once ready to use: an app or a key
//   verified, an SMS or email code added; the S68 audit), a password changed or a reset asked for, the
//   login's email changed, the login locked, deactivated or removed, or it
//   unlocked or reactivated;
// - a token issued for a login (a machine user's): recorded, and logged;
// - impersonation, which the stack never turns on (ADR-003 §4): an alarm;
// - someone given, changed or removed rights in the login service itself (its
//   instance or an organisation of it): recorded, and logged, since that is a
//   break-glass admin's power.
//
// At most 30 types, as Zitadel's event search takes.

/** What a copied event means for us. The first five are the sign-in notices' kinds (0024). */
export type IdpEventClass =
  | 'second_factor_removed'
  | 'second_factor_added'
  | 'password_changed'
  | 'sign_in_email_changed'
  | 'sign_in_blocked'
  | 'sign_in_restored'
  | 'token_issued'
  | 'impersonated'
  | 'rights_changed';

/** The event types copied, by what they mean. */
const BY_CLASS: Readonly<Record<IdpEventClass, readonly string[]>> = {
  second_factor_removed: [
    'user.human.mfa.otp.removed',
    'user.human.mfa.otp.sms.removed',
    'user.human.mfa.otp.email.removed',
    'user.human.mfa.u2f.token.removed',
    'user.human.passwordless.token.removed',
    'user.human.mfa.recoverycode.removed',
  ],
  // Zitadel v4.17.3's own names (internal/repository/user/human_mfa_*.go): an app, a security key or a
  // passkey counts once verified, as it can be used from then; an SMS or email code has no verify step.
  second_factor_added: [
    'user.human.mfa.otp.verified',
    'user.human.mfa.otp.sms.added',
    'user.human.mfa.otp.email.added',
    'user.human.mfa.u2f.token.verified',
    'user.human.passwordless.token.verified',
  ],
  password_changed: ['user.human.password.changed', 'user.human.password.code.added'],
  sign_in_email_changed: ['user.human.email.changed'],
  sign_in_blocked: ['user.locked', 'user.deactivated', 'user.removed'],
  sign_in_restored: ['user.unlocked', 'user.reactivated'],
  token_issued: ['user.token.added'],
  impersonated: ['user.impersonated'],
  rights_changed: [
    'instance.member.added',
    'instance.member.changed',
    'instance.member.removed',
    'instance.member.cascade.removed',
    'org.member.added',
    'org.member.changed',
    'org.member.removed',
    'org.member.cascade.removed',
  ],
};

/** The event types of a second factor removed (B6-3d reads them). */
export const SECOND_FACTOR_REMOVED_EVENTS: readonly string[] = BY_CLASS.second_factor_removed;

/** A security key or a passkey, once usable: what passes the passkey rule (SEC-HA-12), so a new one may restrict (the S68 audit). */
export const PASSKEY_ADDED_EVENTS: readonly string[] = [
  'user.human.mfa.u2f.token.verified',
  'user.human.passwordless.token.verified',
];

/** A security key or a passkey removed. */
export const PASSKEY_REMOVED_EVENTS: readonly string[] = [
  'user.human.mfa.u2f.token.removed',
  'user.human.passwordless.token.removed',
];

/**
 * Whether a change of this class ends every Agent X session the person has
 * (the S68 audit): a second factor added or removed, the password or the
 * login's email changed, or the login blocked. A session opened before the
 * change never outlives it, whoever holds it.
 */
export const endsSessions = (eventClass: IdpEventClass): boolean =>
  eventClass === 'second_factor_removed' ||
  eventClass === 'second_factor_added' ||
  eventClass === 'password_changed' ||
  eventClass === 'sign_in_email_changed' ||
  eventClass === 'sign_in_blocked';

/** Every event type copied, and what it means. */
export const WATCHED_IDP_EVENTS: Readonly<Record<string, IdpEventClass>> = Object.freeze(
  Object.fromEntries(
    (Object.entries(BY_CLASS) as [IdpEventClass, readonly string[]][]).flatMap(([eventClass, types]) =>
      types.map((type) => [type, eventClass]),
    ),
  ),
);

/** The most event types one search may name (Zitadel's own limit). */
export const MOST_WATCHED_TYPES = 30;

/** What the event type means for us; undefined for one we don't copy. */
export const classOfIdpEvent = (type: string): IdpEventClass | undefined =>
  Object.hasOwn(WATCHED_IDP_EVENTS, type) ? WATCHED_IDP_EVENTS[type] : undefined;

/** Whether a class is told to the person and their organisations' admins. */
export const isToldToThePerson = (
  eventClass: IdpEventClass,
): eventClass is Exclude<IdpEventClass, 'token_issued' | 'impersonated' | 'rights_changed'> =>
  eventClass !== 'token_issued' && eventClass !== 'impersonated' && eventClass !== 'rights_changed';
