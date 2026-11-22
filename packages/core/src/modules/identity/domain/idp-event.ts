// The login service's own admin events we copy into our audit trail
// (ADR-003 §4: "Zitadel's admin events (MFA reset, user and role changes) are
// copied into our audit trail. The affected user and their organisation's
// admins are notified"; SEC-OPS-02; B6-2b). Each event type Zitadel v4.17.3
// records (read from its source, S56) is sorted into what it means for us:
//
// - a change to a person's sign-in, told to them and their organisations'
//   admins: a second factor removed (an authenticator app, a security key, a
//   passkey, recovery codes) or added (once ready to use: an app or a key
//   verified, an SMS or email code added; the S68 audit), a password changed, the
//   login's email or phone changed (the phone: where SMS codes go, S210), the
//   login locked, deactivated or removed, or it
//   unlocked or reactivated;
// - a reset of a person's password asked for (S210 R2-2): told to the person
//   alone, at most once an hour, never to the admins, and no session ended, as
//   anyone who knows a login's name can ask for one on the open login app and
//   nothing changes until the reset is used (which is a password changed);
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
  | 'password_reset_asked'
  | 'sign_in_email_changed'
  | 'sign_in_phone_changed'
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
  password_changed: ['user.human.password.changed'],
  // A reset code sent (Zitadel's internal/repository/user/human_password.go): asked for by anyone at the login app's
  // "forgot password", knowing only the login's name. No credential changes until the code is used.
  password_reset_asked: ['user.human.password.code.added'],
  sign_in_email_changed: ['user.human.email.changed'],
  // Read from the pinned image's own binary (v4.20.5, S210): a new number takes the SMS codes from then on.
  sign_in_phone_changed: ['user.human.phone.changed'],
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

/**
 * Whether a change of this class ends every Agent X session the person has
 * (the S68 audit): a second factor added or removed, the password or the
 * login's email or phone changed, or the login blocked. A session opened before the
 * change never outlives it, whoever holds it.
 */
export const endsSessions = (eventClass: IdpEventClass): boolean =>
  eventClass === 'second_factor_removed' ||
  eventClass === 'second_factor_added' ||
  eventClass === 'password_changed' ||
  eventClass === 'sign_in_email_changed' ||
  eventClass === 'sign_in_phone_changed' ||
  eventClass === 'sign_in_blocked';

/** Every event type copied, and what it means. */
export const WATCHED_IDP_EVENTS: Readonly<Record<string, IdpEventClass>> = Object.freeze(
  Object.fromEntries(
    (Object.entries(BY_CLASS) as [IdpEventClass, readonly string[]][]).flatMap(([eventClass, types]) =>
      types.map((type) => [type, eventClass]),
    ),
  ),
);

/**
 * The two feeds the copier reads, each in a search of its own from a read position of its own (S210 final): the resets
 * asked for, which anyone can make in a flood, apart from every real change, so a flood never holds a change back.
 */
export type IdpFeedPart = 'changes' | 'resets';

/** The event types each feed reads: the resets asked for alone, and every other type copied. */
export const FEED_TYPES: Readonly<Record<IdpFeedPart, readonly string[]>> = Object.freeze({
  resets: BY_CLASS.password_reset_asked,
  changes: Object.keys(WATCHED_IDP_EVENTS).filter((type) => WATCHED_IDP_EVENTS[type] !== 'password_reset_asked'),
});

/** The most event types one search may name (Zitadel's own limit). */
export const MOST_WATCHED_TYPES = 30;

/** What the event type means for us; undefined for one we don't copy. */
export const classOfIdpEvent = (type: string): IdpEventClass | undefined =>
  Object.hasOwn(WATCHED_IDP_EVENTS, type) ? WATCHED_IDP_EVENTS[type] : undefined;

/** Whether a class is told to the person and their organisations' admins. */
export const isToldToThePerson = (
  eventClass: IdpEventClass,
): eventClass is Exclude<IdpEventClass, 'token_issued' | 'impersonated' | 'rights_changed' | 'password_reset_asked'> =>
  eventClass !== 'token_issued' &&
  eventClass !== 'impersonated' &&
  eventClass !== 'rights_changed' &&
  eventClass !== 'password_reset_asked';

/**
 * Whether a class is told to the person alone, at most once an hour, and never to the admins (S210 R2-2): a request
 * anyone can make that changes no credential. A flood of them is also copied once a person a page (idp-copier.ts).
 */
export const isToldOnlyToThePerson = (eventClass: IdpEventClass): eventClass is 'password_reset_asked' =>
  eventClass === 'password_reset_asked';

/**
 * Who makes our own routine changes in the login service, as the deployment names them (SA2): the logins allowed to
 * make them (the break-glass admin, or our set-up's service user), and our API's own service users, whose tokens and
 * rights those changes are. Empty, nothing is ours.
 */
export interface OurLoginChanges {
  readonly actors: ReadonlySet<string>;
  readonly serviceUsers: ReadonlySet<string>;
}

/** The roles our service users are given (Secrets-Register): the read-only viewers, and the resets' user manager. */
const OUR_SERVICE_ROLES: ReadonlySet<string> = new Set(['IAM_OWNER_VIEWER', 'ORG_OWNER_VIEWER', 'ORG_USER_MANAGER']);

/** A copied event, as far as telling our own routine change apart needs it. */
interface ChangeSeen {
  readonly type: string;
  readonly eventClass: IdpEventClass;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly editorUserId: string | null;
  readonly member?: { readonly userId: string; readonly roles: readonly string[] };
}

/**
 * Whether a token issued or a grant of rights is one of our own routine changes (SA2), told by an info line rather
 * than the alert. Both sides must hold, so one of our actors' stolen credentials stay loud for anything else:
 * - the change is made by one of our actors;
 * - and it is exactly a change we make: a token issued to one of our service users, or one of them given (or its
 *   roles changed to) only roles our service users hold. A token for anyone else, a grant to anyone else or of any
 *   other role (an owner's), a membership removed, a payload not read whole: not ours, and it alerts.
 * Impersonation and a tied page are never ours: the copier never asks.
 */
export function isOurRoutineChange(event: ChangeSeen, ours: OurLoginChanges): boolean {
  if (event.editorUserId === null || !ours.actors.has(event.editorUserId)) return false;
  if (event.eventClass === 'token_issued') {
    return event.aggregateType === 'user' && ours.serviceUsers.has(event.aggregateId);
  }
  if (event.eventClass !== 'rights_changed' || event.member === undefined) return false;
  const granted = event.type.endsWith('.member.added') || event.type.endsWith('.member.changed');
  const { userId, roles } = event.member;
  return (
    granted && ours.serviceUsers.has(userId) && roles.length > 0 && roles.every((role) => OUR_SERVICE_ROLES.has(role))
  );
}
