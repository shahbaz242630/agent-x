/**
 * The one registry of reason codes (ADR-011 §8, SEC-EVD-06). A reason code
 * says why a request was refused, held, sent for approval or failed. It is
 * recorded with each decision and state change, and returned to API clients,
 * in error responses too.
 *
 * - Code that records a reason types it as `ReasonCode`, so an unregistered
 *   code fails the type check, and lint refuses `as ReasonCode`.
 * - Each code has a description, which is its public documentation. Error
 *   responses send it as their message, so it never names anything internal.
 * - Codes are stable: never rename or reuse one, because clients and past
 *   evidence depend on it. Add new codes in alphabetical order.
 */
export const REASON_CODES = {
  AGGREGATE_THRESHOLD:
    "Together with the same supplier's other open or paid requests in the aggregation window, this request crosses the approval threshold, so a person must approve it.",
  ALREADY_A_MEMBER:
    "You already belong to this organisation, so its invitation can't be accepted. Ask one of its admins if your role should change.",
  BAD_REQUEST: "The request is malformed, so it can't be read.",
  DUPLICATE_ORDER_REFERENCE:
    'An earlier request for the same supplier and order reference is still open, has an unknown outcome or was paid, so this one is refused.',
  FORBIDDEN: "You're signed in, but this address answers other roles only, so the request is refused.",
  HEADERS_TOO_LARGE:
    "The request's headers are larger than accepted, so it is refused. Large cookies are the usual cause.",
  HOLD_CHANGED:
    'The integrity hold was cleared by someone else while this clearing was being made, so nothing was changed. Look at the hold again.',
  IDEMPOTENCY_KEY_BUSY:
    'An earlier request with this Idempotency-Key is still being done. Wait the number of seconds in the Retry-After header, then send the same request again with the same key.',
  IDEMPOTENCY_KEY_INVALID:
    'This address changes something, so each request must carry an Idempotency-Key header: 1 to 255 visible ASCII characters, no spaces, new for each change you mean to make. Send the same key again only to retry the same request.',
  IDEMPOTENCY_KEY_REUSED:
    'This Idempotency-Key was already used for a different request, so this one is refused and nothing was changed. Use a new key for a new change.',
  INTEGRITY_FAILED:
    "Some of the organisation's records couldn't be verified, so this answer is withheld and the organisation is on hold while it is looked into. The Agent X team has been alerted.",
  INTERNAL_ERROR:
    'Something went wrong on our side, so the request failed. Quote the correlation ID if you contact support.',
  INVITATION_CLOSED:
    "This invitation can't be confirmed: it was confirmed already, or it has ended. Ask for a new invitation if one is still needed.",
  INVITATION_INVALID:
    "This invitation can't be accepted by you: its link isn't one we know, or you signed in with another email address. Sign in with the address you were invited at, or ask the organisation's admin for a new invitation.",
  MEMBER_DEACTIVATED:
    "This member was deactivated, so their role can't be changed and they can't be deactivated again. Invite them again to bring them back.",
  NOT_FOUND: 'There is nothing at this address, or the feature is not available.',
  NOT_ON_HOLD:
    "The organisation isn't on its integrity hold, so there is no hold to investigate or clear. Nothing was changed.",
  NO_INVESTIGATION:
    'The integrity hold can only be cleared after its investigation is recorded, and there is no investigation by this ID of the hold as it now stands. Record the investigation first.',
  ORGANIZATION_INVALID:
    'This address acts in one organisation, so the request must name it in an AgentX-Organization header, by its ID. This one named none, or not an ID, so it is refused.',
  ORG_FROZEN:
    'The organisation is frozen, so no new request is accepted. This refusal is temporary: the same idempotency key can be used again once the freeze is lifted.',
  ORIGIN_REFUSED:
    "A browser request that changes something must come from Agent X's own web address, and this one didn't, so it is refused.",
  OWN_MEMBERSHIP:
    "An admin can't change their own role or deactivate themselves, so the organisation always keeps an admin. Ask another admin to make the change.",
  PASSKEY_REQUIRED:
    'Your role here is admin or finance approver, which needs a passkey, and this session was signed in without one, so the request is refused. Sign out, then sign in again with your passkey (a security key, or Windows Hello).',
  PAYLOAD_TOO_LARGE: 'The request body is larger than this address accepts, so it is refused.',
  RATE_LIMITED:
    'Too many requests came from this client address, or from this signed-in person, in the last minute. Wait the number of seconds in the Retry-After header, then try again.',
  REQUEST_TIMEOUT: 'The request took too long to arrive, so it is refused. Send it again.',
  ROLE_UNCHANGED: 'The member already has this role, so nothing was changed.',
  SIGN_IN_FAILED: "The sign-in couldn't be completed, so no session was opened. Start again from the sign-in page.",
  SIGN_IN_UNAVAILABLE:
    "The sign-in service couldn't be reached just now, so no session was opened. Wait the number of seconds in the Retry-After header, then start again from the sign-in page.",
  STEP_UP_FAILED:
    "Signing in again couldn't confirm this change, so it wasn't confirmed. Start the change again, then sign in again as the same person, with your second factor: your passkey, if you're an admin or a finance approver.",
  SUPPLIER_CHANGED:
    "The supplier's payment details changed after the request was decided, so it is refused before hand-off.",
  UNAUTHENTICATED:
    'This address answers only a signed-in person or an agent with its key, and the request came from neither, so it is refused.',
  UNSUPPORTED_MEDIA_TYPE: "The request body's content type isn't accepted at this address, so it is refused.",
} as const satisfies Readonly<Record<string, string>>;

export type ReasonCode = keyof typeof REASON_CODES;

/**
 * True only for a registered code. Use it on a code read back from the
 * database or another outside source, where the compiler can't vouch for it
 * and `as ReasonCode` is refused by lint. Inherited names such as `toString`
 * are not codes.
 */
export function isReasonCode(value: string): value is ReasonCode {
  return Object.hasOwn(REASON_CODES, value);
}
