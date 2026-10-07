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
  AGENT_ADDS_SPENT:
    "The organisation has registered as many agents as it may in 24 hours, so this one wasn't registered. Try again tomorrow; if no one at the organisation registered them, tell its admins at once.",
  AGENT_KEYS_FULL:
    'The agent already has as many working keys as it may: a rotation is still in its overlap. Wait for the older key to expire, or revoke one, then rotate again. Nothing was changed.',
  AGENT_KEYS_SPENT:
    "The organisation has issued as many agent keys as it may in 24 hours, so this one wasn't issued. Try again tomorrow; if no one at the organisation rotated them, tell its admins at once.",
  AGENT_KEY_NOT_LIVE: 'The key is revoked or expired, so there is nothing to rotate. Nothing was changed.',
  AGENT_KEY_REVOKED: 'The key is revoked already. Nothing was changed.',
  AGENT_NOT_ACTIVE:
    'The agent is suspended, so no mandate can be drafted for it. Lift its suspension first. Nothing was changed.',
  AGENT_NOT_SUSPENDED: 'The agent is active, so there is no suspension to lift. Nothing was changed.',
  AGENT_OWNER_NOT_ELIGIBLE:
    "The member can't own an agent: they must be an active admin or developer of the organisation. Nothing was changed.",
  AGENT_OWNER_UNCHANGED: 'The member already owns the agent, so nothing was changed.',
  AGGREGATE_THRESHOLD:
    "Together with the same supplier's other open or paid requests in the aggregation window, this request crosses the approval threshold, so a person must approve it.",
  ALREADY_A_MEMBER:
    "You already belong to this organisation, so its invitation can't be accepted. Ask one of its admins if your role should change.",
  BAD_REQUEST: "The request is malformed, so it can't be read.",
  BANK_ACCOUNT_UNKNOWN:
    "The staging bank holds no account by this ID, so nothing was approved. List the bank's accounts and pick one of them.",
  BANK_FORM_NOT_OPEN:
    "No payee form of this organisation's is open at the staging partner under this address: it was filled in already, or it ran out. Nothing was changed. Start a new registration if one is still needed.",
  BANK_FORM_REFUSED:
    "The staging partner's payee form can't take these details: the account must be a UAE IBAN with valid check digits, and the name readable. Nothing was changed. Fix them and send the form again.",
  BANK_LINK_NOT_WAITING:
    "No link of this organisation's is waiting at the staging bank under this session: it was approved or turned down already, or it ran out. Nothing was changed. Start a new link if one is still needed.",
  CONTACTS_FULL:
    'The organisation already has as many registered contacts as it may, so no other can be added. Remove one first.',
  CONTACT_ADDS_SPENT:
    "The organisation has started adding as many registered contacts as it may in 24 hours, so this one wasn't started. Try again tomorrow; if no one at the organisation started them, tell its admins at once.",
  CONTACT_CLOSED:
    "This registered contact can't be confirmed: it was confirmed already, or it was asked for in another way. Ask for it again if it is still needed.",
  CONTACT_EXISTS: "This address is already one of the organisation's registered contacts, so it was not added again.",
  CONTACT_NOT_ACTIVE:
    "This registered contact isn't active: it was removed already, or it was never confirmed. Nothing was changed.",
  DUPLICATE_ORDER_REFERENCE:
    'An earlier request for the same supplier and order reference is still open, has an unknown outcome or was paid, so this one is refused.',
  FORBIDDEN:
    "You're signed in, or an agent with its key, but this address answers other roles or callers only, so the request is refused.",
  HEADERS_TOO_LARGE:
    "The request's headers are larger than accepted, so it is refused. Large cookies are the usual cause.",
  HISTORY_TOO_LONG:
    "The organisation's records behind this decision are longer than Agent X reads at once, so it wasn't decided. Nothing was changed. Contact Agent X support.",
  HOLD_CHANGED:
    'The integrity hold was cleared by someone else while this clearing was being made, so nothing was changed. Look at the hold again.',
  IDEMPOTENCY_KEY_BUSY:
    'An earlier request with this Idempotency-Key is still being done. Wait the number of seconds in the Retry-After header, then send the same request again with the same key.',
  IDEMPOTENCY_KEY_INVALID:
    'This address changes something, so each request must carry an Idempotency-Key header: 1 to 255 visible ASCII characters, no spaces, new for each change you mean to make. Send the same key again only to retry the same request.',
  IDEMPOTENCY_KEY_REUSED:
    'This Idempotency-Key was already used for a different request, so this one is refused and nothing was changed. Use a new key for a new change.',
  INSUFFICIENT_SCOPE:
    "The agent's key doesn't hold every scope this address needs, so the request is refused. The WWW-Authenticate header names them: ask the organisation for a key that holds them.",
  INTEGRITY_FAILED:
    "Some of the organisation's records couldn't be verified, so this answer is withheld and the organisation is on hold while it is looked into. The Agent X team has been alerted.",
  INTERNAL_ERROR:
    'Something went wrong on our side, so the request failed. Quote the correlation ID if you contact support.',
  INVITATION_CLOSED:
    "This invitation can't be confirmed: it was confirmed already, or it has ended. Ask for a new invitation if one is still needed.",
  INVITATION_INVALID:
    "This invitation can't be accepted by you: its link isn't one we know, or you signed in with another email address. Sign in with the address you were invited at, or ask the organisation's admin for a new invitation.",
  LINK_STARTS_SPENT:
    "The organisation has started as many bank account links as it may in 24 hours, so this one wasn't started. Try again tomorrow; if no one at the organisation started them, tell its admins at once.",
  MANDATE_DRAFTS_SPENT:
    "The organisation has drafted as many mandate versions as it may in 24 hours, so this one wasn't drafted. Try again tomorrow; if no one at the organisation drafted them, tell its admins at once.",
  MANDATE_DRAFT_EXPIRED:
    "The draft's end date has passed, so it can't be accepted. Draft a new version with a later end. Nothing was changed.",
  MANDATE_ENDED:
    'The mandate is revoked or expired, or its end date has passed, so it can no longer change. Draft a new mandate for the agent instead. Nothing was changed.',
  MANDATE_NOT_ACTIVE: 'The mandate is not in force (ACTIVE), so there is nothing to suspend. Nothing was changed.',
  MANDATE_NOT_SUSPENDED: 'The mandate is not suspended, so there is no suspension to lift. Nothing was changed.',
  MANDATE_NOT_WAITING:
    'The version named is not the draft waiting for acceptance: none waits, or a newer draft replaced it. Look at the mandate again and accept the draft it shows. Nothing was changed.',
  MANDATE_OPEN:
    'The agent already has a mandate waiting for acceptance or in force. Draft a new version of that mandate instead. Nothing was changed.',
  MANDATE_PAST_CONSENT:
    "A limit is above what the funding source's bank consent allows, or the mandate's currency is not the source's, and the mandate is strict about its consent. Lower the limit, or make the mandate flexible. Nothing was changed.",
  MANDATE_SUSPENDED:
    'The mandate is suspended, so no new version can be accepted until it is resumed. Nothing was changed.',
  MEMBER_DEACTIVATED:
    "This member was deactivated, so their role can't be changed and they can't be deactivated again. Invite them again to bring them back.",
  MEMBER_ELSEWHERE:
    "This member also belongs to another organisation, and their login signs in to each of them, so one organisation can't reset their second factor. Contact Agent X support, who follow the runbook.",
  NOT_FOUND: 'There is nothing at this address, or the feature is not available.',
  NOT_ON_HOLD:
    "The organisation isn't on its integrity hold, so there is no hold to investigate or clear. Nothing was changed.",
  NO_COUNTING_CONTACTS:
    'The organisation has no registered contact that counts yet (a contact counts 7 days after it is added), so no one can confirm a reset of a second factor. Add a contact, or wait until one counts.',
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
  OWN_RESET:
    "No one can ask to reset their own second factor: another admin must ask for it. If you're the organisation's only admin, contact Agent X support, who follow the runbook.",
  PARTNER_UNAVAILABLE:
    "The payment partner didn't answer, or none is set up here, so nothing was done at the partner. Try again in a few minutes.",
  PASSKEY_REQUIRED:
    'Your role here is admin or finance approver, which needs a passkey, and this session was signed in without one, so the request is refused. Sign out, then sign in again with your passkey (a security key, or Windows Hello).',
  PAYEE_CHANGE_NOT_YOURS:
    'Only the admin who registered these bank details can confirm them, so nothing was changed. Ask them to confirm it, or withdraw the change and register the details again.',
  PAYEE_REGISTRATIONS_SPENT:
    "The organisation has registered as many suppliers' bank details as it may in 24 hours, so this one wasn't started. Try again tomorrow; if no one at the organisation started them, tell its admins at once.",
  PAYEE_ROUTE_NOT_OFFERED:
    "The payment partner doesn't take a supplier's bank details this way, so nothing was started. Use the other way it offers.",
  PAYLOAD_TOO_LARGE: 'The request body is larger than this address accepts, so it is refused.',
  RATE_LIMITED:
    'Too many requests came from this client address, or from this signed-in person, in the last minute. Wait the number of seconds in the Retry-After header, then try again.',
  REQUEST_TIMEOUT: 'The request took too long to arrive, so it is refused. Send it again.',
  RESET_ASKS_SPENT:
    "The organisation's admins have asked for as many resets as they may in 24 hours, so this one wasn't asked for. Try again tomorrow; if no one at the organisation asked for them, tell its admins at once.",
  RESET_CLOSED:
    "This reset can't be confirmed or cancelled any more: it was confirmed already, cancelled, completed, or it lapsed. Nothing was changed. Look at the organisation's resets again.",
  RESET_OPEN:
    "This member already has a reset of their second factor under way, so another isn't asked for. Look at the organisation's resets, and cancel that one first if it is wrong.",
  ROLE_UNCHANGED: 'The member already has this role, so nothing was changed.',
  SECOND_FACTOR_REMOVED:
    "A second factor of yours was removed in the last 7 days, by a reset or at the login service, so for 7 days from then you keep only what a developer or a viewer may do, in every organisation. If you didn't ask for this, tell your organisation's admins at once.",
  SIGN_IN_FAILED: "The sign-in couldn't be completed, so no session was opened. Start again from the sign-in page.",
  SIGN_IN_UNAVAILABLE:
    "The sign-in service couldn't be reached just now, so no session was opened. Wait the number of seconds in the Retry-After header, then start again from the sign-in page.",
  SOLO_PATH_LOCKED:
    "No one else can verify this supplier yet, and an admin or finance approver was removed or had their role changed in the last 14 days, so it can't be verified by one person alone until then. Nothing was changed.",
  SOURCE_NOT_SUSPENDED:
    'The bank account is active, or ended for good, so there is no suspension to lift. Nothing was changed. An ended one needs a new link.',
  SOURCE_NOT_USABLE:
    "The funding source can't fund payments now: it is suspended, unavailable or ended, or its bank consent has expired. No mandate can draw on it. Nothing was changed.",
  STEP_UP_FAILED:
    "Signing in again couldn't confirm this change, so it wasn't confirmed. Start the change again, then sign in again as the same person, with your second factor: your passkey, if you're an admin or a finance approver.",
  SUPPLIER_ADDS_SPENT:
    "The organisation has added as many suppliers as it may in 24 hours, so this one wasn't added. Try again tomorrow; if no one at the organisation added them, tell its admins at once.",
  SUPPLIER_CALL_NOTE_NEEDED:
    "The bank's name check didn't fully match the supplier's name, so a written note of the call-back is needed: who you spoke to and what they confirmed. Nothing was changed.",
  SUPPLIER_CHANGED:
    "The supplier's payment details changed after the request was decided, so it is refused before hand-off.",
  SUPPLIER_CHANGES_SPENT:
    "The organisation has changed its suppliers' details as many times as it may in 24 hours, so this change wasn't made. Try again tomorrow; if no one at the organisation made these changes, tell its admins at once.",
  SUPPLIER_CHANGE_WAITING:
    "A change of this supplier's bank details is already waiting to be confirmed, so another isn't made. Confirm or withdraw that one first.",
  SUPPLIER_COOLING_OFF:
    "The supplier's bank details are still in their 24-hour cooling-off, so it can't be verified yet. Nothing was changed. Look at the supplier for when it ends.",
  SUPPLIER_DETAILS_UNCHANGED:
    "These are the supplier's details already, so nothing was changed, and it stays as verified as it was.",
  SUPPLIER_NAME_MISMATCH:
    "The bank says the account holder's name doesn't match the supplier's, so it can't be verified. Nothing was changed. Call the supplier on its known number, then withdraw or replace the bank details.",
  SUPPLIER_NOT_SUSPENDED: 'The supplier is not suspended, so there is no suspension to lift. Nothing was changed.',
  SUPPLIER_NOT_UNVERIFIED:
    'The supplier is verified or suspended, so there is nothing to verify. Nothing was changed. Look at the supplier again.',
  SUPPLIER_NO_CHANGE_WAITING:
    "No change of this supplier's bank details is waiting, so there is nothing to confirm or withdraw. Nothing was changed. Look at the supplier again.",
  SUPPLIER_NO_PAYEE:
    'The supplier has no bank details registered yet, so there is nothing to verify. Nothing was changed. Register its bank details first.',
  SUPPLIER_PAYEE_TAKEN:
    "Another of the organisation's suppliers is already paid to this bank account, suspended ones included, so it isn't this supplier's too. Nothing was changed. Look at the organisation's suppliers.",
  SUPPLIER_PHONE_TOO_NEW:
    "The supplier's phone number changed less than 30 days ago, so a call-back to it can't verify the supplier yet. Nothing was changed.",
  SUPPLIER_UNKNOWN:
    "A supplier the mandate names is not one of the organisation's. Check the suppliers' IDs. Nothing was changed.",
  TOO_MANY_CONTACTS:
    "The organisation has more registered contact records than Agent X checks at once, so its contacts can't be read or changed. Contact Agent X support.",
  TOO_MANY_RESETS:
    "The organisation has more reset records than Agent X checks at once, so this reset can't be asked for. Contact Agent X support.",
  UNAUTHENTICATED:
    'This address answers only a signed-in person or an agent with its key, and the request came from neither, so it is refused.',
  UNSUPPORTED_MEDIA_TYPE: "The request body's content type isn't accepted at this address, so it is refused.",
  VERIFIER_ENTERED_DETAILS:
    "You entered some of this supplier's details, so a second person must verify them. Nothing was changed.",
  VERIFIER_GRANTED_BY_ENTERER:
    "Your role was given or approved by a person who entered this supplier's details, so you can't be their second person. Nothing was changed. Ask another admin or finance approver.",
  VERIFIER_TOO_NEW:
    "You've been a member of this organisation for less than 14 days, so you can't verify a supplier yet. Nothing was changed.",
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
