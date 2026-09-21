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
  BAD_REQUEST: "The request is malformed, so it can't be read.",
  DUPLICATE_ORDER_REFERENCE:
    'An earlier request for the same supplier and order reference is still open, has an unknown outcome or was paid, so this one is refused.',
  HEADERS_TOO_LARGE:
    "The request's headers are larger than accepted, so it is refused. Large cookies are the usual cause.",
  INTERNAL_ERROR:
    'Something went wrong on our side, so the request failed. Quote the correlation ID if you contact support.',
  NOT_FOUND: 'There is nothing at this address, or the feature is not available.',
  ORG_FROZEN:
    'The organisation is frozen, so no new request is accepted. This refusal is temporary: the same idempotency key can be used again once the freeze is lifted.',
  ORIGIN_REFUSED:
    "A browser request that changes something must come from Agent X's own web address, and this one didn't, so it is refused.",
  PAYLOAD_TOO_LARGE: 'The request body is larger than this address accepts, so it is refused.',
  RATE_LIMITED:
    'Too many requests came from this client address in the last minute. Wait the number of seconds in the Retry-After header, then try again.',
  REQUEST_TIMEOUT: 'The request took too long to arrive, so it is refused. Send it again.',
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
