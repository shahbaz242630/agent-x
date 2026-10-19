// An IP address as the logs keep one (ADR-011 §7): the security events
// (B2-5b) and the activity log (L4) store it in a Postgres `inet` column,
// whose refusal of anything else would lose the row, so they check it first.

const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4 = new RegExp(`^${OCTET}(?:[.]${OCTET}){3}$`);
/**
 * Only what an IPv6 address is written with. Without it, text such as
 * `::1]/x` passes the URL parse (the host ends at the `]`, the rest is a
 * path) and reaches the insert, whose inet refusal would lose the batch
 * (the confirmation review of B2-5a).
 */
const IPV6_CHARACTERS = /^[0-9A-Fa-f:.]{2,45}$/;

/**
 * An IPv4 address in dotted form, or an IPv6 address as a URL's host takes one
 * (no zone, no port). Checked here rather than with node:net, which the
 * boundary rules keep to the outbound fetch.
 */
export const isIpAddress = (text: string): boolean =>
  IPV4.test(text) || (IPV6_CHARACTERS.test(text) && URL.canParse(`http://[${text}]/`));
