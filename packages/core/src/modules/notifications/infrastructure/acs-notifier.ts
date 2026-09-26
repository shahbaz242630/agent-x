// The notifier on Azure Communication Services (B5-3): each notice as one
// plain-text email, sent through ACS's email API (`POST /emails:send`,
// api-version 2025-09-01) and signed with the service's access key (HMAC-SHA256
// over the method, the path and query, the date, the host and the body's hash,
// as ACS asks).
//
// - The service answers 202 once it has taken the email: that is `sent`. Its
//   delivery happens after, and isn't followed here (Carry-Forward: never
//   through Event Grid, whose topic is global).
// - The notice's ID goes as the `Operation-Id`, so ACS names the send by it.
//   What ACS does with one it has seen before isn't documented, so a send may
//   rarely go twice (the outbox is at least once) but is never lost.
// - A refusal no retry can mend (400, 413, 422: the email itself is wrong) is
//   `lasting`; the rest (401 and 403 while a key rotates, 408, 429 past the
//   domain's hourly limit, 5xx, the network) are tried again.
// - A failure is named by a short constant, never ACS's own words, which could
//   quote the address.
// - Tracking stays off for the send too, whatever the domain says.
import { createHash, createHmac } from 'node:crypto';

import type { OutboundFetch } from '@agentx/platform/outbound';

import type { Clock } from '../../../shared-kernel/index.ts';
import type { NoticeMessage } from '../domain/messages.ts';
import type { Notifier, SendOutcome } from './sender.ts';

/** ACS's email API version (Microsoft's stable one, 2025-09-01). */
export const EMAIL_API_VERSION = '2025-09-01';

/** How long one send may take. */
const SEND_TIMEOUT_MS = 10_000;

/** An access key as ACS gives them: base64, padded, at most 1 KB. */
const BASE64 = /^(?:[A-Za-z0-9+/]{4}){1,256}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Statuses that say the email itself is wrong, so no retry can mend it. */
const LASTING = new Set([400, 413, 422]);

export interface AcsSettings {
  /** The service's endpoint, as an origin: `https://<name>.<geo>.communication.azure.com`. */
  readonly endpoint: string;
  /** The address every notice is sent from. */
  readonly sender: string;
  /** The access key, base64, as the service gives it. */
  readonly accessKey: string;
}

/** The headers that sign a request, as ACS checks them. */
export function signedHeaders(
  method: string,
  url: URL,
  body: string,
  accessKey: string,
  now: Date,
): Record<string, string> {
  const date = now.toUTCString();
  const contentHash = createHash('sha256').update(body, 'utf8').digest('base64');
  const toSign = `${method}\n${url.pathname}${url.search}\n${date};${url.host};${contentHash}`;
  const signature = createHmac('sha256', Buffer.from(accessKey, 'base64')).update(toSign, 'utf8').digest('base64');
  return {
    'x-ms-date': date,
    'x-ms-content-sha256': contentHash,
    authorization: `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`,
  };
}

export function createAcsNotifier({
  settings,
  fetch,
  clock,
}: {
  readonly settings: AcsSettings;
  readonly fetch: OutboundFetch;
  readonly clock: Clock;
}): Notifier {
  const { endpoint, sender, accessKey } = settings;
  if (!URL.canParse(endpoint) || new URL(endpoint).origin !== endpoint) {
    throw new RangeError('the email endpoint must be an origin alone');
  }
  if (!BASE64.test(accessKey)) throw new RangeError('the access key must be base64');
  const url = new URL(`/emails:send?api-version=${EMAIL_API_VERSION}`, endpoint);

  return {
    async send(message: NoticeMessage): Promise<SendOutcome> {
      const body = JSON.stringify({
        senderAddress: sender,
        recipients: { to: [{ address: message.to }] },
        content: { subject: message.subject, plainText: message.text },
        userEngagementTrackingDisabled: true,
      });
      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers: {
            ...signedHeaders('POST', url, body, accessKey, clock.now()),
            'content-type': 'application/json',
            'operation-id': message.id,
          },
          body,
          signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
        });
      } catch {
        return { outcome: 'failed', failure: 'email_unreachable', lasting: false };
      }
      // Nothing of the answer is read but its status.
      await response.body?.cancel();
      if (response.status === 202) return { outcome: 'sent' };
      if (LASTING.has(response.status)) return { outcome: 'failed', failure: 'email_refused', lasting: true };
      if (response.status === 401 || response.status === 403) {
        return { outcome: 'failed', failure: 'email_unauthorized', lasting: false };
      }
      if (response.status === 429) return { outcome: 'failed', failure: 'email_throttled', lasting: false };
      return { outcome: 'failed', failure: 'email_unavailable', lasting: false };
    },
  };
}
