// The front door for the partner's messages (Phase 4 E1b; ADR-007 §12–13;
// SEC-PTR-01–06): `POST /v1/partner/events`. No one signs in: the partner's
// signature over the raw body is the only key, checked by its adapter before
// anything is read from the body. A message is a nudge: it is kept in the
// inbox, routed to the organisation its reference names, and the bank check
// (E1a) then asks the bank about the payments it names, so the message's own
// word never moves a payment (SEC-PTR-02, -04).
//
// - The body is read as bytes (the route's own parser), up to 64 KiB; past
//   that, 413 before it is read (SEC-PTR-06). It takes no idempotency key: a
//   replay is one the inbox already holds, and changes nothing (SEC-PTR-03).
//   It comes from the partner's servers, not our pages, so it is let past
//   the origin check (`partnerSigned`); every request still counts against
//   its address's rate limit.
// - A signature that doesn't hold or a signed time outside its window: 401
//   PARTNER_EVENT_REFUSED, the same for both. A signed body that isn't a
//   message: 400 PARTNER_EVENT_MALFORMED. Each is counted in the security
//   events, and the first few an hour from an address kept, encrypted, as
//   evidence, with an alert (SEC-PTR-01).
// - Verified: 202, whether new, a replay, or naming a reference no
//   organisation holds; that last is kept encrypted and alerted (SEC-PTR-05).
import {
  organizationOfConsent,
  organizationOfInstruction,
  type InstructionsTables,
} from '@agentx/core/modules/instructions';
import type { ProviderEvents, ProviderEventsTables } from '@agentx/core/modules/provider-events';
import {
  type EventHeaders,
  type EventReference,
  type EventRefusal,
  type FinancialRailAdapter,
  MOST_EVENT_BYTES,
} from '@agentx/core/modules/providers';
import type { Database } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { sendErrorBody } from './errors.ts';
import type { SecurityEventSink } from './security-recorder.ts';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** The partner's own route, judged by its signature: let past the origin check, which only our pages pass (E1b). */
    readonly partnerSigned?: true;
  }
}

export const PARTNER_EVENTS_PATH = '/v1/partner/events';

/** What taking a message in came to: kept (new, a replay or unknown), or refused and why. */
export type Intake = 'accepted' | EventRefusal;

export interface PartnerEventIntake {
  take(body: Buffer, headers: EventHeaders, ip: string | undefined, log: Logger): Promise<Intake>;
}

export function createPartnerEventIntake({
  database,
  rail,
  events,
  securityEvents,
}: {
  readonly database: Database<ProviderEventsTables & InstructionsTables>;
  readonly rail: FinancialRailAdapter;
  readonly events: ProviderEvents;
  /** Where a refused message is counted (security-recorder.ts). */
  readonly securityEvents: SecurityEventSink;
}): PartnerEventIntake {
  /** The organisation the reference names, from the directory; undefined where none holds it. */
  const routed = (reference: EventReference): Promise<string | undefined> =>
    reference.kind === 'instruction'
      ? organizationOfInstruction(database, reference.instructionId)
      : organizationOfConsent(database, reference.consentId);

  return {
    async take(body, headers, ip, log) {
      const check = await rail.verifyEvent(body, headers);
      if (check.kind === 'refused') {
        const { reason } = check;
        securityEvents.note({ kind: 'partner_event_refused', reason, ip });
        // Said for the first kept from its network each hour: a flood is an alert or two, never one a message.
        if ((await events.keepRefused(database, { reason, ip, body })) === 'first') {
          log.error('partner_event.refused', { reason });
        }
        return reason;
      }
      const { event } = check;
      const orgId = await routed(event.reference);
      const taken = await events.takeIn(database, event, orgId ?? null, body);
      if (orgId === undefined && taken === 'new') {
        log.error('partner_event.unknown_reference', { partner: event.partner, referenceKind: event.reference.kind });
      }
      log.info('partner_event.taken_in', {
        partner: event.partner,
        eventType: event.eventType,
        routed: orgId !== undefined,
        replay: taken === 'replay',
      });
      return 'accepted';
    },
  };
}

const ACCEPTED = z.object({ status: z.literal('accepted') }).register(API_SCHEMAS, {
  description: 'The message was taken in (or was already): the payments it names are checked with the bank.',
});

/**
 * The front door, on a scope whose JSON parser keeps the body's bytes
 * (server.ts). `intake` is there where the partner's rail is built; without
 * it the route is documented and answers 404.
 */
export function registerPartnerEvents(
  app: FastifyInstance,
  intake: PartnerEventIntake | undefined,
  logger: Logger,
): void {
  // `app` is a scope of its own whose JSON parser hands on the body's bytes (server.ts): its signature is over them.
  app.withTypeProvider<ZodTypeProvider>().post(
    PARTNER_EVENTS_PATH,
    {
      schema: {
        summary: "The partner's messages about its payments",
        description:
          "A message from the payment partner, signed over its raw body. It only asks Agent X to check the payments it names with the partner's status query; its own word never moves a payment.",
        response: { 202: ACCEPTED },
      },
      bodyLimit: MOST_EVENT_BYTES,
      config: { access: ['public'], partnerSigned: true },
    },
    async (request, reply) => {
      if (intake === undefined) return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      const body = Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0);
      const taken = await intake.take(body, request.headers, request.ip, logger.child({ correlationId: request.id }));
      if (taken === 'accepted') return reply.code(202).send({ status: 'accepted' });
      return taken === 'malformed'
        ? sendErrorBody(reply, 400, 'PARTNER_EVENT_MALFORMED', request.id)
        : sendErrorBody(reply, 401, 'PARTNER_EVENT_REFUSED', request.id);
    },
  );
}
