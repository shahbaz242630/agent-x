// The pieces many routes' schemas share, written once so every route says
// them alike in the OpenAPI document.
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';

/** An amount as a body sends it (ADR-006 §1): whole minor units, checked at the edge as a safe integer. */
export const AMOUNT = z
  .number()
  .describe('Whole minor units (fils for AED): an integer from 1 to 2^53 − 1, never a string or a fraction.');

/** A mandate named in a route's path. */
export const MANDATE_ID = z.object({ id: z.uuid().describe('The mandate, by its ID.') });

/** The most a bodyless write may be sent with: an empty object, with room to spare. */
export const NOTHING_BODY_LIMIT = 64;

/** The most a confirm's body may be: a challenge's ID, with room to spare. */
export const CHALLENGE_BODY_LIMIT = 128;

export const NOTHING = z
  .strictObject({})
  // Fastify gives a request sent with no body a null one.
  .nullish()
  .describe('Nothing. An empty object, or no body at all.');

/** The step-up a change's ask answers with. */
const STEP_UP_TO_SIGN_IN = z
  .uuid()
  .describe('The step-up to sign in again for, at GET /v1/auth/step-up?challenge=…, before confirming.');

/** The step-up a change's confirm names. */
export const STEP_UP_SIGNED_IN = z.uuid().describe('The step-up the ask answered with, signed in again for.');

/** A change's ask, answered 202 with the step-up to sign in again for; named in the OpenAPI document. */
export const stepUpAsked = (id: string, description: string) =>
  z.object({ stepUpChallengeId: STEP_UP_TO_SIGN_IN }).register(API_SCHEMAS, { id, description });

/** A confirm's body: the step-up its ask answered with, signed in again for. */
export const STEP_UP_CONFIRM = z
  .strictObject({ stepUpChallengeId: STEP_UP_SIGNED_IN })
  .describe('The step-up signed in again for.');

/** A list's page: after an ID, and at most `most` of them unless fewer are asked for. */
export const pageQuery = (most: number) =>
  z.strictObject({
    after: z.uuid().optional().describe('The ID the page starts after: the last page’s `next`.'),
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(most)
      .optional()
      .describe(`How many at most, ${String(most)} unless fewer are asked for.`),
  });

export const NEXT = z.uuid().nullable().describe('The ID to ask the next page after; null at the end.');
