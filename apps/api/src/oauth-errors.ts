// OAuth's own error body (6E3a; RFC 6749 §5.2, RFC 7591 §3.2.2, RFC 7009
// §2.2.1): the contract's second wire exception (contract.ts, oauth-wire.ts).
// A file of its own, as the contract reads it before any route is added.
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';

/** OAuth's error codes, those its endpoints here answer. */
const OAUTH_ERRORS = [
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'unsupported_grant_type',
  'invalid_scope',
  'invalid_target',
  'invalid_redirect_uri',
  'invalid_client_metadata',
] as const;
export type OauthError = (typeof OAUTH_ERRORS)[number];

export const OAUTH_ERROR_BODY = z
  .object({
    error: z.enum(OAUTH_ERRORS).describe('What went wrong, in OAuth’s own words (RFC 6749 §5.2).'),
    error_description: z.string().describe('Why, in plain words. Never a secret, never what was sent.'),
  })
  .register(API_SCHEMAS, {
    id: 'OauthError',
    description:
      'An OAuth endpoint’s refusal, as OAuth clients read one (RFC 6749 §5.2): sent at 400, or 401 for an unknown client.',
  });
