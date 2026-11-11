// The real partner's adapter as tests of anything else declare it (partner.ts):
// one live origin, as every declaration must have, which a live config is
// given on its allowlist, as production's must hold it. The partner's own
// tests declare their origins.
import type { PartnerDeclaration } from './partner.ts';

type Env = Record<string, string | undefined>;

export const STAND_IN_LIVE = 'https://pay.partner.example';
export const STAND_IN: PartnerDeclaration = { liveOrigins: [STAND_IN_LIVE], sandboxOrigins: [] };

/** The settings with the stand-in's live origin on the allowlist where they run live; any other left as they are. */
export function reachingStandIn(env: Env): Env {
  const allowed = env.AGENTX_OUTBOUND_ALLOWED_ORIGINS;
  // An empty allowlist is a test of that setting's own refusal: left for it to see.
  if (env.AGENTX_PARTNER_MODE !== 'live' || allowed === '' || allowed?.split(',').includes(STAND_IN_LIVE)) return env;
  return {
    ...env,
    AGENTX_OUTBOUND_ALLOWED_ORIGINS: allowed === undefined ? STAND_IN_LIVE : `${allowed},${STAND_IN_LIVE}`,
  };
}
