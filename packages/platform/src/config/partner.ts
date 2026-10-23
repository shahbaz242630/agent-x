// ADR-014 §4, the live-money switch (SEC-OPS-07, Phase 4 C1): which payment
// partner the app talks to, and the rules that keep real money behind the
// live-money gate. Start-up refuses:
// - no partner mode in staging or production (never a fallback to the fake)
// - the fake or the sandbox in production, and live anywhere else
// - live without a well-formed gate reference, or a gate reference without live
// - live without the partner's live origin on the outbound allowlist, or with
//   its sandbox origin there; any other mode with its live origin there.
// The real partner's adapter declares its origins (Phase 5); until it does,
// the sandbox and live modes are refused as not built.
import type { Environment, PartnerMode } from './common.ts';

/** What a real partner's adapter declares (ADR-014 §4): where its live service and its sandbox answer, as origins. */
export interface PartnerDeclaration {
  readonly liveOrigins: readonly string[];
  readonly sandboxOrigins: readonly string[];
}

/** The real partner's adapter, once it is built (Phase 5). None yet: the fake alone can run. */
export const BUILT_PARTNER: PartnerDeclaration | undefined = undefined;

/** The payment partner the config names. */
export type Partner =
  | { readonly mode: 'fake' }
  | { readonly mode: 'sandbox' }
  /** Real money: only in production, with the live-money gate's reference, which every start records. */
  | { readonly mode: 'live'; readonly gateRef: string };

/** The settings partnerProblems weighs, each already valid on its own. */
export interface PartnerSettings {
  readonly environment: Environment;
  readonly mode: PartnerMode | undefined;
  readonly gateRef: string | undefined;
  readonly allowedOrigins: readonly string[];
}

const MODE = 'AGENTX_PARTNER_MODE';
const GATE_REF = 'AGENTX_LIVE_MONEY_GATE_REF';
const ALLOWED = 'AGENTX_OUTBOUND_ALLOWED_ORIGINS';

/** Where each mode may run: a mode named where it may not is refused, whatever else is set. */
function modeProblems(environment: Environment, mode: PartnerMode | undefined): string[] {
  if (mode === undefined) {
    return environment === 'staging' || environment === 'production'
      ? [`${MODE}: is required in ${environment}; a missing setting never falls back to the fake`]
      : [];
  }
  if (environment === 'production') {
    return mode === 'live' ? [] : [`${MODE}: ${mode} is refused in production; production pays for real or not at all`];
  }
  return mode === 'live' ? [`${MODE}: live is refused in ${environment}; real money moves only from production`] : [];
}

/** Live needs the gate's reference, and nothing else may carry one. */
function gateRefProblems(mode: PartnerMode | undefined, gateRef: string | undefined): string[] {
  if (mode === 'live') {
    return gateRef === undefined
      ? [`${GATE_REF}: is required with live; real money waits for the live-money gate's signed record`]
      : [];
  }
  return gateRef === undefined ? [] : [`${GATE_REF}: set only with ${MODE} live`];
}

/** The outbound allowlist against the partner's declared origins: a staging app can't reach the live partner. */
function originProblems(
  mode: PartnerMode | undefined,
  allowedOrigins: readonly string[],
  declared: PartnerDeclaration,
): string[] {
  const allowed = (origins: readonly string[]) => origins.filter((origin) => allowedOrigins.includes(origin));
  if (mode !== 'live') {
    return allowed(declared.liveOrigins).length === 0
      ? []
      : [`${ALLOWED}: holds the partner's live origin, refused unless ${MODE} is live`];
  }
  return [
    ...(allowed(declared.liveOrigins).length === declared.liveOrigins.length
      ? []
      : [`${ALLOWED}: must hold the partner's live origin with ${MODE} live`]),
    ...(allowed(declared.sandboxOrigins).length === 0
      ? []
      : [`${ALLOWED}: holds the partner's sandbox origin, refused with ${MODE} live`]),
  ];
}

/** Every rule between the partner mode, the gate reference and the allowlist, against the partner built (if any). */
export function partnerProblems(settings: PartnerSettings, built: PartnerDeclaration | undefined): string[] {
  const { environment, mode, gateRef, allowedOrigins } = settings;
  const notBuilt =
    built === undefined && (mode === 'sandbox' || mode === 'live')
      ? [`${MODE}: ${mode} is not built yet; only fake is, until the partner's adapter (Phase 5)`]
      : [];
  return [
    ...modeProblems(environment, mode),
    ...gateRefProblems(mode, gateRef),
    ...notBuilt,
    ...(built === undefined ? [] : originProblems(mode, allowedOrigins, built)),
  ];
}

/**
 * The partner, once partnerProblems has passed: the mode named, or the fake
 * where nothing is named and nothing real is at stake (development and test).
 */
export function partnerFrom(mode: PartnerMode | undefined, gateRef: string | undefined): Partner {
  if (mode !== 'live') return Object.freeze({ mode: mode ?? 'fake' });
  // partnerProblems refuses live without its reference, so only a caller skipping it gets here.
  if (gateRef === undefined) throw new Error('live has no live-money gate reference: partnerProblems was skipped');
  return Object.freeze({ mode, gateRef });
}

/** The partner as a start-up line names it. */
export const partnerName = (partner: Partner): PartnerMode => partner.mode;

/** The live-money gate reference a start records on the platform chain: only a live start has one. */
export const gateRefOf = (partner: Partner): string | undefined =>
  partner.mode === 'live' ? partner.gateRef : undefined;
