// ADR-014 §4, the live-money switch (SEC-OPS-07, Phase 4 C1): which payment
// partner the app talks to, and the rules that keep real money behind the
// live-money gate. Start-up refuses:
// - no partner mode in staging or production (never a fallback to the fake)
// - the fake or the sandbox in production, and live anywhere else
// - live without a well-formed gate reference, or a gate reference without live
// - live without the partner's live origin on the outbound allowlist, or with
//   its sandbox origin there; any other mode with its live origin there.
// The real partner's adapter declares its origins (Phase 5); until it does,
// the sandbox and live modes are refused as not built. The declaration is
// checked where it is written (PM3, declarePartner): a live origin written
// another way than the allowlist writes it, or none at all, would let a
// staging app reach the live partner unseen. And the live adapter checks at
// the point of use that this process's start was recorded live (startedLive,
// apps/api/src/live-rail.ts).
import { ConfigError, type Environment, type PartnerMode } from './common.ts';
import { isCanonicalOrigin } from './settings.ts';

/** What a real partner's adapter declares (ADR-014 §4): where its live service and its sandbox answer, as origins. */
export interface PartnerDeclaration {
  readonly liveOrigins: readonly string[];
  readonly sandboxOrigins: readonly string[];
}

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
const DECLARED = 'BUILT_PARTNER';

/**
 * A partner's origin as the allowlist must hold it to match: https, written as
 * the URL standard prints it (lowercase, no default port, path, user or query),
 * and no trailing dot, which names the same host but matches no entry without one.
 */
const isPartnerOrigin = (origin: string): boolean =>
  isCanonicalOrigin(origin) && origin.startsWith('https://') && !new URL(origin).hostname.endsWith('.');

/** Which entries (counted from 1) are refused. */
const refusedEntries = (origins: readonly string[], refused: (origin: string) => boolean): number[] =>
  origins.flatMap((origin, index) => (refused(origin) ? [index + 1] : []));

/** The adapter's own declaration (S138 review): the origin rules below are only as good as what it declares. */
export function declarationProblems(declared: PartnerDeclaration): string[] {
  const { liveOrigins, sandboxOrigins } = declared;
  const notOrigins = (list: string, origins: readonly string[]) => {
    const bad = refusedEntries(origins, (origin) => !isPartnerOrigin(origin));
    return bad.length === 0
      ? []
      : [
          `${DECLARED}: ${list} origin ${bad.join(', ')} is not an https origin as the allowlist writes it: ` +
            'lowercase, no default port, path, user name or trailing dot',
        ];
  };
  const both = refusedEntries(liveOrigins, (origin) => sandboxOrigins.includes(origin));
  return [
    ...(liveOrigins.length === 0
      ? [`${DECLARED}: declares no live origin, so nothing would keep an app that isn't live from reaching it`]
      : []),
    ...notOrigins('live', liveOrigins),
    ...notOrigins('sandbox', sandboxOrigins),
    ...(both.length === 0
      ? []
      : [
          `${DECLARED}: live origin ${both.join(', ')} is a sandbox origin too, so live and sandbox can't be told apart`,
        ]),
  ];
}

declare const checked: unique symbol;

/** A declaration declarePartner has checked: the only kind BUILT_PARTNER can hold. */
export type CheckedDeclaration = PartnerDeclaration & { readonly [checked]: true };

/**
 * The real partner's declaration, checked as the module holding it loads: a
 * wrong one throws there, so no test and no start gets past it.
 */
export function declarePartner(declared: PartnerDeclaration): CheckedDeclaration {
  const problems = declarationProblems(declared);
  if (problems.length > 0) throw new ConfigError(problems);
  return Object.freeze({
    liveOrigins: Object.freeze([...declared.liveOrigins]),
    sandboxOrigins: Object.freeze([...declared.sandboxOrigins]),
  }) as CheckedDeclaration;
}

/**
 * The real partner's adapter, once it is built (Phase 5), as
 * `declarePartner({ liveOrigins: [...], sandboxOrigins: [...] })`. None yet:
 * the fake alone can run.
 */
export const BUILT_PARTNER: CheckedDeclaration | undefined = undefined;

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
    // Checked again at every start: a cast can put an unchecked declaration in BUILT_PARTNER.
    ...(built === undefined ? [] : [...declarationProblems(built), ...originProblems(mode, allowedOrigins, built)]),
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

/** The partner this process's recorded start named (boot.ts), or none before one is recorded. */
let started: Partner | undefined;

/**
 * Notes the partner once this process's start is on the platform chain, with
 * the gate reference a live start writes there; undefined as a start begins.
 * Each start in a process names its own; the app starts once.
 */
export function recordedStartWith(partner: Partner | undefined): void {
  started = partner;
}

/**
 * The point-of-use check (ADR-014 §4, the S4 lesson): true only once this
 * process's start was recorded live. The live adapter asks this itself, so a
 * live adapter wired into a process that started as anything else still
 * refuses to move money.
 */
export const startedLive = (): boolean => started?.mode === 'live';
