// The platform chain's growth brake (S210 TR-7, R2-4). Every organisation's
// hand-off walks past what the shared platform chain holds between two anchors,
// and past MOST_WALKED_WITHIN every one is held `too_far` until the next anchor:
// safe, but many accounts signing in and stepping up together (each a platform
// event, person-chain-caps.ts) could stop every payment for a window. So once
// the chain has grown PLATFORM_GROWTH_BRAKE past its last anchor, new sessions
// and step-ups wait (sign-in.ts: 503 with Retry-After), until the anchor check
// anchors it again; a sign-out is never refused.
//
// Read cheaply on the sign-in path: the latest anchor from the anchors this
// process holds in memory (the jobs copy's, or a `web` copy's read-only ones),
// and the platform head's place by one one-row read, the answer kept
// BRAKE_READ_EVERY_MS. With no anchors held yet, or a head that can't be read,
// it lets everyone through: the brake keeps payments moving, and a database
// that can't be read fails the sign-in on its own. So it does, said, when the
// latest anchor held is older than three of the anchor check's runs (S210
// final): a stalled check alerts on its own, and a brake measured from its
// stale anchor would refuse every new sign-in, operators' too, once the chain
// grew past it, until the check ran again.
import { MOST_WALKED_WITHIN } from '@agentx/core/modules/audit';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { Clock } from '@agentx/core/shared-kernel';
import type { Chain } from '@agentx/platform/audit-chain';
import type { Database } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

/**
 * How far the platform chain may grow past its last anchor before new sessions and step-ups wait: four fifths of what
 * a hand-off's walk reads past its anchor, so the brake is on well before any hand-off is held `too_far`, and the room
 * left (10,000 events) takes the sign-outs, downloads and sessions already under way to the next anchor.
 */
export const PLATFORM_GROWTH_BRAKE = (MOST_WALKED_WITHIN * 4) / 5;

/** How long a reading of the brake is kept: one read of the head every 30 seconds a process, however many sign in. */
export const BRAKE_READ_EVERY_MS = 30_000;

/** The anchors a process holds, as far as the brake reads them. */
interface AnchorsHeld {
  latest(chain: Chain): { readonly seq: bigint; readonly at: Date } | undefined;
}

export interface PlatformGrowthBrake {
  /** The anchors this process holds from now: the jobs copy's, or a `web` copy's read-only ones (job-list.ts). */
  useAnchors(anchors: AnchorsHeld): void;
  /** Whether new sessions and step-ups wait now: the platform chain grown PLATFORM_GROWTH_BRAKE past its anchor. */
  engaged(): Promise<boolean>;
}

const PLATFORM: Chain = { kind: 'platform' };

export function createPlatformGrowthBrake({
  database,
  clock,
  logger,
  staleAfterMs,
}: {
  readonly database: Database<PlatformControlsTables>;
  readonly clock: Clock;
  readonly logger: Logger;
  /** How old the latest anchor held may be before the brake lifts (S210 final): three of the anchor check's runs. */
  readonly staleAfterMs: number;
}): PlatformGrowthBrake {
  let anchors: AnchorsHeld | undefined;
  /** The last reading, and when it was taken: one in flight is shared by every sign-in asking meanwhile. */
  let reading: { readonly at: number; readonly engaged: Promise<boolean> } | undefined;

  const headSeq = async (): Promise<bigint | undefined> => {
    const row = await database.selectFrom('platform_controls.audit_head').select('seq').limit(1).executeTakeFirst();
    return row?.seq;
  };

  const read = async (): Promise<boolean> => {
    const anchor = anchors?.latest(PLATFORM);
    if (anchor === undefined) return false;
    let grown: boolean;
    try {
      const head = await headSeq();
      grown = head !== undefined && head - anchor.seq > BigInt(PLATFORM_GROWTH_BRAKE);
    } catch (error) {
      logger.warn('auth.platform_growth_unread', { err: error });
      return false;
    }
    if (!grown) return false;
    // S210 final: an anchor older than three of the anchor check's runs means the check has stalled, which alerts on its
    // own; braking on it would refuse every sign-in, operators' too, until someone fixed it. So the brake lifts.
    const anchorAgeMs = clock.now().getTime() - anchor.at.getTime();
    if (anchorAgeMs > staleAfterMs) {
      logger.warn('auth.platform_growth_anchor_stale', { anchoredAt: anchor.at.toISOString(), staleAfterMs });
      return false;
    }
    return true;
  };

  return {
    useAnchors(given) {
      anchors = given;
      reading = undefined;
    },
    engaged() {
      const now = clock.now().getTime();
      if (reading === undefined || now - reading.at >= BRAKE_READ_EVERY_MS) reading = { at: now, engaged: read() };
      return reading.engaged;
    },
  };
}
