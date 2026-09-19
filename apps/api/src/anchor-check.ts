// The anchor check (ADR-012 §2, SEC-DB-11): every few minutes the API checks
// each audit chain whole against its last anchor, kept in this process's
// memory, and anchors it again. A chain wound back to an earlier state, or
// grown again on a wound-back head, passes its own seals; only the anchor,
// held apart from the database, shows it.
//
// A chain that fails raises the integrity alarm (`audit.integrity_failed`; its
// SEV-1 alert rule is A2c-2) and keeps its last good anchor, so the alarm
// repeats every run until someone looks. A check that can't run (the database
// unreachable) is a warning, not the alarm. The platform chain is checked from
// the start; the organisations' chains join when organisations exist (B1).
import type { Clock } from '@agentx/core/shared-kernel';
import {
  type AnchorPoint,
  type AnchorStore,
  type Chain,
  type ChainReport,
  ChainStoreError,
  createMemoryAnchorStore,
  signAnchor,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** A chain the check covers, and how to check it against its last anchor, if it has one. */
export interface CheckedChain {
  readonly chain: Chain;
  readonly verify: (anchor: AnchorPoint | undefined) => Promise<ChainReport>;
}

export interface AnchorCheck {
  /** Checks every chain once, one after another. Never throws: every outcome is logged. */
  run(): Promise<void>;
}

export interface AnchorCheckOptions {
  readonly chains: readonly CheckedChain[];
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
  readonly anchors?: AnchorStore;
}

export function createAnchorCheck({
  chains,
  keys,
  clock,
  logger,
  anchors = createMemoryAnchorStore(),
}: AnchorCheckOptions): AnchorCheck {
  const checkOne = async ({ chain, verify }: CheckedChain): Promise<void> => {
    // An organisation's ID goes on the line as the logger's own field, which an event can't set.
    const log = chain.kind === 'platform' ? logger : logger.child({ orgId: chain.orgId });
    const last = anchors.latest(chain);
    try {
      const report = await verify(last);
      if (!report.ok) {
        const { reason, seq } = report.problem;
        log.error('audit.integrity_failed', { chain: chain.kind, check: 'anchor', reason, seq });
        return;
      }
      if (last?.seq === report.seq) return;
      anchors.keep(signAnchor(keys, chain, { seq: report.seq, hash: report.hash }, clock.now()));
      log.info('audit.anchored', { chain: chain.kind, seq: report.seq, headHash: report.hash.toString('hex') });
    } catch (error) {
      // A store that breaks its contract may be a hostile database (a planted operator, a view for a table).
      if (error instanceof ChainStoreError) {
        log.error('audit.integrity_failed', { chain: chain.kind, check: 'anchor', reason: 'store' });
      } else {
        log.warn('audit.anchor_check_failed', { chain: chain.kind, err: error });
      }
    }
  };

  return Object.freeze({
    async run(): Promise<void> {
      for (const one of chains) await checkOne(one);
    },
  });
}

/**
 * Runs the check now and then `intervalMs` after each run ends, so runs never
 * overlap. `stop` waits for a run in flight, so the pool it uses can be
 * closed after it.
 */
export function scheduleAnchorCheck(check: AnchorCheck, intervalMs: number): { stop(): Promise<void> } {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running: Promise<void> = Promise.resolve();
  const tick = (): void => {
    running = check.run().then(() => {
      if (stopped) return;
      timer = setTimeout(tick, intervalMs);
      // The server keeps the process alive; the check alone shouldn't.
      timer.unref();
    });
  };
  tick();
  return Object.freeze({
    async stop(): Promise<void> {
      stopped = true;
      clearTimeout(timer);
      await running;
    },
  });
}
