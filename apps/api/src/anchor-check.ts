// The anchor check (ADR-012 §2, SEC-DB-11): every few minutes the API checks
// each audit chain whole against its last anchor, kept in this process's
// memory, and anchors it again. A chain wound back to an earlier state, or
// grown again on a wound-back head, passes its own seals; only the anchor,
// held apart from the database, shows it.
//
// A chain that fails raises the integrity alarm (`audit.integrity_failed`; its
// SEV-1 alert rule is A2c-2) and keeps its last good anchor, so the alarm
// repeats every run until someone looks. Someone with the database's keys can
// also try to stop the check from finishing, and wait for a restart to empty
// this memory: so a database that refuses the check (a right, a table or a
// column gone) is the alarm too, and so is a chain left unchecked for three
// intervals. Anything else that stops a check (the database unreachable) is a
// warning until then. Every run ends with one line, so a check that has
// stopped can be told from one with nothing to say. The platform chain is
// checked from the start; the organisations' chains join when organisations
// exist (B1).
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
  /** How long a chain may go without a completed check before that is the alarm too. */
  readonly staleAfterMs: number;
  readonly anchors?: AnchorStore;
}

/**
 * Postgres's refusals that only a changed database gives the app's role: a
 * right taken away, a table or a column gone. The check can't be run until
 * someone puts them back, which is itself the alarm.
 */
const CHANGED_DATABASE = new Set(['42501', '42P01', '42703']);

const refusedByDatabase = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && CHANGED_DATABASE.has(String(error.code));

type Outcome = 'anchored' | 'unchanged' | 'failed' | 'unchecked';

export function createAnchorCheck({
  chains,
  keys,
  clock,
  logger,
  staleAfterMs,
  anchors = createMemoryAnchorStore(),
}: AnchorCheckOptions): AnchorCheck {
  // From when this process began, so a check that never once completes is caught too.
  const started = clock.now().getTime();
  const lastChecked = new Map<string, number>();
  const keyOf = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId);

  const checkOne = async ({ chain, verify }: CheckedChain): Promise<Outcome> => {
    try {
      // An organisation's ID goes on the line as the logger's own field, which an event can't set.
      const log = chain.kind === 'platform' ? logger : logger.child({ orgId: chain.orgId });
      const last = anchors.latest(chain);
      const alarm = (reason: string, seq?: bigint): Outcome => {
        log.error('audit.integrity_failed', {
          chain: chain.kind,
          check: 'anchor',
          reason,
          ...(seq === undefined ? {} : { seq }),
          ...(last === undefined ? {} : { anchorSeq: last.seq }),
        });
        return 'failed';
      };
      let report: ChainReport;
      try {
        report = await verify(last);
      } catch (error) {
        // A store that breaks its contract may be a hostile database too (a planted operator, a view for a table).
        if (error instanceof ChainStoreError || refusedByDatabase(error)) return alarm('store');
        log.warn('audit.anchor_check_failed', { chain: chain.kind, err: error });
        const since = clock.now().getTime() - (lastChecked.get(keyOf(chain)) ?? started);
        return since >= staleAfterMs ? alarm('unchecked') : 'unchecked';
      }
      lastChecked.set(keyOf(chain), clock.now().getTime());
      if (!report.ok) return alarm(report.problem.reason, report.problem.seq);
      // The check compared the anchored event already; this backs it up should a store not pass the anchor on.
      if (
        last !== undefined &&
        (report.seq < last.seq || (report.seq === last.seq && !report.hash.equals(last.hash)))
      ) {
        return alarm('anchor', last.seq);
      }
      if (last?.seq === report.seq) return 'unchanged';
      const anchor = signAnchor(keys, chain, { seq: report.seq, hash: report.hash }, clock.now());
      anchors.keep(anchor);
      log.info('audit.anchored', {
        chain: chain.kind,
        seq: report.seq,
        headHash: report.hash.toString('hex'),
        keyVersion: anchor.keyVersion,
      });
      return 'anchored';
    } catch (error) {
      // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
      logger.error('audit.anchor_check_crashed', { chain: chain.kind, err: error });
      return 'unchecked';
    }
  };

  return Object.freeze({
    async run(): Promise<void> {
      const outcomes: Outcome[] = [];
      for (const one of chains) outcomes.push(await checkOne(one));
      const count = (outcome: Outcome): number => outcomes.filter((each) => each === outcome).length;
      logger.info('audit.anchor_check_done', {
        chains: outcomes.length,
        anchored: count('anchored'),
        unchanged: count('unchanged'),
        failed: count('failed'),
        unchecked: count('unchecked'),
      });
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
