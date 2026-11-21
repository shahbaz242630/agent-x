// SEC-OPS-05 (ADR-012 §6): every start writes the hash of the settings it
// started with, and the release, to the platform audit chain, beside the log
// line that shows them. The log can be lost or cut short; the chain keeps
// every start in order, sealed, where a change is found. A start that can't be
// written doesn't go on: the caller refuses to start.
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

/**
 * The detail naming the start's own time, by its clock (S206 V6). It bounded the security rows from before 0105 and told
 * a database born sealed from one from before (both passes deleted S208); kept as the start's signed time.
 */
const ROW_MACS_FROM = 'rowMacsFrom';

export interface StartFacts {
  /** The config fingerprint's hash (`sha256:` and 64 hex digits). */
  readonly configHash: string;
  readonly release: string;
  /** ADR-014 §4: a live start's live-money gate reference, recorded beside the config's hash; none otherwise. */
  readonly gateRef: string | undefined;
  /** When it started, by its clock: recorded as ROW_MACS_FROM. Boot always gives it; a test's own start may not. */
  readonly at?: Date | undefined;
}

/**
 * Writes `platform.started` in a transaction of its own (PlatformChain.recordAlone),
 * waiting only so long for the chain's head (PlatformChain.record), and gives
 * back its place in the chain.
 */
export async function recordStart(
  database: Database<PlatformControlsTables>,
  keys: KeyProvider,
  ids: IdGenerator,
  facts: StartFacts,
): Promise<bigint> {
  const recorded = await createPlatformChain({ keys, ids }).recordAlone(database, {
    actor: { type: 'system', id: 'api' },
    action: 'platform.started',
    details: {
      configHash: facts.configHash,
      release: facts.release,
      ...(facts.gateRef === undefined ? {} : { gateRef: facts.gateRef }),
      ...(facts.at === undefined ? {} : { [ROW_MACS_FROM]: facts.at.toISOString() }),
    },
  });
  return recorded.seq;
}
