// SEC-OPS-05 (ADR-012 §6): every start writes the hash of the settings it
// started with, and the release, to the platform audit chain, beside the log
// line that shows them. The log can be lost or cut short; the chain keeps
// every start in order, sealed, where a change is found. A start that can't be
// written doesn't go on: the caller refuses to start.
import { createPlatformChain, type PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

export interface StartFacts {
  /** The config fingerprint's hash (`sha256:` and 64 hex digits). */
  readonly configHash: string;
  readonly release: string;
}

/**
 * Writes `platform.started` in a transaction of its own, waiting only so long
 * for the chain's head (PlatformChain.recordAlone), and gives back its place in
 * the chain.
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
    details: { configHash: facts.configHash, release: facts.release },
  });
  return recorded.seq;
}
