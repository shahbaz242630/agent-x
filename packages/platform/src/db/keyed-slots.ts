// Slots per key: at most so many at once for one key, the rest waiting in the
// order they came, each for a bounded time, holding nothing. Behind an agent's
// decision turns (apps/api agent-turns.ts) and an organisation's share of the
// connections (connection-shares.ts). Only keys in hand have a line, so the
// memory never grows with keys seen.

export interface KeyedSlots {
  /** Takes one of the key's slots: at once while fewer than the limit are taken, otherwise after those before it. Rejects with `exceeded()` past the wait. */
  enter(key: string): Promise<void>;
  /** Gives one back: to the next in line, or closes the line when no one waits. */
  leave(key: string): void;
  /** The keys with a slot taken or waited for: none once all are given back. */
  keysInHand(): number;
}

interface Line {
  taken: number;
  readonly waiting: (() => void)[];
}

export function createKeyedSlots({
  perKey,
  waitMs,
  exceeded,
}: {
  readonly perKey: number;
  readonly waitMs: number;
  readonly exceeded: () => Error;
}): KeyedSlots {
  const lines = new Map<string, Line>();

  return {
    keysInHand: () => lines.size,
    enter(key) {
      let line = lines.get(key);
      if (line === undefined) {
        line = { taken: 0, waiting: [] };
        lines.set(key, line);
      }
      if (line.taken < perKey) {
        line.taken += 1;
        return Promise.resolve();
      }
      const { waiting } = line;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiting.splice(waiting.indexOf(go), 1);
          reject(exceeded());
        }, waitMs);
        function go(): void {
          clearTimeout(timer);
          resolve();
        }
        waiting.push(go);
      });
    },
    leave(key) {
      const line = lines.get(key);
      if (line === undefined) return;
      // Handed on keeps its count: the one leaving passes its place to the next, never freeing it first.
      const next = line.waiting.shift();
      if (next !== undefined) {
        next();
        return;
      }
      line.taken -= 1;
      if (line.taken === 0) lines.delete(key);
    },
  };
}
