// Decision 29: the logger takes only catalogued events as warnings and errors,
// so a missing entry is a type error. This is the other direction: an entry
// whose line was removed from the code is left over, and goes.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { PLAIN_WORDS } from '../../packages/platform/src/observability/plain-words.ts';

const SKIPPED = new Set(['node_modules', 'dist', 'coverage']);
/** The row sweeps name their event from the rows they sweep (apps/api/src/row-sweep.ts). */
const SWEEP_FAILED = '_sweep_failed';

function sourceUnder(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return SKIPPED.has(entry.name) ? [] : sourceUnder(full);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [full] : [];
  });
}

/** Catalogued events no product code names, as a quoted literal. */
function leftOver(events: readonly string[], code: string): string[] {
  return events.filter((event) => {
    const named = event.endsWith(SWEEP_FAILED) ? event.slice(0, -SWEEP_FAILED.length) : event;
    return !code.includes(`'${named}'`);
  });
}

describe('decision 29: no plain words are left over', () => {
  it('every catalogued event is still named in the code', () => {
    const code = ['apps', 'packages']
      .flatMap(sourceUnder)
      .filter((file) => !file.replaceAll('\\', '/').endsWith('observability/plain-words.ts'))
      .map((file) => readFileSync(file, 'utf8'))
      .join('\n');
    expect(leftOver(Object.keys(PLAIN_WORDS), code)).toEqual([]);
  });

  it('the check finds a left-over entry, and reads a sweep by its rows', () => {
    const code = "log.warn('kept.event'); const rows = 'identity.flow';";
    expect(leftOver(['kept.event', 'gone.event', 'identity.flow_sweep_failed'], code)).toEqual(['gone.event']);
  });
});
