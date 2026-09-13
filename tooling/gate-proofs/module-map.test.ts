// The ADR-004 module map must itself be sound: only known names, no module
// listing itself, and no cycles (a cycle in the allowlist would let the code
// form one).
import { describe, expect, it } from 'vitest';

import { AUDIT_MODULE, MODULE_MAP } from '../module-map.ts';

type ModuleMap = Readonly<Record<string, readonly string[]>>;

const modules = Object.keys(MODULE_MAP);

function dependenciesOf(name: string): readonly string[] {
  return MODULE_MAP[name] ?? [];
}

/** Returns one cycle as a path of module names, or null when the map has none. */
function findCycle(map: ModuleMap): string[] | null {
  const done = new Set<string>();
  const onPath: string[] = [];

  const visit = (name: string): string[] | null => {
    const seenAt = onPath.indexOf(name);
    if (seenAt >= 0) return [...onPath.slice(seenAt), name];
    if (done.has(name)) return null;
    onPath.push(name);
    for (const dependency of map[name] ?? []) {
      const cycle = visit(dependency);
      if (cycle) return cycle;
    }
    onPath.pop();
    done.add(name);
    return null;
  };

  for (const name of Object.keys(map)) {
    const cycle = visit(name);
    if (cycle) return cycle;
  }
  return null;
}

describe('ADR-004 module map', () => {
  it('names only modules that are in the map', () => {
    const unknown = modules.flatMap((name) => dependenciesOf(name).filter((dependency) => !(dependency in MODULE_MAP)));
    expect(unknown).toEqual([]);
  });

  it('never lists a module as its own dependency', () => {
    expect(modules.filter((name) => dependenciesOf(name).includes(name))).toEqual([]);
  });

  it('has no cycles', () => {
    expect(findCycle(MODULE_MAP)).toBeNull();
  });

  it('keeps audit a sink that imports no other module', () => {
    expect(dependenciesOf(AUDIT_MODULE)).toEqual([]);
  });

  it('lets no module import evidence, which reads all of them', () => {
    expect(modules.filter((name) => dependenciesOf(name).includes('evidence'))).toEqual([]);
  });
});

describe('the cycle check itself', () => {
  it('finds a cycle several modules long', () => {
    expect(findCycle({ a: ['b'], b: ['c'], c: ['a'], d: [] })).toEqual(['a', 'b', 'c', 'a']);
  });

  it('accepts a diamond, which is not a cycle', () => {
    expect(findCycle({ top: ['left', 'right'], left: ['bottom'], right: ['bottom'], bottom: [] })).toBeNull();
  });
});
