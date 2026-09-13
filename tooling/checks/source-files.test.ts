// Product code is TypeScript (.ts and .tsx) only. The lint rules for product
// code, including the security rules, match .ts and .tsx files; a .js, .mjs or
// .cjs file would get only the general rules, and ESLint skips .mts and .cts
// files entirely. So no other code file may live under packages/ or apps/.
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

/** Folders that hold installed or generated files, not our source. */
const SKIPPED = new Set(['node_modules', 'dist', 'coverage']);
const CODE_FILE = /\.[cm]?[jt]sx?$/;
const TYPESCRIPT_FILE = /\.tsx?$/;

function filesUnder(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return SKIPPED.has(entry.name) ? [] : filesUnder(full);
    return [full.replaceAll('\\', '/')];
  });
}

/** Code files that aren't .ts or .tsx. */
function notTypeScript(files: readonly string[]): string[] {
  return files.filter((file) => CODE_FILE.test(file) && !TYPESCRIPT_FILE.test(file));
}

describe('product code is TypeScript only, so every lint rule reaches it', () => {
  it('has no other code file under packages/ or apps/', () => {
    const files = ['packages', 'apps'].filter((folder) => existsSync(folder)).flatMap(filesUnder);
    expect(files.length).toBeGreaterThan(0);
    expect(notTypeScript(files)).toEqual([]);
  });

  it('the check catches every other code file type, and leaves other files alone', () => {
    const files = ['a.js', 'b.jsx', 'c.mjs', 'd.cjs', 'e.mts', 'f.cts', 'g.ts', 'h.tsx', 'i.d.ts', 'j.json', 'k.css'];
    expect(notTypeScript(files)).toEqual(['a.js', 'b.jsx', 'c.mjs', 'd.cjs', 'e.mts', 'f.cts']);
  });
});
