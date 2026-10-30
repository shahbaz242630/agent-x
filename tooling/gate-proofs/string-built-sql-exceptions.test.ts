// Gate proof for SEC-TEN-07's exceptions: product code turns the string-built
// SQL rule off only on the lines listed here, each with its reason beside it:
// the migration and server set-up files (reviewed SQL from the repository,
// fixed role names), and withTenant's own driver (partner S162, 4D2d P11),
// where a transaction's start and commit travel with their checks in one round
// trip and so can take no parameters. A new one anywhere fails here until it
// is reviewed and added; tests and the test harness may turn it off freely.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '../..');
const TURNED_OFF = /eslint-disable(?:-next-line|-line)?\b[^\n]*agentx\/no-string-built-sql/;

/** Every product source file: packages' and apps' src, tests and the test harness left out. */
function productFiles(): string[] {
  const roots = ['packages', 'apps'].flatMap((top) =>
    readdirSync(path.join(ROOT, top), { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && entry.name !== 'testing')
      .map((entry) => path.join(ROOT, top, entry.name, 'src')),
  );
  return roots.flatMap((root) =>
    readdirSync(root, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile() && /\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name))
      .map((entry) => path.join(entry.parentPath, entry.name)),
  );
}

describe('SEC-TEN-07 the string-built SQL rule is turned off in product code only where reviewed', () => {
  it('finds it off on the listed lines alone: set-up, migrations, and the checked driver', () => {
    const off = productFiles().flatMap((file) =>
      readFileSync(file, 'utf8')
        .split('\n')
        .filter((line) => TURNED_OFF.test(line))
        .map(() => path.relative(ROOT, file).replaceAll('\\', '/')),
    );
    const counted = Object.fromEntries(
      [...new Set(off)].map((file) => [file, off.filter((each) => each === file).length]),
    );
    expect(counted).toEqual({
      'packages/platform/src/db/migrate.ts': 1,
      'packages/platform/src/db/server-setup.ts': 4,
      'packages/platform/src/db/tenant.ts': 3,
    });
  });
});
