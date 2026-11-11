// S185: no destructive command in the code unless tooling/destructive-allowed.ts
// names it, with its guard and the test proving that guard. The shapes and the
// rule are in tooling/destructive-scan.ts. An agent once wrote restore steps that
// would have deleted staging's live server; this is the check that would have
// stopped them reaching main.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { ALLOWED, NOT_COMMANDS } from '../destructive-allowed.ts';
import { type Allowed, allowProblems, hitsIn, isScanned } from '../destructive-scan.ts';
import { LOAD_PROJECT, OUT_DIR } from '../load/plan.ts';

const NUL = String.fromCharCode(0);

const tracked = execFileSync('git', ['-c', 'core.quotePath=false', 'ls-files', '-z'], {
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
})
  .split(NUL)
  .filter((file) => file !== '');

const read = (file: string): string | undefined => (existsSync(file) ? readFileSync(file, 'utf8') : undefined);
const textOf = (file: string): string => read(file) ?? '';
const LISTS = { allowed: ALLOWED, notCommands: NOT_COMMANDS };

describe("the repository's destructive commands", () => {
  const scanned = tracked.filter(isScanned);
  const hits = scanned.flatMap((file) => hitsIn(file, textOf(file)));

  it('reads the code, scripts and workflows, and finds what it is meant to (so the check is not vacuous)', () => {
    expect(scanned.length).toBeGreaterThan(400);
    expect(scanned).toContain('.github/workflows/ci.yml');
    expect(scanned).not.toContain('tooling/checks/destructive-commands.test.ts');
    expect(scanned.some((file) => file.startsWith('db/migrations/'))).toBe(false);
    expect(hits.length).toBeGreaterThan(30);
  });

  it('are each named with a guard in their file and a test proving it, and nothing named is stale', () => {
    expect(allowProblems(hits, LISTS, read)).toEqual([]);
  });

  it('removes recursively only a folder mkdtempSync made in the same file', () => {
    const temporary = ALLOWED.filter(({ guard }) => guard === 'mkdtempSync(');
    expect(temporary.length).toBeGreaterThan(3);
    for (const { file, match } of temporary) {
      const folder = /rmSync\((\w+),/.exec(match)?.[1] ?? '';
      expect(textOf(file), file).toMatch(new RegExp(String.raw`const ${folder} = mkdtempSync\(`));
    }
  });

  it("removes only the load run's own compose project and output folder", () => {
    expect(LOAD_PROJECT).toBe('agentx-load');
    expect(textOf('tooling/load/run.ts')).toContain("export const COMPOSE = [\n  'compose',\n  '-p',\n  LOAD_PROJECT,");
    expect(path.relative(process.cwd(), OUT_DIR)).toBe(path.join('tooling', 'load', '.out'));
  });

  it("removes volumes in CI only of the end-to-end stack on CI's own runner", () => {
    const downs = textOf('.github/workflows/ci.yml')
      .split('\n')
      .filter((line) => /\bdown\b.*--volumes/.test(line));
    expect(downs).toEqual([expect.stringContaining('-f tooling/e2e/compose.e2e.yaml down --volumes') as unknown]);
    expect(textOf('.github/workflows/ci.yml')).not.toMatch(/runs-on: (?!ubuntu-latest)/);
  });

  it('removes in an image build only absolute paths written out', () => {
    for (const file of ['Dockerfile', 'tooling/load/Dockerfile']) {
      const removes = textOf(file)
        .split('\n')
        .filter((line) => /\brm\s+-/.test(line));
      expect(removes, file).toHaveLength(1);
      const targets = (removes[0] ?? '')
        .replace(/^.*?\brm\s+-rf\s+/, '')
        .replace(/\s*\\\s*$/, '')
        .split(/\s+/);
      for (const target of targets)
        expect(target, file).toMatch(/^\/(?:var\/lib\/apt\/lists|usr\/local\/lib\/node_modules|opt\/yarn-)/);
    }
  });

  it("stops only the test server's own container", () => {
    expect(textOf('tooling/test-db/docker.ts')).toMatch(
      /const id = \(\s*await dockerOk\(\s*\[\s*'run',[\s\S]*?const stop = async \(\): Promise<void> => \{\s*await dockerOk\(\['rm', '--force', '--volumes', id\]\);/,
    );
  });
});

describe('the check', () => {
  const PLANTED = 'deploy/azure/restore.ts';
  const proof = { file: 'proof.test.ts', title: 'refuses the live server' };
  const files: Record<string, string> = {
    [PLANTED]: "refuseLive(name);\nrun(['postgres', 'flexible-server', 'delete', '--name', name]);",
    'proof.test.ts': "it('refuses the live server', () => {});",
  };
  const fake = (file: string): string | undefined => files[file];
  const entry: Allowed = {
    file: PLANTED,
    match: "'delete', '--name', name",
    guard: 'refuseLive(name)',
    proof,
    why: 'x',
  };
  const problemsOf = (allowed: readonly Allowed[], text = files[PLANTED] ?? '') =>
    allowProblems(hitsIn(PLANTED, text), { allowed, notCommands: [] }, fake);

  it.each([
    'az postgres flexible-server delete -n psql-agentx-stg-q1w2e3 --yes',
    "run(['postgres', 'flexible-server', 'delete', '-n', 'psql-agentx-stg-q1w2e3'])",
    'az keyvault purge --name kv-agentx-stg-q1w2e3',
    "az.run(['rest', '--method', 'delete', '--url', url])",
    "await fetch(url, { method: 'DELETE' })",
    'Invoke-RestMethod -Method Delete -Uri $url',
    'az group delete -n rg-agentx-staging',
    'az lock delete --name keep',
    'az deployment group create --mode Complete -g rg',
    "deploy({ mode: 'Complete' })",
    'sql`DROP TABLE audit.events`',
    "query('drop schema security cascade')",
    "query('TRUNCATE audit.heads')",
    "db.deleteFrom('audit.events').execute()",
    "query('DELETE FROM security.events')",
    'docker compose down -v',
    'docker compose down --volumes',
    'rmSync(target, { recursive: true, force: true })',
    'rm -rf "$BACKUP_DIR"',
    'Remove-Item $dir -Recurse -Force',
    'git push --force origin main',
    'git push -f',
    "az.run([\n  'rest',\n  '--method',\n  'DELETE',\n  '--url',\n  url,\n]);",
    "ok(server('delete'));",
    "const verb = 'delete';",
    "const verb = 'PURGE';",
    'await sql`truncate audit.heads`.execute(db);',
    "await db.schema.dropTable('audit.events').execute();",
    'curl -X DELETE "$URL"',
    'curl --request DELETE https://management.azure.com/x',
    'rm -Rf "$DIR"',
    'rm -r -f /var/lib/*',
    'rm --recursive $HOME/x',
    'rmdirSync(target, { recursive: true })',
    'await client.beginDeleteAndWait(group, server);',
    'Remove-AzResourceGroup -Name rg-agentx-staging -Force',
    'git push origin +main',
    "spawn('git', ['push', 'origin', '+HEAD:main'])",
    '/* a note */ az postgres flexible-server delete -n x',
  ])('refuses %s when nothing names it', (line) => {
    const problems = problemsOf([], line);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("isn't in destructive-allowed.ts");
  });

  it.each([
    "rmSync('tooling/load/.out', { recursive: true })",
    '// az postgres flexible-server delete in a comment runs nothing',
    'const a = { delete: 1 };',
    "switch (command) { case 'delete': break; }",
    "if (command === 'DELETE') return;",
    "type Verb = 'GET' | 'DELETE';",
    '/* az group delete -n rg, closed on its line */',
    '/**\n * az group delete -n rg\n * rm -rf $HOME\n */',
    '/*\n az group delete -n rg */',
    'rm -rf /var/lib/apt/lists',
    'docker run --rm --network none "$IMAGE" whoami',
  ])('passes %s', (line) => {
    expect(problemsOf([], line)).toEqual([]);
  });

  it('reads `#` as a comment only where it is one', () => {
    expect(hitsIn('a.sh', '# rm -rf $HOME runs nothing\n#!/bin/sh')).toEqual([]);
    expect(hitsIn('Dockerfile', '# rm -rf $HOME')).toEqual([]);
    expect(hitsIn('a.ts', '#x = rmSync(dir, { recursive: true });')).toHaveLength(1);
  });

  it('reads code after a block comment closes on its line', () => {
    expect(hitsIn('a.ts', '/* a\n b */ az group delete -n rg').map(({ line }) => line)).toEqual([2]);
  });

  it('passes a line named with its guard and its proof', () => {
    expect(problemsOf([entry])).toEqual([]);
  });

  it('refuses an entry naming no line: stale', () => {
    expect(problemsOf([entry], 'refuseLive(name);')).toEqual([
      `${PLANTED} ('delete', '--name', name) names no destructive line: take it out`,
    ]);
  });

  it('refuses an entry whose guard is not in its file, or whose proof is not in its test', () => {
    expect(problemsOf([{ ...entry, guard: 'refuseStaging(name)' }])).toEqual([
      `${PLANTED} ('delete', '--name', name): its guard refuseStaging(name) isn't there`,
    ]);
    expect(problemsOf([{ ...entry, proof: { ...proof, title: 'deletes anything' } }])).toEqual([
      `${PLANTED} ('delete', '--name', name): its proof "deletes anything" isn't in proof.test.ts`,
    ]);
    expect(problemsOf([{ ...entry, proof: { file: 'gone.test.ts', title: 'x' } }])).toHaveLength(1);
  });

  it('refuses a second line of the same text unless the entry says how many', () => {
    const twice = `${files[PLANTED] ?? ''}\nrun(['postgres', 'flexible-server', 'delete', '--name', name]);`;
    expect(problemsOf([entry], twice)).toEqual([
      `${PLANTED} ('delete', '--name', name) names 2 lines, not 1: name each on its own`,
    ]);
    expect(problemsOf([{ ...entry, lines: 2 }], twice)).toEqual([]);
  });

  it('reads code, scripts and workflows, but no test and no migration', () => {
    for (const file of [
      'a.ts',
      'a.mts',
      'a.mjs',
      'a.js',
      'a.cjs',
      'a.tsx',
      'a.sh',
      'a.ps1',
      'a.yml',
      'a.yaml',
      'main.bicep',
      'Dockerfile',
      'tooling/load/Dockerfile',
      'package.json',
      'apps/api/package.json',
      '.githooks/pre-push',
      'tooling/migrations-notes/x.ts',
      'db/migrations-old/x.ts',
    ]) {
      expect(isScanned(file), file).toBe(true);
    }
    for (const file of [
      'a.test.ts',
      'a.test.mjs',
      'a.test.tsx',
      '.githooks/README.md',
      'db/migrations/0001_x.sql',
      'README.md',
      'a.json',
      'tooling/destructive-allowed.ts',
      'tooling/destructive-scan.ts',
    ]) {
      expect(isScanned(file), file).toBe(false);
    }
  });
});
