// 6E1b (CO7b): the outside check of a downloaded audit log, against a chain
// built the way Agent X builds one. The chain is made in memory with the
// platform's own linkHash and exported line by line with the evidence
// module's ndjsonLine, so the check and the product can't drift apart
// unnoticed (a differential test). No database and no MAC: the check never
// sees one, and no forged event goes near a real store.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { eventContent, type AuditEvent } from '../../packages/core/src/modules/audit/domain/event.ts';
import { ndjsonLine } from '../../packages/core/src/modules/evidence/infrastructure/log-shown.ts';
import { canonicalDetails } from '../../packages/core/src/shared-kernel/event-facts.ts';
import { GENESIS_HASH, linkHash } from '../../packages/platform/src/audit-chain/chain.ts';

const SCRIPT = path.join(import.meta.dirname, 'check-audit-chain.mjs');
const ORG = '0199a0f0-0000-7000-8000-00000000abcd';
const OTHER_ORG = '0199a0f0-0000-7000-8000-00000000abce';
const USER = '0199a0f0-0000-7000-8000-000000000011';

const dir = mkdtempSync(path.join(tmpdir(), 'chain-check-'));
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** The events of a chain, each with the facts it was recorded with: one a signed state's, its seal among them. */
const EVENTS: readonly AuditEvent[] = [
  {
    actor: { type: 'system', id: 'api' },
    action: 'organisation.created',
    subject: { type: 'organisation', id: ORG, version: 1 },
    details: { name: 'Gulf Supplies LLC' },
  },
  {
    actor: { type: 'user', id: USER },
    action: 'agent.registered',
    subject: { type: 'agent', id: '0199a0f0-0000-7000-8000-00000000a9e1', version: 1 },
    details: { name: 'Buyer', stateFingerprint: 'ab'.repeat(32), stateKeyVersion: 1 },
  },
  {
    actor: { type: 'user', id: USER },
    action: 'mandate.drafted',
    subject: { type: 'mandate', id: '0199a0f0-0000-7000-8000-00000000a9e2', version: 3 },
    details: { limitMinor: 500_000, currency: 'AED', note: 'café “quoted”', approved: true, reason: null },
  },
  {
    actor: { type: 'user', id: USER },
    action: 'audit_log.exported',
    subject: { type: 'audit_log', id: ORG, version: 1 },
    details: { from: '2026-10-01', to: '2026-10-20' },
  },
];

/** The same chain with no signed state's event: every hash can be recomputed. */
const PLAIN = EVENTS.filter((event) => !Object.hasOwn(event.details, 'stateFingerprint'));

/** The chain as Agent X seals it, events 1 to 4, then as a download holds it: newest first, one line each. */
function download(orgId = ORG, events: readonly AuditEvent[] = EVENTS): string[] {
  let prevHash: Buffer = GENESIS_HASH;
  const lines = events.map((event, index) => {
    const seq = BigInt(index + 1);
    const id = `0199a0f0-0000-7000-8000-0000000e0${String(index).padStart(3, '0')}`;
    const recordedAt = new Date(Date.UTC(2026, 9, 19, 9, index, 0, 123));
    const hash = linkHash({ kind: 'organisation', orgId }, prevHash, {
      seq,
      id,
      recordedAt,
      content: eventContent(event, canonicalDetails(event.details)),
    });
    const line = ndjsonLine(
      { seq, id, recordedAt, event, hash: hash.toString('hex'), prevHash: prevHash.toString('hex') },
      new Map(),
    );
    prevHash = hash;
    return line;
  });
  return lines.toReversed();
}

let files = 0;
/** Runs the check on these lines as a file, as anyone would, and gives its exit code and words. */
function check(lines: readonly string[], orgId: string = ORG) {
  files += 1;
  const file = path.join(dir, `audit-${String(files)}.ndjson`);
  writeFileSync(file, `${lines.join('\n')}\n`);
  const run = spawnSync(process.execPath, [SCRIPT, file, '--org', orgId], { encoding: 'utf8' });
  return { code: run.status, out: run.stdout, err: run.stderr };
}

describe('the outside chain check (6E1b, CO7b)', () => {
  it('passes a download whose every event it recomputed, saying what it cannot prove', () => {
    const { code, out } = check(download(ORG, PLAIN));

    expect(code).toBe(0);
    expect(out).toContain("PASSED: events 1 to 3 (3) link up, each to the one before it, and each one's contents give");
    expect(out).toContain("Without Agent X's MAC key");
    expect(out).toContain('after event 3');
  });

  it('says PARTLY CHECKED, exit code 3, never PASSED, for a download with a signed state’s event it could not recompute, naming it', () => {
    const { code, out } = check(download());

    expect(code).toBe(3);
    expect(out).not.toContain('PASSED');
    expect(out).toContain(
      'PARTLY CHECKED: events 1 to 4 (4) link up, each to the one before it; the contents of 3 of them',
    );
    expect(out).toContain('The contents of 1 (event 2) could not be confirmed');
    expect(out).toContain('(sealOmitted)');
  });

  it('passes the same chain oldest first, and an organisation ID in capitals', () => {
    expect(check(download(ORG, PLAIN).toReversed(), ORG.toUpperCase()).code).toBe(0);
  });

  it('passes a range not starting at event 1, saying the events before it are not there', () => {
    const { code, out } = check(download().slice(0, 2));

    expect(code).toBe(0);
    expect(out).toContain('PASSED: events 3 to 4 (2)');
    expect(out).toContain('starts at event 3');
  });

  it('fails one changed byte in a fact, naming the event', () => {
    const lines = download();
    lines[1] = (lines[1] ?? '').replace('500000', '500001');

    const { code, out } = check(lines);
    expect(code).toBe(1);
    expect(out).toContain('Event 3 (line 2): its fields do not give its hash');
  });

  it.each([
    ['its time', (line: string) => line.replace('09:02:00.123Z', '09:02:00.124Z')],
    ['its person', (line: string) => line.replace(USER, USER.replace('11', '12'))],
    ['its action', (line: string) => line.replace('mandate.drafted', 'mandate.approved')],
    ['its version', (line: string) => line.replace('"version":3', '"version":4')],
  ])('fails a change to %s', (_what, change) => {
    const lines = download();
    lines[1] = change(lines[1] ?? '');

    expect(check(lines).code).toBe(1);
  });

  it('fails a dropped line', () => {
    const lines = download();
    lines.splice(1, 1);

    const { code, out } = check(lines);
    expect(code).toBe(1);
    expect(out).toContain('an event is missing, repeated or out of place');
  });

  it('fails a reordered line', () => {
    const lines = download();
    [lines[1], lines[2]] = [lines[2] ?? '', lines[1] ?? ''];

    expect(check(lines).code).toBe(1);
  });

  it('fails a link to the wrong event, though every number follows on', () => {
    const lines = download();
    const event = JSON.parse(lines[0] ?? '') as { prevHash: string };
    lines[0] = JSON.stringify({ ...event, prevHash: 'f'.repeat(64) });

    const { code, out } = check(lines);
    expect(code).toBe(1);
    expect(out).toContain('does not name the hash of event 3 before it');
  });

  it('fails event 1 naming anything but the hash of zeros', () => {
    const lines = download();
    const first = JSON.parse(lines[3] ?? '') as { prevHash: string };
    lines[3] = JSON.stringify({ ...first, prevHash: '1'.repeat(64) });

    const { code, out } = check(lines);
    expect(code).toBe(1);
    expect(out).toContain('starting hash of zeros');
  });

  it("fails another organisation's chain checked as this one's", () => {
    expect(check(download(OTHER_ORG)).code).toBe(1);
  });

  /** The lines with `sealOmitted` taken out, as a download from before it was added held them; `only` those lines alone. */
  const withoutSealOmitted = (lines: readonly string[], only?: number) =>
    lines.map((line, index) => {
      if (only !== undefined && index !== only) return line;
      const { sealOmitted: _gone, ...rest } = JSON.parse(line) as Record<string, unknown>;
      return JSON.stringify(rest);
    });

  it('says PARTLY CHECKED for a download from before `sealOmitted`, an event it can’t recompute unconfirmed, never passed or failed by a guess', () => {
    const { code, out } = check(withoutSealOmitted(download()));

    expect(code).toBe(3);
    expect(out).toContain('The contents of 1 (event 2) could not be confirmed');
    expect(out).toContain('too old to say which');
  });

  it('fails a line without `sealOmitted` whose hash does not recompute, in a file whose other lines carry it: a mixed file was edited', () => {
    // Event 2's line (the third, newest first), its seal left out and its mark taken away.
    const { code, out } = check(withoutSealOmitted(download(), 2));

    expect(code).toBe(1);
    expect(out).toContain('Event 2 (line 3): its fields do not give its hash');
  });

  it('passes a line without `sealOmitted` among lines that carry it when its hash recomputes', () => {
    expect(check(withoutSealOmitted(download(ORG, PLAIN), 1)).code).toBe(0);
  });

  it.each([
    ['a line that is not JSON', ['{not json']],
    ['a line that is not an event', ['{"seq":"1"}']],
    ['no events', ['']],
  ])('says it could not check %s, with exit code 2', (_what, lines) => {
    const { code, out } = check(lines);

    expect(code).toBe(2);
    expect(out).toContain('NOT CHECKED');
  });

  it('explains how to run it when the organisation is missing or not an ID, with exit code 2', () => {
    const file = path.join(dir, 'usage.ndjson');
    writeFileSync(file, download().join('\n'));
    for (const args of [[file], [file, '--org', 'acme']]) {
      const run = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
      expect(run.status).toBe(2);
      expect(run.stderr).toContain('Usage: node check-audit-chain.mjs');
    }
    const missing = spawnSync(process.execPath, [SCRIPT, path.join(dir, 'none.ndjson'), '--org', ORG], {
      encoding: 'utf8',
    });
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain('Could not read');
  });

  it("imports nothing but Node's own modules, so anyone can run it without installing anything", () => {
    const source = readFileSync(SCRIPT, 'utf8');
    const imported = [...source.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gmu)].map(([, from]) => from);
    const required = [...source.matchAll(/\b(?:require|import)\(\s*['"]([^'"]+)['"]/gu)].map(([, from]) => from);

    expect(imported.length).toBeGreaterThan(0);
    expect([...imported, ...required].filter((from) => !from?.startsWith('node:'))).toEqual([]);
  });
});
