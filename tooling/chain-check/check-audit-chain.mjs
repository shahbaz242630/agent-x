#!/usr/bin/env node
// An outside check of a downloaded audit log (Phase 6 6E1b, CO7b; BR-16).
//
// Anyone can run it on the NDJSON file an organisation's admin downloads from
// the audit log, with nothing but Node.js: it imports Node's own modules alone
// and never reaches the network. It reads the file, then says in plain words
// what it proved and what it could not.
//
//   node check-audit-chain.mjs <file.ndjson> --org <organisation ID>
//
// What it proves, for the events in the file:
// - their numbers (`seq`) follow one another with none missing or out of place;
// - each event names the hash of the one before it (`prevHash`), and the first
//   event of the whole chain (number 1) names the starting hash of zeros;
// - each event's own hash is SHA-256 of its organisation's chain name, the
//   hash before it and its own fields, exactly as Agent X computes it
//   (packages/platform/src/audit-chain/chain.ts `linkHash`), so a changed
//   field, time, person or fact shows. A signed state's event, whose seal the
//   download leaves out (`sealOmitted`), can't be recomputed: it is named, and
//   the verdict is PARTLY CHECKED, never PASSED.
//
// What it cannot prove without Agent X's MAC key (never in a download): that
// the whole chain was not rewritten from some point with every hash computed
// afresh, or that no events were left out before the first or after the last
// in the file. Agent X's own checks hold the key and a separately kept anchor
// for those.
//
// Verdicts and exit codes:
// - PASSED (0): every check passed and every event's hash was recomputed.
// - FAILED (1): a check failed.
// - NOT CHECKED (2): the file or the command could not be read.
// - PARTLY CHECKED (3): no check failed, but some events' hashes could not be
//   recomputed (each named), so their contents are not confirmed.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import process from 'node:process';

/** The hash a chain starts from, before its first event: 32 zero bytes, in hex. */
const GENESIS_HASH = '0'.repeat(64);
const HEX_HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEQ = /^[1-9][0-9]*$/;

/** The bytes a hash is taken over: each part's length as 4 bytes, big-endian, then the part (keys/message.ts). */
function encodeMessage(parts) {
  return Buffer.concat(
    parts.flatMap((part) => {
      const bytes = typeof part === 'string' ? Buffer.from(part, 'utf8') : part;
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      return [length, bytes];
    }),
  );
}

/** The details as Agent X stored them: compact JSON, keys in code-unit order (shared-kernel/event-facts.ts). */
function canonicalDetails(details) {
  const byKey = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0);
  return JSON.stringify(Object.fromEntries(Object.entries(details).sort(byKey)));
}

/** An event's hash, recomputed from its own fields and the hash before it (audit-chain/chain.ts `linkHash`). */
function linkHashOf(orgId, event) {
  const message = [
    'audit-link',
    `organisation:${orgId}`,
    Buffer.from(event.prevHash, 'hex'),
    event.seq,
    event.id,
    event.recordedAt,
    'actor',
    event.actor.type,
    event.actor.id,
    'action',
    event.action,
    'subject',
    event.subject.type,
    event.subject.id,
    String(event.subject.version),
    'details',
    canonicalDetails(event.details),
  ];
  return createHash('sha256').update(encodeMessage(message)).digest('hex');
}

const isText = (value) => typeof value === 'string';
const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/** Why a parsed line isn't an event of the download, or undefined when it is one. */
function shapeProblem(event) {
  if (!isPlainObject(event)) return 'it is not an object';
  if (!isText(event.seq) || !SEQ.test(event.seq)) return 'its number (seq) is missing or not a whole number';
  if (!isText(event.id) || !isText(event.action)) return 'its ID or action is missing';
  if (!isText(event.recordedAt) || Number.isNaN(Date.parse(event.recordedAt))) return 'its time is missing';
  if (new Date(event.recordedAt).toISOString() !== event.recordedAt) return 'its time is not in the exact UTC form';
  if (!isPlainObject(event.actor) || !isText(event.actor.type) || !isText(event.actor.id))
    return 'its actor is missing';
  const { subject } = event;
  if (!isPlainObject(subject) || !isText(subject.type) || !isText(subject.id) || !Number.isSafeInteger(subject.version))
    return 'its subject is missing';
  if (!isPlainObject(event.details)) return 'its facts (details) are missing';
  if (!isText(event.hash) || !HEX_HASH.test(event.hash)) return 'its hash is missing or not 64 hex characters';
  if (!isText(event.prevHash) || !HEX_HASH.test(event.prevHash))
    return 'its previous hash is missing or not 64 hex characters';
  if (event.sealOmitted !== undefined && typeof event.sealOmitted !== 'boolean')
    return 'sealOmitted is not true or false';
  return undefined;
}

/** The file's events, each with its line number; or the first line that can't be read, as `problem`. */
function readEvents(text) {
  const events = [];
  const lines = text.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    if (line.trim() === '') continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      return { problem: `Line ${String(index + 1)} is not valid JSON.` };
    }
    const problem = shapeProblem(event);
    if (problem !== undefined) return { problem: `Line ${String(index + 1)} is not an audit event: ${problem}.` };
    events.push({ ...event, line: index + 1 });
  }
  return { events };
}

/** Each next line exactly one number away in the file's own order, so a dropped or moved line shows where it is. */
function orderFailures(events, step) {
  const failures = [];
  for (let at = 1; at < events.length; at += 1) {
    const before = events[at - 1];
    const now = events[at];
    if (BigInt(now.seq) !== BigInt(before.seq) + step) {
      failures.push(
        `Line ${String(now.line)} holds event ${now.seq} right after event ${before.seq} (line ${String(before.line)}): ` +
          'an event is missing, repeated or out of place there.',
      );
    }
  }
  return failures;
}

/** Each event naming the hash of the one before it, and event 1 the starting hash of zeros. */
function linkFailures(oldestFirst) {
  const failures = [];
  for (let at = 1; at < oldestFirst.length; at += 1) {
    const before = oldestFirst[at - 1];
    const now = oldestFirst[at];
    if (BigInt(now.seq) === BigInt(before.seq) + 1n && now.prevHash !== before.hash) {
      failures.push(
        `Event ${now.seq} (line ${String(now.line)}) does not name the hash of event ${before.seq} before it.`,
      );
    }
  }
  const first = oldestFirst[0];
  if (first.seq === '1' && first.prevHash !== GENESIS_HASH) {
    failures.push(`Event 1 (line ${String(first.line)}) should name the starting hash of zeros, and does not.`);
  }
  return failures;
}

/**
 * Each event's hash recomputed from its fields where the line holds them all. A file mixing lines that say whether
 * a seal was left out with lines that don't was put together by hand, so there a line without it is held to its
 * hash like any other.
 */
function hashChecks(org, oldestFirst, saysSeals) {
  const failures = [];
  const notRecomputed = [];
  for (const event of oldestFirst) {
    if (event.sealOmitted === true) {
      notRecomputed.push(event.seq);
    } else if (linkHashOf(org, event) === event.hash) {
      // Its fields give its hash.
    } else if (event.sealOmitted === undefined && !saysSeals) {
      // A download from before `sealOmitted` was added: a signed state's event can't be told from a changed one.
      notRecomputed.push(event.seq);
    } else {
      failures.push(
        `Event ${event.seq} (line ${String(event.line)}): its fields do not give its hash. ` +
          'Something in it was changed after it was recorded, or the organisation ID given is not its organisation.',
      );
    }
  }
  return { failures, notRecomputed };
}

/**
 * Checks the events of one organisation's chain, as a download holds them (newest first, or oldest first). Returns
 * what passed, what failed and what it could not prove, in plain words.
 */
function checkChain(text, orgId) {
  const org = orgId.toLowerCase();
  const read = readEvents(text);
  if (read.problem !== undefined) return { ok: false, readable: false, failures: [read.problem], notes: [] };
  const { events } = read;
  if (events.length === 0) return { ok: false, readable: false, failures: ['The file holds no events.'], notes: [] };

  const notes = [];
  // The file's order: a download is newest first, but oldest first is read as well.
  const step = events.length > 1 && BigInt(events[1].seq) < BigInt(events[0].seq) ? -1n : 1n;
  const oldestFirst = step === 1n ? events : events.toReversed();
  const first = oldestFirst[0];
  // A download says on every line whether a seal was left out; one from before it said none.
  const saysSeals = events.some((event) => event.sealOmitted !== undefined);
  const hashes = hashChecks(org, oldestFirst, saysSeals);
  const failures = [...orderFailures(events, step), ...linkFailures(oldestFirst), ...hashes.failures];
  const { notRecomputed } = hashes;

  const last = oldestFirst.at(-1);
  if (first.seq !== '1') {
    notes.push(
      `The file starts at event ${first.seq}, not the chain's first: the events before it are not here, so the link ` +
        `of event ${first.seq} to the one before it can't be checked.`,
    );
  }
  notes.push(
    `Nothing here can show whether events came after event ${last.seq}, the last in the file.`,
    "Without Agent X's MAC key, which no download holds, this check can't prove the whole chain wasn't rewritten " +
      'from some point with every hash computed afresh; Agent X checks that itself with the key and a separately ' +
      'kept anchor.',
  );
  return {
    ok: failures.length === 0,
    readable: true,
    events: events.length,
    first: first.seq,
    last: last.seq,
    notRecomputed,
    oldFile: !saysSeals,
    failures,
    notes,
  };
}

/** The command: reads the file and the organisation, prints the verdict and sets the exit code. */
function main(args) {
  const orgAt = args.indexOf('--org');
  const orgId = orgAt === -1 ? undefined : args[orgAt + 1];
  const file = args.find((arg, index) => !arg.startsWith('--') && index !== orgAt + 1);
  if (file === undefined || orgId === undefined || !UUID.test(orgId)) {
    process.stderr.write('Usage: node check-audit-chain.mjs <file.ndjson> --org <organisation ID>\n');
    return 2;
  }
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    process.stderr.write(`Could not read ${file}: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
  const report = checkChain(text, orgId);
  const out = [];
  if (!report.readable) {
    out.push('NOT CHECKED: the file could not be read as an audit log download.', ...report.failures);
    process.stdout.write(`${out.join('\n')}\n`);
    return 2;
  }
  const range = `events ${report.first} to ${report.last} (${String(report.events)})`;
  const unconfirmed = report.notRecomputed.length;
  const why = report.oldFile
    ? "each may be a signed state's event whose seal Agent X leaves out of a download: this file is too old to say which"
    : "each is marked as a signed state's event whose seal Agent X leaves out of a download (sealOmitted)";
  if (!report.ok) {
    out.push(`FAILED: ${String(report.failures.length)} problem(s) in ${range}.`);
  } else if (unconfirmed === 0) {
    out.push(`PASSED: ${range} link up, each to the one before it, and each one's contents give its hash.`);
  } else {
    out.push(
      `PARTLY CHECKED: ${range} link up, each to the one before it; the contents of ` +
        `${String(report.events - unconfirmed)} of them give their hash. The contents of ${String(unconfirmed)} ` +
        `(event${unconfirmed === 1 ? '' : 's'} ${report.notRecomputed.join(', ')}) could not be confirmed: ${why}.`,
    );
  }
  out.push(
    ...report.failures.map((failure) => `  - ${failure}`),
    'What this check could not prove:',
    ...report.notes.map((note) => `  - ${note}`),
  );
  process.stdout.write(`${out.join('\n')}\n`);
  if (!report.ok) return 1;
  return unconfirmed === 0 ? 0 : 3;
}

process.exitCode = main(process.argv.slice(2));
