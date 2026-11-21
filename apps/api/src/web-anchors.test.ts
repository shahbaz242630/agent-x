// A `web` copy's anchors and digest, read only (AT13b): what it reads from the store the jobs copy keeps, that it reads
// again what lands, that it never writes the store, never leads and never touches the database, and that a web boot
// gives core the digest it reads.
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { checkStatesWith, statesDigest } from '@agentx/core/modules/audit';
import { rebaseFile, rebaseFileName, signRebase, subjectKey } from '@agentx/platform/audit-chain';
import { type Config, loadConfig } from '@agentx/platform/config';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { folderWriteOnceStore, type WriteOnceStore } from '@agentx/platform/storage';
import { LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { PastDeadline, Stopped } from './background.ts';
import {
  type AnchorsKept,
  anchorsKeptOf,
  anchorsReadOf,
  ReadOnlyStore,
  readOnlyStore,
  WEB_COPY_NAMES,
  webCopyLogger,
} from './anchor-store.ts';
import { type Booted, sharedParts } from './boot.ts';
import { webCopyJobs } from './job-list.ts';
import { createWebAnchorRead, WEB_ANCHORS_EVERY_MS } from './web-anchors.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
// Before any real clock this runs on: the boot's own copy reads with the system's, which passes over files dated ahead.
const AT = new Date('2026-11-01T09:00:00.000Z');
const WALK_BEGAN = new Date(AT.getTime() - 60_000);
const ORG = '0199a0f0-0000-7000-8000-000000000001';
const CHAIN = { kind: 'organisation', orgId: ORG } as const;
const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const KEY = '0199a0f0-0000-7000-8000-0000000000b1';

const folders: string[] = [];
afterEach(() => {
  checkStatesWith(undefined);
  for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
});

const folder = (): string => {
  const made = mkdtempSync(join(tmpdir(), 'web-anchors-'));
  folders.push(made);
  return made;
};

/** Every file under the folder: what the store holds. */
const filesIn = (directory: string): string[] =>
  readdirSync(directory, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => join(entry.parentPath, entry.name))
    .toSorted();

const configWith = (directory: string | null, environment = 'test'): Config =>
  ({
    environment,
    anchorStore: { directory, container: null },
    audit: { anchorSeconds: 300, anchorEpoch: 1 },
  }) as Config;

/** The services each side is made with, its lines in a capture of its own. */
const servicesWith = (capture = new LogCapture()) => ({
  keys,
  logger: testLogger(capture),
  clock: { now: () => AT },
  alertAfterMs: 900_000,
});

/** The jobs copy, over the folder: its store read, then what a walk found recorded and written. */
async function jobsRecord(directory: string, facts: [string, string, bigint][]): Promise<AnchorsKept> {
  const kept = anchorsKeptOf(configWith(directory), servicesWith());
  if (kept === undefined) throw new Error('a folder is named');
  await kept.log.read();
  await kept.digest.read();
  kept.digest.record(CHAIN, new Map(facts.map(([type, id, seq]) => [subjectKey(type, id), seq])), WALK_BEGAN);
  await kept.digest.flush();
  return kept;
}

/** A web copy over the folder, with the run that reads the store again, and its lines. */
function webOver(directory: string) {
  const capture = new LogCapture();
  const services = servicesWith(capture);
  const kept = anchorsReadOf(configWith(directory), services);
  if (kept === undefined) throw new Error('a folder is named');
  const read = createWebAnchorRead({ ...kept, logger: services.logger });
  const said = (event: string) => capture.lines().filter((line) => line.event === event);
  return { ...kept, read, said, capture };
}

describe('a web copy reads the anchors and the digest the jobs copy keeps (AT13b)', () => {
  it('holds nothing until its first read, so every read goes on as before the digest; then what the jobs wrote', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const web = webOver(directory);
    expect(web.digest.state()).toBe('unread');
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
    expect(web.digest.covers(CHAIN, 1n)).toBe(false);

    await web.read.run();
    expect(web.log.state()).toBe('read');
    expect(web.digest.state()).toBe('read');
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBe(7n);
    // A fact it doesn't hold says nothing: today's checks, never an alarm.
    expect(web.digest.latest(CHAIN, 'agent_key', KEY)).toBeUndefined();
  });

  it('speaks with no lease: it never leads, and its digest answers all the same', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const web = webOver(directory);
    await web.read.run();
    await web.read.run();
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBe(7n);
  });

  it('reads again what lands after its first read, each run', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const web = webOver(directory);
    await web.read.run();
    await jobsRecord(directory, [
      ['agent', AGENT, 9n],
      ['agent_key', KEY, 8n],
    ]);
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBe(7n);

    await web.read.run();
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBe(9n);
    expect(web.digest.latest(CHAIN, 'agent_key', KEY)).toBe(8n);
  });

  it('sets a chain rebased since aside, facts and all, so lag never leaves it alarming on a chain wound back', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const web = webOver(directory);
    await web.read.run();
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBe(7n);

    const rebase = signRebase(keys, 1, {
      id: '00000000-0000-4000-8000-000000000001',
      chain: `organisation:${ORG}`,
      seq: 3n,
      hash: Buffer.alloc(32, 3),
      macKeyVersion: 1,
      at: AT,
      reason: 'repaired',
      evidence: 'INC-2026-11-21',
      from: null,
    });
    await folderWriteOnceStore(directory).put(rebaseFileName(1, rebase.id), rebaseFile(rebase));
    await web.read.run();
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
  });

  it('never writes the store: reads add no file, and a write asked of it by mistake is refused and said', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const before = filesIn(directory);
    const web = webOver(directory);
    await web.read.run();
    await web.read.run();
    expect(filesIn(directory)).toEqual(before);
    expect(web.said('audit.anchor_store_write_refused')).toEqual([]);

    // Only the anchor check records and flushes, and a web copy has none: were anything to, the store refuses it.
    web.digest.record(CHAIN, new Map([[subjectKey('agent', AGENT), 11n]]), AT);
    await web.digest.flush();
    expect(filesIn(directory)).toEqual(before);
    expect(web.said('audit.anchor_store_write_refused')).toEqual([
      expect.objectContaining({ level: 'error', file: expect.stringMatching(/^e1\/digests\/deltas\//) as unknown }),
    ]);
  });

  it('never moves a store on to the shards: a web copy over a store no jobs copy has written writes nothing', async () => {
    const directory = folder();
    const web = webOver(directory);
    await web.read.run();
    expect(web.log.state()).toBe('read');
    await web.log.flush();
    expect(filesIn(directory)).toEqual([]);
    expect(web.said('audit.anchor_store_write_refused')).toEqual([]);
  });

  it('keeps the same budget as a copy that keeps them: half the anchors’, counted in theirs', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const web = webOver(directory);
    expect(web.digest.memoryHeld().mostBytes).toBe(Math.floor(web.log.memoryHeld().mostBytes / 2));
    const before = web.log.memoryHeld().bytes;
    await web.read.run();
    expect(web.digest.memoryHeld().bytes).toBeGreaterThan(0);
    expect(web.log.memoryHeld().bytes).toBeGreaterThanOrEqual(before + web.digest.memoryHeld().bytes);
  });

  it('none where no store is named: the anchors’ alert in production alone, information elsewhere (Stage G)', () => {
    const lines = (environment: string) => {
      const capture = new LogCapture();
      expect(anchorsReadOf(configWith(null, environment), servicesWith(capture))).toBeUndefined();
      return capture.lines().map(({ level, event, copy }) => ({ level, event, copy }));
    };
    expect(lines('production')).toEqual([{ level: 'error', event: 'audit.anchor_store_not_set', copy: 'web' }]);
    // Staging's throwaway copy gives its web copies no store on purpose: never the alert telling the partner to deploy.
    for (const environment of ['staging', 'development', 'test']) {
      expect(lines(environment)).toEqual([{ level: 'info', event: 'audit.web_anchors_off', copy: 'web' }]);
    }
    // The jobs copy's rule is unchanged: staging without a store is its alert.
    const jobs = new LogCapture();
    expect(anchorsKeptOf(configWith(null, 'staging'), servicesWith(jobs))).toBeUndefined();
    expect(jobs.lines().map(({ level, event }) => [level, event])).toEqual([['error', 'audit.anchor_store_not_set']]);
  });

  it('a store it can’t read says so as a web copy: a warning under its own name, never that payments wait', async () => {
    const directory = folder();
    const notAFolder = join(directory, 'a-file');
    await folderWriteOnceStore(directory).put('a-file', Buffer.from('x'));
    const web = webOver(notAFolder);
    await web.read.run();
    await web.read.run();
    const problems = web.capture
      .lines()
      .filter(({ level }) => level === 'warn' || level === 'error')
      .map(({ level, event, copy }) => ({ level, event, copy }));
    expect(problems.length).toBeGreaterThan(0);
    for (const problem of problems) {
      expect(problem).toEqual({
        level: 'warn',
        event: expect.stringMatching(/^audit\.web_anchors_/) as unknown,
        copy: 'web',
      });
    }
    expect(web.digest.latest(CHAIN, 'agent', AGENT)).toBeUndefined();
  });
});

describe('a web copy’s logger (AT13b)', () => {
  it('says each store failure under the web copy’s name, as a warning, naming what it was', () => {
    const capture = new LogCapture();
    const logger = webCopyLogger(testLogger(capture));
    for (const [event, web] of Object.entries(WEB_COPY_NAMES)) {
      logger.error(event as keyof typeof WEB_COPY_NAMES, { n: 1 });
      logger.warn(event as keyof typeof WEB_COPY_NAMES, { n: 2 });
      expect(capture.lines().slice(-2)).toEqual([
        expect.objectContaining({ level: 'warn', event: web, was: event, n: 1 }),
        expect.objectContaining({ level: 'warn', event: web, was: event, n: 2 }),
      ]);
    }
    // What pages (the anchor store's alert) is what lasts: a first read that fails is a blip, said as one.
    expect(WEB_COPY_NAMES).toEqual({
      'audit.anchor_store_read_failed': 'audit.web_anchors_read_failed',
      'audit.anchor_shard_unreadable': 'audit.web_anchors_read_failed',
      'audit.state_digest_store_failed': 'audit.web_anchors_read_failed',
      'audit.anchor_store_unreadable': 'audit.web_anchors_read_failed',
      'audit.anchor_store_read_failing': 'audit.web_anchors_read_failing',
      'audit.state_digest_store_failing': 'audit.web_anchors_read_failing',
      'audit.anchor_store_beyond_memory': 'audit.web_anchors_beyond_memory',
      // TR-1: a read of the witness log failing once; its writes and lasting failures keep their names (they page).
      'audit.witness_read_failed': 'audit.web_witness_read_failed',
    });
  });

  it('a store it never reads from the start pages once the alert limit has passed, and not before', async () => {
    const directory = folder();
    await folderWriteOnceStore(directory).put('a-file', Buffer.from('x'));
    const capture = new LogCapture();
    let at = AT.getTime();
    const services = { ...servicesWith(capture), clock: { now: () => new Date(at) } };
    const kept = anchorsReadOf(configWith(join(directory, 'a-file')), services);
    if (kept === undefined) throw new Error('a folder is named');
    const read = createWebAnchorRead({ ...kept, logger: services.logger });
    const paging = () => capture.lines().filter(({ event }) => event === 'audit.web_anchors_read_failing');
    await read.run();
    at += services.alertAfterMs - 1;
    await read.run();
    // A start that failed is a blip until the limit: nothing in the alert's query yet.
    expect(paging()).toEqual([]);
    expect(capture.lines().map(({ event }) => event)).toContain('audit.web_anchors_read_failed');
    at += 1;
    await read.run();
    expect(paging()).toEqual([
      expect.objectContaining({ level: 'warn', copy: 'web', was: 'audit.state_digest_store_failing' }),
    ]);
  });

  it('lets every other line through as it is, the alarm among them, and keeps renaming in a child', () => {
    const capture = new LogCapture();
    const logger = webCopyLogger(testLogger(capture));
    logger.error('audit.integrity_failed', { chain: 'store' });
    logger.warn('audit.anchor_store_foreign', { files: 1 });
    logger.info('audit.anchors_read', { chains: 1 });
    logger.child({ orgId: ORG }).error('audit.anchor_store_read_failing');
    expect(capture.lines().map(({ level, event, orgId }) => [level, event, orgId])).toEqual([
      ['error', 'audit.integrity_failed', undefined],
      ['warn', 'audit.anchor_store_foreign', undefined],
      ['info', 'audit.anchors_read', undefined],
      ['warn', 'audit.web_anchors_read_failing', ORG],
    ]);
    expect(capture.lines().map(({ copy }) => copy)).toEqual(['web', 'web', 'web', 'web']);
  });
});

describe('the read-only store (AT13b)', () => {
  /** A store that records what is asked of it. */
  function recording(): { store: WriteOnceStore; asked: string[] } {
    const asked: string[] = [];
    return {
      asked,
      store: {
        put: (name) => {
          asked.push(`put ${name}`);
          return Promise.resolve();
        },
        list: (start, most, after) => {
          asked.push(`list ${start} ${String(most)} ${String(after)}`);
          return Promise.resolve({ names: ['a'], foreign: 0, next: undefined });
        },
        get: (name) => {
          asked.push(`get ${name}`);
          return Promise.resolve(Buffer.from('g'));
        },
        getAtMost: (name, mostBytes) => {
          asked.push(`getAtMost ${name} ${String(mostBytes)}`);
          return Promise.resolve(Buffer.from('m'));
        },
      },
    };
  }

  it('passes every read through as asked, and refuses every write before it reaches the store', async () => {
    const capture = new LogCapture();
    const { store, asked } = recording();
    const reading = readOnlyStore(store, testLogger(capture));
    expect(await reading.list('e1/', 5, 'x')).toEqual({ names: ['a'], foreign: 0, next: undefined });
    expect(await reading.get('e1/a')).toEqual(Buffer.from('g'));
    expect(await reading.getAtMost('e1/b', 9)).toEqual(Buffer.from('m'));
    await expect(reading.put('e1/c', Buffer.from('c'))).rejects.toBeInstanceOf(ReadOnlyStore);
    expect(asked).toEqual(['list e1/ 5 x', 'get e1/a', 'getAtMost e1/b 9']);
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'error', event: 'audit.anchor_store_write_refused', file: 'e1/c' }),
    ]);
  });
});

describe('the web copy’s run that reads the store again (AT13b)', () => {
  /** A log and a digest that record what is asked of them, each read answered as `answers` says. */
  function standIns(answers: { log?: () => Promise<void>; digest?: () => Promise<void> } = {}) {
    const asked: string[] = [];
    const failed: unknown[] = [];
    const capture = new LogCapture();
    const run = createWebAnchorRead({
      log: {
        read: () => {
          asked.push('anchors');
          return answers.log?.() ?? Promise.resolve();
        },
        readFailed: (error) => {
          failed.push(error);
        },
      },
      digest: {
        read: () => {
          asked.push('digest');
          return answers.digest?.() ?? Promise.resolve();
        },
      },
      logger: testLogger(capture),
    });
    return { run, asked, failed, capture };
  }

  it('reads the anchors first, whose rebases the digest goes by, then the digest', async () => {
    const { run, asked, failed, capture } = standIns();
    await run.run();
    expect(asked).toEqual(['anchors', 'digest']);
    expect(failed).toEqual([]);
    expect(capture.lines()).toEqual([]);
  });

  it('a failed anchors read is said as the jobs say it, and the digest is still read', async () => {
    const error = new Error('the store did not answer');
    const { run, asked, failed } = standIns({ log: () => Promise.reject(error) });
    await run.run();
    expect(failed).toEqual([error]);
    expect(asked).toEqual(['anchors', 'digest']);
  });

  it('a digest read that fails is its warning, never a throw', async () => {
    const { run, capture } = standIns({ digest: () => Promise.reject(new PastDeadline('slow')) });
    await expect(run.run()).resolves.toBeUndefined();
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'warn', event: 'audit.web_anchors_read_failed', copy: 'web', what: 'read' }),
    ]);
  });

  it('a stop while it reads ends the run quietly: nothing said failed, the digest not read', async () => {
    const stopping = new AbortController();
    stopping.abort();
    const { run, asked, failed, capture } = standIns({ log: () => new Promise(() => undefined) });
    await run.run(stopping.signal);
    expect(asked).toEqual(['anchors']);
    expect(failed).toEqual([]);
    expect(capture.lines()).toEqual([]);
  });

  it('a stop during the digest’s read is said by no one', async () => {
    const { run, capture } = standIns({ digest: () => Promise.reject(new Stopped('stopped')) });
    await run.run();
    expect(capture.lines()).toEqual([]);
  });
});

describe('a web boot gives core the digest it reads (AT13b)', () => {
  /** A database nothing here may reach: a web copy's anchors never touch it, nor the lease kept there. */
  const untouched = new Proxy(
    {},
    {
      get: () => {
        throw new Error('the database was reached by a web copy’s anchors');
      },
    },
  );

  const BASE = {
    AGENTX_ENV: 'test',
    AGENTX_DB_HOST: 'db',
    AGENTX_DB_PASSWORD: 'app login for these tests',
    AGENTX_KEYS_DIR: '/mnt/secrets',
    AGENTX_ROLE: 'web',
  };

  function bootedWith(env: Record<string, string>): Booted {
    const config = loadConfig(env);
    return {
      host: {} as Booted['host'],
      config,
      keys,
      logger: createLogger({ service: 'api', config, destination: new LogCapture() }),
      database: untouched as Booted['database'],
      atCrash: () => undefined,
    };
  }

  it('reads the store named every minute, its digest given to core at once, and writes nothing', async () => {
    const directory = folder();
    await jobsRecord(directory, [['agent', AGENT, 7n]]);
    const before = filesIn(directory);
    const booted = bootedWith({ ...BASE, AGENTX_AUDIT_ANCHORS_DIR: directory });
    const jobs = webCopyJobs(booted, sharedParts(booted, undefined));
    expect(jobs.map(({ name }) => name)).toEqual(['anchors_read']);
    expect(WEB_ANCHORS_EVERY_MS).toBe(60_000);
    const digest = statesDigest();
    expect(digest).toBeDefined();
    // Given before its first read: it holds nothing yet, so every read goes on as before the digest.
    expect(digest?.latest(CHAIN, 'agent', AGENT)).toBeUndefined();

    const handle = jobs[0]?.start();
    try {
      await expect.poll(() => digest?.latest(CHAIN, 'agent', AGENT)).toBe(7n);
    } finally {
      await handle?.stop();
    }
    expect(filesIn(directory)).toEqual(before);
  });

  it('none with no store named: core is given none, and reads are as before the digest', () => {
    checkStatesWith({ latest: () => 1n });
    const booted = bootedWith(BASE);
    expect(webCopyJobs(booted, sharedParts(booted, undefined))).toEqual([]);
    expect(statesDigest()).toBeUndefined();
  });
});
