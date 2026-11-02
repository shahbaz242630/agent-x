import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { signAnchor } from '@agentx/platform/audit-chain';
import type { Config } from '@agentx/platform/config';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { LogCapture, testLogger } from '@agentx/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { anchorLogOf } from './anchor-store.ts';

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);
const AT = new Date('2026-11-02T09:00:00.000Z');
const services = { keys, logger: testLogger(new LogCapture()), now: () => AT, unwritableAfterMs: 900_000 };
const CONTAINER = {
  url: 'http://127.0.0.1:1/audit-anchors',
  clientId: 'c',
  identityEndpoint: 'http://127.0.0.1:1/token',
  identityHeader: 'h',
};
const configWith = (anchorStore: Config['anchorStore'], anchorEpoch = 1): Config =>
  ({ anchorStore, audit: { anchorSeconds: 300, anchorEpoch } }) as Config;

const folders: string[] = [];
afterEach(() => {
  for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
});

describe("where the chains' anchors are kept (PL-58)", () => {
  it('memory alone with no store named', () => {
    expect(anchorLogOf(configWith({ directory: null, container: null }), services)).toBeUndefined();
  });

  it('the container where one is named', () => {
    expect(anchorLogOf(configWith({ directory: null, container: CONTAINER }), services)?.state()).toBe('unread');
  });

  it('the folder where one is named, under the epoch the setting names, across a restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchors-'));
    folders.push(directory);
    const log = anchorLogOf(configWith({ directory, container: null }, 2), services);
    await log?.read();
    log?.keep(signAnchor(keys, { kind: 'platform' }, { seq: 4n, hash: Buffer.alloc(32, 4), macKeyVersion: 1 }, AT));
    await log?.flush();

    const after = anchorLogOf(configWith({ directory, container: null }, 2), services);
    await after?.read();
    expect(after?.latest({ kind: 'platform' })?.seq).toBe(4n);

    const newEpoch = anchorLogOf(configWith({ directory, container: null }, 3), services);
    await newEpoch?.read();
    expect(newEpoch?.state()).toBe('read');
    expect(newEpoch?.latest({ kind: 'platform' })).toBeUndefined();
  });
});
