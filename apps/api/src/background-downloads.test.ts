// Phase 3 L5c: the background downloads set up from the config: the store it
// names (the container, or the folder in development and test), and with it
// the routes' use case and the builder; with neither, both off.
import type { Config } from '@agentx/platform/config';
import { folderBlockStore } from '@agentx/platform/storage';
import { describe, expect, it } from 'vitest';

import { backgroundDownloadsFrom, downloadStoreOf } from './background-downloads.ts';

const configWith = (activityDownloads: Config['activityDownloads']) => ({ activityDownloads }) as Config;

const CONTAINER = {
  url: 'https://stagentxdlstg01.blob.core.windows.net/activity-downloads',
  clientId: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b',
  identityEndpoint: 'http://localhost:42356/msi/token',
  identityHeader: 'identity header for these tests',
};

describe('L5c the background downloads, as the config sets them up', () => {
  it('keep their files in the container, or the folder, or nowhere', () => {
    expect(typeof downloadStoreOf(configWith({ directory: null, container: CONTAINER }))?.putBlock).toBe('function');
    expect(typeof downloadStoreOf(configWith({ directory: '/tmp/downloads', container: null }))?.putBlock).toBe(
      'function',
    );
    expect(downloadStoreOf(configWith({ directory: null, container: null }))).toBeUndefined();
  });

  it('are on with a store, the routes and the builder both, and off without one', () => {
    const services = {} as Parameters<typeof backgroundDownloadsFrom>[1];

    expect(backgroundDownloadsFrom(undefined, services)).toEqual({ exports: undefined, builder: undefined });
    const on = backgroundDownloadsFrom(folderBlockStore('/tmp/downloads'), services);
    expect(typeof on.exports?.ask).toBe('function');
    expect(typeof on.builder?.run).toBe('function');
  });
});
