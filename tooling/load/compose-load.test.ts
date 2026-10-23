// The load stack's changes to the compose stack (compose.load.yaml, D2) keep
// its walls: the database reached from this machine alone, k6 on the
// internal network alone with no rights, and the API sized as staging's, its
// rate limits within what its log can hold.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { API_CPUS_VARIABLE, apiCpusOf, LOAD_DB_PORT, STAGING_API_CPUS } from './plan.ts';

interface Service {
  ports?: string[];
  networks?: string[];
  environment?: Record<string, string>;
  cpus?: string;
  mem_limit?: string;
  profiles?: string[];
  read_only?: boolean;
  cap_drop?: string[];
  security_opt?: string[];
  volumes?: string[];
  restart?: string;
}

const { services, networks } = parse(readFileSync('tooling/load/compose.load.yaml', 'utf8')) as {
  services: Record<string, Service>;
  networks: Record<string, { internal?: boolean } | null>;
};

describe('the load stack (compose.load.yaml)', () => {
  it('changes only the database and the API, and adds k6', () => {
    expect(Object.keys(services).sort()).toEqual(['api', 'db', 'k6']);
  });

  it('never comes back by itself once Docker restarts', () => {
    for (const [name, service] of Object.entries(services)) expect(service.restart, name).toBe('no');
  });

  it('publishes the database on loopback alone, on a network of its own, and nothing else', () => {
    expect(services.db?.ports).toEqual([`127.0.0.1:${String(LOAD_DB_PORT)}:5432`]);
    expect(services.db?.networks).toEqual(['internal', 'loopback']);
    expect(Object.keys(networks)).toEqual(['loopback']);
    for (const [name, service] of Object.entries(services)) {
      if (name !== 'db') expect(service.ports, name).toBeUndefined();
    }
  });

  it('runs k6 on the internal network only, read-only with no rights, by hand, its script read-only', () => {
    expect(services.k6).toMatchObject({
      profiles: ['load'],
      networks: ['internal'],
      read_only: true,
      cap_drop: ['ALL'],
      security_opt: ['no-new-privileges:true'],
    });
    expect(services.k6?.volumes).toEqual([
      '../../tooling/load/money-paths.k6.js:/load/money-paths.k6.js:ro',
      '../../tooling/load/.out:/out',
    ]);
  });

  it("sizes the API as staging's unless the runner says otherwise, with rate limits at most half its log cap (the API refuses more)", () => {
    const api = services.api ?? {};
    expect(api.cpus).toBe(`\${${API_CPUS_VARIABLE}:-${String(STAGING_API_CPUS)}}`);
    expect(api.mem_limit).toBe('1g');
    expect(api.environment?.AGENTX_DB_POOL_MAX).toBe('10');
    const cap = Number(api.environment?.AGENTX_LOG_EVENT_CAP_PER_MINUTE);
    const limits = Object.entries(api.environment ?? {}).filter(([name]) => name.startsWith('AGENTX_RATE_LIMIT_'));
    expect(limits).toHaveLength(3);
    for (const [name, value] of limits) expect(Number(value) * 2, name).toBeLessThanOrEqual(cap);
  });

  it('runs the API at staging’s half a CPU unless `--cpus` gives a size above 0, at most 4', () => {
    expect(apiCpusOf(['--keep'])).toBe(0.5);
    expect(apiCpusOf(['--cpus', '2'])).toBe(2);
    expect(apiCpusOf(['--cpus', '4'])).toBe(4);
    for (const bad of [['--cpus'], ['--cpus', '0'], ['--cpus', '4.5'], ['--cpus', 'two'], ['--cpus', '-1']]) {
      expect(apiCpusOf(bad), bad.join(' ')).toBeUndefined();
    }
  });
});
