// The load stack's changes to the compose stack (compose.load.yaml, D2) keep
// its walls: the database reached from this machine alone, k6 on the
// internal network alone with no rights, and the API sized as staging's, its
// rate limits within what its log can hold.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import {
  API_CPUS_VARIABLE,
  DELAY_VARIABLE,
  LOAD_DB_PORT,
  loadConnection,
  loadOrgName,
  optionsOf,
  STAGING_API_CPUS,
} from './plan.ts';

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
  image?: string;
  command?: string[];
  cap_add?: string[];
  network_mode?: string;
}

const { services, networks } = parse(readFileSync('tooling/load/compose.load.yaml', 'utf8')) as {
  services: Record<string, Service>;
  networks: Record<string, { internal?: boolean } | null>;
};

describe('the load stack (compose.load.yaml)', () => {
  it('changes only the database and the API, and adds k6 and the delay', () => {
    expect(Object.keys(services).sort()).toEqual(['api', 'db', 'delay', 'k6']);
  });

  it("counts the database's statements, with Postgres's own counter (4D2d P0)", () => {
    expect(services.db?.command).toEqual([
      'postgres',
      '-c',
      'shared_preload_libraries=pg_stat_statements',
      '-c',
      'pg_stat_statements.max=5000',
    ]);
  });

  it("adds the delay inside the database's own network, by hand, pinned, read-only, with NET_ADMIN alone", () => {
    expect(services.delay).toMatchObject({
      profiles: ['delay'],
      network_mode: 'service:db',
      read_only: true,
      cap_drop: ['ALL'],
      cap_add: ['NET_ADMIN'],
      security_opt: ['no-new-privileges:true'],
      environment: { [DELAY_VARIABLE]: `\${${DELAY_VARIABLE}:-0}` },
    });
    expect(services.delay?.image).toMatch(/^nicolaka\/netshoot:v[\d.]+@sha256:[0-9a-f]{64}$/);
    expect(services.delay?.networks).toBeUndefined();
    // Every interface but loopback, and a failure stops it: never a run said to be delayed that isn't.
    expect(services.delay?.command?.at(-1)).toContain('grep -vx lo');
    expect(services.delay?.command?.at(-1)).toContain('netem delay "$${AGENTX_LOAD_DELAY_MS:?}ms" || exit 1');
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
    expect(api.environment?.AGENTX_DB_POOL_MAX).toBe('20');
    const cap = Number(api.environment?.AGENTX_LOG_EVENT_CAP_PER_MINUTE);
    const limits = Object.entries(api.environment ?? {}).filter(([name]) => name.startsWith('AGENTX_RATE_LIMIT_'));
    expect(limits).toHaveLength(3);
    for (const [name, value] of limits) expect(Number(value) * 2, name).toBeLessThanOrEqual(cap);
  });

  describe('the runner’s arguments', () => {
    it('runs the API at staging’s half a CPU unless `--cpus` gives a size from 0.01 to 4, in either order with `--keep`', () => {
      expect(optionsOf([])).toEqual({ keep: false, apiCpus: 0.5, delayMs: 0 });
      expect(optionsOf(['--keep'])).toEqual({ keep: true, apiCpus: 0.5, delayMs: 0 });
      expect(optionsOf(['--cpus', '2'])).toEqual({ keep: false, apiCpus: 2, delayMs: 0 });
      expect(optionsOf(['--keep', '--cpus', '1.5'])).toEqual({ keep: true, apiCpus: 1.5, delayMs: 0 });
      expect(optionsOf(['--cpus', '0.01', '--keep'])).toEqual({ keep: true, apiCpus: 0.01, delayMs: 0 });
      expect(optionsOf(['--cpus', '4'])).toEqual({ keep: false, apiCpus: 4, delayMs: 0 });
    });

    it('adds no delay unless `--delay-ms` gives a whole number of ms from 0 to 20', () => {
      expect(optionsOf(['--delay-ms', '2'])).toEqual({ keep: false, apiCpus: 0.5, delayMs: 2 });
      expect(optionsOf(['--cpus', '2', '--delay-ms', '0', '--keep'])).toEqual({ keep: true, apiCpus: 2, delayMs: 0 });
      expect(optionsOf(['--delay-ms', '20'])).toEqual({ keep: false, apiCpus: 0.5, delayMs: 20 });
    });

    it.each([
      ['--cpus'],
      ['--cpus', '0'],
      ['--cpus', '0.009'],
      ['--cpus', '4.5'],
      ['--cpus', 'two'],
      ['--cpus', '-1'],
      ['--cpus', '--keep'],
      ['--cpus=2'],
      ['--cpu', '2'],
      ['2'],
      ['--delay-ms'],
      ['--delay-ms', '21'],
      ['--delay-ms', '-1'],
      ['--delay-ms', '1.5'],
      ['--delay-ms', 'two'],
      ['--delay-ms', '--keep'],
      ['--delay-ms=2'],
    ])('refuses %s, never a run at another size or delay than asked', (...bad) => {
      expect(optionsOf(bad)).toBeUndefined();
    });
  });
});

describe("the run's database login (plan.ts)", () => {
  it('reaches the load stack on its loopback port with no TLS on the laptop', () => {
    expect(loadConnection({ AGENTX_LOAD_DB_PASSWORD: 'p' })).toMatchObject({
      host: '127.0.0.1',
      port: LOAD_DB_PORT,
      user: 'agentx_app',
      password: 'p',
      tls: 'disable',
    });
  });

  it("reaches staging's private server on 5432 with its certificate checked when a host is named (D2c)", () => {
    expect(
      loadConnection({
        AGENTX_LOAD_DB_PASSWORD: 'p',
        AGENTX_LOAD_DB_HOST: 'psql-agentx-stg.postgres.database.azure.com',
      }),
    ).toMatchObject({
      host: 'psql-agentx-stg.postgres.database.azure.com',
      port: 5432,
      user: 'agentx_app',
      tls: 'verify-full',
    });
  });

  it('takes a host set but empty as none: the laptop, never an empty host', () => {
    expect(loadConnection({ AGENTX_LOAD_DB_PASSWORD: 'p', AGENTX_LOAD_DB_HOST: '' })).toMatchObject({
      host: '127.0.0.1',
      tls: 'disable',
    });
  });

  it('refuses to start with no password', () => {
    expect(() => loadConnection({})).toThrow('corepack pnpm load');
  });

  it("names a run's organisations so they stand out on staging", () => {
    expect(loadOrgName('local 2026-10-24T10:00:00.000Z')).toBe('Load test D2c local 2026-10-24T10:00:00.000Z');
  });
});
