// SEC-OPS-08 and ADR-010 §7: the compose stack ships no logins and exposes
// one front door. Every login is a variable prepare generates, marked
// required, so nothing starts on a default; every service but the edge sits
// on the internal network, which Docker keeps off the internet and the host;
// the app's containers run read-only with no capabilities.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { MASTER_KEY, PASSWORDS } from '../../deploy/compose/prepare.ts';

const COMPOSE_FILE = 'deploy/compose/compose.yaml';

interface Service {
  image?: string;
  environment?: Record<string, string>;
  networks?: string[] | Record<string, { ipv4_address?: string } | null>;
  ports?: string[];
  privileged?: boolean;
  read_only?: boolean;
  cap_drop?: string[];
  security_opt?: string[];
  stop_grace_period?: string;
  volumes?: string[];
}

interface ComposeFile {
  services: Record<string, Service>;
  networks: Record<string, { internal?: boolean; ipam?: { config?: { subnet?: string; ip_range?: string }[] } }>;
}

const text = readFileSync(COMPOSE_FILE, 'utf8');
const file = parse(text, { merge: true }) as ComposeFile;
const services = Object.entries(file.services);

/** The names a service is on, whatever form the file uses. */
const networksOf = (service: Service): string[] =>
  Array.isArray(service.networks) ? service.networks : Object.keys(service.networks ?? {});

/** Every `${NAME…}` reference in the file, with what follows the name. */
export function variableReferences(compose: string): { name: string; modifier: string }[] {
  return [...compose.matchAll(/\$\{([A-Z0-9_]+)([^}]*)\}/g)].map(([, name, modifier]) => ({
    name: name ?? '',
    modifier: modifier ?? '',
  }));
}

/** Environment entries whose name says they hold a secret (not a switch about one, such as PASSWORDCHANGEREQUIRED). */
const SECRET_NAME = /(?:PASSWORD|MASTERKEY|SECRET|TOKEN)$/;

describe('SEC-OPS-08 the compose stack has no default logins', () => {
  it('names every login as a required variable, so a missing one stops the stack', () => {
    const references = variableReferences(text);
    expect(references.length).toBeGreaterThan(0);
    expect(references.filter((reference) => !reference.modifier.startsWith(':?'))).toEqual([]);
  });

  it('needs exactly the variables prepare generates', () => {
    const referenced = new Set(variableReferences(text).map((reference) => reference.name));
    expect([...referenced].sort()).toEqual([...PASSWORDS, MASTER_KEY].sort());
  });

  it('gives no service a literal secret: every secret-looking setting is a variable', () => {
    const literal = services.flatMap(([name, service]) =>
      Object.entries(service.environment ?? {})
        .filter(([key, value]) => SECRET_NAME.test(key) && !/^\$\{[A-Z0-9_]+:\?/.test(value))
        .map(([key]) => `${name}.${key}`),
    );
    expect(literal).toEqual([]);
  });
});

describe('ADR-010 §7 the compose stack is air-gapped behind one front door', () => {
  it('keeps every service but the edge on the internal network only', () => {
    const elsewhere = services
      .filter(([name]) => name !== 'edge')
      .filter(([, service]) => networksOf(service).join(',') !== 'internal')
      .map(([name]) => name);
    expect(elsewhere).toEqual([]);
  });

  it('marks the internal network internal, and keeps its dynamic addresses away from the edge', () => {
    const internal = file.networks.internal;
    expect(internal?.internal).toBe(true);
    const [config] = internal?.ipam?.config ?? [];
    expect(config?.subnet).toBe('10.77.0.0/24');
    expect(config?.ip_range).toBe('10.77.0.128/25');
  });

  it('puts the edge on both networks with the fixed address the API trusts', () => {
    const edge = file.services.edge;
    expect(networksOf(edge ?? {}).sort()).toEqual(['frontend', 'internal']);
    const networks = edge?.networks;
    const fixed = Array.isArray(networks) ? undefined : networks?.internal?.ipv4_address;
    expect(fixed).toBe('10.77.0.2');
    expect(file.services.api?.environment?.AGENTX_TRUSTED_PROXIES).toBe(fixed);
  });

  it('publishes ports from the edge only, and only on the loopback address', () => {
    const publishing = services.filter(([, service]) => (service.ports ?? []).length > 0).map(([name]) => name);
    expect(publishing).toEqual(['edge']);
    expect(file.services.edge?.ports).toEqual(['127.0.0.1:8080:8080', '127.0.0.1:8081:8081']);
  });

  it('gives no service privileges, and no service the Docker socket', () => {
    expect(services.filter(([, service]) => service.privileged === true).map(([name]) => name)).toEqual([]);
    const socket = services.filter(([, service]) =>
      (service.volumes ?? []).some((volume) => volume.includes('docker.sock')),
    );
    expect(socket.map(([name]) => name)).toEqual([]);
  });

  it.each(['api', 'migrate'])('runs %s read-only, with no capabilities and no privilege escalation', (name) => {
    const service = file.services[name];
    expect(service?.read_only).toBe(true);
    expect(service?.cap_drop).toEqual(['ALL']);
    expect(service?.security_opt).toEqual(['no-new-privileges:true']);
  });

  it('gives the API longer to stop than its own 25-second deadline', () => {
    const grace = file.services.api?.stop_grace_period ?? '';
    expect(grace).toMatch(/^[0-9]+s$/);
    expect(Number.parseInt(grace, 10)).toBeGreaterThanOrEqual(30);
  });

  it('runs the API and the migration job as the app and migration roles, in development, with TLS off only there', () => {
    expect(file.services.api?.environment).toMatchObject({
      AGENTX_ENV: 'development',
      AGENTX_DB_USER: 'agentx_app',
      AGENTX_DB_TLS: 'disable',
      AGENTX_PUBLIC_ORIGIN: 'http://localhost:8080',
    });
    expect(file.services.migrate?.environment).toMatchObject({ AGENTX_ENV: 'development', AGENTX_DB_TLS: 'disable' });
    expect(file.services.migrate?.environment?.AGENTX_DB_PASSWORD).toBeUndefined();
    expect(file.services.api?.environment?.AGENTX_DB_MIGRATION_PASSWORD).toBeUndefined();
  });

  it('the reference reader sees every form of a variable', () => {
    expect(variableReferences('a: ${ONE:?set it}\nb: ${TWO}\nc: ${THREE:-x}\nd: $FOUR')).toEqual([
      { name: 'ONE', modifier: ':?set it' },
      { name: 'TWO', modifier: '' },
      { name: 'THREE', modifier: ':-x' },
    ]);
  });
});
