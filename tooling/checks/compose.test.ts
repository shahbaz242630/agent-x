// SEC-OPS-08 and ADR-010 §7: the compose stack ships no logins and exposes
// one front door. Every login is a variable prepare generates, marked
// required, so nothing starts on a default; every service but the edge sits
// on the internal network, which Docker keeps off the internet and the host;
// the app's containers run read-only with no capabilities.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { LOGIN_CLIENT_KEYS, VARIABLES } from '../../deploy/compose/prepare.ts';

const COMPOSE_FILE = 'deploy/compose/compose.yaml';

interface Service {
  image?: string;
  environment?: Record<string, string>;
  networks?: string[] | Record<string, { ipv4_address?: string } | null>;
  network_mode?: string;
  ports?: string[];
  privileged?: boolean;
  read_only?: boolean;
  cap_drop?: string[];
  cap_add?: string[];
  security_opt?: string[];
  stop_grace_period?: string;
  volumes?: string[];
  command?: string[];
  depends_on?: Record<string, { condition: string }>;
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
const SECRET_NAME = /(?:PASSWORD|MASTERKEY|SECRET|TOKEN|PRIVATE_KEY)$/;

describe('SEC-OPS-08 the compose stack has no default logins', () => {
  it('names every login as a required variable, so a missing one stops the stack', () => {
    const references = variableReferences(text);
    expect(references.length).toBeGreaterThan(0);
    expect(references.filter((reference) => !reference.modifier.startsWith(':?'))).toEqual([]);
  });

  it('needs exactly the variables prepare generates', () => {
    const referenced = new Set(variableReferences(text).map((reference) => reference.name));
    expect([...referenced].sort()).toEqual([...VARIABLES].sort());
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
  it('keeps every service but the edge on the internal network only, or off the network', () => {
    const elsewhere = services
      .filter(([name]) => name !== 'edge')
      .filter(([, service]) => service.network_mode !== 'none' || service.networks !== undefined)
      .filter(([, service]) => networksOf(service).join(',') !== 'internal')
      .map(([name]) => name);
    expect(elsewhere).toEqual([]);
    // The step that only changes a folder's owner needs no network at all.
    expect(file.services['zitadel-volume']?.network_mode).toBe('none');
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

  it("mounts the instance owner's token in Zitadel only, never in the browser-facing login container", () => {
    const mounts = (name: string): string[] =>
      (file.services[name]?.volumes ?? []).map((volume) => volume.split(':')[0] ?? '');
    expect(mounts('zitadel')).toEqual(['zitadel-automation']);
    expect(mounts('login')).toEqual([]);
    expect(mounts('zitadel-volume')).toEqual(['zitadel-automation']);
    const elsewhere = services
      .filter(([name]) => !['zitadel', 'zitadel-volume'].includes(name))
      .filter(([name]) => mounts(name).includes('zitadel-automation'))
      .map(([name]) => name);
    expect(elsewhere).toEqual([]);
  });

  it('gives no service privileges, and no service the Docker socket', () => {
    expect(services.filter(([, service]) => service.privileged === true).map(([name]) => name)).toEqual([]);
    const socket = services.filter(([, service]) =>
      (service.volumes ?? []).some((volume) => volume.includes('docker.sock')),
    );
    expect(socket.map(([name]) => name)).toEqual([]);
  });

  it.each(['api', 'migrate', 'db-setup'])('runs %s read-only', (name) => {
    expect(file.services[name]?.read_only).toBe(true);
  });

  it('drops every capability from every service, adding back only what three third-party images need', () => {
    const allowedAdditions: Record<string, string[]> = {
      // Postgres starts as root to own its data directory, then runs as its own user.
      db: ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID'],
      // nginx starts as root, hands its cache to its worker user and drops to it.
      edge: ['CHOWN', 'SETGID', 'SETUID'],
      // The step that gives Zitadel its token folders.
      'zitadel-volume': ['CHOWN'],
    };
    for (const [name, service] of services) {
      expect(service.cap_drop, name).toEqual(['ALL']);
      expect(service.cap_add ?? [], name).toEqual(allowedAdditions[name] ?? []);
      expect(service.security_opt, name).toEqual(['no-new-privileges:true']);
    }
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

  it("sets the server up with the set-up job, as the superuser, before the migrations and Zitadel's schemas", () => {
    expect(file.services['db-setup']?.command).toEqual(['node', 'apps/db-setup/src/main.ts']);
    expect(file.services['db-setup']?.environment).toMatchObject({
      AGENTX_ENV: 'development',
      AGENTX_DB_TLS: 'disable',
      AGENTX_DB_ADMIN_USER: 'postgres',
    });
    for (const name of ['migrate', 'zitadel-init']) {
      expect(file.services[name]?.depends_on, name).toEqual({
        'db-setup': { condition: 'service_completed_successfully' },
      });
    }
  });

  it("keeps no login in the database container but its superuser's, and mounts no set-up scripts there", () => {
    expect(Object.keys(file.services.db?.environment ?? {}).sort()).toEqual([
      'POSTGRES_INITDB_ARGS',
      'POSTGRES_PASSWORD',
    ]);
    expect(file.services.db?.volumes).toEqual(['db-data:/var/lib/postgresql']);
  });

  it('the reference reader sees every form of a variable', () => {
    expect(variableReferences('a: ${ONE:?set it}\nb: ${TWO}\nc: ${THREE:-x}\nd: $FOUR')).toEqual([
      { name: 'ONE', modifier: ':?set it' },
      { name: 'TWO', modifier: '' },
      { name: 'THREE', modifier: ':-x' },
    ]);
  });
});

describe('ADR-003 and ADR-013: the login service as Azure runs it', () => {
  it('lets the login container sign its calls with its own private key, which only it holds', () => {
    const holders = services
      .filter(([, service]) => JSON.stringify(service.environment ?? {}).includes(LOGIN_CLIENT_KEYS.private))
      .map(([name]) => name);
    expect(holders).toEqual(['login']);
    expect(file.services.login?.environment).toMatchObject({
      SYSTEM_USER_ID: 'login-client',
      AUDIENCE: 'http://localhost:8081',
    });
    expect(Object.keys(file.services.login?.environment ?? {}).filter((name) => name.includes('TOKEN'))).toEqual([]);
  });

  it('gives Zitadel only the public half, for the system user the login pages need and nothing more', () => {
    const users = JSON.parse(file.services.zitadel?.environment?.ZITADEL_SYSTEMAPIUSERS ?? '{}') as unknown;
    expect(users).toEqual({
      'login-client': {
        KeyData: '${AGENTX_LOCAL_LOGIN_CLIENT_PUBLIC_KEY:?}',
        Memberships: [{ MemberType: 'System', Roles: ['IAM_LOGIN_CLIENT'] }],
      },
    });
    expect(LOGIN_CLIENT_KEYS.public).toBe('AGENTX_LOCAL_LOGIN_CLIENT_PUBLIC_KEY');
    const creates = Object.keys(file.services.zitadel?.environment ?? {}).filter((name) =>
      name.includes('LOGINCLIENT'),
    );
    expect(creates).toEqual([]);
  });

  it("switches off Zitadel's daily report to zitadel.com and its metrics endpoint (nothing leaves the UAE)", () => {
    expect(file.services.zitadel?.environment).toMatchObject({
      ZITADEL_SERVICEPING_ENABLED: 'false',
      ZITADEL_METRICS_TYPE: 'none',
    });
  });

  it("switches off the login pages' OpenTelemetry SDK, which starts by default", () => {
    expect(file.services.login?.environment?.OTEL_SDK_DISABLED).toBe('true');
  });
});
