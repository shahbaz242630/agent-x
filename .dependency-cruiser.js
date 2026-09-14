// Module boundaries (ADR-004, ADR-010, ADR-013). Run by `pnpm boundaries` in the CI
// verify job. Every rule has a broken fixture in tooling/gate-proofs.
//
// Paths are matched from the repository root. Rules match `packages/...` after
// the start or a `/`, so the gate-proof fixtures (which mirror this layout
// under tooling/gate-proofs/fixtures/boundaries/) are judged by the same rules.
// Groups are non-capturing except a module's name, which the rules reuse as $1.
import {
  CLOUD_SDKS,
  HTTP_CLIENTS,
  NETWORK_CORE_MODULES,
  OTHER_LOGGERS,
  TELEMETRY_SDKS,
} from './tooling/banned-modules.ts';
import { AUDIT_MODULE, MODULE_MAP } from './tooling/module-map.ts';

const ROOT = '(?:^|/)';
const CORE = `${ROOT}packages/core/src/`;
const MODULES = `${CORE}modules/`;
/** Test files may also import the test framework, so the purity rules skip them. */
const TEST_FILE = '\\.test\\.tsx?$';
/**
 * Matches an npm package by name, whether installed (pnpm's resolved path
 * ends in `…/node_modules/<name>/…`) or unresolvable (the bare name).
 */
const npm = (namePattern) => `(?:^|/node_modules/)(?:${namePattern})(?:/|$)`;

/** A module folder whose name is not in the map. */
const UNKNOWN_MODULE = `${MODULES}(?!(?:${Object.keys(MODULE_MAP).join('|')})/)[^/]+/`;

/** Vendor libraries confined to one adapter folder (ADR-004 §8). */
const CONFINED = [
  {
    name: 'postgres-driver-only-in-platform-db',
    packages: 'pg|pg-pool|pg-cursor|postgres',
    allowedIn: `${ROOT}packages/platform/src/db/`,
  },
  {
    name: 'query-builder-only-in-infrastructure',
    packages: 'kysely',
    allowedIn: `(?:${ROOT}packages/platform/src/db/|${MODULES}[^/]+/infrastructure/)`,
  },
  {
    // ADR-013: the logger, which redacts every line, is the one way to write
    // logs. Only pino itself: its add-ons are banned everywhere (OTHER_LOGGERS).
    name: 'logger-only-in-platform-observability',
    packages: 'pino',
    allowedIn: `${ROOT}packages/platform/src/observability/`,
  },
];

const moduleMapRules = Object.entries(MODULE_MAP).map(([name, allowed]) => ({
  name: `module-map/${name}`,
  comment: `ADR-004: ${name} may import only ${allowed.length > 0 ? allowed.join(', ') : 'shared-kernel'} (plus audit).`,
  severity: 'error',
  from: { path: `${MODULES}${name}/` },
  to: {
    path: MODULES,
    pathNot: `${MODULES}(?:${[name, ...allowed, AUDIT_MODULE].join('|')})/`,
  },
}));

/** @type {import('dependency-cruiser').IConfiguration} */
export default {
  forbidden: [
    {
      name: 'no-circular',
      comment: 'ADR-004: no cycles between files.',
      severity: 'error',
      from: {},
      to: { circular: true },
    },
    {
      name: 'not-to-unresolvable',
      comment: 'Every import must resolve to a real file or package.',
      severity: 'error',
      from: {},
      to: { couldNotResolve: true },
    },
    {
      name: 'no-deep-module-imports',
      comment: "ADR-004: another module's code is reached only through its index.ts.",
      severity: 'error',
      from: { path: `${MODULES}([^/]+)/` },
      to: {
        path: `${MODULES}[^/]+/.+`,
        pathNot: [`${MODULES}$1/`, `${MODULES}[^/]+/index\\.ts$`],
      },
    },
    {
      name: 'no-deep-module-imports-from-outside',
      comment: 'ADR-004: code outside the modules reaches a module only through its index.ts.',
      severity: 'error',
      from: { pathNot: MODULES },
      to: {
        path: `${MODULES}[^/]+/.+`,
        pathNot: `${MODULES}[^/]+/index\\.ts$`,
      },
    },
    ...moduleMapRules,
    {
      name: 'module-not-in-map/imports',
      comment: 'ADR-004: a new module is added to tooling/module-map.ts before it imports anything.',
      severity: 'error',
      from: { path: UNKNOWN_MODULE },
      to: {},
    },
    {
      name: 'module-not-in-map/imported',
      comment: 'ADR-004: a new module is added to tooling/module-map.ts before anything imports it.',
      severity: 'error',
      from: {},
      to: { path: UNKNOWN_MODULE },
    },
    {
      name: 'domain-is-pure',
      comment: 'ADR-004: domain code imports only its own domain folder and shared-kernel.',
      severity: 'error',
      from: { path: `${MODULES}([^/]+)/domain/`, pathNot: TEST_FILE },
      to: { pathNot: [`${MODULES}$1/domain/`, `${CORE}shared-kernel/`] },
    },
    {
      name: 'application-not-to-infrastructure',
      comment: 'ADR-004: use cases depend on ports, never on SQL or adapters.',
      severity: 'error',
      from: { path: `${MODULES}[^/]+/application/` },
      to: { path: `${MODULES}[^/]+/infrastructure/` },
    },
    {
      name: 'business-code-not-to-platform',
      comment: 'ADR-004: only infrastructure code talks to the database and platform services.',
      severity: 'error',
      from: { path: `(?:${CORE}shared-kernel/|${MODULES}[^/]+/(?:domain|application)/)` },
      to: { path: `(?:${ROOT}packages/platform/|${npm('@agentx/platform')})` },
    },
    {
      name: 'shared-kernel-is-a-leaf',
      comment: 'ADR-004: shared-kernel imports only itself and the uuid library.',
      severity: 'error',
      from: { path: `${CORE}shared-kernel/`, pathNot: TEST_FILE },
      to: { pathNot: [`${CORE}shared-kernel/`, npm('uuid')] },
    },
    {
      name: 'platform-not-to-modules',
      comment: 'ADR-004: platform code serves the modules and never imports them.',
      severity: 'error',
      from: { path: `${ROOT}packages/platform/` },
      to: { path: MODULES },
    },
    {
      name: 'no-cloud-sdk',
      comment: 'ADR-010: product code runs on any cloud or a bank server, so it imports no cloud SDK.',
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/` },
      to: { path: npm(CLOUD_SDKS.join('|')) },
    },
    {
      name: 'no-telemetry-sdk',
      comment: 'SEC-DATA-03 (ADR-013): no telemetry SDK anywhere in product code; logs leave only as stdout.',
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/` },
      to: { path: npm(TELEMETRY_SDKS.join('|')) },
    },
    {
      name: 'no-other-logger',
      comment: 'ADR-013: no logging library but pino, and no pino add-on, anywhere in product code.',
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/` },
      to: { path: npm(OTHER_LOGGERS.join('|')) },
    },
    // Tests outside the outbound folder are covered too. Importing only a
    // module's types is fine: types do no I/O. The console is not exempt: it
    // calls its own origin with the browser's fetch (allowed by lint) and needs
    // no HTTP library.
    {
      name: 'network-only-through-platform-outbound',
      comment: 'SEC-WEB-05: outbound HTTP goes through @agentx/platform/outbound, which enforces the allowlist.',
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/`, pathNot: `${ROOT}packages/platform/src/outbound/` },
      to: {
        path: [`^(?:${NETWORK_CORE_MODULES.join('|')})$`, npm(HTTP_CLIENTS.join('|'))],
        dependencyTypesNot: ['type-only'],
      },
    },
    ...CONFINED.map(({ name, packages, allowedIn }) => ({
      name,
      comment: 'ADR-004 §8: vendor libraries live behind one adapter.',
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/`, pathNot: allowedIn },
      to: { path: npm(packages) },
    })),
    {
      name: 'testing-only-in-tests',
      comment: 'Rule Book §6: test helpers never ship in product code.',
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/`, pathNot: [TEST_FILE, `${ROOT}packages/testing/`] },
      to: { path: `(?:${ROOT}packages/testing/|${npm('@agentx/testing')})` },
    },
    {
      name: 'product-code-uses-declared-dependencies',
      comment:
        "Product code imports only packages in its own package.json dependencies: not a devDependency, and not a tool that only resolves from the repository root's devDependencies.",
      severity: 'error',
      from: { path: `${ROOT}(?:packages|apps)/`, pathNot: TEST_FILE },
      to: { dependencyTypes: ['npm-dev', 'npm-no-pkg', 'npm-unknown'] },
    },
  ],
  options: {
    // Installed packages stay in the graph (the vendor rules need them) but are
    // not walked. Only our own build output is left out: a package's resolved
    // path such as node_modules/…/uuid/dist/index.js must stay in.
    doNotFollow: { path: 'node_modules' },
    exclude: { path: '^(?:packages|apps)/[^/]+/(?:dist|coverage)/' },
    tsConfig: { fileName: 'tsconfig.json' },
    tsPreCompilationDeps: true,
    enhancedResolveOptions: {
      exportsFields: ['exports'],
      conditionNames: ['import', 'require', 'node', 'default', 'types'],
      mainFields: ['module', 'main', 'types', 'typings'],
    },
  },
};
