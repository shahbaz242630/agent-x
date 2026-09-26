/**
 * The ADR-004 module map: which modules each module may import, always through
 * the other module's index.ts. Every module may also use shared-kernel and the
 * audit sink. .dependency-cruiser.js turns this into rules, and a gate proof
 * checks the map itself has no cycles or unknown names.
 */
const DEPENDENCIES = {
  directory: [],
  organizations: ['directory'],
  identity: ['organizations', 'directory', 'notifications'],
  agents: ['organizations', 'directory'],
  suppliers: ['organizations'],
  providers: [],
  'funding-sources': ['organizations', 'providers', 'directory'],
  mandates: ['agents', 'funding-sources', 'suppliers'],
  policies: [],
  'limit-reservations': ['mandates'],
  approvals: ['identity'],
  notifications: [],
  'spend-requests': [
    'organizations',
    'agents',
    'suppliers',
    'funding-sources',
    'mandates',
    'policies',
    'limit-reservations',
    'approvals',
    'notifications',
  ],
  'platform-controls': [],
  'security-events': [],
  routing: ['funding-sources', 'mandates'],
  instructions: ['suppliers', 'providers'],
  transactions: ['instructions'],
  handoff: [
    'spend-requests',
    'approvals',
    'routing',
    'instructions',
    'transactions',
    'providers',
    'platform-controls',
    'organizations',
    'agents',
    'mandates',
    'funding-sources',
    'suppliers',
    'directory',
  ],
  'provider-events': ['providers', 'directory'],
  outcomes: ['transactions', 'limit-reservations', 'spend-requests', 'provider-events', 'providers'],
  reconciliation: ['transactions', 'providers', 'outcomes'],
  audit: [],
} as const satisfies Record<string, readonly string[]>;

/** The sink every module may call. */
export const AUDIT_MODULE = 'audit';

/**
 * evidence only reports: it reads the other modules' public queries, and no
 * module imports it, so it may depend on all of them without creating a cycle.
 */
export const MODULE_MAP: Readonly<Record<string, readonly string[]>> = {
  ...DEPENDENCIES,
  evidence: Object.keys(DEPENDENCIES).filter((name) => name !== AUDIT_MODULE),
};
