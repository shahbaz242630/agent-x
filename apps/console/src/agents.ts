// An organisation's agents and their keys (6D1): what one agent's page reads
// (GET /v1/agents/:id, never a key's secret), who the members are (GET
// /v1/members: an agent's owner is a membership), the rules a new agent's name
// and scopes keep, and who may press what. Registering, rotating a key and
// handing an agent over each answer with a new key, shown once (key-once.tsx);
// revoking stops a key at once. The roles only decide which buttons show; the
// API checks again whatever is pressed (agents.ts, agent-key-changes.ts).
import { useQuery } from '@tanstack/react-query';

import { api, isIntegrityFailed, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import type { Role } from './session.tsx';
import { t } from './text.ts';
import { isVisibleName, unitsMost } from './visible-name.ts';

/** What an agent's keys may be given, as the API names them (SCOPES). */
export const SCOPES = ['requests:read', 'requests:write', 'sources:read', 'suppliers:read'] as const;
export type Scope = (typeof SCOPES)[number];

export interface AgentKey {
  readonly id: string;
  readonly status: 'ACTIVE' | 'REVOKED';
  readonly scopes: readonly Scope[];
  readonly expiresAt: string;
}

export interface Agent {
  readonly id: string;
  readonly name: string;
  /** The membership of the member responsible for it. */
  readonly owner: string;
  readonly status: 'ACTIVE' | 'SUSPENDED';
  readonly scopes: readonly Scope[];
  readonly createdAt: string;
}

interface AgentDetails {
  readonly agent: Agent;
  readonly keys: readonly AgentKey[];
}

export interface Member {
  readonly id: string;
  readonly userId: string;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'DEACTIVATED';
  /** When they joined the organisation (6D4b). */
  readonly joinedAt: string;
}

/** Who may register an agent (REGISTERING_ROLES). */
export const REGISTERING: readonly Role[] = ['admin', 'developer'];
/** Who may rotate or revoke an agent's keys (KEY_CHANGING_ROLES): the same roles, rotating held to the owner for a developer. */
export const KEY_CHANGING: readonly Role[] = ['admin', 'developer'];
/** Who may hand an agent to another owner (HANDING_OVER_ROLES): an admin. */
export const HANDING_OVER: readonly Role[] = ['admin'];
/** Who may own an agent (the API's OWNING_ROLES): an active admin or developer. */
export const OWNING: readonly Role[] = ['admin', 'developer'];

/** An agent's address in the API. */
export const agentAt = (id: string): string => `/v1/agents/${encodeURIComponent(id)}`;

/** One agent with its keys; asked for only by a UUID, as any other address names no agent (shown as not found). */
export function useAgent(id: string, organization: string) {
  return useQuery({
    queryKey: ['agents', organization, 'one', id],
    enabled: isUuid(id),
    queryFn: () => api.get<AgentDetails>(agentAt(id), { organization }),
  });
}

/** The organisation's members, deactivated ones too: an owner is named by membership, and a new one chosen among them. */
export function useMembers(organization: string) {
  return useQuery({
    queryKey: ['members', organization],
    queryFn: () => api.get<{ readonly members: readonly Member[] }>('/v1/members', { organization }),
    select: ({ members }) => members,
  });
}

/** The most characters an agent's name may have (the API's MAX_NAME, counted in code points, as the table does). */
const NAME_MOST = 100;
/** The most UTF-16 units such a name can take, which a field's maxLength counts (unitsMost). */
export const NAME_UNITS_MOST = unitsMost(NAME_MOST);

/** Whether a name keeps the API's rules for an agent's (isAgentName), checked before anything is sent; the API checks again. */
export const isAgentName = (name: string): boolean => isVisibleName(name, NAME_MOST);

/** Whether a key still works: not revoked, and not past its expiry. */
export const isLive = (key: AgentKey, now = Date.now()): boolean =>
  key.status === 'ACTIVE' && new Date(key.expiresAt).getTime() > now;

/** The refusals an agent's change can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'AGENT_ADDS_SPENT',
  'AGENT_KEYS_FULL',
  'AGENT_KEYS_SPENT',
  'AGENT_KEYS_TOO_MANY',
  'AGENT_KEY_NOT_LIVE',
  'AGENT_KEY_REVOKED',
  'AGENT_OWNER_NOT_ELIGIBLE',
  'AGENT_OWNER_UNCHANGED',
  'STEP_UP_NOT_ASKED',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/** What a refusal or failure of an agent's change says: a record that failed the integrity check as itself (a 503). */
export function agentRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('agents.integrity');
  return refusalText(error, REFUSALS, 'agents.refused');
}
