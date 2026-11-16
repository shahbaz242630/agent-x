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
/**
 * The most UTF-16 units such a name can take, which a field's maxLength counts: two for a character beyond the
 * basic plane (an emoji), so a valid name of 100 such characters can still be typed; the 100 is checked in code.
 */
export const NAME_UNITS_MOST = NAME_MOST * 2;
// The API's own rules for a visible name, as packages/core/src/shared-kernel/visible-name.ts has them, word for word:
// what may not show anywhere; a joiner allowed only where a script needs it to shape a word; something readable; no
// mark first nor five piled up.
const INVISIBLE = /[\p{C}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Script=Braille}]/u;
const JOINER_IN_A_WORD =
  /(?<=\p{M})\p{Join_Control}(?=[\p{L}\p{M}])|(?<=[\p{L}\p{M}])\p{Join_Control}(?=\p{M})|(?<=\p{Script=Arabic})\p{Join_Control}(?=\p{Script=Arabic})/gu;
const JOINERS = /\p{Join_Control}/gu;
const READABLE = /[\p{L}\p{N}]/u;
const STACKED = /(?:^\p{M})|\p{M}{5}/u;

/**
 * Whether a name keeps the API's rules for an agent's (isAgentName), checked
 * before anything is sent: 1 to 100 characters, a letter or digit, no space at
 * either end, nothing invisible, no pile of marks. The API checks again.
 */
export function isAgentName(name: string): boolean {
  const composed = name.normalize('NFC');
  const length = Array.from(composed).length;
  return (
    length > 0 &&
    length <= NAME_MOST &&
    composed.trim() === composed &&
    READABLE.test(composed) &&
    !INVISIBLE.test(composed.replace(JOINER_IN_A_WORD, '')) &&
    !STACKED.test(composed.replace(JOINERS, ''))
  );
}

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
