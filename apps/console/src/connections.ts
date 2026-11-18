// An agent's connections (6E3b, ADR-016): the MCP apps a person allowed to act
// as the agent, each by a connection key the API made at their consent
// (GET /v1/agents/:id/connections; such keys are left out of the Keys list),
// and what the `/connect` page reads and sends for an app asking to be
// connected (GET /v1/oauth/requests/:id, its consent, confirm and deny). The
// app's name is what it says it is, never proof: the host it sends the person
// back to is what it can't hide. The roles only decide what shows; the API
// checks again whatever is pressed.
import { useQuery } from '@tanstack/react-query';

import { type Agent, agentAt, type Scope, SCOPES } from './agents.ts';
import { api, isIntegrityFailed, isUuid } from './api.ts';
import { refusalText } from './refusals.ts';
import { pageQuery } from './requests.ts';
import { t } from './text.ts';

/** One connection, as the agent's page lists it. */
export interface Connection {
  readonly keyId: string;
  readonly clientId: string;
  /** What the app says it is, when it registered: never proof of who it is. */
  readonly clientName: string;
  /** Where the app sends the person back; none for a device's connection (6E3c). */
  readonly redirectHost: string | null;
  readonly via: 'code' | 'device';
  readonly scopes: readonly Scope[];
  /** The membership of the member who allowed it. */
  readonly madeBy: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly lastConnectedAt: string | null;
  readonly status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
}

/** An agent's connections in the API. */
export const connectionsAt = (agentId: string): string => `${agentAt(agentId)}/connections`;

/** An agent's connections; asked for only by a UUID, as the agent's own page is. */
export function useConnections(agentId: string, organization: string) {
  return useQuery({
    queryKey: ['agents', organization, 'connections', agentId],
    enabled: isUuid(agentId),
    queryFn: () => api.get<{ readonly connections: readonly Connection[] }>(connectionsAt(agentId), { organization }),
    select: ({ connections }) => connections,
  });
}

/** Where the person types a device's code (6E3c, RFC 8628): the console's `/device` page. */
export const DEVICE = '/device';

/** Where `/connect` sends the browser once a device's request is answered: the device learns it by polling. */
export const deviceAnswered = (answer: 'allowed' | 'denied'): string =>
  `${DEVICE}?${new URLSearchParams({ answered: answer }).toString()}`;

/** An app asking to be connected, as the browser that opened its request (or claimed a device's) is shown it. */
export interface ConnectionRequest {
  readonly id: string;
  /** A browser's sign-in, or a device's (6E3c), which sends no one back. */
  readonly via: 'code' | 'device';
  readonly client: {
    readonly id: string;
    readonly name: string;
    /** The host whose metadata document named the app (6E3c, CIMD); null for an app that registered itself. */
    readonly verifiedBy: string | null;
  };
  /** None for a device. */
  readonly redirectUri: string | null;
  /** Shown in bold: what a name chosen to mislead can't hide. None for a device. */
  readonly redirectHost: string | null;
  /** Sent back to an app on the person's own computer. */
  readonly loopback: boolean;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly endsAt: string;
}

/** A request's address in the API. */
export const requestAt = (id: string): string => `/v1/oauth/requests/${encodeURIComponent(id)}`;

/** The request this browser opened; any other, or one decided or ended, is the API's 404. */
export function useConnectionRequest(id: string) {
  return useQuery({
    queryKey: ['oauth-request', id],
    enabled: isUuid(id),
    queryFn: () => api.get<ConnectionRequest>(requestAt(id)),
    // Opened once: a decision ends it, and reading it again then would only say it ended.
    refetchOnWindowFocus: false,
  });
}

interface AgentPage {
  readonly agents: readonly Agent[];
  readonly next: string | null;
}

/** The most pages of agents read for the picker: 50 a page, far beyond any organisation's agents. */
const MOST_PAGES = 20;

/** The agents from the page after `after` on, each page read in turn. */
async function agentsFrom(organization: string, after: string | undefined, pages: number): Promise<readonly Agent[]> {
  const page = await api.get<AgentPage>(`/v1/agents?${pageQuery(after)}`, { organization });
  if (page.next === null || pages <= 1) return page.agents;
  return [...page.agents, ...(await agentsFrom(organization, page.next, pages - 1))];
}

/** Every agent of an organisation, for choosing which one an app acts as; read again whenever the tab is back in view. */
export function useAgentsOf(organization: string | undefined) {
  return useQuery({
    queryKey: ['agents', organization, 'all'],
    enabled: organization !== undefined,
    queryFn: () => agentsFrom(organization ?? '', undefined, MOST_PAGES),
    // An agent registered in another tab shows as soon as the person comes back.
    staleTime: 0,
  });
}

/** A scope that lets the agent do something, not only see: never ticked for the person (decision 8). */
export const isWriteScope = (scope: Scope): boolean => scope.endsWith(':write');

/** The scopes that can be ticked: asked for by the app and held by the agent, in the API's order. */
export const tickable = (asked: readonly Scope[], held: readonly Scope[]): readonly Scope[] =>
  SCOPES.filter((scope) => asked.includes(scope) && held.includes(scope));

/** The hosts plain http may go back to: the machine's own loopback, a native app's (the server's rule, redirects.ts). */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['127.0.0.1', '[::1]', 'localhost']);

/**
 * Where the browser may be sent back to: the address the API answered, only ever a web one. 6F1 G5: https, or http to
 * the loopback alone, as the server lets a client register them.
 */
export const isWebAddress = (address: unknown): address is string => {
  if (typeof address !== 'string' || !/^https?:\/\//i.test(address) || !URL.canParse(address)) return false;
  const url = new URL(address);
  return url.protocol === 'https:' || LOOPBACK_HOSTS.has(url.hostname);
};

/** The refusals a consent can meet that the person can act on, in plain words; any other by its code. */
const CONSENT_REFUSALS = new Set([
  'CONNECTION_AGENT_NOT_ACTIVE',
  'CONNECTION_SCOPES_REFUSED',
  'CONNECTIONS_FULL',
  'CONNECTIONS_SPENT',
  'CONNECTIONS_TOO_MANY',
  'STEP_UP_NOT_ASKED',
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/** What a refused or failed consent, confirm or deny says. */
export function connectRefusal(error: unknown): string {
  if (isIntegrityFailed(error)) return t('agents.integrity');
  return refusalText(error, CONSENT_REFUSALS, 'connect.refused');
}
