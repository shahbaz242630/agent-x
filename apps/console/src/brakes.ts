// The brakes (6B2): what each list of things that can be stopped is read
// from, and who may stop or start each again. An agent's suspend is the kill
// switch; a supplier's and a bank account's suspend and the organisation's
// freeze are brakes of the same kind. Every one acts at once with no step-up
// (the API's own rule): the person confirms the consequence in the API's
// words and chooses what happens to pending requests, and it is done.
// Starting again asks for a passkey (the shared step-up). The roles here only
// decide which buttons show; the API checks again whatever is pressed.
import { useInfiniteQuery } from '@tanstack/react-query';

import { api, ApiError, type RequestOptions } from './api.ts';
import { refusalText } from './refusals.ts';
import { pageQuery } from './requests.ts';
import type { Role } from './session.tsx';
import { t } from './text.ts';

/** The kinds of thing with a brake, each its own list. */
export type Kind = 'agents' | 'suppliers' | 'sources';

/** One thing that can be stopped, as its row shows it. */
export interface Braked {
  readonly id: string;
  readonly name: string;
  /** What else tells it apart: an agent's ID (two may share a name, SEC-AG-10), an account's masked number. */
  readonly detail: string;
  readonly suspended: boolean;
  /** For good (a bank account ended): no brake either way. */
  readonly ended: boolean;
}

interface AgentRead {
  readonly id: string;
  readonly name: string;
  readonly status: 'ACTIVE' | 'SUSPENDED';
}

interface SupplierRead {
  readonly id: string;
  readonly displayName: string;
  readonly status: 'UNVERIFIED' | 'VERIFIED' | 'SUSPENDED';
}

interface SourceRead {
  readonly id: string;
  readonly holderName: string;
  readonly hint: string;
  readonly status: 'ACTIVE' | 'SUSPENDED' | 'ENDED';
}

interface Kept {
  /** The list's address; its answer holds its things under the kind's own name. */
  readonly path: string;
  readonly read: (listed: never) => Braked;
  /** Who may suspend: the API's SUSPENDING_ROLES for this kind. Reactivating is an admin's alone for every kind. */
  readonly suspending: readonly Role[];
  /** Reactivating chooses what happens to the held requests (a supplier, decision 9); the others choose nothing. */
  readonly reactivateChooses: boolean;
  /** Each has its own page (an agent's, 6D1), its row's name linking there. */
  readonly linked: boolean;
}

export const KINDS: Readonly<Record<Kind, Kept>> = {
  agents: {
    path: '/v1/agents',
    read: (agent: AgentRead) => ({
      id: agent.id,
      name: agent.name,
      detail: agent.id,
      suspended: agent.status === 'SUSPENDED',
      ended: false,
    }),
    suspending: ['admin', 'developer'],
    reactivateChooses: false,
    linked: true,
  },
  suppliers: {
    path: '/v1/suppliers',
    read: (supplier: SupplierRead) => ({
      id: supplier.id,
      name: supplier.displayName,
      detail: t(`brakes.supplier.${supplier.status}`),
      suspended: supplier.status === 'SUSPENDED',
      ended: false,
    }),
    suspending: ['admin', 'approver'],
    reactivateChooses: true,
    linked: false,
  },
  sources: {
    path: '/v1/funding-sources',
    read: (source: SourceRead) => ({
      id: source.id,
      name: source.holderName,
      detail: source.hint,
      suspended: source.status === 'SUSPENDED',
      ended: source.status === 'ENDED',
    }),
    suspending: ['admin', 'approver'],
    reactivateChooses: false,
    linked: false,
  },
};

/** Who may start any of them again: an admin (each kind's REACTIVATING_ROLES), as may unfreeze the organisation. */
export const REACTIVATING: readonly Role[] = ['admin'];
/** Who may freeze the organisation (FREEZING_ROLES). */
export const FREEZING: readonly Role[] = ['admin', 'approver'];

interface Page {
  readonly listed: readonly Braked[];
  readonly next: string | null;
  readonly unchecked: readonly string[];
}

type Answer = Readonly<Record<string, unknown>> & {
  readonly next: string | null;
  readonly unchecked: readonly string[];
};

/** One kind's list in the organisation, a page at a time. */
export function useBrakeList(kind: Kind, organization: string) {
  return useInfiniteQuery({
    queryKey: ['brakes', organization, kind],
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: Page) => last.next ?? undefined,
    queryFn: async ({ pageParam }): Promise<Page> => {
      const { path, read } = KINDS[kind];
      const answer = await api.get<Answer>(`${path}?${pageQuery(pageParam)}`, { organization });
      const things = answer[kind] as readonly never[];
      return { listed: things.map(read), next: answer.next, unchecked: answer.unchecked };
    },
  });
}

/** The refusals a brake can meet that the person can act on, said in plain words; any other by its code. */
const REFUSALS = new Set([
  'STEP_UP_ASKED',
  'BAD_REQUEST',
  'PENDING_REQUESTS_CANCELLED',
  'STATEMENT_CHANGED',
  'ORG_NOT_FROZEN',
  'AGENT_NOT_SUSPENDED',
  'SUPPLIER_NOT_SUSPENDED',
  'SOURCE_NOT_SUSPENDED',
  'SOURCE_NOT_USABLE',
  'FORBIDDEN',
  'NOT_FOUND',
]);

/**
 * Sends a brake, which acts at once (200). A 202 would be the API asking for a
 * passkey, which a brake never needs (the kill switch is never behind step-up):
 * refused here, so it is never said done when nothing stopped.
 */
export async function atOnce(path: string, options: RequestOptions): Promise<void> {
  const { status } = await api.write<unknown>(path, options);
  if (status !== 200) throw new ApiError(status, 'STEP_UP_ASKED');
}

/** What a brake's refusal or failure says. */
export const brakeRefusal = (error: unknown): string => refusalText(error, REFUSALS, 'brakes.refused');
