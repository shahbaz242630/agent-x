// Who is signed in, and which of their organisations the console acts in
// (6A1). Both come from the API (GET /v1/auth/session, GET
// /v1/auth/organizations); the console only remembers which organisation was
// last chosen, in this browser, as a convenience: the API checks the
// membership on every request whatever the console names.
import { useQuery } from '@tanstack/react-query';
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from 'react';

import { api, isSignedOut } from './api.ts';

export interface Session {
  readonly userId: string;
  readonly authenticatedAt: string;
  readonly methods: readonly string[];
  readonly idleExpiresAt: string;
  readonly expiresAt: string;
}

type Role = 'admin' | 'approver' | 'developer' | 'viewer';

export interface Organization {
  readonly id: string;
  readonly name: string;
  readonly role: Role;
  readonly frozen: boolean;
}

export interface Organizations {
  readonly organizations: readonly Organization[];
  readonly unreadable: readonly string[];
}

/** The session, or null for no one signed in; a failure of any other kind is the query's error. */
export function useSession() {
  return useQuery({
    queryKey: ['session'],
    queryFn: async (): Promise<Session | null> => {
      try {
        return await api.get<Session>('/v1/auth/session');
      } catch (error) {
        if (isSignedOut(error)) return null;
        throw error;
      }
    },
  });
}

export function useOrganizations() {
  return useQuery({
    queryKey: ['organizations'],
    queryFn: () => api.get<Organizations>('/v1/auth/organizations'),
  });
}

/** Where this browser remembers the last organisation chosen. */
const CHOSEN_KEY = 'agentx.organization';

function remembered(): string | null {
  try {
    return localStorage.getItem(CHOSEN_KEY);
  } catch {
    // Storage blocked (a private window, a policy): nothing remembered.
    return null;
  }
}

function remember(id: string | null): void {
  try {
    if (id === null) localStorage.removeItem(CHOSEN_KEY);
    else localStorage.setItem(CHOSEN_KEY, id);
  } catch {
    // Storage blocked: the choice lasts until the page is reloaded.
  }
}

/**
 * The organisation chosen among `organizations`: the one remembered if the
 * person still belongs to it, the only one if there is one, otherwise none
 * yet. `choose(null)` goes back to choosing.
 */
export function useChosen(organizations: readonly Organization[]) {
  const [chosenId, setChosenId] = useState<string | null>(remembered);
  const chosen = useMemo(() => {
    const found = organizations.find((organization) => organization.id === chosenId);
    if (found !== undefined) return found;
    return organizations.length === 1 ? organizations[0] : undefined;
  }, [organizations, chosenId]);
  const choose = useCallback((id: string | null) => {
    remember(id);
    setChosenId(id);
  }, []);
  return { chosen, choose };
}

interface Acting {
  readonly organization: Organization;
  readonly session: Session;
  readonly choose: (id: string | null) => void;
  readonly canSwitch: boolean;
}

const ActingContext = createContext<Acting | undefined>(undefined);

export function ActingProvider({ value, children }: { readonly value: Acting; readonly children: ReactNode }) {
  return <ActingContext value={value}>{children}</ActingContext>;
}

/** The organisation the console acts in, and the person's session: only inside the signed-in shell. */
export function useActing(): Acting {
  const acting = useContext(ActingContext);
  if (acting === undefined) throw new Error('useActing ran outside the signed-in shell');
  return acting;
}
