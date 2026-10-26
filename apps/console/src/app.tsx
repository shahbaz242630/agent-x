// The console's frame (6A1): who is signed in decides what shows. No one: the
// sign-in page. Signed in: their organisations, chosen among when there are
// several, then the shell with its tabs. A session that ends while the page is
// open (any request answered 401) goes back to the sign-in page, saying so.
import { QueryCache, QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import {
  createRootRoute,
  createRoute,
  createRouter,
  type RouterHistory,
  redirect,
  RouterProvider,
  useRouterState,
} from '@tanstack/react-router';
import type { ReactElement } from 'react';
import { ApiError, isSignedOut } from './api.ts';
import { Approvals } from './pages/approvals.tsx';
import { Choose, NoOrganization } from './pages/choose.tsx';
import { Failed, NotFound } from './pages/failed.tsx';
import { More } from './pages/more.tsx';
import { RequestPage } from './pages/request.tsx';
import { Shell } from './pages/shell.tsx';
import { SignedOut } from './pages/signed-out.tsx';
import { Soon } from './pages/soon.tsx';
import {
  ActingProvider,
  ENDED,
  endSession,
  type Session,
  useChosen,
  useOrganizations,
  useSession,
} from './session.tsx';
import { t } from './text.ts';

function Loading() {
  return (
    <p className="loading" role="status">
      {t('loading')}
    </p>
  );
}

function SignedIn({ session }: { readonly session: Session }) {
  const organizations = useOrganizations();
  const listed = organizations.data?.organizations ?? [];
  // The raw query, not the router's parsed one, which reads values as JSON.
  const linked = useRouterState({ select: ({ location }) => new URLSearchParams(location.searchStr).get('org') });
  const { chosen, choose } = useChosen(listed, linked);
  if (organizations.isPending) return <Loading />;
  if (organizations.isError) return <Failed onRetry={() => void organizations.refetch()} />;
  const unreadable = organizations.data.unreadable.length;
  if (listed.length === 0) return <NoOrganization unreadable={unreadable} />;
  if (chosen === undefined) return <Choose organizations={listed} unreadable={unreadable} onChoose={choose} />;
  return (
    <ActingProvider value={{ organization: chosen, session, choose, canSwitch: listed.length > 1 }}>
      <Shell />
    </ActingProvider>
  );
}

function Root() {
  const session = useSession();
  const queries = useQueryClient();
  if (session.isPending) return <Loading />;
  if (session.isError) return <Failed onRetry={() => void session.refetch()} />;
  if (session.data === null) return <SignedOut ended={queries.getQueryData<boolean>(ENDED) === true} />;
  return <SignedIn session={session.data} />;
}

const root = createRootRoute({ component: Root, notFoundComponent: NotFound });

/** One request's page, the approver's email's link (6B1): `/approvals/<id>`, its organisation in `?org=`. */
function Request(): ReactElement {
  // From the address this route matched (`/approvals/<id>`): the route's own typed read would refer to the
  // route tree it is part of, and read as untyped.
  const id = useRouterState({ select: ({ location }) => location.pathname.split('/')[2] ?? '' });
  return <RequestPage key={id} id={id} />;
}

const requestRoute = createRoute({ getParentRoute: () => root, path: '/approvals/$id', component: Request });

const routes = root.addChildren([
  createRoute({
    getParentRoute: () => root,
    path: '/',
    beforeLoad: () => {
      // eslint-disable-next-line @typescript-eslint/only-throw-error -- the router's own way to send a page on: it throws its redirect
      throw redirect({ to: '/approvals' });
    },
  }),
  createRoute({ getParentRoute: () => root, path: '/approvals', component: () => <Approvals list="waiting" /> }),
  createRoute({ getParentRoute: () => root, path: '/approvals/all', component: () => <Approvals list="all" /> }),
  requestRoute,
  createRoute({ getParentRoute: () => root, path: '/payments', component: () => <Soon what="soon.payments" /> }),
  createRoute({ getParentRoute: () => root, path: '/agents', component: () => <Soon what="soon.agents" /> }),
  createRoute({ getParentRoute: () => root, path: '/more', component: More }),
]);

/** A refusal (4xx) answers the same however often it is asked: only a failure on the way is read again. */
const refused = (error: unknown): boolean => error instanceof ApiError && error.status < 500;

/** The console's queries: a 401 anywhere means the session is gone, so the session reads as none. */
export function createQueries(): QueryClient {
  const queries: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      onError: (error) => {
        if (isSignedOut(error)) endSession(queries);
      },
    }),
    defaultOptions: {
      queries: { retry: (count, error) => !refused(error) && count < 2, staleTime: 30_000 },
    },
  });
  return queries;
}

export function createConsoleRouter(history?: RouterHistory) {
  return createRouter({ routeTree: routes, ...(history !== undefined && { history }) });
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createConsoleRouter>;
  }
}

export function App({
  queries,
  router,
}: {
  readonly queries: QueryClient;
  readonly router: ReturnType<typeof createConsoleRouter>;
}) {
  return (
    <QueryClientProvider client={queries}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
