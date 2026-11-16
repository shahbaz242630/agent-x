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
import { isRefusal, isSignedOut } from './api.ts';
import { AgentPage } from './pages/agent.tsx';
import { RegisterAgent } from './pages/agent-register.tsx';
import { AccessLog } from './pages/access-log.tsx';
import { Approvals } from './pages/approvals.tsx';
import { AuditLog } from './pages/audit-log.tsx';
import { BrakeList } from './pages/brakes.tsx';
import { Choose, NoOrganization } from './pages/choose.tsx';
import { EvidencePage } from './pages/evidence.tsx';
import { Failed, Loading, NotFound } from './pages/failed.tsx';
import { More } from './pages/more.tsx';
import { PaymentPage } from './pages/payment.tsx';
import { Payments } from './pages/payments.tsx';
import { PolicyPage } from './pages/policy.tsx';
import { RequestPage } from './pages/request.tsx';
import { Shell } from './pages/shell.tsx';
import { SignedOut } from './pages/signed-out.tsx';
import { SimulatePage } from './pages/simulate.tsx';
import { SupplierPage } from './pages/supplier.tsx';
import { AddSupplier } from './pages/supplier-add.tsx';
import {
  ActingProvider,
  ENDED,
  endSession,
  type Session,
  useChosen,
  useOrganizations,
  useSession,
} from './session.tsx';

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

/**
 * The ID an address such as `/approvals/<id>` names, from the address this route matched: the route's own typed
 * read would refer to the route tree it is part of, and read as untyped.
 */
const useIdInAddress = (at = 2): string =>
  useRouterState({ select: ({ location }) => location.pathname.split('/')[at] ?? '' });

/** One request's page, the approver's email's link (6B1): `/approvals/<id>`, its organisation in `?org=`. */
function Request(): ReactElement {
  const id = useIdInAddress();
  return <RequestPage key={id} id={id} />;
}

/** One agent's page (6D1): `/agents/<id>`, with its keys. */
function AgentAt(): ReactElement {
  const id = useIdInAddress();
  return <AgentPage key={id} id={id} />;
}

/** The Agents tab: the agents with their brake (6B2), and registering one (6D1). */
function Agents(): ReactElement {
  return (
    <BrakeList kind="agents">
      <RegisterAgent />
    </BrakeList>
  );
}

/** One supplier's page (6D2): `/more/suppliers/<id>`, the ID the address's fourth part. */
function SupplierAt(): ReactElement {
  const id = useIdInAddress(3);
  return <SupplierPage key={id} id={id} />;
}

/** The Suppliers list: each with its brake (6B2), and adding one (6D2). */
function Suppliers(): ReactElement {
  return (
    <BrakeList kind="suppliers">
      <AddSupplier />
    </BrakeList>
  );
}

/** One request's evidence, printable (6C2): `/approvals/<id>/evidence`. */
function Evidence(): ReactElement {
  const id = useIdInAddress();
  return <EvidencePage key={id} id={id} />;
}

/** One payment's page (6C1): `/payments/<id>`, its organisation in `?org=` as a request's. */
function Payment(): ReactElement {
  const id = useIdInAddress();
  return <PaymentPage key={id} id={id} />;
}

/** A mandate's own policy (6D3b): `/more/mandates/<id>/policy`, the ID the address's fourth part. */
function MandatePolicy(): ReactElement {
  const id = useIdInAddress(3);
  return <PolicyPage key={id} target={{ kind: 'mandate', mandateId: id }} />;
}

/** The simulator for a mandate's agent (6D3b): `/more/mandates/<id>/simulate`. */
function Simulate(): ReactElement {
  const id = useIdInAddress(3);
  return <SimulatePage key={id} mandateId={id} />;
}

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
  createRoute({ getParentRoute: () => root, path: '/approvals/$id', component: Request }),
  createRoute({ getParentRoute: () => root, path: '/approvals/$id/evidence', component: Evidence }),
  createRoute({ getParentRoute: () => root, path: '/payments', component: () => <Payments list="all" /> }),
  createRoute({
    getParentRoute: () => root,
    path: '/payments/exceptions',
    component: () => <Payments list="exceptions" />,
  }),
  createRoute({ getParentRoute: () => root, path: '/payments/$id', component: Payment }),
  createRoute({ getParentRoute: () => root, path: '/agents', component: Agents }),
  createRoute({ getParentRoute: () => root, path: '/agents/$id', component: AgentAt }),
  createRoute({ getParentRoute: () => root, path: '/more', component: More }),
  createRoute({ getParentRoute: () => root, path: '/more/suppliers', component: Suppliers }),
  createRoute({ getParentRoute: () => root, path: '/more/suppliers/$id', component: SupplierAt }),
  createRoute({ getParentRoute: () => root, path: '/more/sources', component: () => <BrakeList kind="sources" /> }),
  createRoute({ getParentRoute: () => root, path: '/more/audit-log', component: AuditLog }),
  createRoute({ getParentRoute: () => root, path: '/more/access-log', component: AccessLog }),
  createRoute({
    getParentRoute: () => root,
    path: '/more/policy',
    component: () => <PolicyPage target={{ kind: 'organization' }} />,
  }),
  createRoute({ getParentRoute: () => root, path: '/more/mandates/$id/policy', component: MandatePolicy }),
  createRoute({ getParentRoute: () => root, path: '/more/mandates/$id/simulate', component: Simulate }),
]);

/** The console's queries: a 401 anywhere means the session is gone, so the session reads as none. */
export function createQueries(): QueryClient {
  const queries: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      onError: (error) => {
        if (isSignedOut(error)) endSession(queries);
      },
    }),
    defaultOptions: {
      queries: { retry: (count, error) => !isRefusal(error) && count < 2, staleTime: 30_000 },
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
