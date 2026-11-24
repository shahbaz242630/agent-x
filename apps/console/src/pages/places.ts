// Every place the console's navigation goes (CO11, Calm Ledger): the sidebar
// draws them in groups, the phone's bottom bar the four marked `tab`, and the
// Ctrl+K command bar searches the same list, so the three never disagree.
// Who is shown what follows the More page: the logs and the integrity hold
// are an admin's alone (decisions 24, 26; the API refuses anyone else anyway).
import type { Role } from '../session.tsx';
import type { TextKey } from '../text.ts';
import type { IconName } from './icons.tsx';

/** The addresses a place may name: the router's own, so a typo is a type error. */
type To =
  | '/approvals'
  | '/payments'
  | '/agents'
  | '/more'
  | '/more/mandates'
  | '/more/policy'
  | '/more/suppliers'
  | '/more/sources'
  | '/more/members'
  | '/more/audit-log'
  | '/more/access-log'
  | '/more/security-events'
  | '/more/integrity-hold'
  | '/more/my-activity';

export interface Place {
  readonly to: To;
  readonly label: TextKey;
  readonly icon: IconName;
  /** One of the phone's four bottom tabs. */
  readonly tab?: true;
  /** Only an admin is shown it. */
  readonly admin?: true;
  /** Lit only on its own address, not on the pages under it. */
  readonly exact?: true;
}

export interface PlaceGroup {
  readonly label: TextKey;
  readonly places: readonly Place[];
}

const PLACES: readonly PlaceGroup[] = [
  {
    label: 'nav.group.work',
    places: [
      { to: '/approvals', label: 'nav.approvals', icon: 'approve', tab: true },
      { to: '/payments', label: 'nav.payments', icon: 'pay', tab: true },
    ],
  },
  {
    label: 'nav.group.control',
    places: [
      { to: '/agents', label: 'nav.agents', icon: 'agent', tab: true },
      { to: '/more/mandates', label: 'mandates.title', icon: 'doc' },
      { to: '/more/policy', label: 'policies.title.organization', icon: 'rules' },
      { to: '/more/suppliers', label: 'brakes.suppliers.title', icon: 'truck' },
      { to: '/more/sources', label: 'brakes.sources.title', icon: 'bank' },
    ],
  },
  {
    label: 'members.people',
    places: [{ to: '/more/members', label: 'members.title', icon: 'people' }],
  },
  {
    label: 'more.records',
    places: [
      { to: '/more/audit-log', label: 'logs.audit.title', icon: 'records', admin: true },
      { to: '/more/access-log', label: 'logs.access.title', icon: 'lock', admin: true },
      { to: '/more/security-events', label: 'securityEvents.title', icon: 'shield', admin: true },
      { to: '/more/integrity-hold', label: 'hold.title', icon: 'sign', admin: true },
      { to: '/more/my-activity', label: 'myActivity.title', icon: 'user' },
    ],
  },
  {
    label: 'nav.group.organisation',
    places: [{ to: '/more', label: 'nav.more', icon: 'gear', tab: true, exact: true }],
  },
];

/** The groups this role is shown, each with only the places it may open; a group left empty is dropped. */
export function placesFor(role: Role): readonly PlaceGroup[] {
  return PLACES.map((group) => ({
    label: group.label,
    places: group.places.filter((place) => place.admin !== true || role === 'admin'),
  })).filter((group) => group.places.length > 0);
}
