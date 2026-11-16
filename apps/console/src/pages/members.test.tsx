// 6D4b: the members, a member's page, invitations, registered contacts and
// factor resets, against a stand-in API. Members show by role and IDs, never
// names; an admin changes another member's role (none picked), deactivates
// them or asks a reset of their second factor, each by passkey; invites (an
// email and a role, none picked), confirms or declines who accepted by the
// invitation's ID; adds and removes registered contacts; cancels a reset at
// once. A draft's confirm (invitation, contact, reset) sends no body; an
// invitation's link is shown once. Each dialog is pinned to what it showed.
// Buttons show by role; refusals are said plainly.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { draftConfirm, isEmail } from '../people.ts';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const MINE = '0199a0f0-0000-7000-8000-0000000000b1';
const OTHER = '0199a0f0-0000-7000-8000-0000000000b3';
const GONE = '0199a0f0-0000-7000-8000-0000000000b4';
const RESET = '0199a0f0-0000-7000-8000-0000000000f1';
const CONTACT = '0199a0f0-0000-7000-8000-0000000000c1';
const INVITATION = '0199a0f0-0000-7000-8000-0000000000e1';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';
const LINK = 'https://console.example.test/invitations/accept#token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const member = (id: string, userId: string, role: string, status = 'ACTIVE') => ({
  id,
  userId,
  role,
  status,
  joinedAt: PAST,
});
const MEMBERS = [
  member(MINE, ME, 'admin'),
  member(OTHER, '0199a0f0-0000-7000-8000-000000000033', 'approver'),
  member(GONE, '0199a0f0-0000-7000-8000-000000000044', 'viewer', 'DEACTIVATED'),
];
const reset = (change: Record<string, unknown> = {}) => ({
  id: RESET,
  status: 'AWAITING_CONTACT',
  person: OTHER,
  requestedBy: MINE,
  expiresAt: FUTURE,
  confirmedBy: null,
  coolingOffUntil: null,
  ...change,
});
const contact = (change: Record<string, unknown> = {}) => ({
  id: CONTACT,
  email: 'owner@company.example',
  status: 'ACTIVE',
  countsFrom: PAST,
  counts: true,
  ...change,
});

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const ASKED = { status: 202, body: { stepUpChallengeId: CHALLENGE } };
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });

function as(role: string) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: { userId: ME, authenticatedAt: PAST, methods: ['user', 'mfa'], idleExpiresAt: FUTURE, expiresAt: FUTURE },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/members', { status: 200, body: { members: MEMBERS } });
  answer('GET /v1/factor-resets', { status: 200, body: { resets: [reset()] } });
  answer('GET /v1/registered-contacts', { status: 200, body: { contacts: [contact()] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  sessionStorage.clear();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? refused(404, 'NOT_FOUND');
      if (status === 0) return Promise.reject(new TypeError('Failed to fetch'));
      return Promise.resolve(new Response(JSON.stringify(reply ?? {}), { status }));
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function open(path: string) {
  const history = createMemoryHistory({ initialEntries: [path] });
  const queries = createQueries();
  render(<App queries={queries} router={createConsoleRouter(history)} />);
  return { history, queries };
}

/** Everything a store holds, as one text. */
const held = (store: Storage): string =>
  Array.from(
    { length: store.length },
    (_, at) => `${store.key(at) ?? ''}=${store.getItem(store.key(at) ?? '') ?? ''}`,
  ).join(' ');

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);
const posts = () => sent.filter((one) => one.method === 'POST');
const kept = (): unknown => JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
const press = async (name: string | RegExp) => {
  await userEvent.click(await screen.findByRole('button', { name }));
};
const dialog = () => screen.findByRole('dialog');
const inDialog = async (name: string) => {
  await userEvent.click(within(await dialog()).getByRole('button', { name }));
};
const confirmButton = async (name = 'Continue with passkey') =>
  within(await dialog()).getByRole<HTMLButtonElement>('button', { name });

describe('the members (6D4b)', () => {
  it('lists every member by role and IDs, never a name, from the More page', async () => {
    as('admin');
    const { history } = open('/more');
    await userEvent.click(await screen.findByRole('link', { name: 'Members' }));
    expect(history.location.pathname).toBe('/more/members');
    expect(await screen.findByRole('link', { name: 'Admin (you)' })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Approver' })).toBeDefined();
    expect(screen.getByText(MINE)).toBeDefined();
    expect(screen.getByText('Deactivated')).toBeDefined();
    expect(screen.getAllByText(/^Member since /)).toHaveLength(3);
    // An admin reaches the contacts and resets, and invites.
    expect(screen.getByRole('link', { name: 'Registered contacts' })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Second-factor resets' })).toBeDefined();
    expect(screen.getByRole('heading', { name: 'Invite someone' })).toBeDefined();
  });

  it.each(['approver', 'developer', 'viewer'])('shows a %s the members with nothing to change', async (role) => {
    as(role);
    open('/more/members');
    expect(await screen.findByRole('link', { name: 'Approver' })).toBeDefined();
    expect(screen.queryByRole('heading', { name: 'Invite someone' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Registered contacts' })).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('says members whose records failed the integrity check as that, and offers a retry for anything else', async () => {
    as('viewer');
    answer('GET /v1/members', refused(503, 'INTEGRITY_FAILED'));
    open('/more/members');
    expect(await screen.findByText(/failed its integrity check/, {}, { timeout: 8000 })).toBeDefined();
    cleanup();
    as('viewer');
    answer('GET /v1/members', refused(403, 'FORBIDDEN'), { status: 200, body: { members: MEMBERS } });
    open('/more/members');
    await press('Try again');
    expect(await screen.findByRole('link', { name: 'Approver' })).toBeDefined();
  }, 15_000);
});

describe('a member’s page (6D4b)', () => {
  const page = `/more/members/${OTHER}`;
  const at = `/v1/members/${OTHER}`;

  it('shows the member as the API gives them, with their resets, and opens from the list', async () => {
    as('admin');
    const { history } = open('/more/members');
    await userEvent.click(await screen.findByRole('link', { name: 'Approver' }));
    expect(history.location.pathname).toBe(page);
    expect(await screen.findByRole('heading', { name: 'Approver' })).toBeDefined();
    expect(screen.getByText('0199a0f0-0000-7000-8000-000000000033')).toBeDefined();
    expect(screen.getByText(/doesn't show which sign-in factors/)).toBeDefined();
    expect(await screen.findByText(/Waiting for a registered contact to confirm it/)).toBeDefined();
    expect(screen.getByRole('button', { name: `Cancel reset ${RESET}` })).toBeDefined();
  });

  it('changes a role chosen among the other three, none picked, by passkey', async () => {
    as('admin');
    answer(`POST ${at}/role`, ASKED);
    open(page);
    const options = await screen.findAllByRole<HTMLInputElement>('radio');
    expect(options.map((one) => one.value)).toEqual(['admin', 'developer', 'viewer']);
    expect(options.some((one) => one.checked)).toBe(false);
    await press('Change role');
    expect(await screen.findByText('Choose their new role.')).toBeDefined();
    expect(posts()).toHaveLength(0);

    await userEvent.click(screen.getByLabelText(/^Viewer:/));
    await press('Change role');
    expect(within(await dialog()).getByText('From Approver to Viewer')).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/role`)[0]?.body).toEqual({ role: 'viewer' });
    expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    expect(kept()).toMatchObject({
      label: `Change member ${OTHER} to Viewer`,
      confirmPath: `${at}/role/confirm`,
      body: { role: 'viewer' },
      organization: ORG.id,
    });
  });

  it('deactivates by passkey with nothing in the body', async () => {
    as('admin');
    answer(`POST ${at}/deactivate`, ASKED);
    open(page);
    await press('Deactivate');
    expect(within(await dialog()).getByText(/every session they have ends/)).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/deactivate`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({ confirmPath: `${at}/deactivate/confirm`, body: {} });
  });

  it('asks a reset kept as a draft, whose confirm takes nothing but the draft’s own address', async () => {
    as('admin');
    answer(`POST ${at}/factor-reset`, {
      status: 202,
      body: { reset: reset({ status: 'DRAFT' }), stepUpChallengeId: CHALLENGE },
    });
    open(page);
    await press('Ask a reset');
    expect(within(await dialog()).getByText(/emails your organisation's registered contacts/)).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/factor-reset`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({
      label: `Reset the second factor of member ${OTHER}`,
      confirmPath: `/v1/factor-resets/${RESET}/confirm`,
      body: {},
      drafted: true,
    });
  });

  it.each([
    ['RESET_OPEN', /already under way/],
    ['NO_COUNTING_CONTACTS', /counts 7 days after it is confirmed/],
    ['MEMBER_ELSEWHERE', /Agent X's own team resets/],
    ['PASSKEY_REQUIRED', /signed in with a passkey/],
  ])('says a reset refused with %s in its own words', async (code, said) => {
    as('admin');
    answer(`POST ${at}/factor-reset`, refused(409, code));
    open(page);
    await press('Ask a reset');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(said)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('refuses a reset answered with no step-up or no draft, as nothing was sent to the contacts', async () => {
    as('admin');
    answer(`POST ${at}/factor-reset`, { status: 202, body: { reset: reset({ status: 'AWAITING_CONTACT' }) } });
    open(page);
    await press('Ask a reset');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(kept()).toBeNull();
  });

  it.each([
    ['OWN_MEMBERSHIP', 409, /another admin must/],
    ['ROLE_UNCHANGED', 409, /already have this role/],
    ['SECOND_FACTOR_REMOVED', 403, /removed in the last 7 days/],
    ['SOMETHING_NEW', 409, /reason SOMETHING_NEW/],
    ['INTEGRITY_FAILED', 503, /failed its integrity check/],
  ])('says a role change refused with %s plainly', async (code, status, said) => {
    as('admin');
    answer(`POST ${at}/role`, refused(status, code));
    open(page);
    await userEvent.click(await screen.findByLabelText(/^Admin:/));
    await press('Change role');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('holds the dialog to the member as it showed them: changed since, it can’t be confirmed', async () => {
    as('admin');
    const { queries } = open(page);
    await userEvent.click(await screen.findByLabelText(/^Developer:/));
    await press('Change role');
    expect((await confirmButton()).disabled).toBe(false);
    answer('GET /v1/members', {
      status: 200,
      body: { members: [MEMBERS[0], member(OTHER, '0199a0f0-0000-7000-8000-000000000033', 'admin'), MEMBERS[2]] },
    });
    await queries.invalidateQueries();
    expect(await within(await dialog()).findByText(/has changed since you opened this/)).toBeDefined();
    expect((await confirmButton()).disabled).toBe(true);
    // The dialog still shows the member as they were when it opened.
    expect(within(await dialog()).getByText('From Approver to Developer')).toBeDefined();
  });

  it('offers nothing on your own membership, and says another admin changes it', async () => {
    as('admin');
    open(`/more/members/${MINE}`);
    expect(await screen.findByText(/This is you. Another admin changes your role/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Change role' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Deactivate' })).toBeNull();
  });

  it('offers nothing on a deactivated member', async () => {
    as('admin');
    open(`/more/members/${GONE}`);
    expect(await screen.findByText('Deactivated', { selector: '.kicker' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Change role' })).toBeNull();
  });

  it('shows anyone but an admin the member with nothing to press, and reads no resets', async () => {
    as('approver');
    open(page);
    expect(await screen.findByText("Only an admin can change a member's role or membership.")).toBeDefined();
    expect(screen.queryByRole('button')).toBeNull();
    expect(sentTo('GET', '/v1/factor-resets')).toHaveLength(0);
  });

  it.each([
    ['an address that is no member’s ID', '/more/members/not-an-id'],
    ['a membership not in the organisation', `/more/members/${CHALLENGE}`],
  ])('says %s can’t be found', async (_what, path) => {
    as('admin');
    open(path);
    expect(await screen.findByText("This member can't be found in this organisation.")).toBeDefined();
    expect(screen.getByRole('link', { name: 'Back to members' })).toBeDefined();
  });
});

describe('the factor resets (6D4b)', () => {
  it.each([
    [{ status: 'DRAFT' }, /Not sent yet/, true],
    [{ status: 'COOLING_OFF', coolingOffUntil: FUTURE }, /second factor is removed .* unless cancelled first/, true],
    [{ status: 'COOLING_OFF' }, /^Confirmed: cooling off$/, true],
    [{ status: 'COMPLETED' }, /Done: the second factor was removed/, false],
    [{ status: 'CANCELLED' }, /Cancelled: nothing was removed/, false],
    [{ status: 'EXPIRED' }, /Lapsed/, false],
  ])('says where a reset stands (%o), cancellable only while open', async (change, said, cancellable) => {
    as('admin');
    answer('GET /v1/factor-resets', { status: 200, body: { resets: [reset(change)] } });
    open('/more/factor-resets');
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByRole('button', { name: `Cancel reset ${RESET}` }) !== null).toBe(cancellable);
  });

  it('cancels at once, with no passkey, once confirmed', async () => {
    as('admin');
    answer(`POST /v1/factor-resets/${RESET}/cancel`, { status: 200, body: { reset: reset({ status: 'CANCELLED' }) } });
    open('/more/factor-resets');
    await press(`Cancel reset ${RESET}`);
    await inDialog('Cancel the reset');
    expect(sentTo('POST', `/v1/factor-resets/${RESET}/cancel`)[0]?.body).toEqual({});
    expect(await screen.findByText("Cancelled: the second factor isn't removed.")).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('says a cancel refused plainly', async () => {
    as('admin');
    answer(`POST /v1/factor-resets/${RESET}/cancel`, refused(409, 'RESET_CLOSED'));
    open('/more/factor-resets');
    await press(`Cancel reset ${RESET}`);
    await inDialog('Cancel the reset');
    expect(await screen.findByText(/already sent, ended or ran out/)).toBeDefined();
  });

  it('holds a cancel to the reset as it showed it', async () => {
    as('admin');
    const { queries } = open('/more/factor-resets');
    await press(`Cancel reset ${RESET}`);
    answer('GET /v1/factor-resets', { status: 200, body: { resets: [reset({ status: 'COMPLETED' })] } });
    await queries.invalidateQueries();
    expect(await within(await dialog()).findByText(/has changed since you opened this/)).toBeDefined();
    expect((await confirmButton('Cancel the reset')).disabled).toBe(true);
  });

  it('says none, a failed read with a retry, and an admin’s alone', async () => {
    as('admin');
    answer('GET /v1/factor-resets', { status: 200, body: { resets: [] } });
    open('/more/factor-resets');
    expect(await screen.findByText('No resets.')).toBeDefined();
    cleanup();
    as('admin');
    answer('GET /v1/factor-resets', refused(409, 'TOO_MANY_RESETS'), { status: 200, body: { resets: [] } });
    open('/more/factor-resets');
    await press('Try again');
    expect(await screen.findByText('No resets.')).toBeDefined();
    cleanup();
    as('developer');
    open('/more/factor-resets');
    expect(await screen.findByText('Only an admin can see the resets.')).toBeDefined();
  });
});

describe('the registered contacts (6D4b)', () => {
  it('lists each with whether it counts now, or from when', async () => {
    as('admin');
    answer('GET /v1/registered-contacts', {
      status: 200,
      body: {
        contacts: [contact(), contact({ id: GONE, email: 'new@company.example', counts: false, countsFrom: FUTURE })],
      },
    });
    open('/more/contacts');
    expect(await screen.findByText('Counts now')).toBeDefined();
    expect(screen.getByText(/^Counts from /)).toBeDefined();
    expect(screen.getByText('new@company.example')).toBeDefined();
  });

  it('says when there are none, and that a lost second factor can’t be reset then', async () => {
    as('admin');
    answer('GET /v1/registered-contacts', { status: 200, body: { contacts: [] } });
    open('/more/contacts');
    expect(await screen.findByText(/no registered contacts yet/)).toBeDefined();
  });

  it('adds one checked by the API’s rule, kept as a draft, confirmed by passkey', async () => {
    as('admin');
    answer('POST /v1/registered-contacts', {
      status: 202,
      body: { contact: contact({ status: 'DRAFT', countsFrom: null, counts: false }), stepUpChallengeId: CHALLENGE },
    });
    open('/more/contacts');
    await userEvent.type(await screen.findByLabelText('Their email address'), 'not an address');
    await press('Add');
    expect(await screen.findByText(/Enter an email address/)).toBeDefined();
    expect(posts()).toHaveLength(0);
    await userEvent.clear(screen.getByLabelText('Their email address'));
    await userEvent.type(screen.getByLabelText('Their email address'), 'director@company.example');
    await press('Add');
    expect(within(await dialog()).getByText('director@company.example')).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', '/v1/registered-contacts')[0]?.body).toEqual({ email: 'director@company.example' });
    expect(kept()).toMatchObject({
      confirmPath: `/v1/registered-contacts/${CONTACT}/confirm`,
      body: {},
      drafted: true,
    });
  });

  it('says an add refused plainly', async () => {
    as('admin');
    answer('POST /v1/registered-contacts', refused(409, 'CONTACTS_FULL'));
    open('/more/contacts');
    await userEvent.type(await screen.findByLabelText('Their email address'), 'director@company.example');
    await press('Add');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/5 registered contacts, the most/)).toBeDefined();
  });

  it('removes one by passkey, the dialog held to the contact as it showed it', async () => {
    as('admin');
    answer(`POST /v1/registered-contacts/${CONTACT}/remove`, ASKED);
    open('/more/contacts');
    await press('Remove owner@company.example');
    expect(within(await dialog()).getByText('owner@company.example')).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `/v1/registered-contacts/${CONTACT}/remove`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({ confirmPath: `/v1/registered-contacts/${CONTACT}/remove/confirm`, body: {} });
    // Asked again with the contact gone meanwhile: said, and not confirmable.
    cleanup();
    as('admin');
    const again = open('/more/contacts');
    await press('Remove owner@company.example');
    answer('GET /v1/registered-contacts', { status: 200, body: { contacts: [] } });
    await again.queries.invalidateQueries();
    expect(await within(await dialog()).findByText(/has changed since you opened this/)).toBeDefined();
    expect((await confirmButton()).disabled).toBe(true);
  });

  it('offers a failed read again, and shows anyone but an admin nothing', async () => {
    as('admin');
    answer('GET /v1/registered-contacts', refused(409, 'TOO_MANY_CONTACTS'), {
      status: 200,
      body: { contacts: [contact()] },
    });
    open('/more/contacts');
    await press('Try again');
    expect(await screen.findByText('Counts now')).toBeDefined();
    cleanup();
    sent = [];
    as('approver');
    open('/more/contacts');
    expect(await screen.findByText('Only an admin can see and change the registered contacts.')).toBeDefined();
    expect(sentTo('GET', '/v1/registered-contacts')).toHaveLength(0);
  });
});

describe('invitations (6D4b)', () => {
  it('invites with an email and a role chosen, none picked, kept as a draft and opened by passkey', async () => {
    as('admin');
    answer('POST /v1/members/invitations', {
      status: 202,
      body: {
        invitation: { id: INVITATION, role: 'developer', status: 'DRAFT', expiresAt: FUTURE },
        stepUpChallengeId: CHALLENGE,
      },
    });
    open('/more/members');
    const invite = within(await screen.findByRole('region', { name: 'Invite someone' }));
    expect(invite.getAllByRole<HTMLInputElement>('radio').some((one) => one.checked)).toBe(false);
    await userEvent.click(invite.getByRole('button', { name: 'Invite' }));
    expect(await invite.findByText(/Enter an email address/)).toBeDefined();
    await userEvent.type(invite.getByLabelText('Their email address'), 'dev@company.example');
    await userEvent.click(invite.getByRole('button', { name: 'Invite' }));
    expect(await invite.findByText('Choose their role.')).toBeDefined();
    expect(posts()).toHaveLength(0);

    await userEvent.click(invite.getByLabelText(/^Developer:/));
    await userEvent.click(invite.getByRole('button', { name: 'Invite' }));
    expect(within(await dialog()).getByText('dev@company.example')).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', '/v1/members/invitations')[0]?.body).toEqual({
      email: 'dev@company.example',
      role: 'developer',
    });
    expect(kept()).toMatchObject({
      label: 'Invite dev@company.example as Developer',
      confirmPath: `/v1/members/invitations/${INVITATION}/confirm`,
      body: {},
      drafted: true,
    });
  });

  it('confirms who accepted by the invitation’s ID, by passkey', async () => {
    as('admin');
    answer(`POST /v1/members/invitations/${INVITATION}/approve`, ASKED);
    open('/more/members');
    const waiting = within(await screen.findByRole('region', { name: 'Someone waiting for you to confirm them' }));
    await userEvent.type(waiting.getByLabelText('Invitation ID'), 'not-an-id');
    await userEvent.click(waiting.getByRole('button', { name: 'Confirm them' }));
    expect(await waiting.findByText(/Enter the invitation ID exactly/)).toBeDefined();
    await userEvent.clear(waiting.getByLabelText('Invitation ID'));
    await userEvent.type(waiting.getByLabelText('Invitation ID'), ` ${INVITATION.toUpperCase()} `);
    await userEvent.click(waiting.getByRole('button', { name: 'Confirm them' }));
    expect(within(await dialog()).getByText(INVITATION)).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `/v1/members/invitations/${INVITATION}/approve`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({ confirmPath: `/v1/members/invitations/${INVITATION}/approve/confirm`, body: {} });
  });

  it('declines at once, and says a refusal plainly', async () => {
    as('admin');
    answer(
      `POST /v1/members/invitations/${INVITATION}/decline`,
      { status: 200, body: { invitation: { id: INVITATION, role: 'admin', status: 'DECLINED', expiresAt: FUTURE } } },
      refused(409, 'INVITATION_CLOSED'),
    );
    open('/more/members');
    const waiting = within(await screen.findByRole('region', { name: 'Someone waiting for you to confirm them' }));
    await userEvent.type(waiting.getByLabelText('Invitation ID'), INVITATION);
    await userEvent.click(waiting.getByRole('button', { name: 'Decline them' }));
    await inDialog('Decline');
    expect(await screen.findByText("Declined: they don't join the organisation.")).toBeDefined();
    await userEvent.click(waiting.getByRole('button', { name: 'Decline them' }));
    await inDialog('Decline');
    expect(await screen.findByText(/no longer open/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });
});

describe('a draft confirmed on the way back from the passkey (6D4b)', () => {
  function back(confirmPath: string, label: string) {
    sessionStorage.setItem(
      `agentx.step-up.${CHALLENGE}`,
      JSON.stringify({
        challenge: CHALLENGE,
        label,
        confirmPath,
        body: {},
        organization: ORG.id,
        idempotencyKey: '0199a0f0-0000-4000-8000-00000000c0de',
        drafted: true,
      }),
    );
    return open(`/more/members?stepped=${CHALLENGE}`);
  }
  const confirmAt = `/v1/members/invitations/${INVITATION}/confirm`;

  it('sends the draft’s confirm with nothing in its body, and shows the invitation’s link once, hidden first', async () => {
    as('admin');
    const opened = { id: INVITATION, role: 'developer', status: 'OPEN', expiresAt: FUTURE };
    answer(`POST ${confirmAt}`, { status: 200, body: { invitation: opened, link: LINK } });
    const { history, queries } = back(confirmAt, 'Invite dev@company.example as Developer');
    await press('Confirm');
    expect(sentTo('POST', confirmAt)[0]?.body).toEqual({});
    expect(await screen.findByRole('heading', { name: 'The invitation link' })).toBeDefined();
    expect(screen.queryByText(LINK)).toBeNull();
    await press('Show');
    expect(screen.getByText(LINK)).toBeDefined();
    // Never kept: not in storage, the address or the query cache.
    expect(held(sessionStorage)).not.toContain('token=');
    expect(held(localStorage)).not.toContain('token=');
    expect(history.location.href).not.toContain('token=');
    expect(
      JSON.stringify(
        queries
          .getQueryCache()
          .getAll()
          .map((query) => query.state.data),
      ),
    ).not.toContain('token=');
    await press("Done, I've saved it");
    expect(screen.queryByText(LINK)).toBeNull();
  });

  it('says a retried confirm’s link can’t be shown again', async () => {
    as('admin');
    const opened = { id: INVITATION, role: 'developer', status: 'OPEN', expiresAt: FUTURE };
    answer(`POST ${confirmAt}`, { status: 200, body: { invitation: opened } });
    back(confirmAt, 'Invite dev@company.example as Developer');
    await press('Confirm');
    expect(await screen.findByText(/made on your first try and can't be shown again/)).toBeDefined();
  });

  it('says an approval done, never asking about a link: only opening an invitation gives one', async () => {
    as('admin');
    const at = `/v1/members/invitations/${INVITATION}/approve/confirm`;
    const decided = { id: INVITATION, role: 'admin', status: 'ACCEPTED', expiresAt: FUTURE };
    answer(`POST ${at}`, { status: 200, body: { invitation: decided } });
    sessionStorage.setItem(
      `agentx.step-up.${CHALLENGE}`,
      JSON.stringify({
        challenge: CHALLENGE,
        label: `Confirm who accepted invitation ${INVITATION}`,
        confirmPath: at,
        body: {},
        organization: ORG.id,
        idempotencyKey: '0199a0f0-0000-4000-8000-00000000c0de',
      }),
    );
    open(`/more/members?stepped=${CHALLENGE}`);
    await press('Confirm');
    expect(sentTo('POST', at)[0]?.body).toEqual({ stepUpChallengeId: CHALLENGE });
    expect(await screen.findByText(`Done: Confirm who accepted invitation ${INVITATION}`)).toBeDefined();
    expect(screen.queryByText(/can't be shown again/)).toBeNull();
  });

  it('confirms a contact or a reset with nothing in its body, and says it done', async () => {
    as('admin');
    const at = `/v1/registered-contacts/${CONTACT}/confirm`;
    answer(`POST ${at}`, { status: 200, body: { contact: contact({ counts: false, countsFrom: FUTURE }) } });
    back(at, 'Add the registered contact director@company.example');
    await press('Confirm');
    expect(sentTo('POST', at)[0]?.body).toEqual({});
    expect(await screen.findByText('Done: Add the registered contact director@company.example')).toBeDefined();
  });
});

describe('the people rules (6D4b)', () => {
  it.each([
    ['name@company.ae', true],
    ['first.last+tag@sub.company.example', true],
    ['.name@company.ae', false],
    ['name@company', false],
    ['name company@company.ae', false],
    [`${'a'.repeat(250)}@b.ae`, false],
  ])('checks %s as an email the API would take: %s', (typed, taken) => {
    expect(isEmail(typed)).toBe(taken);
  });

  it.each([
    [{ invitation: { id: INVITATION, status: 'DRAFT' } }, `/v1/members/invitations/${INVITATION}/confirm`],
    [{ invitation: { id: INVITATION, status: 'OPEN' } }, undefined],
    [{ invitation: { id: 'not-an-id', status: 'DRAFT' } }, undefined],
    [{ invitation: { id: INVITATION } }, undefined],
    [{ invitation: null }, undefined],
    [{}, undefined],
    [null, undefined],
  ])('names a draft’s confirm only for a DRAFT with an ID (%o)', (answered, path) => {
    expect(draftConfirm('invitation', '/v1/members/invitations')(answered)).toBe(path);
  });
});
