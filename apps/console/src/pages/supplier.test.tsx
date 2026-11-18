// 6D2: a supplier's page, its bank details, verifying it and its payment
// emails, and adding one, against a stand-in API. The page shows the supplier
// as the API gives it (never an account number); new bank details are asked
// "did they tell you by email?" first (ADR-012), the warning and a call-back
// tick on yes, then go to the partner passed through or on its own page, the
// pending requests' fate chosen in the API's `payee` words with none picked;
// confirming them, verifying and the payment-email switch go by passkey, a
// withdraw at once. Buttons show by role; refusals are said plainly.
import { createMemoryHistory } from '@tanstack/react-router';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App, createConsoleRouter, createQueries } from '../app.tsx';
import { dropAllTries, heldTry } from '../held-tries.ts';

vi.mock('../navigate.ts', () => ({ goTo: vi.fn() }));
const { goTo } = await import('../navigate.ts');

const ORG = { id: '0199a0f0-0000-7000-8000-00000000aaaa', name: 'Staging-Test-Org-1', role: 'admin', frozen: false };
const ME = '0199a0f0-0000-7000-8000-000000000011';
const SUPPLIER = '0199a0f0-0000-7000-8000-0000000000d1';
const WHOSE = { user: ME, organization: ORG.id, supplier: SUPPLIER };
const OTHER = '0199a0f0-0000-7000-8000-000000000099';
const REGISTRATION = '0199a0f0-0000-7000-8000-0000000000e1';
const CHALLENGE = '0199a0f0-0000-7000-8000-0000000c0ffe';
const MINE = '0199a0f0-0000-7000-8000-0000000000b1';
const APPROVER = '0199a0f0-0000-7000-8000-0000000000b3';
const IBAN = 'AE07 0331 2345 6789 0123 456';
const PAST = '2026-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';

const MEMBERS = [
  { id: MINE, userId: ME, role: 'admin', status: 'ACTIVE', joinedAt: PAST },
  { id: APPROVER, userId: '0199a0f0-0000-7000-8000-000000000033', role: 'approver', status: 'ACTIVE', joinedAt: PAST },
];
const PAYEE = { registrationId: REGISTRATION, payeeHint: 'AE…3456', nameCheck: 'match', maskedName: 'GU** TR*****' };
const supplier = (change: Record<string, unknown> = {}) => ({
  id: SUPPLIER,
  status: 'UNVERIFIED',
  displayName: 'Gulf Traders',
  changeWaiting: false,
  coolingOffUntil: PAST,
  verifiedBy: null,
  version: 2,
  phone: '+971501234567',
  phoneSince: PAST,
  email: 'accounts@gulf.example',
  tradeLicence: 'DED-12345',
  source: { kind: 'registry', ref: 'DED/12345' },
  enteredBy: MINE,
  enteredAt: PAST,
  payee: PAYEE,
  remittanceEmail: 'on',
  pendingChange: null,
  ...change,
});
const registration = (change: Record<string, unknown> = {}) => ({
  id: REGISTRATION,
  supplierId: SUPPLIER,
  route: 'pass_through',
  status: 'REGISTERED',
  nameCheck: 'match',
  maskedName: 'GU** TR*****',
  payeeHint: 'AE…3456',
  failure: null,
  form: null,
  ...change,
});
const STATEMENTS = {
  statements: [
    {
      id: 'payee',
      version: 2,
      words: [
        { choice: 'cancel', text: 'Its requests are cancelled.' },
        { choice: 'pause', text: 'Its requests are held.' },
      ],
    },
  ],
};

interface Answer {
  readonly status: number;
  readonly body?: unknown;
}
let answers: Map<string, Answer[]>;
let sent: { method: string; path: string; body: unknown; key: string | null }[];

/** Answers `method path` with these in turn, the last one again after. */
const answer = (at: string, ...given: Answer[]) => answers.set(at, given);
const ASKED = { status: 202, body: { stepUpChallengeId: CHALLENGE } };
const refused = (status: number, code: string) => ({ status, body: { error: { code } } });

function as(role: string, shown: Record<string, unknown> = supplier()) {
  answer('GET /v1/auth/session', {
    status: 200,
    body: {
      userId: ME,
      authenticatedAt: PAST,
      methods: ['pwd', 'user', 'mfa'],
      idleExpiresAt: FUTURE,
      expiresAt: FUTURE,
    },
  });
  answer('GET /v1/auth/organizations', { status: 200, body: { organizations: [{ ...ORG, role }], unreadable: [] } });
  answer('GET /v1/statements', { status: 200, body: STATEMENTS });
  answer('GET /v1/members', { status: 200, body: { members: MEMBERS } });
  answer(`GET /v1/suppliers/${SUPPLIER}`, { status: 200, body: shown });
  answer('GET /v1/suppliers', { status: 200, body: { suppliers: [shown], next: null, unchecked: [] } });
}

beforeEach(() => {
  answers = new Map();
  sent = [];
  sessionStorage.clear();
  // A try held for Try again lives in the tab's memory, as the module does across these tests: each starts with none.
  dropAllTries();
  vi.mocked(goTo).mockClear();
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      const method = init.method ?? 'GET';
      const body: unknown = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
      sent.push({ method, path, body, key: new Headers(init.headers).get('idempotency-key') });
      const queue = answers.get(`${method} ${path.split('?')[0] ?? path}`);
      const next = queue === undefined ? undefined : queue.length > 1 ? queue.shift() : queue[0];
      const { status, body: reply } = next ?? refused(404, 'NOT_FOUND');
      // Status 0: no answer at all, as the browser's fetch fails on a dropped connection.
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
  render(<App queries={createQueries()} router={createConsoleRouter(history)} />);
  return history;
}

const sentTo = (method: string, path: string) => sent.filter((one) => one.method === method && one.path === path);
const posts = () => sent.filter((one) => one.method === 'POST');
const kept = (): unknown => JSON.parse(sessionStorage.getItem(`agentx.step-up.${CHALLENGE}`) ?? 'null');
const page = `/more/suppliers/${SUPPLIER}`;
const at = `/v1/suppliers/${SUPPLIER}`;
const press = async (name: string | RegExp) => {
  await userEvent.click(await screen.findByRole('button', { name }));
};
const inDialog = async (name: string) => {
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name }));
};

describe('a supplier’s page (6D2)', () => {
  it('shows the supplier as the API gives it: its call-back phone, source, who entered it, its bank account masked', async () => {
    as('admin');
    open(page);

    expect(await screen.findByRole('heading', { name: 'Gulf Traders' })).toBeDefined();
    expect(screen.getByText(SUPPLIER)).toBeDefined();
    expect(screen.getAllByText('+971501234567').length).toBeGreaterThan(0);
    expect(screen.getByText('Trade registry: DED/12345')).toBeDefined();
    expect(screen.getByText('accounts@gulf.example')).toBeDefined();
    expect(await screen.findByText(/Admin \(you\)/)).toBeDefined();
    expect(screen.getByText('AE…3456')).toBeDefined();
    expect(screen.getByText('GU** TR*****')).toBeDefined();
    expect(screen.getByText("The bank says the holder's name matches")).toBeDefined();
    expect(screen.getByText(/Payment emails to the supplier/)).toBeDefined();
    expect(screen.getByText(/^On: when a payment to it succeeds/)).toBeDefined();
    // Its cooling-off ended: no time left is shown.
    expect(screen.queryByText('Cooling-off ends')).toBeNull();
  });

  it('opens from the supplier’s row on the Suppliers list, where its brake stays', async () => {
    as('admin');
    const history = open('/more/suppliers');
    expect(await screen.findByRole('button', { name: 'Suspend Gulf Traders' })).toBeDefined();
    await userEvent.click(screen.getByRole('link', { name: 'Gulf Traders' }));
    expect(await screen.findByRole('heading', { name: 'Gulf Traders' })).toBeDefined();
    expect(history.location.pathname).toBe(page);
  });

  it('says what isn’t given, and names a verifier it can’t find among the members plainly', async () => {
    as('approver', supplier({ email: null, tradeLicence: null, status: 'VERIFIED', verifiedBy: APPROVER }));
    answer('GET /v1/members', refused(403, 'FORBIDDEN'));
    open(page);
    expect(await screen.findByText('Verified by')).toBeDefined();
    expect(screen.getAllByText('Not given')).toHaveLength(2);
    expect(screen.getAllByText(/A member/).length).toBeGreaterThan(0);
    expect(screen.getByText(/It has no email on file/)).toBeDefined();
    // Verified: nothing to verify.
    expect(screen.queryByRole('heading', { name: 'Verify' })).toBeNull();
  });

  it('shows when its cooling-off ends, with the time left, and holds verifying until then', async () => {
    as('admin', supplier({ coolingOffUntil: FUTURE }));
    open(page);
    expect(await screen.findByText('Cooling-off ends')).toBeDefined();
    expect(screen.getByText(/h left$/)).toBeDefined();
    expect(screen.getByText(/24-hour cooling-off after new bank details hasn't ended yet/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Verify' })).toBeNull();
  });

  it.each([
    ['no bank details yet', { payee: null }, /no bank details yet. An admin adds them first/],
    ['new details waiting', { changeWaiting: true }, /New bank details are waiting/],
    ['no cooling-off begun', { coolingOffUntil: null }, /cooling-off after new bank details/],
    ['the bank’s name check “no match”', { payee: { ...PAYEE, nameCheck: 'no_match' } }, /can't be verified with/],
  ])('says why it can’t be verified yet: %s', async (_what, change, said) => {
    as('admin', supplier(change));
    open(page);
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Verify' })).toBeNull();
  });

  it.each([
    ['an address that is no supplier’s ID', '/more/suppliers/not-an-id', undefined, /can't be found in this/],
    ['a supplier the API has none of', page, refused(404, 'NOT_FOUND'), /can't be found/],
    ['a supplier whose records failed', page, refused(503, 'INTEGRITY_FAILED'), /integrity/],
  ])('says %s plainly', { timeout: 10_000 }, async (_what, path, given, said) => {
    as('admin');
    if (given !== undefined) answer(`GET ${at}`, given);
    open(path);
    expect(await screen.findByText(said, {}, { timeout: 8000 })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Back to suppliers' })).toBeDefined();
  });

  it('shows a viewer the supplier with nothing to press', async () => {
    as('viewer');
    open(page);
    expect(await screen.findByText('Only an admin or an approver can verify a supplier.')).toBeDefined();
    expect(screen.queryByRole('button')).toBeNull();
  });

  it('offers a developer no way to verify a supplier', async () => {
    as('developer');
    open(page);
    expect(await screen.findByText('Only an admin or an approver can verify a supplier.')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Verify' })).toBeNull();
  });
});

describe('verifying by a call-back (6D2)', () => {
  it('asks for the tick first, then confirms and goes by passkey with the call-back alone', async () => {
    as('admin');
    answer(`POST ${at}/verify`, ASKED);
    open(page);
    expect(await screen.findByText(/Call the supplier on \+971501234567, the number on file/)).toBeDefined();
    // The tick is never made for them.
    expect(screen.getByRole<HTMLInputElement>('checkbox').checked).toBe(false);
    await press('Verify');
    expect(await screen.findByText(/Tick that you called the supplier back/)).toBeDefined();
    expect(posts()).toHaveLength(0);

    await userEvent.click(
      screen.getByLabelText('I called +971501234567 and the supplier confirmed these bank details'),
    );
    await press('Verify');
    await inDialog('Continue with passkey');

    expect(sentTo('POST', `${at}/verify`)[0]?.body).toEqual({ calledBack: true });
    expect(goTo).toHaveBeenCalledWith(expect.stringContaining(`/v1/auth/step-up?challenge=${CHALLENGE}`));
    expect(kept()).toMatchObject({
      label: 'Verify Gulf Traders',
      confirmPath: `${at}/verify/confirm`,
      body: { calledBack: true },
      organization: ORG.id,
    });
  });

  it('needs a note of the call when the name check wasn’t a full match, by the API’s rules', async () => {
    as('approver', supplier({ payee: { ...PAYEE, nameCheck: 'partial' } }));
    answer(`POST ${at}/verify`, ASKED);
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    const note = screen.getByLabelText(/Your note of the call \(needed/);

    await press('Verify');
    expect(await screen.findByText(/Write who you spoke to/)).toBeDefined();
    await userEvent.type(note, 'Spoke to Sara, call 050 123 4567');
    await press('Verify');
    expect(await screen.findByText(/Write who you spoke to/)).toBeDefined();
    expect(posts()).toHaveLength(0);

    await userEvent.clear(note);
    await userEvent.type(note, '  Spoke to Sara in accounts; she read back the account ending  ');
    await press('Verify');
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/verify`)[0]?.body).toEqual({
      calledBack: true,
      note: 'Spoke to Sara in accounts; she read back the account ending',
    });
  });

  it('sends an optional note when one is written on a full match', async () => {
    as('admin');
    answer(`POST ${at}/verify`, ASKED);
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await userEvent.type(screen.getByLabelText(/Your note of the call \(if you want one\)/), 'Spoke to Omar');
    await press('Verify');
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/verify`)[0]?.body).toEqual({ calledBack: true, note: 'Spoke to Omar' });
  });

  it('checks an optional note by the same rules, and sends nothing while it breaks them', async () => {
    as('admin');
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await userEvent.type(screen.getByLabelText(/Your note of the call \(if you want one\)/), 'Called 050 123 4567');
    await press('Verify');
    expect(await screen.findByText(/Write who you spoke to/)).toBeDefined();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts()).toHaveLength(0);
  });

  it.each([
    ['VERIFIER_ENTERED_DETAILS', 403, /someone else must verify the supplier/],
    ['SUPPLIER_PHONE_TOO_NEW', 409, /changed less than 30 days ago/],
    ['SOMETHING_NEW', 409, /reason SOMETHING_NEW/],
    ['INTEGRITY_FAILED', 503, /failed Agent X's integrity check/],
  ])('says a verify refused with %s plainly, and reads the supplier again', async (code, status, said) => {
    as('admin');
    answer(`POST ${at}/verify`, refused(status, code));
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await press('Verify');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(said)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
    if (status < 500) expect(sentTo('GET', at).length).toBeGreaterThan(1);
  });

  it('refuses a verify answered with no passkey asked, as nothing was made', async () => {
    as('admin');
    answer(`POST ${at}/verify`, { status: 200, body: supplier({ status: 'VERIFIED' }) });
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await press('Verify');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('goes to the sign-in page when the session ended', async () => {
    as('admin');
    answer(`POST ${at}/verify`, refused(401, 'UNAUTHENTICATED'));
    open(page);
    await userEvent.click(await screen.findByRole('checkbox'));
    await press('Verify');
    await inDialog('Continue with passkey');
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
  });
});

describe('payment emails to the supplier (6D2)', () => {
  it('lets an admin turn them off by passkey, sending only the new choice', async () => {
    as('admin');
    answer(`POST ${at}/remittance-email`, ASKED);
    open(page);
    await press('Turn payment emails off');
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/^Off: it isn't emailed/)).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/remittance-email`)[0]?.body).toEqual({ remittanceEmail: 'off' });
    expect(kept()).toMatchObject({
      label: 'Turn payment emails off for Gulf Traders',
      confirmPath: `${at}/remittance-email/confirm`,
      body: { remittanceEmail: 'off' },
    });
  });

  it('turns them on when off, and says a refusal plainly', async () => {
    as('admin', supplier({ remittanceEmail: 'off' }));
    answer(`POST ${at}/remittance-email`, refused(409, 'SUPPLIER_REMITTANCE_UNCHANGED'));
    open(page);
    await press('Turn payment emails on');
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/remittance-email`)[0]?.body).toEqual({ remittanceEmail: 'on' });
    expect(await screen.findByText(/already set that way/)).toBeDefined();
  });

  it('refuses a change answered with no passkey asked, as nothing was made', async () => {
    as('admin');
    answer(`POST ${at}/remittance-email`, { status: 200, body: supplier({ remittanceEmail: 'off' }) });
    open(page);
    await press('Turn payment emails off');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('sends nothing when its confirm is backed out of', async () => {
    as('admin');
    open(page);
    await press('Turn payment emails off');
    await inDialog('Cancel');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts()).toHaveLength(0);
  });

  it('shows an approver the setting with no switch', async () => {
    as('approver');
    open(page);
    expect(await screen.findByText(/^On: when a payment/)).toBeDefined();
    expect(screen.queryByRole('button', { name: /Turn payment emails/ })).toBeNull();
  });
});

const WAITING = supplier({
  changeWaiting: true,
  pendingChange: {
    version: 3,
    enteredAt: PAST,
    payee: { ...PAYEE, payeeHint: 'AE…9999', nameCheck: 'partial' },
  },
});

describe('new bank details waiting (6D2)', () => {
  it('lets an admin confirm them by passkey, with nothing in the body', async () => {
    as('admin', WAITING);
    answer(`POST ${at}/payee-change/approve`, ASKED);
    open(page);
    expect(await screen.findByText('New bank details waiting')).toBeDefined();
    expect(screen.getByText('AE…9999')).toBeDefined();
    // New details waiting: none can be given again until they are confirmed or withdrawn.
    expect(screen.queryByRole('button', { name: 'Change bank details' })).toBeNull();
    await press('Confirm new bank details');
    expect(within(await screen.findByRole('dialog')).getByText(/24-hour cooling-off/)).toBeDefined();
    await inDialog('Continue with passkey');
    expect(sentTo('POST', `${at}/payee-change/approve`)[0]?.body).toEqual({});
    expect(kept()).toMatchObject({ confirmPath: `${at}/payee-change/approve/confirm`, body: {} });
  });

  it('says plainly when only the admin who entered them may confirm them', async () => {
    as('admin', WAITING);
    answer(`POST ${at}/payee-change/approve`, refused(403, 'PAYEE_CHANGE_NOT_YOURS'));
    open(page);
    await press('Confirm new bank details');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/Only the admin who entered these bank details/)).toBeDefined();
  });

  it('refuses a confirm answered with no passkey asked, as nothing was made', async () => {
    as('admin', WAITING);
    answer(`POST ${at}/payee-change/approve`, { status: 200, body: supplier() });
    open(page);
    await press('Confirm new bank details');
    await inDialog('Continue with passkey');
    expect(await screen.findByText(/answered without asking for your passkey/)).toBeDefined();
    expect(goTo).not.toHaveBeenCalled();
  });

  it('offers a developer no way to withdraw or confirm them', async () => {
    as('developer', WAITING);
    open(page);
    expect(await screen.findByText('New bank details waiting')).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Withdraw new details' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Confirm new bank details' })).toBeNull();
  });

  it('lets an approver withdraw them at once, with no passkey, and reads the supplier again', async () => {
    as('approver', WAITING);
    // Read again after, the details waiting are gone: what was done is still said.
    answer(`GET ${at}`, { status: 200, body: WAITING }, { status: 200, body: supplier() });
    answer(`POST ${at}/payee-change/withdraw`, { status: 200, body: supplier() });
    open(page);
    expect(await screen.findByRole('button', { name: 'Withdraw new details' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Confirm new bank details' })).toBeNull();
    await press('Withdraw new details');
    await inDialog('Withdraw now');
    await vi.waitFor(() => {
      expect(screen.queryByText('New bank details waiting')).toBeNull();
    });
    expect(screen.getByText('The new bank details were withdrawn.')).toBeDefined();
    expect(sentTo('POST', `${at}/payee-change/withdraw`)[0]?.body).toBeUndefined();
    expect(goTo).not.toHaveBeenCalled();
    expect(sentTo('GET', at).length).toBeGreaterThan(1);
  });

  it('keeps a refusal said once the re-read shows no details waiting any more', async () => {
    as('approver', WAITING);
    answer(`GET ${at}`, { status: 200, body: WAITING }, { status: 200, body: supplier() });
    answer(`POST ${at}/payee-change/withdraw`, refused(409, 'SUPPLIER_NO_CHANGE_WAITING'));
    open(page);
    await press('Withdraw new details');
    await inDialog('Withdraw now');
    await vi.waitFor(() => {
      expect(screen.queryByText('New bank details waiting')).toBeNull();
    });
    expect(screen.getByText(/No new bank details are waiting any more/)).toBeDefined();
  });
});

/** What a pass-through with no answer or decision says. */
const UNANSWERED = /didn't answer, so it isn't known yet/;

/** A check while the partner's form is still being filled in: nothing changed. */
const ASKED_FORM = { status: 202, body: registration({ route: 'hosted', status: 'STARTED' }) };

/** Holds each POST until released, in turn, so what shows while one is on its way can be seen. */
function holdPosts(): () => Promise<void> {
  const stub = vi.mocked(fetch);
  const answering = stub.getMockImplementation();
  const held: (() => void)[] = [];
  stub.mockImplementation((input, init) => {
    const go = () => answering?.(input, init) ?? Promise.reject(new Error('No stand-in API'));
    if (init?.method !== 'POST') return go();
    return new Promise<Response>((resolve, reject) => {
      held.push(() => {
        go().then(resolve, reject);
      });
    });
  });
  return async () => {
    await vi.waitFor(() => {
      expect(held.length).toBeGreaterThan(0);
    });
    held.shift()?.();
  };
}

/** Opens new bank details, says how they came, and chooses how to give them. */
async function giving(told: 'Yes, by email, a letter or a message' | 'No', route: 'here' | 'hosted') {
  await press('Change bank details');
  await userEvent.click(screen.getByLabelText(told));
  if (told !== 'No') {
    await userEvent.click(
      screen.getByLabelText('I called +971501234567 and the supplier confirmed the new bank details are theirs'),
    );
  }
  await userEvent.click(
    screen.getByLabelText(
      route === 'here'
        ? 'Type them here: they go straight to the bank partner, and Agent X never keeps them'
        : "On the bank partner's own page",
    ),
  );
}

/** Types the bank details to pass through, and goes on to the confirm with the pending requests held. */
async function typed(iban = IBAN) {
  await userEvent.type(screen.getByLabelText("Account holder's name"), 'Gulf Traders LLC');
  await userEvent.type(screen.getByLabelText('IBAN'), iban);
  await press('Continue');
  await userEvent.click(await within(await screen.findByRole('dialog')).findByLabelText('Its requests are held.'));
}

describe('giving new bank details (6D2, ADR-012)', () => {
  it('asks whether they came by email first, none picked, and on yes warns and wants the call-back first', async () => {
    as('admin');
    open(page);
    await press('Change bank details');
    expect(screen.getAllByRole('radio').every((one) => !(one as HTMLInputElement).checked)).toBe(true);
    await press('Continue');
    expect(await screen.findByText(/Say whether the bank details came by email/)).toBeDefined();

    await userEvent.click(screen.getByLabelText('Yes, by email, a letter or a message'));
    expect(screen.getByText(/how most payment fraud starts/)).toBeDefined();
    expect(screen.getByText(/never a number in the message or on an invoice/)).toBeDefined();
    await press('Continue');
    expect(await screen.findByText(/Call the supplier on \+971501234567 first, and tick that you did/)).toBeDefined();

    await userEvent.click(
      screen.getByLabelText('I called +971501234567 and the supplier confirmed the new bank details are theirs'),
    );
    await press('Continue');
    expect(await screen.findByText('Choose how to give the bank details.')).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('gives no warning on no', async () => {
    as('admin');
    open(page);
    await press('Change bank details');
    await userEvent.click(screen.getByLabelText('No'));
    expect(screen.queryByText(/how most payment fraud starts/)).toBeNull();
  });

  it('checks the holder’s name and the IBAN by the API’s rules before anything is sent', async () => {
    as('admin');
    open(page);
    await giving('No', 'here');
    await press('Continue');
    expect(await screen.findByText(/Enter the account holder's name/)).toBeDefined();
    await userEvent.type(screen.getByLabelText("Account holder's name"), 'Gulf Traders LLC');
    await userEvent.type(screen.getByLabelText('IBAN'), 'AE08 0331 2345 6789 0123 456');
    await press('Continue');
    expect(await screen.findByText(/isn't a UAE IBAN with valid check digits/)).toBeDefined();
    expect(posts()).toHaveLength(0);
  });

  it('passes the details through with the pending requests’ fate chosen in the API’s words, nothing kept', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 201, body: registration() });
    open(page);
    await giving('Yes, by email, a letter or a message', 'here');
    await userEvent.type(screen.getByLabelText("Account holder's name"), 'Gulf Traders LLC');
    await userEvent.type(screen.getByLabelText('IBAN'), IBAN);
    await press('Continue');
    const dialog = await screen.findByRole('dialog');
    const send = within(dialog).getByRole('button', { name: 'Send to the bank partner' });
    const options = await within(dialog).findAllByRole('radio');
    expect(options.map((one) => one.getAttribute('value'))).toEqual(['cancel', 'pause']);
    expect(send.hasAttribute('disabled')).toBe(true);
    expect(within(dialog).getByText(IBAN)).toBeDefined();
    await userEvent.click(within(dialog).getByLabelText('Its requests are held.'));
    await userEvent.click(send);

    expect(sentTo('POST', `${at}/payee-registrations/pass-through`)[0]?.body).toEqual({
      name: 'Gulf Traders LLC',
      iban: IBAN,
      pendingRequests: 'pause',
      statementVersion: 2,
    });
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    // The form is closed and nothing typed is kept anywhere: not on screen, not in the tab's storage.
    expect(screen.queryByLabelText('IBAN')).toBeNull();
    expect(sessionStorage).toHaveLength(0);
    expect(goTo).not.toHaveBeenCalled();
    expect(sentTo('GET', at).length).toBeGreaterThan(1);
  });

  it('asks the partner again with the same key when its answer was lost, and a new key only once stopped', async () => {
    as('admin');
    answer(
      `POST ${at}/payee-registrations/pass-through`,
      refused(503, 'PARTNER_UNAVAILABLE'),
      refused(503, 'PARTNER_UNAVAILABLE'),
      { status: 201, body: registration({ status: 'FAILED', failure: 'invalid_details' }) },
    );
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    // Unanswered, only the same request can go again: no fresh one with a new key.
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();

    await press('Try again');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    const [first, again] = sentTo('POST', `${at}/payee-registrations/pass-through`);
    expect(again?.key).toBe(first?.key);
    expect(again?.body).toEqual(first?.body);

    // Nothing can be retyped while it waits: only the confirmed Stop trying drops the key.
    expect(screen.getByLabelText<HTMLInputElement>('IBAN').disabled).toBe(true);
    await press('Stop trying');
    expect(within(await screen.findByRole('dialog')).getByText(/could be registered twice/)).toBeDefined();
    await inDialog('Stop trying');
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    expect(screen.getByLabelText<HTMLInputElement>('IBAN').disabled).toBe(false);
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(false);
    await press('Continue');
    await userEvent.click(await within(await screen.findByRole('dialog')).findByLabelText('Its requests are held.'));
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(/couldn't use these bank details/)).toBeDefined();
    expect(sentTo('POST', `${at}/payee-registrations/pass-through`)[2]?.key).not.toBe(first?.key);
  });

  it.each([
    ['no answer at all', { status: 0 }],
    ['a server error', refused(500, 'UNAVAILABLE')],
    ['a gateway timeout', refused(504, 'UNREADABLE')],
  ])('keeps the same key for %s, and holds Cancel until it is asked again', async (_what, lost) => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, lost, { status: 201, body: registration() });
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    // Cancel would drop the key, and a fresh one would register the details again.
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);

    await press('Try again');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    const [first, again] = sentTo('POST', `${at}/payee-registrations/pass-through`);
    expect(again?.key).toBe(first?.key);
    expect(again?.body).toEqual(first?.body);
  });

  it.each([
    ['SUPPLIER_PAYEE_TAKEN', /already paid to this bank account/],
    ['PAYEE_REGISTRATIONS_SPENT', /as many bank details today/],
  ])('keeps no key once a retry meets the use case’s own %s: that try is ended', async (code, said) => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 }, refused(409, code));
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    await press('Try again');
    expect(await screen.findByText(said)).toBeDefined();
    expect(heldTry(WHOSE)).toBeUndefined();
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(false);
    expect(screen.getByLabelText<HTMLInputElement>('IBAN').disabled).toBe(false);
  });

  it.each([
    ['STATEMENT_CHANGED', 409, /words for what happens to pending requests have changed since the first try/],
    ['FORBIDDEN', 403, /role in this organisation can't do this\. Ask an admin\. The earlier try is still held/],
    ['PAYEE_ROUTE_NOT_OFFERED', 409, /doesn't take bank details that way\. .* The earlier try is still held/],
    ['ORG_FROZEN', 409, /frozen.* The earlier try is still held/],
    // Also said from the pass-through's Tx 2, its registration left open at the partner for this key.
    ['SUPPLIER_CHANGE_WAITING', 409, /Another change to this supplier is waiting.* The earlier try is still held/],
    ['IDEMPOTENCY_KEY_REUSED', 400, /reason IDEMPOTENCY_KEY_REUSED.* The earlier try is still held/],
  ])('keeps a held try locked with its key when a gate refuses its retry with %s', async (code, status, said) => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 }, refused(status, code), {
      status: 201,
      body: registration(),
    });
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    await press('Try again');
    expect(await screen.findByText(said)).toBeDefined();
    expect(screen.getByLabelText<HTMLInputElement>('IBAN').disabled).toBe(true);
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);
    await press('Try again');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    const sentKeys = sentTo('POST', `${at}/payee-registrations/pass-through`).map((one) => one.key);
    expect(new Set(sentKeys).size).toBe(1);
  });

  it('starts the IBAN empty once a restored try is stopped, never the whole number again', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 });
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    await userEvent.click(screen.getByRole('link', { name: 'Back to suppliers' }));
    await userEvent.click(await screen.findByRole('link', { name: 'Gulf Traders' }));
    await press('Stop trying');
    await inDialog('Stop trying');
    const iban = screen.getByLabelText<HTMLInputElement>('IBAN');
    expect(iban.disabled).toBe(false);
    expect(iban.value).toBe('');
    expect(screen.getByLabelText<HTMLInputElement>("Account holder's name").value).toBe('Gulf Traders LLC');
  });

  it('holds Cancel and Try again while a pass-through is on its way', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 }, { status: 201, body: registration() });
    open(page);
    await giving('No', 'here');
    await typed();
    const release = holdPosts();
    const dialog = await screen.findByRole('dialog');
    await inDialog('Send to the bank partner');
    // The form's own Cancel, not the confirm's: pressed now, the request on its way would be lost with its key.
    const formCancel = () =>
      screen.getAllByRole('button', { name: 'Cancel', hidden: true }).find((one) => !dialog.contains(one));
    await vi.waitFor(() => {
      expect(formCancel()?.hasAttribute('disabled')).toBe(true);
    });
    await release();
    expect(await screen.findByText(UNANSWERED)).toBeDefined();

    await press('Try again');
    await vi.waitFor(() => {
      expect(screen.getByRole('button', { name: 'Try again' }).hasAttribute('disabled')).toBe(true);
    });
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);
    await release();
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
  });

  it('locks the holder, the IBAN and the way of giving them while a try waits, and keeps the key until stopped', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 }, { status: 201, body: registration() });
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();

    const hosted = screen.getByLabelText<HTMLInputElement>("On the bank partner's own page");
    // Disabled by its fieldset, as the browser reads it.
    expect(hosted.matches(':disabled')).toBe(true);
    await userEvent.click(hosted);
    expect(hosted.checked).toBe(false);
    for (const label of ["Account holder's name", 'IBAN']) {
      const field = screen.getByLabelText<HTMLInputElement>(label);
      expect(field.disabled).toBe(true);
      await userEvent.type(field, 'x');
      expect(field.value).not.toContain('x');
    }
    expect(screen.getByRole('button', { name: 'Try again' })).toBeDefined();

    // Stopping needs its confirm: backed out of, the key is still kept.
    await press('Stop trying');
    await inDialog('Cancel');
    expect(screen.getByRole('button', { name: 'Try again' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);

    await press('Stop trying');
    await inDialog('Stop trying');
    await press('Continue');
    await userEvent.click(await within(await screen.findByRole('dialog')).findByLabelText('Its requests are held.'));
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    const [first, again] = sentTo('POST', `${at}/payee-registrations/pass-through`);
    expect(again?.key).not.toBe(first?.key);
  });

  it('checks and sends the holder’s name trimmed, as the confirm shows it', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 201, body: registration() });
    open(page);
    await giving('No', 'here');
    await userEvent.type(screen.getByLabelText("Account holder's name"), '  Gulf Traders LLC  ');
    await userEvent.type(screen.getByLabelText('IBAN'), IBAN);
    await press('Continue');
    await userEvent.click(await within(await screen.findByRole('dialog')).findByLabelText('Its requests are held.'));
    await inDialog('Send to the bank partner');
    expect(sentTo('POST', `${at}/payee-registrations/pass-through`)[0]?.body).toMatchObject({
      name: 'Gulf Traders LLC',
    });
  });

  it('says a pass-through refused for a record that failed its integrity check as that, not as unanswered', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, refused(503, 'INTEGRITY_FAILED'));
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(/failed Agent X's integrity check/)).toBeDefined();
    expect(screen.queryByText(UNANSWERED)).toBeNull();
  });

  it('clears what the partner answered once anything else is pressed', async () => {
    as('admin');
    answer(`GET ${at}`, { status: 200, body: supplier() }, { status: 200, body: WAITING });
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 201, body: registration() });
    answer(`POST ${at}/payee-change/withdraw`, { status: 200, body: supplier() });
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    await press('Withdraw new details');
    await inDialog('Withdraw now');
    expect(await screen.findByText('The new bank details were withdrawn.')).toBeDefined();
    expect(screen.queryByText(/The bank partner has the new bank details/)).toBeNull();
  });

  it('clears what the partner answered when new details are opened again', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 201, body: registration() });
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    await press('Change bank details');
    expect(screen.queryByText(/The bank partner has the new bank details/)).toBeNull();
  });

  it('keeps no key after a refusal: the API decided, so nothing is asked again', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, refused(409, 'PAYEE_REGISTRATIONS_SPENT'));
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(/as many bank details today/)).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(false);
  });

  /** Sends the details and leaves the try with no answer, held for Try again. */
  const unansweredTry = async (...after: Answer[]) => {
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 }, ...after);
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
  };
  const passThroughs = () => sentTo('POST', `${at}/payee-registrations/pass-through`);

  it.each([
    ['still being worked on', refused(409, 'IDEMPOTENCY_KEY_BUSY'), /still being worked on/],
    ['too many tries', refused(429, 'RATE_LIMITED'), /too many tries just now/],
  ])(
    'keeps the try held when a retry is answered %s: the same key, locked, Cancel held',
    async (_what, undecided, said) => {
      as('admin');
      await unansweredTry(undecided, { status: 201, body: registration() });
      await press('Try again');
      expect(await screen.findByText(said)).toBeDefined();
      expect(screen.getByLabelText<HTMLInputElement>('IBAN').disabled).toBe(true);
      expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);
      await press('Try again');
      expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
      const [first, , third] = passThroughs();
      expect(third?.key).toBe(first?.key);
      expect(third?.body).toEqual(first?.body);
      // Answered, the try is held no longer.
      expect(heldTry(WHOSE)).toBeUndefined();
    },
  );

  it('comes back locked with the same key after leaving the page, the IBAN shown masked', async () => {
    as('admin');
    await unansweredTry({ status: 201, body: registration() });
    await userEvent.click(screen.getByRole('link', { name: 'Back to suppliers' }));
    await userEvent.click(await screen.findByRole('link', { name: 'Gulf Traders' }));

    const iban = await screen.findByLabelText<HTMLInputElement>('IBAN');
    expect(iban.disabled).toBe(true);
    expect(iban.value).toBe('AE…3456');
    expect(screen.getByLabelText<HTMLInputElement>("Account holder's name").value).toBe('Gulf Traders LLC');
    expect(screen.getByRole('button', { name: 'Cancel' }).hasAttribute('disabled')).toBe(true);
    expect(screen.queryByRole('button', { name: 'Continue' })).toBeNull();
    // Stopping still needs its confirm.
    await press('Stop trying');
    await inDialog('Cancel');
    await press('Try again');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    const [first, again] = passThroughs();
    expect(again?.key).toBe(first?.key);
    expect(again?.body).toEqual(first?.body);
  });

  it('comes back with how the details came, as said before sending: the warning and the call-back tick', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations/pass-through`, { status: 0 });
    open(page);
    await giving('Yes, by email, a letter or a message', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText(UNANSWERED)).toBeDefined();
    await userEvent.click(screen.getByRole('link', { name: 'Back to suppliers' }));
    await userEvent.click(await screen.findByRole('link', { name: 'Gulf Traders' }));

    expect(await screen.findByLabelText('IBAN')).toBeDefined();
    expect(screen.getByLabelText<HTMLInputElement>('Yes, by email, a letter or a message').checked).toBe(true);
    expect(screen.getByText(/how most payment fraud starts/)).toBeDefined();
    expect(
      screen.getByLabelText<HTMLInputElement>(
        'I called +971501234567 and the supplier confirmed the new bank details are theirs',
      ).checked,
    ).toBe(true);
  });

  it('keeps the page and the held try when a re-read of the supplier fails, saying so in place', async () => {
    as('admin');
    await unansweredTry(refused(409, 'IDEMPOTENCY_KEY_BUSY'));
    answer(`GET ${at}`, refused(403, 'FORBIDDEN'));
    // The busy answer is a refusal, so everything shown is read again: this time it fails.
    await press('Try again');
    await vi.waitFor(() => {
      expect(screen.getAllByRole('button', { name: 'Try again' })).toHaveLength(2);
    });
    expect(screen.getByRole('heading', { name: 'Gulf Traders' })).toBeDefined();
    expect(screen.getByLabelText<HTMLInputElement>('IBAN').disabled).toBe(true);
    expect(heldTry(WHOSE)?.key).toBe(passThroughs()[0]?.key);

    // The read's own Try again (above the supplier) reads it again and sends nothing to the bank partner.
    const before = posts().length;
    answer(`GET ${at}`, { status: 200, body: supplier() });
    const [readAgain] = screen.getAllByRole('button', { name: 'Try again' });
    if (readAgain === undefined) throw new Error('the read’s Try again is missing');
    await userEvent.click(readAgain);
    await vi.waitFor(() => {
      expect(screen.getAllByRole('button', { name: 'Try again' })).toHaveLength(1);
    });
    expect(posts()).toHaveLength(before);
    expect(heldTry(WHOSE)?.key).toBe(passThroughs()[0]?.key);
  });

  it('says a first read that fails, and shows the supplier once Try again reads it', async () => {
    as('admin');
    answer(`GET ${at}`, refused(403, 'FORBIDDEN'));
    open(page);
    await screen.findByRole('button', { name: 'Try again' }, { timeout: 5000 });
    expect(screen.queryByRole('heading', { name: 'Gulf Traders' })).toBeNull();
    answer(`GET ${at}`, { status: 200, body: supplier() });
    await press('Try again');
    expect(await screen.findByRole('heading', { name: 'Gulf Traders' })).toBeDefined();
  });

  it('keeps a held try through a session that ends, for the same person alone', async () => {
    as('admin');
    await unansweredTry(refused(401, 'UNAUTHENTICATED'), { status: 201, body: registration() });
    await press('Try again');
    expect(await screen.findByText('Your session ended. Sign in again to carry on.')).toBeDefined();
    const kept = heldTry(WHOSE);
    expect(kept).toBeDefined();
    cleanup();

    // Someone else signs in on the tab: nothing of the first person's try shows.
    as('admin');
    answer('GET /v1/auth/session', {
      status: 200,
      body: { userId: OTHER, authenticatedAt: PAST, methods: ['pwd'], idleExpiresAt: FUTURE, expiresAt: FUTURE },
    });
    open(page);
    expect(await screen.findByRole('button', { name: 'Change bank details' })).toBeDefined();
    expect(screen.queryByLabelText('IBAN')).toBeNull();
    cleanup();

    // The same person signs in again: the form is back, locked, and goes on with the same key.
    as('admin');
    open(page);
    const iban = await screen.findByLabelText<HTMLInputElement>('IBAN');
    expect(iban.disabled).toBe(true);
    await press('Try again');
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    expect(sentTo('POST', `${at}/payee-registrations/pass-through`)[0]?.key).toBe(kept?.key);
  });

  it('drops every held try when signing out and when the page is left', async () => {
    as('admin');
    answer('POST /v1/auth/sign-out', { status: 200 });
    await unansweredTry();
    await userEvent.click(screen.getByRole('link', { name: /More/ }));
    await press('Sign out');
    await vi.waitFor(() => {
      expect(heldTry(WHOSE)).toBeUndefined();
    });
    cleanup();

    as('admin');
    await unansweredTry();
    window.dispatchEvent(new Event('pagehide'));
    expect(heldTry(WHOSE)).toBeUndefined();
  });

  it('keeps a refusal said once the re-read shows a change waiting and the form gone', async () => {
    as('admin');
    answer(`GET ${at}`, { status: 200, body: supplier() }, { status: 200, body: WAITING });
    answer(`POST ${at}/payee-registrations/pass-through`, refused(409, 'SUPPLIER_CHANGE_WAITING'));
    open(page);
    await giving('No', 'here');
    await typed();
    await inDialog('Send to the bank partner');
    expect(await screen.findByText('New bank details waiting')).toBeDefined();
    expect(screen.queryByLabelText('IBAN')).toBeNull();
    expect(screen.getByText(/Another change to this supplier is waiting/)).toBeDefined();
    // Kept: the API may have said it after the partner registered the payee, so the same key must finish it.
    expect(heldTry(WHOSE)).toBeDefined();
  });

  it('asks the browser never to save or offer back the holder’s name or the IBAN', async () => {
    as('admin');
    open(page);
    await giving('No', 'here');
    for (const field of [screen.getByLabelText("Account holder's name"), screen.getByLabelText('IBAN')]) {
      expect(field.getAttribute('autocomplete')).toBe('off');
      expect(field.getAttribute('spellcheck')).toBe('false');
    }
  });

  it('sends the person to the partner’s own page, and checks it once they are back', async () => {
    as('admin');
    answer(`POST ${at}/payee-registrations`, {
      status: 201,
      body: registration({
        route: 'hosted',
        status: 'STARTED',
        nameCheck: null,
        maskedName: null,
        payeeHint: null,
        form: { url: 'https://partner.example/form/1', expiresAt: FUTURE },
      }),
    });
    answer(`POST ${at}/payee-registrations/${REGISTRATION}/check`, ASKED_FORM, {
      status: 200,
      body: registration({ route: 'hosted' }),
    });
    open(page);
    await giving('No', 'hosted');
    expect(screen.queryByLabelText('IBAN')).toBeNull();
    await press('Continue');
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(await within(dialog).findByLabelText('Its requests are cancelled.'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue to the bank partner' }));
    expect(sentTo('POST', `${at}/payee-registrations`)[0]?.body).toEqual({
      pendingRequests: 'cancel',
      statementVersion: 2,
    });

    const link = await screen.findByRole('link', { name: "Open the bank partner's page" });
    expect(link.getAttribute('href')).toBe('https://partner.example/form/1');
    expect(link.getAttribute('target')).toBe('_blank');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    await press("I've finished: check");
    expect(await screen.findByText(/doesn't have the details yet/)).toBeDefined();
    await press("I've finished: check");
    expect(await screen.findByText(/The bank partner has the new bank details/)).toBeDefined();
    expect(sentTo('POST', `${at}/payee-registrations/${REGISTRATION}/check`)[1]?.body).toBeUndefined();
  });

  it.each(['http://partner.example/form/1', 'javascript:alert(1)'])(
    '6F1 G5: links to no partner page that isn’t https (%s), and says so',
    async (url) => {
      as('admin');
      answer(`POST ${at}/payee-registrations`, {
        status: 201,
        body: registration({
          route: 'hosted',
          status: 'STARTED',
          nameCheck: null,
          maskedName: null,
          payeeHint: null,
          form: { url, expiresAt: FUTURE },
        }),
      });
      open(page);
      await giving('No', 'hosted');
      await press('Continue');
      const dialog = await screen.findByRole('dialog');
      await userEvent.click(await within(dialog).findByLabelText('Its requests are cancelled.'));
      await userEvent.click(within(dialog).getByRole('button', { name: 'Continue to the bank partner' }));
      expect(await screen.findByText(/gave a page address Agent X won't open/)).toBeDefined();
      expect(screen.queryByRole('link', { name: "Open the bank partner's page" })).toBeNull();
    },
  );

  it.each([
    ['PAYEE_ROUTE_NOT_OFFERED', 409, /doesn't take bank details that way/],
    ['SUPPLIER_CHANGE_WAITING', 409, /Another change to this supplier is waiting/],
    ['STATEMENT_CHANGED', 409, /words you confirmed with have changed/],
  ])('says a registration refused with %s plainly', async (code, status, said) => {
    as('admin');
    answer(`POST ${at}/payee-registrations`, refused(status, code));
    open(page);
    await giving('No', 'hosted');
    await press('Continue');
    await userEvent.click(await within(await screen.findByRole('dialog')).findByLabelText('Its requests are held.'));
    await inDialog('Continue to the bank partner');
    expect(await screen.findByText(said)).toBeDefined();
  });

  it('drops everything typed when cancelled', async () => {
    as('admin');
    open(page);
    await giving('No', 'here');
    await userEvent.type(screen.getByLabelText('IBAN'), IBAN);
    await press('Cancel');
    await press('Change bank details');
    expect(screen.queryByLabelText('IBAN')).toBeNull();
    expect(screen.getByLabelText<HTMLInputElement>('No').checked).toBe(false);
  });

  it('offers adding the first bank details to an admin, and nothing to an approver', async () => {
    as('admin', supplier({ payee: null }));
    open(page);
    expect(await screen.findByRole('button', { name: 'Add bank details' })).toBeDefined();
    cleanup();
    as('approver', supplier({ payee: null }));
    open(page);
    expect(await screen.findByText('No bank details yet.')).toBeDefined();
    expect(screen.queryByRole('button', { name: /bank details$/ })).toBeNull();
  });
});

describe('adding a supplier (6D2)', () => {
  const fill = async () => {
    await userEvent.type(screen.getByLabelText('Name'), 'Gulf Traders');
    await userEvent.type(screen.getByLabelText('Phone for call-backs'), '+971501234567');
    await userEvent.click(screen.getByLabelText('An official trade registry'));
    await userEvent.type(screen.getByLabelText("The registry number, or the website's address"), 'DED/12345');
    await userEvent.click(screen.getByLabelText('No'));
  };

  it('checks every field by the API’s rules, none chosen for them, then adds it and opens its page', async () => {
    as('admin');
    answer('POST /v1/suppliers', { status: 201, body: supplier({ payee: null }) });
    const history = open('/more/suppliers');
    await press('Add a supplier');
    expect(screen.getAllByRole('radio').every((one) => !(one as HTMLInputElement).checked)).toBe(true);
    await press('Add supplier');
    expect(await screen.findByText(/Enter its name/)).toBeDefined();
    expect(screen.getByText(/Enter the phone in international form/)).toBeDefined();
    expect(screen.getByText('Choose where you checked its details.')).toBeDefined();
    expect(screen.getByText(/Enter the registry number/)).toBeDefined();
    expect(screen.getByText('Choose whether it is emailed when it is paid.')).toBeDefined();
    expect(screen.queryByText("This isn't one email address.")).toBeNull();

    await fill();
    await press('Add supplier');
    expect(within(await screen.findByRole('dialog')).getByText(/added unverified/)).toBeDefined();
    await inDialog('Add');

    expect(sentTo('POST', '/v1/suppliers')[0]?.body).toEqual({
      displayName: 'Gulf Traders',
      phone: '+971501234567',
      source: { kind: 'registry', ref: 'DED/12345' },
      remittanceEmail: 'off',
    });
    expect(await screen.findByRole('heading', { name: 'Gulf Traders' })).toBeDefined();
    expect(history.location.pathname).toBe(page);
  });

  it('sends an email and trade licence when given, and says a bad one in place', async () => {
    as('admin');
    answer('POST /v1/suppliers', refused(409, 'SUPPLIER_ADDS_SPENT'));
    open('/more/suppliers');
    await press('Add a supplier');
    await fill();
    await userEvent.type(screen.getByLabelText('Email (if known)'), 'not an email');
    await userEvent.type(screen.getByLabelText('Trade licence number (if known)'), '-12');
    await press('Add supplier');
    expect(await screen.findByText("This isn't one email address.")).toBeDefined();
    expect(screen.getByText(/A trade licence number has only/)).toBeDefined();

    await userEvent.clear(screen.getByLabelText('Email (if known)'));
    await userEvent.type(screen.getByLabelText('Email (if known)'), 'accounts@gulf.example');
    await userEvent.clear(screen.getByLabelText('Trade licence number (if known)'));
    await userEvent.type(screen.getByLabelText('Trade licence number (if known)'), 'DED-12345');
    await userEvent.click(screen.getByLabelText(/^Yes: its email gets/));
    await press('Add supplier');
    await inDialog('Add');
    expect(sentTo('POST', '/v1/suppliers')[0]?.body).toMatchObject({
      email: 'accounts@gulf.example',
      tradeLicence: 'DED-12345',
      remittanceEmail: 'on',
    });
    expect(await screen.findByText(/added as many suppliers today/)).toBeDefined();
  });

  it('closes the form when cancelled', async () => {
    as('admin');
    open('/more/suppliers');
    await press('Add a supplier');
    await press('Cancel');
    expect(screen.queryByLabelText('Name')).toBeNull();
  });

  it.each(['approver', 'viewer'])('offers an %s no way to add one', async (role) => {
    as(role);
    open('/more/suppliers');
    expect(await screen.findByRole('link', { name: 'Gulf Traders' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Add a supplier' })).toBeNull();
  });
});
