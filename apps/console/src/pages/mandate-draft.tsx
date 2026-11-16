// Drafting a mandate (6D3a, BR-05): `/more/mandates/new`, an admin's, for one
// of the organisation's active agents, with its time zone and split window
// (fixed for good) and its first terms; and a new version of one,
// `/more/mandates/<id>/new-version`, its terms filled in from the version in
// force (or the waiting draft) to change, every setting chosen again with
// none picked (Rule Book §1.9). Checked by the API's own rules before anything
// is sent, then confirmed with the terms shown in full and the over-limit
// choice made in the API's `over_limit` words, none picked; its version is
// sent back (CO3). A draft grants nothing: it waits for an admin to accept it
// with a passkey, so it is sent at once, no passkey.
//
// A draft sent with no answer may have been made: its key is held in this
// tab's memory (held-tries.ts) until the API truly decides, and the page
// offers only Try again (the same request, answered as made if the first one
// was) or a confirmed Stop trying, never a fresh send that could draft twice.
import { Link, useNavigate, useRouterState } from '@tanstack/react-router';
import { Fragment, type ReactNode, useState } from 'react';

import { api, isMissing, isUuid } from '../api.ts';
import { useBrakeList } from '../brakes.ts';
import { Confirm } from '../confirm.tsx';
import { type DraftWhose, type HeldDraft, heldDraft, holdDraft } from '../held-tries.ts';
import {
  decidesTheDraft,
  draftBody,
  draftFailure,
  draftProblems,
  type DraftProblem,
  type DraftTyped,
  isEnded,
  MANAGING,
  type MandateDetails,
  mandateAt,
  mandateRefusal,
  NO_TERMS,
  termsBody,
  termsFrom,
  termsProblems,
  type TermsTyped,
  useMandate,
  useSourceList,
  WINDOW_HOURS,
} from '../mandates.ts';
import { useActing } from '../session.tsx';
import { t, type TextKey } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Choices } from './choices.tsx';
import { Loading, NotShown } from './failed.tsx';
import { LineField } from './line-field.tsx';
import { type Broken, TermsFields } from './mandate-fields.tsx';
import { termRows, type Terms, useNames } from './mandate-terms.tsx';

/** A draft's body as sent: its terms, and for a new mandate its agent, zone and window. */
type Body = Terms & { readonly agentId?: string; readonly timeZone?: string; readonly splitWindowHours?: number };

/** The terms about to be sent, in full, as the confirm shows them. */
function Summary({ body, agent }: { readonly body: Body; readonly agent?: string | undefined }) {
  const names = useNames();
  const rows: (readonly [TextKey, string])[] = [];
  if (agent !== undefined) rows.push(['mandates.agent', agent]);
  if (body.timeZone !== undefined) rows.push(['mandates.timeZone', body.timeZone]);
  if (body.splitWindowHours !== undefined) {
    rows.push(['mandates.splitWindow', t('mandates.hours', { hours: String(body.splitWindowHours) })]);
  }
  rows.push(...termRows(body, names));
  return (
    <dl className="facts">
      {rows.map(([label, words]) => (
        <Fragment key={label}>
          <dt>{t(label)}</dt>
          <dd>{words}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

/** Sending a draft with its key held until the API decides it; `path` the draft's address. */
function useDraftSend(whose: DraftWhose, path: string) {
  const { organization } = useActing();
  const navigate = useNavigate();
  const { busy, said, run } = useChange(mandateRefusal);
  const [held, setShown] = useState(() => heldDraft(whose) ?? null);
  const hold = (tried: HeldDraft | null) => {
    holdDraft(whose, tried);
    setShown(tried);
  };
  const send = (tried: HeldDraft, retry: boolean, after?: () => void) =>
    run(
      async () => {
        try {
          const made = await api.post<MandateDetails>(path, {
            organization: organization.id,
            body: tried.body,
            idempotencyKey: tried.key,
          });
          hold(null);
          await navigate({ to: '/more/mandates/$id', params: { id: made.id } });
        } catch (error) {
          // No answer, or no decision: the draft may be made, and a fresh key could draft it twice (decidesTheDraft).
          hold(decidesTheDraft(error, retry) ? null : tried);
          throw error;
        }
      },
      { ...(after !== undefined && { after }), refusal: (error) => draftFailure(error, retry) },
    );
  return { busy, said, held, hold, send };
}

/** A draft sent with no answer: only the same request again, or a confirmed stop. */
function Held({
  held,
  busy,
  said,
  onRetry,
  onStop,
}: {
  readonly held: HeldDraft;
  readonly busy: boolean;
  readonly said: string | null;
  readonly onRetry: () => void;
  readonly onStop: () => void;
}) {
  const [stopping, setStopping] = useState(false);
  const purpose = typeof held.body.purpose === 'string' ? held.body.purpose : '';
  return (
    <section className="stack" aria-labelledby="held-title">
      <h2 id="held-title">{t('mandates.held.title')}</h2>
      <p className="notice">{t('mandates.held.text', { purpose })}</p>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setStopping(true);
          }}
        >
          {t('mandates.held.stop')}
        </button>
        <button type="button" className="primary" disabled={busy} onClick={onRetry}>
          {t('mandates.held.tryAgain')}
        </button>
      </div>
      <Said said={said} />
      {stopping && (
        <Confirm
          text={t('mandates.held.stopText')}
          title={t('mandates.held.stopTitle')}
          confirmLabel={t('mandates.held.stop')}
          onCancel={() => {
            setStopping(false);
          }}
          onConfirm={() => {
            setStopping(false);
            onStop();
          }}
        />
      )}
    </section>
  );
}

/** The form's frame: what it is, the fields, Cancel and Review, the confirm once reviewed, or the held draft instead. */
function DraftFrame({
  whose,
  path,
  title,
  back,
  children,
  review,
  agent,
}: {
  readonly whose: DraftWhose;
  readonly path: string;
  readonly title: string;
  readonly back: ReactNode;
  readonly children: ReactNode;
  /** The body to confirm, once nothing in the form would be refused; none (problems now said) otherwise. */
  readonly review: () => Body | undefined;
  readonly agent?: string | undefined;
}) {
  const { busy, said, held, hold, send } = useDraftSend(whose, path);
  const [confirming, setConfirming] = useState<Body | null>(null);
  const close = () => {
    setConfirming(null);
  };
  return (
    <section className="stack">
      {back}
      <h1>{title}</h1>
      {held === null ? (
        <>
          <p className="muted">{t('mandates.draft.intro')}</p>
          {children}
          <div className="actions">
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => {
                setConfirming(review() ?? null);
              }}
            >
              {t('mandates.draft.review')}
            </button>
          </div>
          <Said said={said} />
        </>
      ) : (
        <Held
          held={held}
          busy={busy}
          said={said}
          onRetry={() => void send(held, true)}
          onStop={() => {
            hold(null);
          }}
        />
      )}
      {confirming !== null && (
        <Confirm
          statement="over_limit"
          title={t('mandates.draft.confirmTitle')}
          confirmLabel={t('mandates.draft.confirm')}
          busy={busy}
          onCancel={close}
          onConfirm={(overLimit, statementVersion) =>
            void send({ key: crypto.randomUUID(), body: { ...confirming, overLimit, statementVersion } }, false, close)
          }
        >
          <Summary body={confirming} agent={agent} />
          <p>{t('mandates.draft.overLimitAsk')}</p>
        </Confirm>
      )}
    </section>
  );
}

/** What each problem says, in place. */
const brokenBy =
  (problems: readonly DraftProblem[]): Broken =>
  (problem) =>
    problems.includes(problem) ? t(`mandates.form.broken.${problem}`) : undefined;

/** The currency of the chosen bank account, as the API takes the mandate's: the version's own while it isn't listed. */
function useCurrency(source: string | null, fallback: string | undefined): string | undefined {
  const { organization } = useActing();
  const listed = useSourceList(organization.id);
  const found = (listed.data?.pages ?? []).flatMap((page) => page.listed).find(({ id }) => id === source);
  return found?.controls.currency ?? fallback;
}

/** Every IANA time zone the browser knows, for the admin to choose from: none picked for them. */
const ZONES: readonly string[] = Intl.supportedValuesOf('timeZone');

/** The new mandate's own: its agent among the organisation's active ones, its time zone and split window. */
function MandateOwn({
  typed,
  set,
  broken,
}: {
  readonly typed: DraftTyped;
  readonly set: (part: Partial<DraftTyped>) => void;
  readonly broken: Broken;
}) {
  const { organization } = useActing();
  const agents = useBrakeList('agents', organization.id);
  const active = (agents.data?.pages ?? []).flatMap((page) => page.listed).filter(({ suspended }) => !suspended);
  return (
    <>
      <Choices
        legend={t('mandates.form.agent')}
        options={active.map((agent) => [agent.id, `${agent.name} · ${agent.id}`] as const)}
        chosen={typed.agentId}
        onChoose={(agentId) => {
          set({ agentId });
        }}
        broken={broken('agent')}
      />
      {agents.isSuccess && active.length === 0 && <p className="muted">{t('mandates.form.noAgents')}</p>}
      <label className="field" htmlFor="mandate-zone">
        {t('mandates.form.timeZone')}
      </label>
      <select
        id="mandate-zone"
        value={typed.timeZone}
        aria-describedby="mandate-zone-hint"
        aria-invalid={broken('timeZone') !== undefined}
        onChange={(event) => {
          set({ timeZone: event.target.value });
        }}
      >
        <option value="">{t('mandates.form.timeZonePick')}</option>
        {ZONES.map((zone) => (
          <option key={zone} value={zone}>
            {zone}
          </option>
        ))}
      </select>
      <p id="mandate-zone-hint" className="fine">
        {t('mandates.form.timeZoneHint')}
      </p>
      {broken('timeZone') !== undefined && (
        <p className="notice" role="alert">
          {broken('timeZone')}
        </p>
      )}
      <LineField
        label={t('mandates.form.splitWindow')}
        hint={t('mandates.form.splitWindowHint', {
          least: String(WINDOW_HOURS.least),
          most: String(WINDOW_HOURS.most),
        })}
        most={3}
        value={typed.splitWindowHours}
        onChange={(splitWindowHours) => {
          set({ splitWindowHours });
        }}
        broken={broken('splitWindowHours')}
      />
    </>
  );
}

/** A new mandate: its agent (from `?agent=`, the agent page's link, when it names one), zone, window and first terms. */
function DraftForm() {
  const { organization, session } = useActing();
  const linked = useRouterState({ select: ({ location }) => new URLSearchParams(location.searchStr).get('agent') });
  const [typed, setTyped] = useState<DraftTyped>(() => ({
    ...NO_TERMS,
    agentId: linked !== null && isUuid(linked) ? linked : null,
    timeZone: '',
    splitWindowHours: '',
  }));
  const [problems, setProblems] = useState<readonly DraftProblem[]>([]);
  const currency = useCurrency(typed.fundingSourceId, undefined);
  const agents = useBrakeList('agents', organization.id);
  const agent = (agents.data?.pages ?? []).flatMap((page) => page.listed).find(({ id }) => id === typed.agentId);
  const set = (part: Partial<DraftTyped>) => {
    setTyped({ ...typed, ...part });
    setProblems([]);
  };
  const review = () => {
    const found = draftProblems(typed);
    // A source not listed can't be told apart from one the API would refuse: chosen again from the list.
    if (currency === undefined && !found.includes('source')) found.push('source');
    setProblems(found);
    return found.length === 0 && currency !== undefined ? draftBody(typed, currency) : undefined;
  };
  const broken = brokenBy(problems);
  return (
    <DraftFrame
      whose={{ user: session.userId, organization: organization.id, mandate: null }}
      path="/v1/mandates"
      title={t('mandates.draft.title')}
      back={
        <Link to="/more/mandates" className="back">
          {t('mandates.back')}
        </Link>
      }
      review={review}
      agent={agent?.name}
    >
      <MandateOwn typed={typed} set={set} broken={broken} />
      <TermsFields typed={typed} set={set} broken={broken} inForce={null} />
    </DraftFrame>
  );
}

/** Only an admin drafts: anyone else is told so. */
function AdminsOnly({ back }: { readonly back: ReactNode }) {
  return (
    <section className="stack">
      {back}
      <p className="muted">{t('mandates.viewOnly')}</p>
    </section>
  );
}

export function DraftMandate() {
  const { organization } = useActing();
  if (!MANAGING.includes(organization.role)) {
    return (
      <AdminsOnly
        back={
          <Link to="/more/mandates" className="back">
            {t('mandates.back')}
          </Link>
        }
      />
    );
  }
  return <DraftForm />;
}

/** A new version's terms, from the version in force (or the waiting draft) to change. */
function RedraftForm({ mandate, back }: { readonly mandate: MandateDetails; readonly back: ReactNode }) {
  const { organization, session } = useActing();
  const from = mandate.current ?? mandate.pending;
  const [typed, setTyped] = useState<TermsTyped>(() => (from === null ? NO_TERMS : termsFrom(from)));
  const [problems, setProblems] = useState<readonly DraftProblem[]>([]);
  const currency = useCurrency(typed.fundingSourceId, from?.currency);
  const set = (part: Partial<TermsTyped>) => {
    setTyped({ ...typed, ...part });
    setProblems([]);
  };
  const review = () => {
    const found = termsProblems(typed);
    setProblems(found);
    return found.length === 0 && currency !== undefined ? termsBody(typed, currency) : undefined;
  };
  return (
    <DraftFrame
      whose={{ user: session.userId, organization: organization.id, mandate: mandate.id }}
      path={`${mandateAt(mandate.id)}/supersede`}
      title={t('mandates.redraft.title', { purpose: from?.purpose ?? mandate.id })}
      back={back}
      review={review}
    >
      <p className="muted">{t('mandates.redraft.intro')}</p>
      <TermsFields typed={typed} set={set} broken={brokenBy(problems)} inForce={mandate.current} />
    </DraftFrame>
  );
}

export function NewVersion({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const shown = useMandate(id, organization.id);
  const back = (
    <Link to="/more/mandates/$id" params={{ id }} className="back">
      {t('mandates.redraft.back')}
    </Link>
  );
  const missing = isMissing(id, shown.error);
  if (missing || shown.isError) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={shown.error}
        notFound={t('mandates.notFound')}
        integrity={t('mandates.integrity')}
        onRetry={() => void shown.refetch()}
      />
    );
  }
  if (shown.isPending) return <Loading />;
  if (!MANAGING.includes(organization.role)) return <AdminsOnly back={back} />;
  if (isEnded(shown.data.status)) {
    return (
      <section className="stack">
        {back}
        <p className="muted">{t('mandates.endedNote')}</p>
      </section>
    );
  }
  return <RedraftForm mandate={shown.data} back={back} />;
}
