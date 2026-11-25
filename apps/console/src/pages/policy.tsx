// A policy's page (6D3b; BR-07, BR-08, PRD §5): the organisation's own at
// `/more/policy`, every agent's defaults, and a mandate's own at
// `/more/mandates/<id>/policy`, narrowing it for its agent within its terms.
// Every member reads the rules in force in plain words; an admin changes them
// (CHANGING_ROLES): every rule chosen in the shared editor, none picked for
// them, checked by the API's own rules in place, then the preview (decision
// 19): which requests waiting for approval the new rules would reject, each
// with its rules' words and what to do, and, when any would, what happens to
// them, the admin's to choose in the API's words. Confirmed with the new rules
// and the API's words for each choice (the organisation's monthly cap and
// approval wait, the waiting requests'), then asked: the ask's own plan of
// waiting requests must be the one the admin read, or it is shown again to
// read and choose afresh; then the passkey, and the change is confirmed back
// on this page (stepped-up.tsx), sending the versions of the words shown (CO3).
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { useMembers } from '../agents.ts';
import { api, ApiError, isMissing } from '../api.ts';
import { useBrakeList } from '../brakes.ts';
import { Confirm } from '../confirm.tsx';
import {
  CHANGING,
  PILOT_CURRENCY,
  type Draft,
  draftInForce,
  type MandateTerms,
  type Policy,
  policyAt,
  policyRefusal,
  type Problem,
  type Rules,
  rulesFrom,
  SIMULATING,
  type Target,
  usePolicy,
  useMandateTerms,
  useStatements,
  WAITING,
  WAITING_MOVED,
  type Waiting,
  type WaitingPreview,
  waitingOffered,
  waitingSeen,
  wordsOf,
} from '../policies.ts';
import { amountText, minorDigits, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { askFirst, changeAt } from '../step-up.ts';
import { t } from '../text.ts';
import { memberText } from './agent.tsx';
import { Said, useChange } from './change.tsx';
import { Choices } from './choices.tsx';
import { Loading, NotShown, Retry } from './failed.tsx';
import { MandateLink } from './mandate.tsx';
import { RuleEditor, RulesShown, SupplierNames, useSupplierNames } from './policy-rules.tsx';

/** The organisation's monthly cap in plain words where its choice says more than the amount: not chosen, or none. */
function orgMonthly(policy: Policy): string | undefined {
  if (policy.monthlyCapChoice === null) return t('policies.org.capNotChosen');
  return policy.monthlyCapChoice === 'none' ? t('policies.org.capNone') : undefined;
}

/** A mandate's terms, the bounds its own policy is held within. */
function Bounds({ terms, names }: { readonly terms: MandateTerms; readonly names: ReadonlyMap<string, string> }) {
  const money = (minor: number) => amountText(minor, terms.currency);
  return (
    <section className="stack" aria-labelledby="bounds-title">
      <h2 id="bounds-title">{t('policies.bounds.title')}</h2>
      <p className="muted">{t('policies.bounds.body')}</p>
      <dl className="facts">
        <dt>{t('policies.rule.perOrder')}</dt>
        <dd>{money(terms.perOrderLimitMinor)}</dd>
        <dt>{t('policies.bounds.monthly')}</dt>
        <dd>{money(terms.monthlyLimitMinor)}</dd>
        <dt>{t('policies.rule.threshold')}</dt>
        <dd>{t('policies.rule.above', { amount: money(terms.approvalThresholdMinor) })}</dd>
        <dt>{t('policies.rule.suppliers')}</dt>
        <dd>
          <SupplierNames ids={terms.supplierIds} names={names} />
        </dd>
      </dl>
    </section>
  );
}

/** The rules in force, who made them and when; the organisation's cap and wait as chosen. */
function InForce({ policy, names }: { readonly policy: Policy; readonly names: ReadonlyMap<string, string> }) {
  const { organization, session } = useActing();
  const members = useMembers(organization.id);
  const current = policy.current;
  const org = policy.scope === 'organization';
  const who = (membership: string) =>
    memberText(
      (members.data ?? []).find((member) => member.id === membership),
      session.userId.toLowerCase(),
    );
  return (
    <section className="stack" aria-labelledby="in-force-title">
      <h2 id="in-force-title">{t('policies.inForce')}</h2>
      {org && policy.monthlyCapChoice === null && (
        <p className="notice" role="status">
          {t('policies.org.capNotChosenNotice')}
        </p>
      )}
      {current === null ? (
        <p className="muted">{t(`policies.noneSet.${policy.scope}`)}</p>
      ) : (
        <>
          <RulesShown rules={current} names={names} monthly={org ? orgMonthly(policy) : undefined} />
          <p className="fine">
            {t('policies.version', {
              n: String(current.version),
              who: who(current.madeBy),
              time: timeText(current.madeAt),
            })}
          </p>
        </>
      )}
      {org && (
        <p>
          {policy.approvalWaitHours === null
            ? t('policies.org.waitNotChosen', { n: String(policy.approvalWaitInForceHours ?? '') })
            : t('policies.org.wait', { n: String(policy.approvalWaitHours) })}
        </p>
      )}
    </section>
  );
}

/** The rules checked and the requests waiting they would reject, as the preview answered. */
interface Checked {
  readonly rules: Rules;
  readonly wait: number | null;
  readonly preview: WaitingPreview;
}

type StatementsRead = ReturnType<typeof useStatements>['data'];

/** The waiting requests the change would reject, each with its rules' words and what to do; and the admin's choice. */
function WaitingShown({
  preview,
  read,
  unloaded,
  waiting,
  onWaiting,
  broken,
}: {
  readonly preview: WaitingPreview;
  readonly read: StatementsRead;
  readonly unloaded: boolean;
  readonly waiting: Waiting | null;
  readonly onWaiting: (choice: Waiting) => void;
  readonly broken: boolean;
}) {
  const { organization } = useActing();
  const agents = useBrakeList('agents', organization.id);
  const agentNames = new Map(
    (agents.data?.pages.flatMap((page) => page.listed) ?? []).map(({ id, name }) => [id.toLowerCase(), name]),
  );
  if (!waitingOffered(preview)) return <p role="status">{t('policies.preview.none')}</p>;
  const options = WAITING.flatMap((choice) => {
    const words = wordsOf(read, 'waiting_requests', choice);
    return words === undefined ? [] : [[choice, words.text] as const];
  });
  return (
    <section className="stack" aria-labelledby="waiting-title">
      <h3 id="waiting-title">{t('policies.preview.title')}</h3>
      <ul className="rows">
        {preview.rejected.map((request) => (
          <li key={request.id} className="row">
            <div className="row-main">
              <Link to="/approvals/$id" params={{ id: request.id }}>
                {agentNames.get(request.agentId.toLowerCase()) ?? t('policies.preview.agent')}
              </Link>
              <span className="muted mono">{request.agentId}</span>
              {request.reasons.map((reason) => (
                <span key={reason.code} className="reason">
                  {reason.message} {reason.whatToDo}
                </span>
              ))}
            </div>
            <b className="amount">{amountText(request.amountMinor, request.currency)}</b>
          </li>
        ))}
      </ul>
      {preview.more && <p className="muted">{t('policies.preview.more')}</p>}
      {unloaded && (
        <p className="notice" role="alert">
          {t('confirm.unloaded')}
        </p>
      )}
      {options.length === WAITING.length && (
        <Choices
          legend={t('policies.preview.choose')}
          options={options}
          chosen={waiting}
          onChoose={onWaiting}
          broken={broken ? t('policies.preview.chooseBroken') : undefined}
        />
      )}
    </section>
  );
}

/** What changing a policy sends: its rules, with the organisation's monthly cap choice and approval wait. */
function bodyOf(target: Target, { rules, wait }: Pick<Checked, 'rules' | 'wait'>): Readonly<Record<string, unknown>> {
  if (target.kind === 'mandate') return { ...rules };
  return { ...rules, monthlyCapChoice: rules.monthlyCapMinor === null ? 'none' : 'amount', approvalWaitHours: wait };
}

/** The API's words each choice is confirmed with, as read now: none until all the change needs are read. */
function wordsFor(target: Target, checked: Checked, waiting: Waiting | null, read: StatementsRead) {
  const shown: { readonly text: string; readonly field: string; readonly version: number }[] = [];
  const add = (id: string, choice: string, field: string) => {
    const words = wordsOf(read, id, choice);
    if (words !== undefined) shown.push({ text: words.text, field, version: words.version });
    return words !== undefined;
  };
  let all = true;
  if (target.kind === 'organization') {
    all = add('monthly_cap', checked.rules.monthlyCapMinor === null ? 'none' : 'amount', 'monthlyCapStatementVersion');
    all = add('approval_wait', 'confirm', 'approvalWaitStatementVersion') && all;
  }
  if (waiting !== null) all = add('waiting_requests', waiting, 'waitingStatementVersion') && all;
  return all ? shown : undefined;
}

/** An admin's change of a policy: the editor, the preview, the choice for the waiting requests, and the confirm. */
function PolicyChange({
  target,
  policy,
  currency,
  within,
}: {
  readonly target: Target;
  readonly policy: Policy;
  readonly currency: string;
  readonly within: MandateTerms | null;
}) {
  const { organization } = useActing();
  const org = target.kind === 'organization';
  const digits = minorDigits(currency);
  const start = () => draftInForce(policy, digits);
  const { listed, names, more } = useSupplierNames(organization.id);
  const { busy, said, run } = useChange(policyRefusal);
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<Draft>(start);
  const [problems, setProblems] = useState<readonly Problem[]>([]);
  const [checked, setChecked] = useState<Checked | null>(null);
  const [waiting, setWaiting] = useState<Waiting | null>(null);
  const [waitingBroken, setWaitingBroken] = useState(false);
  const [moved, setMoved] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const statements = useStatements(checked !== null);
  const read = statements.isFetching || statements.isError ? undefined : statements.data;
  // A mandate's may name only its own suppliers; the organisation's, any of the organisation's.
  const suppliers = within === null ? listed.map(({ id }) => id) : within.supplierIds;
  const offered = checked !== null && waitingOffered(checked.preview);
  const words = checked === null ? undefined : wordsFor(target, checked, offered ? waiting : null, read);
  const unchecked = () => {
    setChecked(null);
    setWaiting(null);
    setWaitingBroken(false);
    setMoved(false);
  };
  const change = (part: Partial<Draft>) => {
    setDraft({ ...draft, ...part });
    setProblems([]);
    unchecked();
  };
  const check = () => {
    const made = rulesFrom(draft, { currency, digits, withWait: org, within });
    if ('problems' in made) {
      setProblems(made.problems);
      return;
    }
    unchecked();
    void run(async () => {
      const preview = await api.post<WaitingPreview>(`${policyAt(target)}/change/preview`, {
        organization: organization.id,
        body: bodyOf(target, made),
      });
      setChecked({ ...made, preview });
    });
  };
  const toConfirm = () => {
    setWaitingBroken(offered && waiting === null);
    if (offered && waiting === null) return;
    // The words are read afresh as the confirm opens (as the shared confirm reads them): it waits for them.
    void statements.refetch();
    setConfirming(true);
  };
  const send = (sent: Checked) =>
    run(
      async () => {
        const body = { ...bodyOf(target, sent), ...(offered && waiting !== null && { waitingRequests: waiting }) };
        const versions = Object.fromEntries((words ?? []).map(({ field, version }) => [field, version]));
        try {
          const asked = await askFirst(
            changeAt(`${policyAt(target)}/change`, t(`policies.label.${target.kind}`), body, organization.id),
          );
          // Asked and answered with no passkey asked: nothing is said done that wasn't confirmed by one.
          if ('done' in asked) throw new ApiError(200, 'STEP_UP_NOT_ASKED');
          const plan = (asked.answer as { readonly waiting?: WaitingPreview }).waiting;
          if (plan !== undefined && waitingSeen(plan) === waitingSeen(sent.preview)) {
            return asked.stepUp(undefined, versions);
          }
          // The requests waiting moved since the preview: shown again as the ask weighed them, to read and choose afresh.
          setConfirming(false);
          setWaiting(null);
          setChecked(plan === undefined ? null : { ...sent, preview: plan });
          setMoved(true);
          return 'held';
        } catch (error) {
          if (error instanceof ApiError && WAITING_MOVED.has(error.code)) unchecked();
          throw error;
        }
      },
      {
        after: () => {
          setConfirming(false);
        },
      },
    );
  if (!open) {
    return (
      <>
        <button
          type="button"
          className="primary"
          onClick={() => {
            setOpen(true);
          }}
        >
          {t('policies.change')}
        </button>
        <Said said={said} />
      </>
    );
  }
  return (
    <section className="stack" aria-labelledby="change-title">
      <h2 id="change-title">{t('policies.change')}</h2>
      <p className="muted">
        {t(`policies.edit.${policy.current === null ? 'intro' : 'introInForce'}.${target.kind}`, { currency })}
      </p>
      <RuleEditor
        draft={draft}
        onChange={change}
        problems={problems}
        currency={currency}
        organization={org}
        withWait={org}
        suppliers={suppliers}
        names={names}
        more={within === null ? more : undefined}
      />
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setOpen(false);
            setDraft(start());
            setProblems([]);
            unchecked();
          }}
        >
          {t('confirm.cancel')}
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={check}>
          {t('policies.check')}
        </button>
      </div>
      {moved && (
        <p className="notice" role="alert">
          {t('policies.preview.moved')}
        </p>
      )}
      {checked !== null && (
        <>
          <WaitingShown
            preview={checked.preview}
            read={read}
            unloaded={statements.isError}
            waiting={waiting}
            onWaiting={(choice) => {
              setWaiting(choice);
              setWaitingBroken(false);
            }}
            broken={waitingBroken}
          />
          <button type="button" className="primary" disabled={busy} onClick={toConfirm}>
            {t('brakes.passkeyConfirm')}
          </button>
        </>
      )}
      <Said said={said} />
      {confirming && checked !== null && (
        <Confirm
          text={t(`policies.confirm.text.${target.kind}`)}
          title={t(`policies.confirm.title.${target.kind}`)}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          ready={words !== undefined}
          onCancel={() => {
            setConfirming(false);
          }}
          onConfirm={() => void send(checked)}
        >
          <RulesShown
            rules={checked.rules}
            names={names}
            monthly={org && checked.rules.monthlyCapMinor === null ? t('policies.org.capNone') : undefined}
          />
          {checked.wait !== null && <p>{t('policies.org.wait', { n: String(checked.wait) })}</p>}
          {words === undefined ? (
            <p className="notice" role="alert">
              {statements.isFetching ? t('loading') : t('confirm.unloaded')}
            </p>
          ) : (
            words.map(({ field, text }) => (
              <p key={field} className="statement">
                {text}
              </p>
            ))
          )}
        </Confirm>
      )}
    </section>
  );
}

/** The editor, once what it needs is read: a mandate's terms, for a mandate's policy. */
function Changing({
  target,
  policy,
  terms,
  termsFailed,
  ended,
}: {
  readonly target: Target;
  readonly policy: Policy;
  readonly terms: MandateTerms | null | undefined;
  /** The mandate couldn't be read at all, with the way to read it again; never for a failed re-read of one shown. */
  readonly termsFailed: (() => void) | undefined;
  /** The mandate was revoked or expired: its rules can't change (MANDATE_ENDED). */
  readonly ended: boolean;
}) {
  if (target.kind === 'organization') {
    return <PolicyChange target={target} policy={policy} currency={PILOT_CURRENCY} within={null} />;
  }
  if (termsFailed !== undefined) return <Retry onRetry={termsFailed} />;
  if (ended) return <p className="muted">{t('policies.ended')}</p>;
  if (terms === undefined) return <Loading />;
  if (terms === null) return <p className="muted">{t('policies.noTerms')}</p>;
  return <PolicyChange target={target} policy={policy} currency={terms.currency} within={terms} />;
}

export function PolicyPage({ target }: { readonly target: Target }) {
  const { organization } = useActing();
  const shown = usePolicy(target, organization.id);
  const mandateId = target.kind === 'mandate' ? target.mandateId : '';
  const mandate = useMandateTerms(mandateId, organization.id);
  const { names } = useSupplierNames(organization.id);
  const back =
    target.kind === 'organization' ? (
      <Link to="/more" className="back to-more">
        {t('policies.back')}
      </Link>
    ) : (
      <MandateLink id={mandateId}>{t('policies.backMandate')}</MandateLink>
    );
  const missing = target.kind === 'mandate' && isMissing(mandateId, shown.error);
  const policy = shown.data;
  if (missing || (shown.isError && policy === undefined)) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={shown.error}
        notFound={t('policies.notFound')}
        integrity={t('policies.integrity')}
        onRetry={() => void shown.refetch()}
      />
    );
  }
  if (policy === undefined) return <Loading />;
  const terms = target.kind === 'mandate' ? mandate.data?.terms : null;
  const ended = mandate.data?.ended === true;
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{t(`policies.kicker.${target.kind}`)}</span>
      <h1>{t(`policies.title.${target.kind}`)}</h1>
      <p className="muted">{t(`policies.intro.${target.kind}`)}</p>
      {target.kind === 'mandate' && !ended && SIMULATING.includes(organization.role) && (
        <Link to="/more/mandates/$id/simulate" params={{ id: mandateId }}>
          {t('policies.simulate.open')}
        </Link>
      )}
      {terms !== null && terms !== undefined && <Bounds terms={terms} names={names} />}
      <InForce policy={policy} names={names} />
      {CHANGING.includes(organization.role) ? (
        <Changing
          target={target}
          policy={policy}
          terms={terms}
          // Only a mandate never read: a failed re-read keeps the editor, and the draft in it.
          termsFailed={mandate.isError && mandate.data === undefined ? () => void mandate.refetch() : undefined}
          ended={ended}
        />
      ) : (
        <p className="muted">{t('policies.viewOnly')}</p>
      )}
    </section>
  );
}
