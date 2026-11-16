// The policy simulator (6D3b; BR-22; partner decision 9): at
// `/more/mandates/<id>/simulate`, for admins, approvers and developers
// (SIMULATING_ROLES). The person enters a test request as the mandate's agent
// would ask it (an amount, the supplier, the bank account to pay from, an
// order number if they want the duplicate check), chooses which rules weigh
// it (those in force, or proposed rules for this mandate's policy, the
// organisation's or both, chosen in the shared editor), and sees what it would
// get now: allowed, needs approval or refused, with each reason in the API's
// words, and the proposed rules weighed. Nothing is made, reserved or sent to
// anyone (the API's simulate writes nothing), which the answer says.
import { useState } from 'react';

import { api, isMissing, isUuid } from '../api.ts';
import { useBrakeList } from '../brakes.ts';
import {
  amountHint,
  type Checked,
  type Draft,
  draftFrom,
  type MandateTerms,
  PILOT_CURRENCY,
  type Policy,
  policyRefusal,
  type Problem,
  type Rules,
  rulesFrom,
  SIMULATING,
  type Simulation,
  simulateAt,
  useMandateTerms,
  usePolicy,
} from '../policies.ts';
import { amountMinor } from '../mandates.ts';
import { amountText, minorDigits } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { isVisibleName } from '../visible-name.ts';
import { Said, useChange } from './change.tsx';
import { Choices, FieldBroken } from './choices.tsx';
import { Loading, NotShown } from './failed.tsx';
import { AMOUNT_MOST, LineField } from './line-field.tsx';
import { MandateLink } from './mandate.tsx';
import { RuleEditor, RulesShown, useSupplierNames } from './policy-rules.tsx';

/** Which rules weigh the test request: those in force, or proposed ones in place of a policy's, or of both. */
const WEIGHED = ['inForce', 'mandate', 'organization', 'both'] as const;
type Weighed = (typeof WEIGHED)[number];

/** The most characters an order number may have (ORDER_REFERENCE_MOST). */
const ORDER_REFERENCE_MOST = 100;

interface Typed {
  readonly amount: string;
  readonly supplier: string;
  readonly source: string;
  readonly orderReference: string;
  readonly weighed: Weighed | null;
}

const EMPTY: Typed = { amount: '', supplier: '', source: '', orderReference: '', weighed: null };

type Field = 'amount' | 'supplier' | 'source' | 'orderReference' | 'weighed';

/** What the proposed rules were, as weighed: shown with the answer. */
interface Proposed {
  readonly organizationPolicy?: Rules;
  readonly mandatePolicy?: Rules;
}

const weighsOrganization = (weighed: Weighed | null) => weighed === 'organization' || weighed === 'both';
const weighsMandate = (weighed: Weighed | null) => weighed === 'mandate' || weighed === 'both';

/** Each field of the test request the API would refuse, checked before anything is sent. */
function typedProblems(typed: Typed, digits: number): readonly Field[] {
  const problems: Field[] = [];
  if (amountMinor(typed.amount, digits) === undefined) problems.push('amount');
  if (!isUuid(typed.supplier)) problems.push('supplier');
  if (!isUuid(typed.source)) problems.push('source');
  if (typed.orderReference !== '' && !isVisibleName(typed.orderReference, ORDER_REFERENCE_MOST)) {
    problems.push('orderReference');
  }
  if (typed.weighed === null) problems.push('weighed');
  return problems;
}

/** A choice from a list, none picked: `''` until the person picks one. */
function Pick({
  id,
  label,
  none,
  options,
  value,
  onChange,
  broken,
}: {
  readonly id: string;
  readonly label: string;
  readonly none: string;
  readonly options: readonly (readonly [string, string])[];
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly broken: string | undefined;
}) {
  return (
    <>
      <label className="field" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        aria-invalid={broken !== undefined}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      >
        <option value="">{none}</option>
        {options.map(([value, words]) => (
          <option key={value} value={value}>
            {words}
          </option>
        ))}
      </select>
      <FieldBroken said={broken} />
    </>
  );
}

/** What the simulator answered, with the proposed rules it weighed; nothing made. */
function Answer({
  simulation,
  proposed,
  names,
  currency,
  mandateId,
}: {
  readonly simulation: Simulation;
  readonly proposed: Proposed;
  readonly names: ReadonlyMap<string, string>;
  /** The test request's currency, the mandate's: what the agent's month is counted in. */
  readonly currency: string;
  /** The page's mandate: the agent's mandate in force weighed may be another. */
  readonly mandateId: string;
}) {
  const { organizationPolicy, mandatePolicy } = proposed;
  const other = simulation.mandateId !== null && simulation.mandateId.toLowerCase() !== mandateId.toLowerCase();
  const capFrom =
    other && simulation.monthlyCapFrom === 'mandate-policy'
      ? t('policies.simulate.capFrom.mandate-policy.other')
      : t(`policies.simulate.capFrom.${simulation.monthlyCapFrom}`);
  return (
    <section className="stack" aria-labelledby="answer-title" role="status">
      <h2 id="answer-title">{t('policies.simulate.answer')}</h2>
      <span className="kicker">{t(`decision.${simulation.decision}`)}</span>
      <p>{t(`policies.simulate.decision.${simulation.decision}`)}</p>
      {simulation.reasons.length > 0 && (
        <ul className="plain">
          {simulation.reasons.map((reason) => (
            <li key={reason.code}>{reason.message}</li>
          ))}
        </ul>
      )}
      <dl className="facts">
        <dt>{t('policies.simulate.capFrom')}</dt>
        <dd>{capFrom}</dd>
        {simulation.month !== null && (
          <>
            <dt>{t('policies.simulate.month', { month: simulation.month })}</dt>
            <dd className="amount">{amountText(simulation.monthSpentMinor, currency)}</dd>
          </>
        )}
      </dl>
      {simulation.mandateId === null && <p className="notice">{t('policies.simulate.noMandate')}</p>}
      {other && <p className="notice">{t('policies.simulate.otherMandate')}</p>}
      {organizationPolicy === undefined && mandatePolicy === undefined && (
        <p className="muted">{t('policies.simulate.weighedInForce')}</p>
      )}
      {organizationPolicy !== undefined && (
        <>
          <h3>{t('policies.simulate.proposed.organization')}</h3>
          <RulesShown
            rules={organizationPolicy}
            names={names}
            monthly={organizationPolicy.monthlyCapMinor === null ? t('policies.org.capNone') : undefined}
          />
        </>
      )}
      {mandatePolicy !== undefined && (
        <>
          <h3>{t('policies.simulate.proposed.mandate')}</h3>
          <RulesShown rules={mandatePolicy} names={names} />
        </>
      )}
      <p className="notice">{t('policies.simulate.nothingMade')}</p>
    </section>
  );
}

/** The proposed rules of one policy, checked; their problems kept to say in place. */
function proposedOf(draft: Draft, checked: Checked, problems: Problem[]): Rules | undefined {
  const made = rulesFrom(draft, checked);
  if ('problems' in made) {
    problems.push(...made.problems);
    return undefined;
  }
  return made.rules;
}

function Simulator({ mandateId, terms }: { readonly mandateId: string; readonly terms: MandateTerms }) {
  const { organization } = useActing();
  const orgPolicy = usePolicy({ kind: 'organization' }, organization.id);
  const mandatePolicy = usePolicy({ kind: 'mandate', mandateId }, organization.id);
  const sources = useBrakeList('sources', organization.id);
  const { listed, names, more } = useSupplierNames(organization.id);
  const { busy, said, run } = useChange(policyRefusal);
  const [typed, setTyped] = useState<Typed>(EMPTY);
  const [problems, setProblems] = useState<readonly Field[]>([]);
  const [orgDraft, setOrgDraft] = useState<Draft | null>(null);
  const [mandateDraft, setMandateDraft] = useState<Draft | null>(null);
  const [orgProblems, setOrgProblems] = useState<readonly Problem[]>([]);
  const [mandateProblems, setMandateProblems] = useState<readonly Problem[]>([]);
  const [answer, setAnswer] = useState<{ readonly simulation: Simulation; readonly proposed: Proposed } | null>(null);
  const currency = terms.currency;
  const digits = minorDigits(currency);
  const orgDigits = minorDigits(PILOT_CURRENCY);
  const changed = () => {
    setProblems([]);
    setAnswer(null);
  };
  const set = (part: Partial<Typed>) => {
    setTyped({ ...typed, ...part });
    changed();
  };
  const choose = (weighed: Weighed) => {
    set({ weighed });
    // A proposal starts from the rules in force, its every choice the person's to make.
    const inForce = (policy: Policy | undefined) => policy?.current ?? null;
    if (weighsOrganization(weighed) && orgDraft === null) {
      setOrgDraft(draftFrom(inForce(orgPolicy.data), orgDigits, orgPolicy.data?.suggestedMonthlyCapMinor));
    }
    if (weighsMandate(weighed) && mandateDraft === null) {
      setMandateDraft(draftFrom(inForce(mandatePolicy.data), digits));
    }
  };
  const broken = (field: Field) => (problems.includes(field) ? t(`policies.simulate.broken.${field}`) : undefined);
  const simulate = () => {
    const found = typedProblems(typed, digits);
    const ruleProblems: { organization: Problem[]; mandate: Problem[] } = { organization: [], mandate: [] };
    // A proposal chosen is always weighed as chosen, never quietly as the rules in force: an unmade one is refused.
    const organizationPolicy = weighsOrganization(typed.weighed)
      ? proposedOf(
          orgDraft ?? draftFrom(null, orgDigits),
          { currency: PILOT_CURRENCY, digits: orgDigits, withWait: false },
          ruleProblems.organization,
        )
      : undefined;
    const mandatePolicy = weighsMandate(typed.weighed)
      ? proposedOf(
          mandateDraft ?? draftFrom(null, digits),
          { currency, digits, withWait: false, within: terms },
          ruleProblems.mandate,
        )
      : undefined;
    const proposed: Proposed = {
      ...(organizationPolicy !== undefined && { organizationPolicy }),
      ...(mandatePolicy !== undefined && { mandatePolicy }),
    };
    setProblems(found);
    setOrgProblems(ruleProblems.organization);
    setMandateProblems(ruleProblems.mandate);
    const amount = amountMinor(typed.amount, digits);
    if (found.length > 0 || amount === undefined) return;
    if (ruleProblems.organization.length > 0 || ruleProblems.mandate.length > 0) return;
    const whatIf =
      proposed.organizationPolicy === undefined && proposed.mandatePolicy === undefined ? {} : { whatIf: proposed };
    void run(async () => {
      const simulation = await api.post<Simulation>(simulateAt(mandateId), {
        organization: organization.id,
        body: {
          amountMinor: amount,
          currency,
          supplierId: typed.supplier,
          fundingSourceId: typed.source,
          ...(typed.orderReference !== '' && { orderReference: typed.orderReference }),
          ...whatIf,
        },
      });
      setAnswer({ simulation, proposed });
    });
  };
  const ownAccount = terms.fundingSourceId.toLowerCase();
  const accounts = (sources.data?.pages.flatMap((page) => page.listed) ?? [])
    .filter((source) => !source.ended)
    .map(({ id, name, detail }) => {
      const words = `${name} · ${detail}`;
      return [
        id,
        id.toLowerCase() === ownAccount ? t('policies.simulate.ownAccount', { account: words }) : words,
      ] as const;
    });
  return (
    <section className="stack" aria-labelledby="simulate-form-title">
      <h2 id="simulate-form-title">{t('policies.simulate.request')}</h2>
      <LineField
        label={t('policies.edit.amount', { currency })}
        hint={amountHint(currency)}
        most={AMOUNT_MOST}
        value={typed.amount}
        onChange={(amount) => {
          set({ amount });
        }}
        broken={broken('amount')}
      />
      <Pick
        id="simulate-supplier"
        label={t('policies.simulate.supplier')}
        none={t('policies.simulate.supplierPick')}
        options={listed.map(({ id, name }) => [id, name] as const)}
        value={typed.supplier}
        onChange={(supplier) => {
          set({ supplier });
        }}
        broken={broken('supplier')}
      />
      {more !== undefined && (
        <button type="button" className="secondary" onClick={more}>
          {t('policies.edit.moreSuppliers')}
        </button>
      )}
      <Pick
        id="simulate-source"
        label={t('policies.simulate.source')}
        none={t('policies.simulate.sourcePick')}
        options={accounts}
        value={typed.source}
        onChange={(source) => {
          set({ source });
        }}
        broken={broken('source')}
      />
      <LineField
        label={t('policies.simulate.orderReference')}
        hint={t('policies.simulate.orderReferenceHint')}
        most={ORDER_REFERENCE_MOST * 2}
        value={typed.orderReference}
        onChange={(orderReference) => {
          set({ orderReference });
        }}
        broken={broken('orderReference')}
      />
      <Choices
        legend={t('policies.simulate.weighed')}
        options={WEIGHED.map((weighed) => [weighed, t(`policies.simulate.weighed.${weighed}`)] as const)}
        chosen={typed.weighed}
        onChoose={choose}
        broken={broken('weighed')}
      />
      {weighsMandate(typed.weighed) && mandateDraft !== null && (
        <section className="stack" aria-labelledby="proposed-mandate-title">
          <h3 id="proposed-mandate-title">{t('policies.simulate.proposed.mandate')}</h3>
          <RuleEditor
            draft={mandateDraft}
            onChange={(part) => {
              setMandateDraft({ ...mandateDraft, ...part });
              setMandateProblems([]);
              changed();
            }}
            problems={mandateProblems}
            currency={currency}
            organization={false}
            withWait={false}
            suppliers={terms.supplierIds}
            names={names}
          />
        </section>
      )}
      {weighsOrganization(typed.weighed) && orgDraft !== null && (
        <section className="stack" aria-labelledby="proposed-org-title">
          <h3 id="proposed-org-title">{t('policies.simulate.proposed.organization')}</h3>
          <RuleEditor
            draft={orgDraft}
            onChange={(part) => {
              setOrgDraft({ ...orgDraft, ...part });
              setOrgProblems([]);
              changed();
            }}
            problems={orgProblems}
            currency={PILOT_CURRENCY}
            organization
            withWait={false}
            suppliers={listed.map(({ id }) => id)}
            names={names}
            more={more}
          />
        </section>
      )}
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={simulate}>
          {t('policies.simulate.button')}
        </button>
      </div>
      <p className="fine">{t('policies.simulate.writesNothing')}</p>
      <Said said={said} />
      {answer !== null && (
        <Answer
          simulation={answer.simulation}
          proposed={answer.proposed}
          names={names}
          currency={currency}
          mandateId={mandateId}
        />
      )}
    </section>
  );
}

export function SimulatePage({ mandateId }: { readonly mandateId: string }) {
  const { organization } = useActing();
  const mandate = useMandateTerms(mandateId, organization.id);
  const back = <MandateLink id={mandateId}>{t('policies.backMandate')}</MandateLink>;
  const may = SIMULATING.includes(organization.role);
  const missing = isMissing(mandateId, mandate.error);
  const terms = mandate.data?.terms;
  if (missing || (mandate.isError && terms === undefined)) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={mandate.error}
        notFound={t('policies.notFound')}
        integrity={t('policies.integrity')}
        onRetry={() => void mandate.refetch()}
      />
    );
  }
  let shown = <Loading />;
  if (!may) shown = <p className="muted">{t('policies.simulate.viewOnly')}</p>;
  else if (mandate.data?.ended === true) shown = <p className="muted">{t('policies.simulate.ended')}</p>;
  else if (terms === null) shown = <p className="muted">{t('policies.noTerms')}</p>;
  else if (terms !== undefined) shown = <Simulator mandateId={mandateId} terms={terms} />;
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{t('policies.simulate.kicker')}</span>
      <h1>{t('policies.simulate.title')}</h1>
      <p className="muted">{t('policies.simulate.intro')}</p>
      {shown}
    </section>
  );
}
