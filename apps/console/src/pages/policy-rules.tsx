// A policy's rules (6D3b): shown in plain words (the organisation's policy,
// a mandate's, the proposed rules a simulation weighed), and the one editor
// both policies and the simulator's proposed rules are chosen with. Every
// rule is a choice with none picked for the admin (Rule Book §1.9): none, or
// an amount typed in the currency's major units (its field holding the rule in
// force to keep or change); a per-order cap also says what happens above it;
// the supplier list is any supplier, or the ones ticked. What is wrong is said
// in place once checked (rulesFrom, on Check).
import { useBrakeList } from '../brakes.ts';
import { amountHint, type Draft, OVER, type Problem, type Rules, WAITS } from '../policies.ts';
import { amountText } from '../requests.ts';
import { t } from '../text.ts';
import { Choices, FieldBroken, Tick } from './choices.tsx';
import { AMOUNT_MOST, LineField } from './line-field.tsx';

/** The suppliers' names by ID (lower case), as far as the list has been read: an ID not in it is shown as itself. */
export function useSupplierNames(organization: string) {
  const list = useBrakeList('suppliers', organization);
  const listed = list.data?.pages.flatMap((page) => page.listed) ?? [];
  return {
    listed,
    names: new Map(listed.map(({ id, name }) => [id.toLowerCase(), name])),
    more: list.hasNextPage ? () => void list.fetchNextPage() : undefined,
  };
}

export function SupplierNames({
  ids,
  names,
}: {
  readonly ids: readonly string[];
  readonly names: ReadonlyMap<string, string>;
}) {
  return (
    <ul className="plain">
      {ids.map((id) => {
        const name = names.get(id.toLowerCase());
        return <li key={id}>{name ?? <span className="mono">{id}</span>}</li>;
      })}
    </ul>
  );
}

/** A policy's rules in plain words, amounts as the currency shows them; `monthly` in place of its monthly cap's own words. */
export function RulesShown({
  rules,
  names,
  monthly,
}: {
  readonly rules: Rules;
  readonly names: ReadonlyMap<string, string>;
  readonly monthly?: string | undefined;
}) {
  const money = (minor: number) => amountText(minor, rules.currency);
  const cap = rules.perOrderCap;
  const threshold = rules.approvalThresholdMinor;
  return (
    <dl className="facts">
      <dt>{t('policies.rule.perOrder')}</dt>
      <dd>
        {cap === null ? t('policies.rule.none') : t(`policies.rule.over.${cap.over}`, { amount: money(cap.capMinor) })}
      </dd>
      <dt>{t('policies.rule.monthly')}</dt>
      <dd>{monthly ?? (rules.monthlyCapMinor === null ? t('policies.rule.none') : money(rules.monthlyCapMinor))}</dd>
      <dt>{t('policies.rule.threshold')}</dt>
      <dd>
        {threshold === null ? t('policies.rule.noThreshold') : t('policies.rule.above', { amount: money(threshold) })}
      </dd>
      <dt>{t('policies.rule.suppliers')}</dt>
      <dd>
        {rules.supplierIds === null ? (
          t('policies.rule.anySupplier')
        ) : (
          <SupplierNames ids={rules.supplierIds} names={names} />
        )}
      </dd>
    </dl>
  );
}

/** What is wrong with a draft's part, in place; none while it is fine or not yet checked. */
const brokenIn = (problems: readonly Problem[]) => (problem: Problem) =>
  problems.includes(problem) ? t(`policies.problem.${problem}`) : undefined;

/** One amount rule: none, or an amount, chosen; the amount's field once an amount is chosen. */
function AmountRule<T extends string>({
  legend,
  options,
  amountChoice,
  chosen,
  onChoose,
  amount,
  onAmount,
  currency,
  broken,
}: {
  readonly legend: string;
  readonly options: readonly (readonly [T, string])[];
  /** The choice that takes an amount. */
  readonly amountChoice: T;
  readonly chosen: T | null;
  readonly onChoose: (choice: T) => void;
  readonly amount: string;
  readonly onAmount: (typed: string) => void;
  readonly currency: string;
  readonly broken: readonly [string | undefined, string | undefined];
}) {
  return (
    <>
      <Choices legend={legend} options={options} chosen={chosen} onChoose={onChoose} broken={broken[0]} />
      {chosen === amountChoice && (
        <LineField
          label={t('policies.edit.amount', { currency })}
          hint={amountHint(currency)}
          most={AMOUNT_MOST}
          value={amount}
          onChange={onAmount}
          broken={broken[1]}
        />
      )}
    </>
  );
}

/** The suppliers rule: any, or only those ticked among `options` (and any already chosen beyond them, to untick). */
function SupplierRule({
  draft,
  onChange,
  options,
  names,
  more,
  broken,
  anyWords,
}: {
  readonly draft: Draft;
  readonly onChange: (part: Partial<Draft>) => void;
  readonly options: readonly string[];
  readonly names: ReadonlyMap<string, string>;
  readonly more: (() => void) | undefined;
  readonly broken: (problem: Problem) => string | undefined;
  readonly anyWords: string;
}) {
  const chosen = new Set(draft.supplierIds.map((id) => id.toLowerCase()));
  const shown = [...new Set([...options.map((id) => id.toLowerCase()), ...chosen])];
  const tick = (id: string, ticked: boolean) => {
    const rest = draft.supplierIds.filter((one) => one.toLowerCase() !== id);
    onChange({ supplierIds: ticked ? [...rest, id] : rest });
  };
  return (
    <>
      <Choices
        legend={t('policies.edit.suppliers')}
        options={[
          ['any', anyWords],
          ['only', t('policies.edit.suppliers.only')],
        ]}
        chosen={draft.suppliers}
        onChoose={(suppliers) => {
          onChange({ suppliers });
        }}
        broken={broken('suppliers')}
      />
      {draft.suppliers === 'only' && (
        <div className="stack">
          {shown.length === 0 && <p className="muted">{t('policies.edit.noSuppliers')}</p>}
          {shown.map((id) => (
            <Tick
              key={id}
              label={names.get(id) ?? id}
              ticked={chosen.has(id)}
              onTick={(ticked) => {
                tick(id, ticked);
              }}
            />
          ))}
          {more !== undefined && (
            <button type="button" className="secondary" onClick={more}>
              {t('policies.edit.moreSuppliers')}
            </button>
          )}
          <FieldBroken said={broken('supplierIds')} />
        </div>
      )}
    </>
  );
}

/** The problems that are about the rules together, not one field: said under the editor. */
const TOGETHER: readonly Problem[] = [
  'thresholdAbovePerOrder',
  'perOrderAboveMonthly',
  'thresholdAboveMonthly',
  'perOrderAboveMandate',
  'monthlyAboveMandate',
  'thresholdAboveMandate',
  'supplierOutsideMandate',
];

/**
 * The editor for a policy's rules, the organisation's (`organization`: its
 * monthly cap is the organisation-wide one, and with `withWait` the approval
 * wait too) or a mandate's. `suppliers` are the ones that may be ticked.
 */
export function RuleEditor({
  draft,
  onChange,
  problems,
  currency,
  organization,
  withWait,
  suppliers,
  names,
  more,
}: {
  readonly draft: Draft;
  readonly onChange: (part: Partial<Draft>) => void;
  readonly problems: readonly Problem[];
  readonly currency: string;
  readonly organization: boolean;
  readonly withWait: boolean;
  readonly suppliers: readonly string[];
  readonly names: ReadonlyMap<string, string>;
  readonly more?: (() => void) | undefined;
}) {
  const broken = brokenIn(problems);
  const scope = organization ? 'organization' : 'mandate';
  const together = TOGETHER.filter((problem) => problems.includes(problem));
  return (
    <div className="stack">
      <AmountRule
        legend={t('policies.edit.perOrder')}
        options={[
          ['none', t('policies.edit.perOrder.none')],
          ['cap', t('policies.edit.perOrder.cap')],
        ]}
        amountChoice="cap"
        chosen={draft.perOrder}
        onChoose={(perOrder) => {
          onChange({ perOrder });
        }}
        amount={draft.perOrderAmount}
        onAmount={(perOrderAmount) => {
          onChange({ perOrderAmount });
        }}
        currency={currency}
        broken={[broken('perOrder'), broken('perOrderAmount')]}
      />
      {draft.perOrder === 'cap' && (
        <Choices
          legend={t('policies.edit.over')}
          options={OVER.map((over) => [over, t(`policies.edit.over.${over}`)] as const)}
          chosen={draft.over}
          onChoose={(over) => {
            onChange({ over });
          }}
          broken={broken('over')}
        />
      )}
      <AmountRule
        legend={t(`policies.edit.monthly.${scope}`)}
        options={[
          ['none', t(`policies.edit.monthly.none.${scope}`)],
          ['amount', t('policies.edit.monthly.amount')],
        ]}
        amountChoice="amount"
        chosen={draft.monthly}
        onChoose={(monthly) => {
          onChange({ monthly });
        }}
        amount={draft.monthlyAmount}
        onAmount={(monthlyAmount) => {
          onChange({ monthlyAmount });
        }}
        currency={currency}
        broken={[broken('monthly'), broken('monthlyAmount')]}
      />
      <AmountRule
        legend={t('policies.edit.threshold')}
        options={[
          ['none', t('policies.edit.threshold.none')],
          ['amount', t('policies.edit.threshold.amount')],
        ]}
        amountChoice="amount"
        chosen={draft.threshold}
        onChoose={(threshold) => {
          onChange({ threshold });
        }}
        amount={draft.thresholdAmount}
        onAmount={(thresholdAmount) => {
          onChange({ thresholdAmount });
        }}
        currency={currency}
        broken={[broken('threshold'), broken('thresholdAmount')]}
      />
      <SupplierRule
        draft={draft}
        onChange={onChange}
        options={suppliers}
        names={names}
        more={more}
        broken={broken}
        anyWords={t(`policies.edit.suppliers.any.${scope}`)}
      />
      {withWait && (
        <Choices
          legend={t('policies.edit.wait')}
          options={WAITS.map((hours) => [hours, t('policies.wait.hours', { n: hours })] as const)}
          chosen={draft.wait}
          onChoose={(wait) => {
            onChange({ wait });
          }}
          broken={broken('wait')}
        />
      )}
      {together.length > 0 && (
        <ul className="notice" role="alert">
          {together.map((problem) => (
            <li key={problem}>{t(`policies.problem.${problem}`)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
