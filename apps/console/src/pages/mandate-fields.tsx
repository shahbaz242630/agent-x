// A mandate version's terms as an admin types and chooses them (6D3a): its
// purpose, its three limits typed in dirhams (read exactly, mandates.ts), the
// suppliers it may pay, the bank account it draws on, and every setting the
// API leaves to the admin with none picked (Rule Book §1.9, decision 15): the
// split check, above the bank consent's limits, and when it ends. A new
// version shows beside each setting what the version in force holds, to choose
// again. What the API would refuse is said in place once checked.
import { useId } from 'react';

import { type Braked, useBrakeList } from '../brakes.ts';
import {
  type MandateVersion,
  PURPOSE_MOST,
  type SourceListed,
  SUPPLIERS_MOST,
  type TermsProblem,
  type TermsTyped,
  amountWords,
  useSourceList,
} from '../mandates.ts';
import { amountText, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t, type TextKey } from '../text.ts';
import { unitsMost } from '../visible-name.ts';
import { Choices } from './choices.tsx';
import { LineField } from './line-field.tsx';
import { sourceText } from './mandate-terms.tsx';

/** The longest an amount may be typed: 2^53 − 1 fils in dirhams, grouped, with its decimals. */
const AMOUNT_MOST = 24;

/** What a field says is wrong, once checked: its own words for each problem it holds. */
export type Broken = (problem: TermsProblem | 'agent' | 'timeZone' | 'splitWindowHours') => string | undefined;

/** What a version in force holds for a setting, said beside it to choose again. */
function InForce({ words }: { readonly words: string | undefined }) {
  return words === undefined ? null : <p className="fine">{t('mandates.form.inForce', { words })}</p>;
}

/** The suppliers it may pay, ticked from the organisation's (any already named but not listed yet kept by ID). */
function Suppliers({
  chosen,
  onChange,
  broken,
}: {
  readonly chosen: readonly string[];
  readonly onChange: (ids: readonly string[]) => void;
  readonly broken: string | undefined;
}) {
  const { organization } = useActing();
  const listed = useBrakeList('suppliers', organization.id);
  const loaded = (listed.data?.pages ?? []).flatMap((page) => page.listed);
  const unlisted = chosen
    .filter((id) => !loaded.some((supplier) => supplier.id === id))
    .map((id): Braked => ({ id, name: id, detail: '', suspended: false, ended: false }));
  const toggle = (id: string, on: boolean) => {
    onChange(on ? [...chosen, id] : chosen.filter((each) => each !== id));
  };
  return (
    <>
      <fieldset className="options" aria-invalid={broken !== undefined}>
        <legend>{t('mandates.form.suppliers')}</legend>
        <p className="fine">{t('mandates.form.suppliersHint', { most: String(SUPPLIERS_MOST) })}</p>
        {[...loaded, ...unlisted].map((supplier) => (
          <label key={supplier.id} className="option">
            <input
              type="checkbox"
              checked={chosen.includes(supplier.id)}
              onChange={(event) => {
                toggle(supplier.id, event.target.checked);
              }}
            />
            <span>
              {supplier.name} <span className="muted">{supplier.detail}</span>
            </span>
          </label>
        ))}
        {listed.isSuccess && loaded.length === 0 && <p className="muted">{t('mandates.form.noSuppliers')}</p>}
        {listed.hasNextPage && (
          <button
            type="button"
            className="secondary"
            disabled={listed.isFetchingNextPage}
            onClick={() => void listed.fetchNextPage()}
          >
            {t('approvals.more')}
          </button>
        )}
      </fieldset>
      {broken !== undefined && (
        <p className="notice" role="alert">
          {broken}
        </p>
      )}
    </>
  );
}

/** A bank account as a choice: its holder and number's end, and what its bank consent allows. */
function sourceChoice(source: SourceListed): string {
  const { currency, maxPaymentMinor, maxPeriodMinor, period } = source.controls;
  const allows = t('mandates.form.sourceAllows', {
    payment: amountText(Number(maxPaymentMinor), currency),
    period: amountText(Number(maxPeriodMinor), currency),
    per: t(`mandates.form.per.${period}`),
  });
  return `${sourceText(source)} · ${allows}`;
}

/** The bank accounts it may draw on: those not ended, and any already named but not listed yet, by ID. */
function useSourceOptions(chosen: string | null): readonly (readonly [string, string])[] {
  const { organization } = useActing();
  const listed = useSourceList(organization.id);
  const sources = (listed.data?.pages ?? []).flatMap((page) => page.listed).filter(({ status }) => status !== 'ENDED');
  const options = sources.map((source) => [source.id, sourceChoice(source)] as const);
  return chosen === null || sources.some(({ id }) => id === chosen) ? options : [...options, [chosen, chosen]];
}

/** When the version in force ends, in words; none for a new mandate. */
function endsWords(version: MandateVersion | null): string | undefined {
  if (version === null) return undefined;
  return version.endsAt === null ? t('mandates.endsNever') : timeText(version.endsAt);
}

/** When it ends: none chosen until the admin picks, a date and time in their own zone if it does. */
function Ends({
  typed,
  set,
  broken,
  inForce,
}: {
  readonly typed: TermsTyped;
  readonly set: (part: Partial<TermsTyped>) => void;
  readonly broken: Broken;
  readonly inForce: MandateVersion | null;
}) {
  const id = useId();
  return (
    <>
      <Choices
        legend={t('mandates.form.ends')}
        options={[
          ['never', t('mandates.form.ends.never')],
          ['on', t('mandates.form.ends.on')],
        ]}
        chosen={typed.ends}
        onChoose={(ends) => {
          set({ ends });
        }}
        broken={broken('ends')}
      />
      <InForce words={endsWords(inForce)} />
      {typed.ends === 'on' && (
        <>
          <label className="field" htmlFor={id}>
            {t('mandates.form.endsAt')}
          </label>
          <input
            id={id}
            type="datetime-local"
            value={typed.endsAt}
            aria-invalid={broken('endsAt') !== undefined}
            onChange={(event) => {
              set({ endsAt: event.target.value });
            }}
          />
          {broken('endsAt') !== undefined && (
            <p className="notice" role="alert">
              {broken('endsAt')}
            </p>
          )}
        </>
      )}
    </>
  );
}

/** Each limit: its field, its words' keys. */
const LIMITS = [
  ['perOrder', 'mandates.form.perOrder'],
  ['monthly', 'mandates.form.monthly'],
  ['threshold', 'mandates.form.threshold'],
] as const satisfies readonly (readonly [TermsProblem & keyof TermsTyped, TextKey])[];

/** A limit's problem: unreadable as typed, or out of the nesting (approval threshold ≤ per-order ≤ monthly). */
function limitBroken(field: (typeof LIMITS)[number][0], broken: Broken): string | undefined {
  const nested = { perOrder: 'perOrderAbove', monthly: undefined, threshold: 'thresholdAbove' } as const;
  const above = nested[field];
  return broken(field) ?? (above === undefined ? undefined : broken(above));
}

export function TermsFields({
  typed,
  set,
  broken,
  inForce,
  currency,
}: {
  readonly typed: TermsTyped;
  readonly set: (part: Partial<TermsTyped>) => void;
  readonly broken: Broken;
  /** The version in force, for a new version: what it holds is said beside each setting. */
  readonly inForce: MandateVersion | null;
  /** The chosen bank account's currency, which the amounts are typed in; none until one is chosen. */
  readonly currency: string | undefined;
}) {
  const amounts = amountWords(currency);
  const sources = useSourceOptions(typed.fundingSourceId);
  const was = <T,>(read: (version: MandateVersion) => T, words: (value: T) => string) =>
    inForce === null ? undefined : words(read(inForce));
  return (
    <>
      <LineField
        label={t('mandates.form.purpose')}
        hint={t('mandates.form.purposeHint')}
        most={unitsMost(PURPOSE_MOST)}
        value={typed.purpose}
        onChange={(purpose) => {
          set({ purpose });
        }}
        broken={broken('purpose')}
      />
      {LIMITS.map(([field, words]) => (
        <LineField
          key={field}
          label={t(words, amounts)}
          hint={t(`${words}Hint`, amounts)}
          most={AMOUNT_MOST}
          value={typed[field]}
          onChange={(value) => {
            set({ [field]: value });
          }}
          broken={limitBroken(field, broken)}
        />
      ))}
      <Suppliers
        chosen={typed.supplierIds}
        onChange={(supplierIds) => {
          set({ supplierIds });
        }}
        broken={broken('suppliers')}
      />
      <Choices
        legend={t('mandates.form.source')}
        options={sources}
        chosen={typed.fundingSourceId}
        onChoose={(fundingSourceId) => {
          set({ fundingSourceId });
        }}
        broken={broken('source') ?? broken('currency')}
      />
      {sources.length === 0 && <p className="muted">{t('mandates.form.noSources')}</p>}
      <Choices
        legend={t('mandates.form.splitCheck')}
        options={[
          ['on', t('mandates.form.split.on')],
          ['off', t('mandates.form.split.off')],
        ]}
        chosen={typed.splitCheck}
        onChoose={(splitCheck) => {
          set({ splitCheck });
        }}
        broken={broken('splitCheck')}
      />
      <InForce
        words={was(
          ({ splitCheck }) => splitCheck,
          (on) => t(on ? 'mandates.split.on' : 'mandates.split.off'),
        )}
      />
      <Choices
        legend={t('mandates.form.consentLimits')}
        options={[
          ['strict', t('mandates.form.consent.strict')],
          ['flexible', t('mandates.form.consent.flexible')],
        ]}
        chosen={typed.consentLimits}
        onChoose={(consentLimits) => {
          set({ consentLimits });
        }}
        broken={broken('consentLimits')}
      />
      <InForce
        words={was(
          ({ consentLimits }) => consentLimits,
          (limits) => t(`mandates.consent.${limits}`),
        )}
      />
      <Ends typed={typed} set={set} broken={broken} inForce={inForce} />
    </>
  );
}
