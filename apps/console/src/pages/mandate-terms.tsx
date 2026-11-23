// A mandate's terms as the console shows them (6D3a): each version's in plain
// words, amounts in AED with two decimals, its suppliers and bank account by
// name where the lists the page has read name them (by ID otherwise), and
// every setting the admin chose. A waiting draft is shown beside the version
// in force, each changed term marked, so the admin sees what accepting it
// changes; the API's warnings for each version are said under it. Names are
// for reading only: each ID stays beside its name, and what is signed (the
// terms fingerprint, a passkey's acceptance) is the IDs alone.
import { Fragment, type ReactNode } from 'react';

import { useBrakeList } from '../brakes.ts';
import type { MandateVersion, SourceListed } from '../mandates.ts';
import { useSourceList } from '../mandates.ts';
import { amountText, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t, type TextKey } from '../text.ts';
import { Tag } from './tag.tsx';

/** What the page can name: the suppliers and bank accounts read so far, by ID. */
export interface Names {
  readonly suppliers: ReadonlyMap<string, string>;
  readonly sources: ReadonlyMap<string, SourceListed>;
}

/** The suppliers' and bank accounts' names, from their lists' pages read so far. */
export function useNames(): Names {
  const { organization } = useActing();
  const suppliers = useBrakeList('suppliers', organization.id);
  const sources = useSourceList(organization.id);
  return {
    suppliers: new Map(
      (suppliers.data?.pages ?? []).flatMap((page) => page.listed).map((supplier) => [supplier.id, supplier.name]),
    ),
    sources: new Map((sources.data?.pages ?? []).flatMap((page) => page.listed).map((source) => [source.id, source])),
  };
}

/** A bank account as a person knows it: its holder and the end of its number, as the Bank accounts list shows it. */
export const sourceText = (source: SourceListed): string => `${source.holderName} · ${source.hint}`;

/** A thing by its name with its ID beside it, muted; by its ID alone while no list read so far names it. */
export function Named({ name, id }: { readonly name: string | undefined; readonly id: string }) {
  return name === undefined ? (
    <span className="mono">{id}</span>
  ) : (
    <>
      {name} <span className="muted mono">{id}</span>
    </>
  );
}

/** A term: its label, its words (what a draft is compared by), and how it is shown where that differs. */
export type TermRow = readonly [TextKey, string, ReactNode?];

/** The terms a version holds, or a draft about to be sent: what termRows says. */
export type Terms = Pick<
  MandateVersion,
  | 'purpose'
  | 'currency'
  | 'perOrderLimitMinor'
  | 'monthlyLimitMinor'
  | 'approvalThresholdMinor'
  | 'supplierIds'
  | 'fundingSourceId'
  | 'splitCheck'
  | 'consentLimits'
  | 'endsAt'
>;

/** Each term, its label and its words, in the order shown: a version's over-limit choice last, a draft's chosen at its confirm. */
export function termRows(
  version: Terms & Partial<Pick<MandateVersion, 'overLimit'>>,
  names: Names,
): readonly TermRow[] {
  const money = (minor: number) => amountText(minor, version.currency);
  const source = names.sources.get(version.fundingSourceId);
  const suppliers = version.supplierIds.map((id, at) => (
    <Fragment key={id}>
      {at > 0 && ', '}
      <Named name={names.suppliers.get(id)} id={id} />
    </Fragment>
  ));
  return [
    ['mandates.term.purpose', version.purpose],
    ['mandates.term.perOrder', money(version.perOrderLimitMinor)],
    ['mandates.term.monthly', money(version.monthlyLimitMinor)],
    ['mandates.term.threshold', money(version.approvalThresholdMinor)],
    ['mandates.term.suppliers', version.supplierIds.map((id) => names.suppliers.get(id) ?? id).join(', '), suppliers],
    [
      'mandates.term.source',
      source === undefined ? version.fundingSourceId : sourceText(source),
      <Named key="source" name={source && sourceText(source)} id={version.fundingSourceId} />,
    ],
    ['mandates.term.splitCheck', t(version.splitCheck ? 'mandates.split.on' : 'mandates.split.off')],
    ['mandates.term.consentLimits', t(`mandates.consent.${version.consentLimits}`)],
    ['mandates.term.ends', version.endsAt === null ? t('mandates.endsNever') : timeText(version.endsAt)],
    ...(version.overLimit === undefined
      ? []
      : [['mandates.term.overLimit', t(`mandates.overLimit.${version.overLimit}`)] as const]),
  ];
}

/** The API's warnings for a version: past the bank consent, past the agent's monthly cap, the split check off. */
function Warnings({ version }: { readonly version: MandateVersion }) {
  const said = [
    ...version.consentWarnings.map((warning) => t('mandates.warn.consent', { warning })),
    ...version.capWarnings.map((warning) => t('mandates.warn.cap', { warning })),
    ...(version.splitCheckWarning === null ? [] : [t('mandates.warn.split', { warning: version.splitCheckWarning })]),
  ];
  return said.length === 0 ? null : (
    <ul className="plain stack">
      {said.map((words) => (
        <li key={words} className="notice">
          {t('mandates.warn.version', { version: String(version.version) })} {words}
        </li>
      ))}
    </ul>
  );
}

/** A version's heading: its number, and when it was drafted. */
const headed = (key: TextKey, version: MandateVersion) =>
  t(key, { version: String(version.version), time: timeText(version.draftedAt) });

/**
 * The terms: the version in force, the waiting draft, or both side by side,
 * each term the draft changes marked. At least one is given.
 */
export function TermsTable({
  current,
  pending,
}: {
  readonly current: MandateVersion | null;
  readonly pending: MandateVersion | null;
}) {
  const names = useNames();
  const shown = [current, pending].filter((version) => version !== null);
  const rows = shown.map((version) => termRows(version, names));
  const [first = [], second] = rows;
  return (
    <>
      <div className="table-scroll">
        <table className="events">
          <thead>
            <tr>
              <th scope="col">{t('mandates.term')}</th>
              {current !== null && <th scope="col">{headed('mandates.inForce', current)}</th>}
              {pending !== null && <th scope="col">{headed('mandates.waiting', pending)}</th>}
            </tr>
          </thead>
          <tbody>
            {first.map(([label, words, shownAs], at) => {
              const [, draft, draftShownAs] = second?.[at] ?? [];
              return (
                <tr key={label}>
                  <th scope="row">{t(label)}</th>
                  <td>{shownAs ?? words}</td>
                  {draft !== undefined && (
                    <td>
                      {draftShownAs ?? draft}
                      {draft !== words && <Tag warn>{t('mandates.changed')}</Tag>}
                    </td>
                  )}
                </tr>
              );
            })}
            <tr>
              <th scope="row">{t('mandates.term.hash')}</th>
              {shown.map((version) => (
                <td key={version.id} className="hashes">
                  {version.termsHash}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
      {shown.map((version) => (
        <Warnings key={version.id} version={version} />
      ))}
    </>
  );
}
