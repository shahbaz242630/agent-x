// What the audit log's and the access log's screens share (6C2): who may see
// them (admins, decision 24), their filters kept in the page's own address,
// the form that sets them, the reading of their pages, and the download of
// what they show as CSV or NDJSON, itself logged.
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { type ChangeEvent, type ReactNode, useId, useState } from 'react';

import { isIntegrityFailed, isRefusal } from '../api.ts';
import {
  downloadLog,
  type FilterName,
  type Filters,
  filtersIn,
  type Format,
  FORMATS,
  type Log,
  logRefusal,
  pageAddress,
} from '../logs.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';

/** The log's filters as the address holds them, the raw query (the router's own reads values as JSON), and a way to set them. */
export function useFilters(log: Log) {
  const navigate = useNavigate();
  const search = useRouterState({ select: ({ location }) => location.searchStr });
  return {
    search,
    filters: filtersIn(log, search),
    go: (next: Filters) => void navigate({ href: pageAddress(log, next) }),
  };
}

/** A filter field: free text, or one of `options` ('' for any). */
export interface Field {
  readonly name: FilterName;
  readonly options?: readonly string[];
}

/** What a select's option says: '' is anyone; an actor type its kind. */
const optionText = (option: string): string =>
  option === '' ? t('logs.anyone') : t(`logs.actor.${option as 'user' | 'agent' | 'system'}`);

/** The filters to set, applied together: kept as typed while typed, sent to the address on Apply. */
export function FilterForm({
  filters,
  fields,
  onApply,
}: {
  readonly filters: Filters;
  readonly fields: readonly Field[];
  readonly onApply: (filters: Filters) => void;
}) {
  const id = useId();
  const [draft, setDraft] = useState<Filters>(filters);
  /** A field's id, value as typed ('' left empty) and change, the same for a date, a text or a choice. */
  const bound = (name: keyof Filters) => ({
    id: `${id}-${name}`,
    value: draft[name] ?? '',
    onChange: (event: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
      const { value } = event.target;
      setDraft((was) => ({ ...was, [name]: value }));
    },
  });
  const field = (name: keyof Filters, control: ReactNode) => (
    <div key={name} className="filter">
      <label className="field" htmlFor={`${id}-${name}`}>
        {t(`logs.filter.${name}`)}
      </label>
      {control}
    </div>
  );
  const dates = (['from', 'to'] as const).map((name) => field(name, <input type="date" {...bound(name)} />));
  return (
    <form
      className="filters"
      onSubmit={(event) => {
        event.preventDefault();
        onApply(draft);
      }}
    >
      {dates}
      {fields.map(({ name, options }) =>
        field(
          name,
          options === undefined ? (
            // At most what the API takes: 20 actions of up to 64 characters with their commas; 64 for an ID or kind.
            <input type="text" maxLength={name === 'actions' ? 1300 : 64} {...bound(name)} />
          ) : (
            <select {...bound(name)}>
              {options.map((option) => (
                <option key={option} value={option}>
                  {optionText(option)}
                </option>
              ))}
            </select>
          ),
        ),
      )}
      <button type="submit" className="secondary">
        {t('logs.apply')}
      </button>
    </form>
  );
}

/** A log's page for someone who isn't an admin: only an admin may read it (decision 24), so nothing is asked. */
export const AdminsOnly = () => <p className="notice">{t('logs.adminsOnly')}</p>;

/** A log's pages read so far: loading, refused or failed in plain words, none in the range, or each shown by `row`. */
export function Pages<T>({
  pages,
  row,
}: {
  readonly pages: {
    readonly isPending: boolean;
    readonly error: Error | null;
    readonly refetch: () => unknown;
    readonly data: { readonly pages: readonly { readonly items: readonly T[] }[] } | undefined;
    readonly hasNextPage: boolean;
    readonly isFetchingNextPage: boolean;
    readonly fetchNextPage: () => unknown;
  };
  readonly row: (item: T) => ReactNode;
}) {
  if (pages.error !== null) {
    // A refusal (filters it can't read) or a record failing its check is said in words; anything else is retried.
    return isRefusal(pages.error) || isIntegrityFailed(pages.error) ? (
      <p className="notice" role="alert">
        {logRefusal(pages.error)}
      </p>
    ) : (
      <Retry onRetry={() => void pages.refetch()} />
    );
  }
  if (pages.isPending) return <Loading />;
  const shown = pages.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <>
      {shown.length === 0 ? (
        <p className="muted">{t('logs.none')}</p>
      ) : (
        <ol className="rows">{shown.map((item) => row(item))}</ol>
      )}
      {pages.hasNextPage && (
        <button
          type="button"
          className="secondary"
          disabled={pages.isFetchingNextPage}
          onClick={() => void pages.fetchNextPage()}
        >
          {t('logs.older')}
        </button>
      )}
    </>
  );
}

/** The format a download is made in. */
export function FormatField({ format, onChange }: { readonly format: Format; readonly onChange: (f: Format) => void }) {
  const id = useId();
  return (
    <div className="filter">
      <label className="field" htmlFor={id}>
        {t('logs.format')}
      </label>
      <select
        id={id}
        value={format}
        onChange={(event) => {
          onChange(event.target.value as Format);
        }}
      >
        {FORMATS.map((one) => (
          <option key={one} value={one}>
            {t(`logs.format.${one}`)}
          </option>
        ))}
      </select>
    </div>
  );
}

/** The log as filtered, downloaded in the format chosen and saved: each download is recorded in the audit log. */
export function Download({
  log,
  filters,
  format,
}: {
  readonly log: Log;
  readonly filters: Filters;
  readonly format: Format;
}) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(logRefusal);
  return (
    <>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() =>
          void run(() => downloadLog(log, filters, format, organization.id), { done: t('logs.downloaded') })
        }
      >
        {t('logs.download')}
      </button>
      <p className="fine">{t('logs.downloadLogged')}</p>
      <Said said={said} />
    </>
  );
}
