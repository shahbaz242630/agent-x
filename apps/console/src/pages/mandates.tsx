// The organisation's mandates (6D3a): `/more/mandates`, every member's to
// read. Each row names its agent (by its name where the Agents list read so
// far names it), its purpose and its status; a mandate's page holds its terms
// and what can be done with it. An admin drafts a new one from here. The list
// pages as the API does, 50 at a time.
import { Link } from '@tanstack/react-router';

import { useBrakeList } from '../brakes.ts';
import { isEnded, MANAGING, type MandateListed, useMandateList } from '../mandates.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Loading, Retry } from './failed.tsx';

function Row({ mandate, agent }: { readonly mandate: MandateListed; readonly agent: string | undefined }) {
  const ended = isEnded(mandate.status);
  return (
    <li className="row">
      <span className="row-main">
        <span>
          <Link to="/more/mandates/$id" params={{ id: mandate.id }}>
            {mandate.purpose}
          </Link>
          <span className={ended ? 'tag' : 'tag warn'}>{t(`mandates.status.${mandate.status}`)}</span>
        </span>
        <span className="muted">{t('mandates.forAgent', { agent: agent ?? mandate.agentId })}</span>
      </span>
    </li>
  );
}

export function MandateList() {
  const { organization } = useActing();
  const listed = useMandateList(organization.id);
  const agents = useBrakeList('agents', organization.id);
  const names = new Map(
    (agents.data?.pages ?? []).flatMap((page) => page.listed).map((agent) => [agent.id, agent.name]),
  );
  const pages = listed.data?.pages ?? [];
  const shown = pages.flatMap((page) => page.listed);
  const unchecked = pages.reduce((count, page) => count + page.unchecked.length, 0);
  return (
    <section className="stack">
      <Link to="/more" className="back">
        {t('mandates.backToMore')}
      </Link>
      <h1>{t('mandates.title')}</h1>
      <p className="muted">{t('mandates.intro')}</p>
      {MANAGING.includes(organization.role) ? (
        <Link to="/more/mandates/new" className="button primary">
          {t('mandates.draft.open')}
        </Link>
      ) : (
        <p className="muted">{t('mandates.viewOnly')}</p>
      )}
      {listed.isPending && <Loading />}
      {listed.isError && <Retry onRetry={() => void listed.refetch()} />}
      {listed.isSuccess && shown.length === 0 && <p className="muted">{t('mandates.none')}</p>}
      {shown.length > 0 && (
        <ul className="rows">
          {shown.map((mandate) => (
            <Row key={mandate.id} mandate={mandate} agent={names.get(mandate.agentId)} />
          ))}
        </ul>
      )}
      {unchecked > 0 && (
        <p className="notice" role="status">
          {t('brakes.unchecked', { count: String(unchecked) })}
        </p>
      )}
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
    </section>
  );
}
