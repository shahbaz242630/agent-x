// Linking a bank account (6D4a, ADR-014 §4, BR-01): an admin's, on the Bank
// accounts list. Start asks the bank partner for a link (POST
// /v1/funding-sources/link-sessions) and answers its page, which takes the
// admin on to their bank: opened in a new tab, so this page waits here, the
// link kept in this tab (sources.ts) should it be reloaded meanwhile. Back
// from the bank, the admin chooses what happens to the account's pending
// requests when its consent runs out, in the API's `consent_expiry` words
// with none picked, and Agent X asks the partner, server to server, how the
// link ended: still waiting at the bank (ask again later), linked, turned down
// or cancelled at the bank, run out, or unknown to the partner, each said
// plainly. Nothing that comes back through the browser is believed: only the
// API's confirm. A start with no answer keeps its idempotency key, so Try
// again asks the partner for the same link, never a second one.
import { Link } from '@tanstack/react-router';
import { useRef, useState } from 'react';

import { api, ApiError } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import {
  decides,
  isBankPage,
  keepLink,
  type Link as BankLink,
  LINKING,
  type Source,
  SOURCES_PATH,
  sourceRefusal,
  type Started,
  startedLink,
} from '../sources.ts';
import { t, type TextKey } from '../text.ts';
import { Said, useChange } from './change.tsx';

/** What the confirm answered: the link, and the account it made once linked. */
interface Confirmed {
  readonly link: BankLink;
  readonly source: Source | null;
}

/** How a settled link ended, in plain words. */
const ENDED: Readonly<Record<Exclude<BankLink['status'], 'open' | 'linked'>, TextKey>> = {
  rejected: 'sources.link.rejected',
  expired: 'sources.link.expired',
  unknown: 'sources.link.unknown',
};

/** What the page says after asking how the link ended. */
type Told =
  | { readonly kind: 'waiting' }
  | { readonly kind: 'linked'; readonly source: Source }
  | { readonly kind: 'ended'; readonly words: TextKey };

function ToldText({ told }: { readonly told: Told }) {
  if (told.kind === 'waiting') return <p className="notice">{t('sources.link.waiting')}</p>;
  if (told.kind === 'ended') return <p className="notice">{t(told.words)}</p>;
  const { source } = told;
  return (
    <p className="notice" role="status">
      {t('sources.link.linked', { name: source.holderName, hint: source.hint })}{' '}
      <Link to="/more/sources/$id" params={{ id: source.id }}>
        {t('sources.link.see')}
      </Link>
    </p>
  );
}

/** The link waiting at the bank: its page, and asking how it ended once back. */
function AtBank({
  started,
  busy,
  onBack,
  onForget,
}: {
  readonly started: Started;
  readonly busy: boolean;
  readonly onBack: () => void;
  readonly onForget: () => void;
}) {
  return (
    <>
      <p>{t('sources.link.atBank', { time: timeText(started.link.expiresAt) })}</p>
      {isBankPage(started.authoriseUrl) ? (
        <a className="link" href={started.authoriseUrl} target="_blank" rel="noopener noreferrer">
          {t('sources.link.open')}
        </a>
      ) : (
        <p className="notice">{t('sources.link.badPage')}</p>
      )}
      <div className="actions">
        <button type="button" className="secondary" disabled={busy} onClick={onForget}>
          {t('sources.link.forget')}
        </button>
        <button type="button" className="primary" disabled={busy} onClick={onBack}>
          {t('sources.link.back')}
        </button>
      </div>
    </>
  );
}

export function LinkSource() {
  const { organization, session } = useActing();
  const [started, setStarted] = useState(() => startedLink(session.userId, organization.id));
  const [told, setTold] = useState<Told | null>(null);
  const [open, setOpen] = useState(false);
  const { busy, said, run } = useChange(sourceRefusal);
  // The start's key while it has no answer: Try again asks for the same link (sources.ts, decides).
  const startKey = useRef<string | null>(null);
  if (!LINKING.includes(organization.role)) return null;

  const keep = (next: Started | null) => {
    keepLink(session.userId, organization.id, next);
    setStarted(next ?? undefined);
  };
  const start = () =>
    run(async () => {
      setTold(null);
      const idempotencyKey = startKey.current ?? crypto.randomUUID();
      startKey.current = idempotencyKey;
      try {
        const answer = await api.post<Started>(`${SOURCES_PATH}/link-sessions`, {
          organization: organization.id,
          idempotencyKey,
        });
        startKey.current = null;
        keep({ link: answer.link, authoriseUrl: answer.authoriseUrl });
      } catch (error) {
        if (decides(error)) startKey.current = null;
        throw error;
      }
    });
  const confirm = (link: BankLink, consentExpiry: string, statementVersion?: number) =>
    run(async () => {
      setTold(null);
      try {
        const { status, body } = await api.write<Confirmed>(
          `${SOURCES_PATH}/link-sessions/${encodeURIComponent(link.id)}/confirm`,
          { organization: organization.id, body: { consentExpiry, statementVersion } },
        );
        setOpen(false);
        if (status === 202 || body.link.status === 'open') {
          setTold({ kind: 'waiting' });
          return;
        }
        keep(null);
        if (body.link.status === 'linked' && body.source !== null) setTold({ kind: 'linked', source: body.source });
        else if (body.link.status === 'linked') setTold({ kind: 'ended', words: 'sources.link.linkedUnread' });
        else setTold({ kind: 'ended', words: ENDED[body.link.status] });
      } catch (error) {
        setOpen(false);
        // Not this organisation's link (another person's tab, or long gone): nothing to ask about any more.
        if (error instanceof ApiError && error.status === 404) keep(null);
        throw error;
      }
    });

  return (
    <section className="stack" aria-labelledby="link-title">
      <h2 id="link-title">{t('sources.link.title')}</h2>
      {started === undefined ? (
        <>
          <p className="muted">{t('sources.link.body')}</p>
          <button type="button" className="primary" disabled={busy} onClick={() => void start()}>
            {t('sources.link.start')}
          </button>
        </>
      ) : (
        <AtBank
          started={started}
          busy={busy}
          onBack={() => {
            setOpen(true);
          }}
          onForget={() => {
            setTold(null);
            keep(null);
          }}
        />
      )}
      {told !== null && <ToldText told={told} />}
      <Said said={said} />
      {open && started !== undefined && (
        <Confirm
          statement="consent_expiry"
          title={t('sources.link.confirmTitle')}
          confirmLabel={t('sources.link.confirm')}
          busy={busy}
          onCancel={() => {
            setOpen(false);
          }}
          onConfirm={(choice, version) => void confirm(started.link, choice, version)}
        >
          <p>{t('sources.link.confirmBody')}</p>
        </Confirm>
      )}
    </section>
  );
}
