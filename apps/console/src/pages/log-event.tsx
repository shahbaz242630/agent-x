// How a log's actor, an event's chain hashes and a table of signed events are
// shown (6C2), the same on the audit log, the access log and a request's
// evidence: who by name and email where known, their ID beside it (two people
// or agents may share a name, SEC-AG-10), and each hash whole, in mono.
import { type Actor, actorText, type LogEvent } from '../logs.ts';
import { timeText } from '../requests.ts';
import { t } from '../text.ts';

/** Who it was by, with a press that narrows the log to them where the screen offers one. */
export function ActorLine({ actor, onOnly }: { readonly actor: Actor; readonly onOnly?: () => void }) {
  return (
    <span className="muted">
      {t('logs.by')} {actorText(actor)} <span className="mono">{actor.id}</span>
      {onOnly !== undefined && (
        <>
          {' '}
          <button type="button" className="link" onClick={onOnly}>
            {t('logs.onlyActor')}
          </button>
        </>
      )}
    </span>
  );
}

/** An event's hash and the one before it in the chain: what links it there. */
export function Hashes({ hash, prevHash }: { readonly hash: string; readonly prevHash: string }) {
  return (
    <span className="hashes mono">
      {t('logs.hash')} {hash}
      <br />
      {t('logs.prevHash')} {prevHash}
    </span>
  );
}

/** Signed events as a table, in the order given: when, what, who, about what, and their hashes. */
export function EventTable({ events }: { readonly events: readonly LogEvent[] }) {
  return (
    <div className="table-scroll">
      <table className="events">
        <thead>
          <tr>
            <th scope="col">{t('logs.column.seq')}</th>
            <th scope="col">{t('logs.column.when')}</th>
            <th scope="col">{t('logs.column.action')}</th>
            <th scope="col">{t('logs.column.actor')}</th>
            <th scope="col">{t('logs.column.subject')}</th>
            <th scope="col">{t('logs.column.hashes')}</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td className="mono">{event.seq}</td>
              <td>
                {timeText(event.recordedAt)}
                <br />
                <span className="mono fine">{event.recordedAt}</span>
              </td>
              <td className="mono">{event.action}</td>
              <td>
                {actorText(event.actor)}
                <br />
                <span className="mono fine">{event.actor.id}</span>
              </td>
              <td className="mono">
                {event.subject.type}
                <br />
                <span className="fine">{event.subject.id}</span>
              </td>
              <td>
                <Hashes hash={event.hash} prevHash={event.prevHash} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
