// The organisation's freeze (6B2, decisions 10, 11 and 14), under More (look
// A): freezing is the brake for everything at once, one confirm and no
// passkey; the person reads what happens to pending requests in the API's
// `freeze` words, chooses one (cancel first, as the API lists them), and it is
// done. Unfreezing is an admin's, by passkey: a reason, and what happens to
// the held requests in the `unfreeze` words, then the shared step-up. The
// banner at the top of every page says the organisation is frozen (shell.tsx).
import { useState } from 'react';

import { atOnce, FREEZING, REACTIVATING } from '../brakes.ts';
import { Confirm } from '../confirm.tsx';
import { useActing } from '../session.tsx';
import { ask } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './brakes.tsx';
import { LineField, NOTE_MOST } from './line-field.tsx';

export function Freeze() {
  const { organization } = useActing();
  const { busy, said, run } = useChange();
  // Which pop-up was opened: one opened as a freeze never turns into an unfreeze (someone else froze it meanwhile).
  const [open, setOpen] = useState<'freeze' | 'unfreeze' | null>(null);
  const [reason, setReason] = useState('');
  const names = { name: organization.name };
  const frozen = organization.frozen;
  const may = (frozen ? REACTIVATING : FREEZING).includes(organization.role);
  const close = () => {
    setOpen(null);
  };
  const freeze = (pendingRequests: string, statementVersion?: number) =>
    run(
      () =>
        atOnce('/v1/organization/freeze', {
          organization: organization.id,
          body: { pendingRequests, confirmed: true, statementVersion },
        }),
      t('freeze.done'),
      close,
    );
  // The reason and choice are asked with; the version of the words shown goes with the confirm (CO3).
  const unfreeze = (pendingRequests: string, statementVersion?: number) =>
    run(
      () =>
        ask(
          {
            label: t('unfreeze.label', names),
            askPath: '/v1/organization/unfreeze',
            confirmPath: '/v1/organization/unfreeze/confirm',
            body: { reason: reason.trim(), pendingRequests },
            organization: organization.id,
          },
          { statementVersion },
        ),
      t('unfreeze.done'),
      close,
    );
  const kind = frozen ? 'unfreeze' : 'freeze';
  return (
    <section className="stack" aria-labelledby={`${kind}-title`}>
      <h2 id={`${kind}-title`}>{t(`${kind}.heading`)}</h2>
      <p className="muted">{t(`${kind}.body`)}</p>
      {may ? (
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setOpen(kind);
          }}
        >
          {t(`${kind}.button`)}
        </button>
      ) : (
        <p className="muted">{t(`${kind}.viewOnly`)}</p>
      )}
      <Said said={said} />
      {open === kind && (
        <Confirm
          statement={kind}
          title={t(`${kind}.title`, names)}
          confirmLabel={t(frozen ? 'brakes.passkeyConfirm' : 'freeze.confirm')}
          busy={busy}
          ready={!frozen || reason.trim().length > 0}
          onCancel={close}
          onConfirm={(choice, version) => void (frozen ? unfreeze(choice, version) : freeze(choice, version))}
        >
          {frozen && (
            // One line of up to 200 characters, as the reason is kept for good (keptNote): no long numbers.
            <LineField
              label={t('unfreeze.reason')}
              hint={t('unfreeze.reasonHint')}
              most={NOTE_MOST}
              value={reason}
              onChange={setReason}
            />
          )}
        </Confirm>
      )}
    </section>
  );
}
