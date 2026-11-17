// A registered contact confirming a reset of a member's lost second factor
// (CO9; ADR-012 §8, SEC-OPS-04): the page their email's link opens,
// `/factor-resets/confirm#token=…`, signed in or not (the API's route is
// public: the token is the proof). The token is read from the fragment once
// and the address cleaned of it (arrived-token.ts); it goes nowhere but
// `POST /v1/factor-resets/confirm`. Nothing happens on arrival: the page says
// what confirming does, the contact ticks that they checked it is real (never
// ticked for them) and presses. Confirmed, the factor is removed when the
// cooling-off ends, unless an admin cancels first.
import { useState } from 'react';

import { api } from '../api.ts';
import { useArrivedToken } from '../arrived-token.ts';
import { contactLinkRefusal } from '../people.ts';
import { timeText } from '../requests.ts';
import { t } from '../text.ts';
import { Tick } from './choices.tsx';
import { Panel } from './panel.tsx';

/** The token's form, as the API takes it: letters, digits, `.`, `-` and `_`, at most 256. */
const TOKEN = /^[A-Za-z0-9._-]{1,256}$/;

type Sent =
  | { readonly kind: 'ready' | 'sending' }
  | { readonly kind: 'done'; readonly until: string }
  | { readonly kind: 'refused'; readonly said: string };

export function ResetConfirm() {
  const arrived = useArrivedToken(TOKEN);
  const [ticked, setTicked] = useState(false);
  const [broken, setBroken] = useState(false);
  const [sent, setSent] = useState<Sent>({ kind: 'ready' });
  if (arrived === 'none' || arrived === 'malformed') {
    return (
      <Panel id="reset-confirm" title={t('resets.contact.title')} narrow>
        <p className="notice" role="alert">
          {t(arrived === 'none' ? 'resets.contact.noLink' : 'resets.contact.badLink')}
        </p>
      </Panel>
    );
  }
  if (sent.kind === 'done') {
    return (
      <Panel id="reset-confirm" title={t('resets.contact.doneTitle')} narrow>
        <p role="status">{t('resets.contact.done', { time: timeText(sent.until) })}</p>
      </Panel>
    );
  }
  const send = async () => {
    if (!ticked) {
      setBroken(true);
      return;
    }
    setSent({ kind: 'sending' });
    try {
      const answer = await api.post<{ readonly coolingOffUntil: string }>('/v1/factor-resets/confirm', {
        body: { token: arrived.token },
      });
      setSent({ kind: 'done', until: answer.coolingOffUntil });
    } catch (error) {
      // Said, and the button stays: pressing again is safe (the same contact's second press answers as the first).
      setSent({ kind: 'refused', said: contactLinkRefusal(error) });
    }
  };
  return (
    <Panel id="reset-confirm" title={t('resets.contact.title')} narrow>
      <p>{t('resets.contact.what')}</p>
      <p>{t('resets.contact.check')}</p>
      <p className="muted">{t('resets.contact.notYou')}</p>
      <Tick
        label={t('resets.contact.tick')}
        ticked={ticked}
        onTick={(now) => {
          setTicked(now);
          setBroken(false);
        }}
        broken={broken ? t('resets.contact.tickBroken') : undefined}
      />
      {sent.kind === 'refused' && (
        <p className="notice" role="alert">
          {sent.said}
        </p>
      )}
      <button type="button" className="primary" disabled={sent.kind === 'sending'} onClick={() => void send()}>
        {t('resets.contact.button')}
      </button>
    </Panel>
  );
}
