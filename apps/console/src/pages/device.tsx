// Connecting a device (6E3c, RFC 8628 §3.3; ADR-016): the page a device with
// no browser of its own (a headless gateway, a CLI) tells the person to open,
// `/device`, drawn before any organisation is chosen, as `/connect` is. The
// person types the code the device shows (or follows its link, the code
// filled in); the API finds the device's request and makes it this browser's
// alone, and the person goes on to `/connect` to answer it as any app's: the
// same names, warnings, pickers and step-up. Answered, `/connect` comes back
// here (`?answered=allowed|denied`) to say to go back to the device, which
// learns the answer by polling. Five tries a minute: a code typed wrong says
// so, and nothing more.
import { useRouterState } from '@tanstack/react-router';
import { type SyntheticEvent, useState } from 'react';

import { api, ApiError, isSignedOut, signInAddress } from '../api.ts';
import { DEVICE } from '../connections.ts';
import { goTo } from '../navigate.ts';
import type { Session } from '../session.tsx';
import { t } from '../text.ts';
import { CONNECT } from './connect.tsx';
import { Panel } from './panel.tsx';

/** The page's own address with the code typed so far: where sign-in comes back to. */
const pageOf = (code: string): string =>
  code === '' ? DEVICE : `${DEVICE}?${new URLSearchParams({ user_code: code }).toString()}`;

type Sent = 'ready' | 'sending' | { readonly said: string };

/** What a lookup refused says: a code that finds nothing, too many tries, or anything else. */
function refusalOf(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) return t('device.notFound');
  if (error instanceof ApiError && error.status === 429) return t('device.tooMany');
  return t('device.failed');
}

function CodeForm({ typed }: { readonly typed: string }) {
  const [code, setCode] = useState(typed);
  const [sent, setSent] = useState<Sent>('ready');
  const send = async (event: SyntheticEvent) => {
    event.preventDefault();
    setSent('sending');
    try {
      const { requestId } = await api.post<{ readonly requestId: string }>('/v1/oauth/device/lookup', {
        body: { userCode: code },
      });
      goTo(`${CONNECT}?${new URLSearchParams({ request: requestId }).toString()}`);
    } catch (error) {
      if (isSignedOut(error)) {
        goTo(signInAddress(pageOf(code)));
        return;
      }
      setSent({ said: refusalOf(error) });
    }
  };
  return (
    <form className="stack" onSubmit={(event) => void send(event)}>
      <label className="field" htmlFor="device-code">
        {t('device.codeLabel')}
      </label>
      <input
        id="device-code"
        className="mono"
        autoComplete="off"
        autoCapitalize="characters"
        spellCheck={false}
        maxLength={32}
        value={code}
        onChange={(event) => {
          setCode(event.target.value);
        }}
      />
      <p className="fine">{t('device.codeHint')}</p>
      {typeof sent === 'object' && (
        <p className="notice" role="alert">
          {sent.said}
        </p>
      )}
      <div className="actions">
        <button type="submit" className="primary" disabled={sent === 'sending' || code.trim() === ''}>
          {t('device.find')}
        </button>
      </div>
    </form>
  );
}

export function Device({ session }: { readonly session: Session | null }) {
  // The raw query, not the router's parsed one, which reads values as JSON.
  const search = useRouterState({ select: ({ location }) => location.searchStr });
  const query = new URLSearchParams(search);
  const answered = query.get('answered');
  const typed = query.get('user_code') ?? '';
  if (answered === 'allowed' || answered === 'denied') {
    return (
      <Panel id="device" title={t('device.title')} narrow>
        <p className="notice" role="status">
          {t(answered === 'allowed' ? 'device.allowed' : 'device.denied')}
        </p>
      </Panel>
    );
  }
  return (
    <Panel id="device" title={t('device.title')} narrow>
      <p>{t('device.intro')}</p>
      <p className="notice">{t('device.warning')}</p>
      {session === null ? (
        <>
          <p>{t('device.signInFirst')}</p>
          <button
            type="button"
            className="primary"
            onClick={() => {
              goTo(signInAddress(pageOf(typed)));
            }}
          >
            {t('signedOut.button')}
          </button>
        </>
      ) : (
        <CodeForm typed={typed} />
      )}
    </Panel>
  );
}
