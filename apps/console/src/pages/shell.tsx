import { Link, Outlet } from '@tanstack/react-router';
import { useState } from 'react';

import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { HoldBanner } from './hold.tsx';
import { KeyHold } from './key-once.tsx';
import { SignInLate } from './sign-in-late.tsx';
import { SteppedUp } from './stepped-up.tsx';

const TABS = [
  { to: '/approvals', label: 'nav.approvals' },
  { to: '/payments', label: 'nav.payments' },
  { to: '/agents', label: 'nav.agents' },
  { to: '/more', label: 'nav.more' },
] as const;

/** The signed-in frame: the organisation acted in, the tabs, and a frozen or held organisation said at the top. */
export function Shell() {
  const { organization, choose, canSwitch } = useActing();
  // A new agent key on screen, not yet saved: switching organisation (no navigation to ask about) waits for Done.
  const [held, setHeld] = useState(false);
  return (
    <div className="shell">
      <header className="bar">
        <span className="brand">{t('brand')}</span>
        {canSwitch ? (
          <button
            type="button"
            className="org"
            disabled={held}
            title={held ? t('keyOnce.switchHeld') : undefined}
            onClick={() => {
              choose(null);
            }}
            aria-label={t('nav.switch')}
          >
            {organization.name} ▾
          </button>
        ) : (
          <span className="org">{organization.name}</span>
        )}
      </header>
      <nav className="tabs" aria-label="Sections">
        {TABS.map((tab) => (
          <Link key={tab.to} to={tab.to} activeProps={{ className: 'on', 'aria-current': 'page' }}>
            {t(tab.label)}
          </Link>
        ))}
      </nav>
      {organization.frozen && (
        <p className="banner" role="status">
          {t('frozen.banner')}
        </p>
      )}
      <HoldBanner />
      <main className="body">
        <KeyHold onHeld={setHeld}>
          <SteppedUp />
        </KeyHold>
        <SignInLate />
        <Outlet />
      </main>
    </div>
  );
}
