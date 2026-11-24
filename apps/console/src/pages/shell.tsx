import { Link, Outlet } from '@tanstack/react-router';
import { useState } from 'react';

import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { CommandBar } from './command.tsx';
import { HoldBanner } from './hold.tsx';
import { Icon } from './icons.tsx';
import { KeyHold } from './key-once.tsx';
import { placesFor } from './places.ts';
import { SignInLate } from './sign-in-late.tsx';
import { SteppedUp } from './stepped-up.tsx';

/** The organisation's initials, for its square beside the name. */
const initials = (name: string): string =>
  name
    .split(/[\s-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word[0]?.toUpperCase() ?? '')
    .join('');

/**
 * The signed-in frame (CO11, Calm Ledger): the organisation acted in and every place to go in one navigation, a
 * sidebar on a wide screen and four tabs along the bottom on a phone (the rest reached from More); the top bar with the
 * command bar (Ctrl+K); a frozen or held organisation said at the top.
 */
export function Shell() {
  const { organization, choose, canSwitch } = useActing();
  // A new agent key on screen, not yet saved: switching organisation (no navigation to ask about) waits for Done.
  const [held, setHeld] = useState(false);
  const role = t(`choose.role.${organization.role}`);
  const orgFace = (
    <>
      <span className="org-av" aria-hidden="true">
        {initials(organization.name)}
      </span>
      <span className="org-name">
        <b>{organization.name}</b>
        <small>{role}</small>
      </span>
    </>
  );
  return (
    <div className="shell">
      <aside className="side">
        <Link to="/approvals" className="brand side-brand">
          <span className="brand-mark" aria-hidden="true">
            <Icon name="mark" size={16} />
          </span>
          {t('brand')}
        </Link>
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
            {orgFace}
            <Icon name="updown" size={15} />
          </button>
        ) : (
          <span className="org">{orgFace}</span>
        )}
        <nav className="nav" aria-label="Sections">
          {placesFor(organization.role).map((group) => (
            <div key={group.label} className="nav-group">
              <span className="grp">{t(group.label)}</span>
              {group.places.map((place) => (
                <Link
                  key={place.to}
                  to={place.to}
                  className={place.tab === true ? 'tab-place' : undefined}
                  activeOptions={{ exact: place.exact === true }}
                  activeProps={{ className: place.tab === true ? 'tab-place on' : 'on', 'aria-current': 'page' }}
                >
                  <Icon name={place.icon} />
                  <span>{t(place.label)}</span>
                </Link>
              ))}
            </div>
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="bar">
          <Link to="/approvals" className="brand bar-brand" aria-label={t('brand')}>
            <span className="brand-mark" aria-hidden="true">
              <Icon name="mark" size={16} />
            </span>
          </Link>
          <span className="bar-org">{organization.name}</span>
          <span className="grow" />
          <CommandBar />
        </header>
        {organization.frozen && (
          <p className="banner" role="status">
            <Icon name="brake" />
            <span>{t('frozen.banner')}</span>
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
    </div>
  );
}
