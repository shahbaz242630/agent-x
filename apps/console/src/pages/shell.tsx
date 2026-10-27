import { Link, Outlet } from '@tanstack/react-router';

import { useActing } from '../session.tsx';
import { t } from '../text.ts';

const TABS = [
  { to: '/approvals', label: 'nav.approvals' },
  { to: '/payments', label: 'nav.payments' },
  { to: '/agents', label: 'nav.agents' },
  { to: '/more', label: 'nav.more' },
] as const;

/** The signed-in frame: the organisation acted in, the tabs, and a frozen organisation said at the top. */
export function Shell() {
  const { organization, choose, canSwitch } = useActing();
  return (
    <div className="shell">
      <header className="bar">
        <span className="brand">{t('brand')}</span>
        {canSwitch ? (
          <button
            type="button"
            className="org"
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
      <main className="body">
        <Outlet />
      </main>
    </div>
  );
}
