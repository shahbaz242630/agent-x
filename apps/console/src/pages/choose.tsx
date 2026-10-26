import type { Organization } from '../session.tsx';
import { t } from '../text.ts';

/** More than one organisation and none chosen yet: each with the person's role in it. */
export function Choose({
  organizations,
  unreadable,
  onChoose,
}: {
  readonly organizations: readonly Organization[];
  readonly unreadable: number;
  readonly onChoose: (id: string) => void;
}) {
  return (
    <main className="center">
      <section className="panel" aria-labelledby="choose">
        <span className="brand">{t('brand')}</span>
        <h1 id="choose">{t('choose.title')}</h1>
        <p className="muted">{t('choose.body')}</p>
        <ul className="choices">
          {organizations.map((organization) => (
            <li key={organization.id}>
              <button
                type="button"
                className="choice"
                onClick={() => {
                  onChoose(organization.id);
                }}
              >
                <span>{organization.name}</span>
                <span className="muted">
                  {t(`choose.role.${organization.role}`)}
                  {organization.frozen && <span className="tag warn">{t('choose.frozen')}</span>}
                </span>
              </button>
            </li>
          ))}
        </ul>
        {unreadable > 0 && <p className="notice">{t('choose.unreadable')}</p>}
      </section>
    </main>
  );
}

/** Signed in, but in no organisation: how to get into one. */
export function NoOrganization({ unreadable }: { readonly unreadable: number }) {
  return (
    <main className="center">
      <section className="panel narrow" aria-labelledby="none">
        <span className="brand">{t('brand')}</span>
        <h1 id="none">{t('none.title')}</h1>
        <p className="muted">{t('none.body')}</p>
        {unreadable > 0 && <p className="notice">{t('choose.unreadable')}</p>}
      </section>
    </main>
  );
}
