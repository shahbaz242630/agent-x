import type { Organization } from '../session.tsx';
import { t } from '../text.ts';
import { Panel, Unreadable } from './panel.tsx';

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
    <Panel id="choose" title={t('choose.title')}>
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
      <Unreadable count={unreadable} />
    </Panel>
  );
}

/** Signed in, but in no organisation: how to get into one. */
export function NoOrganization({ unreadable }: { readonly unreadable: number }) {
  return (
    <Panel id="none" title={t('none.title')} narrow>
      <p className="muted">{t('none.body')}</p>
      <Unreadable count={unreadable} />
    </Panel>
  );
}
