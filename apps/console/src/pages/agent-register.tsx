// Registering an agent (6D1), on the Agents tab for an admin or a developer
// (REGISTERING_ROLES), who becomes its owner. Its name and what it may do,
// each scope ticked by the person (none ticked for them, Rule Book §1.9),
// checked by the API's own rules before anything is sent; confirmed in the
// console's words (the API states none for it), then by passkey. Its first key
// comes in the confirm's answer, shown once (stepped-up.tsx, key-once.tsx).
import { useId, useState } from 'react';

import { agentRefusal, isAgentName, NAME_UNITS_MOST, REGISTERING, type Scope, SCOPES } from '../agents.ts';
import { Confirm } from '../confirm.tsx';
import { useActing } from '../session.tsx';
import { byPasskey } from '../step-up.ts';
import { t } from '../text.ts';
import { Scopes } from './agent.tsx';
import { Said, useChange } from './change.tsx';
import { LineField } from './line-field.tsx';

type Broken = 'none' | 'name' | 'scopes';

export function RegisterAgent() {
  const { organization } = useActing();
  const { busy, said, run } = useChange(agentRefusal);
  const [opened, setOpened] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<readonly Scope[]>([]);
  const [broken, setBroken] = useState<Broken>('none');
  const scopesHint = useId();
  if (!REGISTERING.includes(organization.role)) return null;
  if (!opened) {
    return (
      <>
        <button
          type="button"
          className="primary"
          onClick={() => {
            setOpened(true);
          }}
        >
          {t('agents.register')}
        </button>
        <Said said={said} />
      </>
    );
  }
  const toggle = (scope: Scope) => {
    setScopes(scopes.includes(scope) ? scopes.filter((one) => one !== scope) : [...scopes, scope]);
    setBroken('none');
  };
  // Sent in the API's own order, so the same ticks always send the same body.
  const asked = SCOPES.filter((scope) => scopes.includes(scope));
  const register = () =>
    run(() => byPasskey('/v1/agents', t('agents.registerLabel', { name }), { name, scopes: asked }, organization.id), {
      after: () => {
        setConfirming(false);
      },
    });
  return (
    <section className="stack" aria-labelledby="register-title">
      <h2 id="register-title">{t('agents.registerTitle')}</h2>
      <p className="muted">{t('agents.registerIntro')}</p>
      <LineField
        label={t('agents.name')}
        hint={t('agents.nameHint')}
        most={NAME_UNITS_MOST}
        value={name}
        onChange={(value) => {
          setName(value);
          setBroken('none');
        }}
        broken={broken === 'name' ? t('agents.nameBroken') : undefined}
      />
      <fieldset className="options" aria-describedby={scopesHint}>
        <legend>{t('agents.scopesLegend')}</legend>
        {SCOPES.map((scope) => (
          <label key={scope} className="option">
            <input
              type="checkbox"
              checked={scopes.includes(scope)}
              onChange={() => {
                toggle(scope);
              }}
            />
            <span>{t(`agents.scope.${scope}`)}</span>
          </label>
        ))}
      </fieldset>
      <p id={scopesHint} className="fine">
        {t('agents.scopesHint')}
      </p>
      {broken === 'scopes' && (
        <p className="notice" role="alert">
          {t('agents.scopesBroken')}
        </p>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setOpened(false);
            setBroken('none');
          }}
        >
          {t('confirm.cancel')}
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => {
            // Checked here by the API's own rules before anything is sent: what it would refuse is said in place.
            if (!isAgentName(name)) setBroken('name');
            else if (asked.length === 0) setBroken('scopes');
            else setConfirming(true);
          }}
        >
          {t('agents.registerButton')}
        </button>
      </div>
      <Said said={said} />
      {confirming && (
        <Confirm
          text={t('agents.registerText')}
          title={t('agents.registerConfirmTitle', { name })}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={() => {
            setConfirming(false);
          }}
          onConfirm={() => void register()}
        >
          <p className="amount">{name}</p>
          <Scopes scopes={asked} />
        </Confirm>
      )}
    </section>
  );
}
