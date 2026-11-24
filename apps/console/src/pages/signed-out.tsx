import './landing.css';

import { useState } from 'react';

import { signInAddress } from '../api.ts';
import { goTo } from '../navigate.ts';
import { t } from '../text.ts';
import { Icon, type IconName } from './icons.tsx';
import { cameBackLate, withoutSignInLate } from './sign-in-late.tsx';

/** Where this tab notes, across the page load sign-out ends with, that the person signed out themselves. */
const SIGNED_OUT = 'agentx.signedOut';

/** Signing out (the More page), just before the page reloads: the front page then says so, once. */
export function markSignedOut(): void {
  try {
    sessionStorage.setItem(SIGNED_OUT, '1');
  } catch {
    // Storage blocked: the front page shows without the note.
  }
}

/** Whether this load follows a sign-out: read once, then forgotten, so a reload shows the plain front page. */
function tookSignedOut(): boolean {
  try {
    const was = sessionStorage.getItem(SIGNED_OUT) === '1';
    sessionStorage.removeItem(SIGNED_OUT);
    return was;
  } catch {
    return false;
  }
}

const CONTROLS: readonly { readonly icon: IconName; readonly key: 'mandates' | 'passkey' | 'brakes' | 'evidence' }[] = [
  { icon: 'doc', key: 'mandates' },
  { icon: 'fingerprint', key: 'passkey' },
  { icon: 'brake', key: 'brakes' },
  { icon: 'sign', key: 'evidence' },
];

const STEPS = ['ask', 'decide', 'bank'] as const;

const TRUST: readonly { readonly icon: IconName; readonly key: 'uae' | 'passkeys' | 'signed' | 'bank' }[] = [
  { icon: 'pin', key: 'uae' },
  { icon: 'fingerprint', key: 'passkeys' },
  { icon: 'shield', key: 'signed' },
  { icon: 'bank', key: 'bank' },
];

/** The example card beside the headline: one request waiting for a passkey. Pictures only: no real request. */
function HeroCards() {
  return (
    <div className="hero-visual" aria-hidden="true">
      <div className="glass float side-card one">
        <span className="card-t">
          <Icon name="pay" size={15} />
          {t('landing.card.followed')}
        </span>
        <span className="line">
          <span className="muted">{t('landing.card.submitted')}</span>
          <span className="tag good">{t('landing.card.done')}</span>
        </span>
        <span className="line">
          <span>{t('landing.card.paid')}</span>
          <span className="mono">{t('landing.card.paidAmount')}</span>
        </span>
      </div>
      <div className="glass main-card">
        <span className="line">
          <span className="card-t">
            <Icon name="approve" size={15} />
            {t('landing.card.approval')}
          </span>
          <span className="tag warn">{t('landing.card.waiting')}</span>
        </span>
        <span className="hero-amount mono">
          <small>{t('landing.card.currency')}</small> {t('landing.card.amount')}
        </span>
        <span className="muted">{t('landing.card.supplier')}</span>
        <span className="fp">
          <Icon name="fingerprint" size={30} />
        </span>
        <span className="muted center-text">{t('landing.card.touch')}</span>
      </div>
      <div className="glass float side-card two">
        <span className="card-t">
          <Icon name="brake" size={15} />
          {t('landing.card.brake')}
        </span>
        <span className="muted">{t('landing.card.brakeText')}</span>
      </div>
    </div>
  );
}

/**
 * No one signed in (CO11): the public front page, in the Glass Vault manner (soft light behind frosted cards, the
 * passkey moment as the picture) in Calm Ledger's colours. One way in, back to the page they asked for; a late
 * sign-in or an ended session is said at the top.
 */
export function SignedOut({ ended }: { readonly ended: boolean }) {
  const signIn = () => {
    goTo(signInAddress(withoutSignInLate(window.location.pathname, window.location.search)));
  };
  const late = cameBackLate(window.location.search);
  const [signedOut] = useState(tookSignedOut);
  return (
    <div className="landing">
      <div className="aurora" aria-hidden="true">
        <i className="b1" />
        <i className="b2" />
        <i className="b3" />
      </div>
      <header className="l-top">
        <span className="brand">
          <span className="brand-mark" aria-hidden="true">
            <Icon name="mark" size={16} />
          </span>
          {t('brand')}
        </span>
        <nav className="l-links" aria-label={t('landing.nav')}>
          <a href="#how">{t('landing.how.eyebrow')}</a>
          <a href="#controls">{t('landing.controls.eyebrow')}</a>
          <a href="#trust">{t('landing.trust.eyebrow')}</a>
        </nav>
        <button type="button" className="primary" onClick={signIn}>
          {t('signedOut.button')}
        </button>
      </header>
      <main>
        <section className="hero" aria-labelledby="signed-out">
          <div className="hero-copy">
            {late && (
              <p className="notice" role="alert">
                {t('signIn.late')}
              </p>
            )}
            {signedOut && !ended && (
              <p className="notice good" role="status">
                {t('signedOut.done')}
              </p>
            )}
            {ended && (
              <p className="notice" role="status">
                {t('signedOut.ended')}
              </p>
            )}
            <span className="eyebrow">{t('landing.eyebrow')}</span>
            <h1 id="signed-out">
              {t('landing.title')} <em>{t('landing.titleAccent')}</em>
            </h1>
            <p className="lead">{t('signedOut.body')}</p>
            <div className="ctas">
              <button type="button" className="primary big" onClick={signIn}>
                {t('landing.signIn')}
                <Icon name="arrow" size={16} />
              </button>
              <a className="secondary big" href="#how">
                {t('landing.seeHow')}
              </a>
            </div>
            <p className="fine">{t('landing.invite')}</p>
          </div>
          <HeroCards />
        </section>

        <section className="l-section" id="controls" aria-labelledby="controls-title">
          <span className="eyebrow">{t('landing.controls.eyebrow')}</span>
          <h2 id="controls-title">{t('landing.controls.title')}</h2>
          <p className="sub">{t('landing.controls.text')}</p>
          <div className="features">
            {CONTROLS.map(({ icon, key }) => (
              <article key={key} className="glass feature">
                <span className="fi">
                  <Icon name={icon} size={22} />
                </span>
                <h3>{t(`landing.controls.${key}.title`)}</h3>
                <p>{t(`landing.controls.${key}.text`)}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="l-section" id="how" aria-labelledby="how-title">
          <span className="eyebrow">{t('landing.how.eyebrow')}</span>
          <h2 id="how-title">{t('landing.how.title')}</h2>
          <p className="sub">{t('landing.how.text')}</p>
          <ol className="steps">
            {STEPS.map((key, index) => (
              <li key={key} className="glass step">
                <span className="sn mono">{String(index + 1).padStart(2, '0')}</span>
                <h3>{t(`landing.how.${key}.title`)}</h3>
                <p>{t(`landing.how.${key}.text`)}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="l-section" id="trust" aria-labelledby="trust-title">
          <h2 id="trust-title" className="visually-hidden">
            {t('landing.trust.eyebrow')}
          </h2>
          <ul className="glass trust">
            {TRUST.map(({ icon, key }) => (
              <li key={key}>
                <Icon name={icon} size={22} />
                <span>
                  <b>{t(`landing.trust.${key}.title`)}</b>
                  <span className="muted">{t(`landing.trust.${key}.text`)}</span>
                </span>
              </li>
            ))}
          </ul>
          <div className="cta-band">
            <h2>{t('landing.cta')}</h2>
            <button type="button" className="primary big" onClick={signIn}>
              {t('landing.ctaButton')}
              <Icon name="arrow" size={16} />
            </button>
          </div>
        </section>
      </main>
      <footer className="l-foot">
        <span>{t('brand')}</span>
        <span className="mono">{t('landing.foot')}</span>
      </footer>
    </div>
  );
}
