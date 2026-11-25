// CN1a "Connect your agent" (S218, Phase-6/Connect-Options-Plan.md), on an
// agent's page above its keys: one tab per AI tool, each with its one line to
// copy (or Cursor's and VS Code's own install buttons, or the address for the
// web apps), filled with this console's own address. Signing in is the form
// shown first: the tool opens Agent X in the browser, the person signs in and
// picks this agent, and it appears under Connected apps. The key form, for
// servers and CI, reads the key from an environment variable; no snippet ever
// holds a key (connect-snippets.ts). Shown to everyone who sees the page: it
// holds nothing secret, and connecting still needs the person's sign-in.
import { type KeyboardEvent, useId, useRef, useState } from 'react';

import { type Agent } from '../agents.ts';
import { type Client, CLIENTS, command, installLink, KEY_VARIABLE, mcpUrl, type Way } from '../connect-snippets.ts';
import { t } from '../text.ts';

type Copied = 'not yet' | 'copied' | 'failed';

/** The tools whose key line has `$AGENTX_KEY` filled in by the shell (Codex reads the variable itself). */
const SHELL_FILLED: readonly Client[] = ['claude-code', 'gemini', 'other'];

/** A line to copy, with its Copy button: said copied only once the clipboard has it, and said when it can't. */
function Copyable({ text, label }: { readonly text: string; readonly label: string }) {
  const [copied, setCopied] = useState<Copied>('not yet');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied('copied');
    } catch {
      setCopied('failed');
    }
  };
  return (
    <div className="snippet">
      <pre className="mono" aria-label={label}>
        {text}
      </pre>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          aria-label={t('connectAgent.copyNamed', { what: label })}
          onClick={() => void copy()}
        >
          {t('connectAgent.copy')}
        </button>
        {copied !== 'not yet' && (
          <span className={copied === 'failed' ? 'notice' : 'fine'} role="status">
            {t(copied === 'copied' ? 'connectAgent.copied' : 'connectAgent.copyFailed')}
          </span>
        )}
      </div>
    </div>
  );
}

/** What the chosen tool's tab shows: its line or button, and the steps after it. */
function ClientPanel({
  client,
  way,
  url,
  agent,
}: {
  readonly client: Client;
  readonly way: Way;
  readonly url: string;
  readonly agent: string;
}) {
  const line = command(client, way, url);
  const keyed = way === 'key';
  const editor = client === 'cursor' || client === 'vscode';
  return (
    <div className="stack">
      {client === 'web' ? (
        <>
          <Copyable key={url} text={url} label={t('connectAgent.address')} />
          <ol className="connect-steps">
            <li>{t('connectAgent.web.claude')}</li>
            <li>{t('connectAgent.web.chatgpt')}</li>
            <li>{t('connectAgent.signInPick', { name: agent })}</li>
          </ol>
          <p className="fine">{t('connectAgent.web.noKey')}</p>
        </>
      ) : (
        <>
          {editor && !keyed && (
            <p>
              <a className="button primary" href={installLink(client, url)}>
                {t(`connectAgent.install.${client}`)}
              </a>
            </p>
          )}
          {line !== undefined && <Copyable key={line} text={line} label={t(`connectAgent.line.${client}`)} />}
          <ol className="connect-steps">
            <li>{t(keyed && editor ? `connectAgent.stepKey.${client}` : `connectAgent.step.${client}`)}</li>
            {keyed ? (
              <>
                {/* VS Code asks for the key itself (its settings' prompt); the others read it from the environment. */}
                <li>
                  {t(client === 'vscode' ? 'connectAgent.keyStep.vscode' : 'connectAgent.keyStep', {
                    variable: KEY_VARIABLE,
                  })}
                </li>
                {/* A line the shell fills in: PowerShell names an environment variable its own way. */}
                {SHELL_FILLED.includes(client) && <li>{t('connectAgent.keyShell', { variable: KEY_VARIABLE })}</li>}
              </>
            ) : (
              <>
                <li>{t(`connectAgent.signIn.${client}`)}</li>
                <li>{t('connectAgent.signInPick', { name: agent })}</li>
              </>
            )}
          </ol>
        </>
      )}
    </div>
  );
}

export function ConnectAgent({ agent }: { readonly agent: Agent }) {
  const [client, setClient] = useState<Client>('claude-code');
  const [way, setWay] = useState<Way>('sign-in');
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const id = useId();
  const url = mcpUrl(window.location.origin);
  // Arrow keys move along the tabs, wrapping, and Home/End jump to either end (WAI-ARIA tabs): the tab focused is the
  // tab chosen (its onFocus), and the chosen tab alone is in the Tab order.
  const onKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const count = CLIENTS.length;
    const moves: Readonly<Record<string, number>> = {
      ArrowRight: (index + 1) % count,
      ArrowLeft: (index + count - 1) % count,
      Home: 0,
      End: count - 1,
    };
    const next = moves[event.key];
    if (next === undefined) return;
    event.preventDefault();
    tabs.current[next]?.focus();
  };
  return (
    <section className="stack connect-agent" aria-labelledby={`${id}-title`}>
      <h2 id={`${id}-title`}>{t('connectAgent.title')}</h2>
      <p className="muted">{t('connectAgent.intro', { name: agent.name })}</p>
      {agent.status !== 'ACTIVE' && <p className="notice">{t('connectAgent.suspended')}</p>}
      <div className="tabs" role="tablist" aria-label={t('connectAgent.tools')}>
        {CLIENTS.map((one, index) => (
          <button
            key={one}
            ref={(button) => {
              tabs.current[index] = button;
            }}
            type="button"
            role="tab"
            id={`${id}-tab-${one}`}
            aria-selected={one === client}
            aria-controls={`${id}-panel`}
            tabIndex={one === client ? 0 : -1}
            onClick={() => {
              setClient(one);
            }}
            onFocus={() => {
              setClient(one);
            }}
            onKeyDown={(event) => {
              onKey(event, index);
            }}
          >
            {t(`connectAgent.client.${one}`)}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${client}`} className="stack">
        {client !== 'web' && (
          <fieldset className="ways">
            <legend className="visually-hidden">{t('connectAgent.wayLegend')}</legend>
            {(['sign-in', 'key'] as const).map((one) => (
              <label key={one} className="way">
                <input
                  type="radio"
                  name={`${id}-way`}
                  checked={way === one}
                  onChange={() => {
                    setWay(one);
                  }}
                />
                <span>{t(`connectAgent.way.${one}`)}</span>
              </label>
            ))}
          </fieldset>
        )}
        <ClientPanel client={client} way={client === 'web' ? 'sign-in' : way} url={url} agent={agent.name} />
      </div>
      <p className="fine">{t('connectAgent.after')}</p>
    </section>
  );
}
