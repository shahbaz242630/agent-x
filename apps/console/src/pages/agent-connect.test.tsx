// CN1a: "Connect your agent" on an agent's page. Each tool's tab shows its own
// line filled with this console's address (`/v1/mcp` on the same origin), the
// sign-in form first; the key form names the AGENTX_KEY variable and never a
// key; Cursor's and VS Code's buttons carry the right address; Copy says
// copied only once the clipboard has it; the tabs move by arrow keys; and no
// rendered snippet holds anything shaped like a key.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type Agent } from '../agents.ts';
import { CLIENTS, command, installLink, mcpUrl } from '../connect-snippets.ts';
import { ConnectAgent } from './agent-connect.tsx';

const AGENT: Agent = {
  id: '0199a0f0-0000-7000-8000-0000000000c1',
  name: 'Invoice agent',
  owner: '0199a0f0-0000-7000-8000-0000000000b1',
  status: 'ACTIVE',
  scopes: ['requests:write'],
  createdAt: '2026-10-26T05:00:00.000Z',
};
const URL_HERE = `${window.location.origin}/v1/mcp`;
/** An agent key's shape (axk_<32 hex>_<secret>), or any long run that could be a token. */
const KEY_SHAPED = /axk_|[A-Za-z0-9_-]{40,}/;

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const tab = (name: string) => screen.getByRole('tab', { name });
const shownText = () => screen.getByRole('tabpanel').textContent;

describe('the lines each tool takes', () => {
  const url = 'https://app.example.test/v1/mcp';

  it('builds the address from the origin', () => {
    expect(mcpUrl('https://app.example.test')).toBe(url);
  });

  it.each([
    ['claude-code', 'claude mcp add --transport http agentx https://app.example.test/v1/mcp'],
    ['codex', 'codex mcp add agentx --url https://app.example.test/v1/mcp'],
    ['gemini', 'gemini mcp add --transport http agentx https://app.example.test/v1/mcp'],
    ['other', 'npx add-mcp https://app.example.test/v1/mcp -n agentx'],
  ] as const)('%s signs in with no key in its line', (client, line) => {
    expect(command(client, 'sign-in', url)).toBe(line);
  });

  it.each(CLIENTS.filter((client) => client !== 'web'))('%s with a key reads it from AGENTX_KEY only', (client) => {
    const line = command(client, 'key', url) ?? '';
    expect(line).toContain(client === 'vscode' ? 'input:agentx-key' : 'AGENTX_KEY');
    expect(line).not.toMatch(KEY_SHAPED);
  });

  it('gives the web apps the address alone', () => {
    expect(command('web', 'sign-in', url)).toBeUndefined();
  });

  it('writes the settings each editor takes', () => {
    expect(JSON.parse(command('cursor', 'sign-in', url) ?? '')).toEqual({ mcpServers: { agentx: { url } } });
    expect(JSON.parse(command('vscode', 'sign-in', url) ?? '')).toEqual({
      servers: { agentx: { type: 'http', url } },
    });
    expect(JSON.parse(command('cursor', 'key', url) ?? '')).toEqual({
      mcpServers: { agentx: { url, headers: { Authorization: 'Bearer ${env:AGENTX_KEY}' } } },
    });
    expect(JSON.parse(command('vscode', 'key', url) ?? '')).toEqual({
      servers: { agentx: { type: 'http', url, headers: { Authorization: 'Bearer ${input:agentx-key}' } } },
      inputs: [{ type: 'promptString', id: 'agentx-key', description: 'Agent X key', password: true }],
    });
  });

  it("encodes the address in Cursor's and VS Code's install links", () => {
    const cursor = new URL(installLink('cursor', url));
    expect(cursor.protocol).toBe('cursor:');
    expect(cursor.searchParams.get('name')).toBe('agentx');
    expect(JSON.parse(atob(cursor.searchParams.get('config') ?? ''))).toEqual({ url });
    const vscode = installLink('vscode', url);
    expect(vscode.startsWith('vscode:mcp/install?')).toBe(true);
    expect(JSON.parse(decodeURIComponent(vscode.slice('vscode:mcp/install?'.length)))).toEqual({
      name: 'agentx',
      type: 'http',
      url,
    });
  });
});

describe('the panel', () => {
  it("shows Claude Code's sign-in line first, with this console's address and the agent to pick", () => {
    render(<ConnectAgent agent={AGENT} />);
    expect(screen.getByRole('heading', { name: 'Connect your agent' })).toBeTruthy();
    expect(tab('Claude Code').getAttribute('aria-selected')).toBe('true');
    expect(screen.getByLabelText('Claude Code command').textContent).toBe(
      `claude mcp add --transport http agentx ${URL_HERE}`,
    );
    expect(shownText()).toContain('type /mcp');
    expect(shownText()).toContain('pick Invoice agent');
    expect(screen.getByRole<HTMLInputElement>('radio', { name: /Sign in with Agent X/ }).checked).toBe(true);
  });

  it('switches to the key form, naming the variable and never a key', async () => {
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(screen.getByRole('radio', { name: /With a key/ }));
    expect(screen.getByLabelText('Claude Code command').textContent).toBe(
      `claude mcp add --transport http agentx ${URL_HERE} --header "Authorization: Bearer $AGENTX_KEY"`,
    );
    expect(shownText()).toContain('AGENTX_KEY environment variable');
  });

  it('says how each tool takes its key: VS Code asks, PowerShell writes $env, no button for a key', async () => {
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(screen.getByRole('radio', { name: /With a key/ }));
    expect(shownText()).toContain('In PowerShell, write $env:AGENTX_KEY');
    await userEvent.click(tab('Codex'));
    expect(shownText()).not.toContain('PowerShell');
    await userEvent.click(tab('VS Code'));
    expect(shownText()).toContain('VS Code asks for this agent');
    expect(shownText()).not.toContain('Add to VS Code');
    await userEvent.click(tab('Cursor'));
    expect(shownText()).toContain("Put these settings in Cursor's mcp.json.");
    expect(shownText()).not.toContain('Add to Cursor');
  });

  it('clears "Copied." when another line is shown', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: () => Promise.resolve() },
      configurable: true,
    });
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(screen.getByRole('button', { name: 'Copy the Claude Code command' }));
    expect(await screen.findByRole('status')).toBeTruthy();
    await userEvent.click(tab('Codex'));
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('shows every tab with no key-shaped text, in either form', async () => {
    render(<ConnectAgent agent={AGENT} />);
    for (const way of [/Sign in with Agent X/, /With a key/]) {
      for (const name of [
        'Claude Code',
        'Codex',
        'Gemini CLI',
        'Cursor',
        'VS Code',
        'Claude and ChatGPT apps',
        'Other tools',
      ]) {
        await userEvent.click(tab(name));
        const radio = screen.queryByRole('radio', { name: way });
        if (radio !== null) await userEvent.click(radio);
        expect(shownText()).not.toMatch(KEY_SHAPED);
        for (const link of within(screen.getByRole('tabpanel')).queryAllByRole('link')) {
          expect(link.getAttribute('href')).not.toMatch(/AGENTX_KEY|axk_/);
        }
      }
    }
  });

  it('gives Cursor and VS Code their install buttons for signing in, not for a key', async () => {
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(tab('Cursor'));
    expect(screen.getByRole('link', { name: 'Add to Cursor' }).getAttribute('href')).toBe(
      installLink('cursor', URL_HERE),
    );
    await userEvent.click(tab('VS Code'));
    expect(screen.getByRole('link', { name: 'Add to VS Code' }).getAttribute('href')).toBe(
      installLink('vscode', URL_HERE),
    );
    await userEvent.click(screen.getByRole('radio', { name: /With a key/ }));
    expect(screen.queryByRole('link', { name: 'Add to VS Code' })).toBeNull();
  });

  it('gives the web apps the address and how to add it, with no key choice', async () => {
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(tab('Claude and ChatGPT apps'));
    expect(screen.getByLabelText("Agent X's address for AI tools").textContent).toBe(URL_HERE);
    expect(screen.queryByRole('radio')).toBeNull();
    expect(shownText()).toContain('Add custom connector');
  });

  it('copies the line, saying so only once the clipboard has it', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(tab('Codex'));
    await userEvent.click(screen.getByRole('button', { name: 'Copy the Codex command' }));
    expect(writeText).toHaveBeenCalledWith(`codex mcp add agentx --url ${URL_HERE}`);
    expect((await screen.findByRole('status')).textContent).toBe('Copied.');
  });

  it("says when the browser won't copy", async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    render(<ConnectAgent agent={AGENT} />);
    await userEvent.click(screen.getByRole('button', { name: 'Copy the Claude Code command' }));
    expect((await screen.findByRole('status')).textContent).toContain('copy it yourself');
  });

  it('moves along the tabs by arrow keys, Home and End, wrapping at either end', () => {
    render(<ConnectAgent agent={AGENT} />);
    fireEvent.keyDown(tab('Claude Code'), { key: 'ArrowLeft' });
    expect(tab('Other tools').getAttribute('aria-selected')).toBe('true');
    expect(document.activeElement).toBe(tab('Other tools'));
    fireEvent.keyDown(tab('Other tools'), { key: 'ArrowRight' });
    expect(tab('Claude Code').getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(tab('Claude Code'), { key: 'End' });
    expect(tab('Other tools').getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(tab('Other tools'), { key: 'Home' });
    expect(tab('Claude Code').getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(tab('Claude Code'), { key: 'ArrowRight' });
    expect(tab('Codex').getAttribute('aria-selected')).toBe('true');
    expect(tab('Codex').tabIndex).toBe(0);
    expect(tab('Claude Code').tabIndex).toBe(-1);
    fireEvent.keyDown(tab('Codex'), { key: 'a' });
    expect(tab('Codex').getAttribute('aria-selected')).toBe('true');
  });

  it('says a suspended agent is refused until reactivated', () => {
    render(<ConnectAgent agent={{ ...AGENT, status: 'SUSPENDED' }} />);
    expect(screen.getByText(/suspended, so a tool connected as it is refused/)).toBeTruthy();
  });
});
