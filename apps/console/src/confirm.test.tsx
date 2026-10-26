// 6A2: the shared confirm shows a change's consequence in the API's own
// words, read afresh on each opening, picks no choice for the person, and
// confirms nothing whose words couldn't be loaded.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { Confirm } from './confirm.tsx';

const STATEMENTS = {
  statements: [
    {
      id: 'freeze',
      version: 3,
      words: [
        { choice: 'cancel', text: 'Every request is cancelled now.' },
        { choice: 'pause', text: 'Its requests are held as they are.' },
      ],
    },
    { id: 'mark_failed', version: 1, words: [{ choice: 'confirm', text: 'Marking this payment failed frees it.' }] },
  ],
};

let answer: () => Promise<Response>;

beforeEach(() => {
  answer = () => Promise.resolve(new Response(JSON.stringify(STATEMENTS), { status: 200 }));
  vi.stubGlobal(
    'fetch',
    vi.fn(() => answer()),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function shown(
  statement: string,
  busy = false,
  queries = new QueryClient({ defaultOptions: { queries: { retry: false } } }),
) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <QueryClientProvider client={queries}>
      <Confirm
        statement={statement}
        title="Freeze the organisation?"
        confirmLabel="Freeze"
        onConfirm={onConfirm}
        onCancel={onCancel}
        busy={busy}
      >
        <p>Staging-Test-Org-1</p>
      </Confirm>
    </QueryClientProvider>,
  );
  return { onConfirm, onCancel };
}

const confirmButton = () => screen.getByRole('button', { name: 'Freeze' });

describe('the shared confirm', () => {
  it('shows each choice in the API’s words with none picked, and confirms the one chosen', async () => {
    const { onConfirm } = shown('freeze');

    expect(screen.getByRole('dialog', { name: 'Freeze the organisation?' })).toBeDefined();
    expect(screen.getByText('Staging-Test-Org-1')).toBeDefined();
    const pause = await screen.findByRole('radio', { name: 'Its requests are held as they are.' });
    expect(screen.getByRole('radio', { name: 'Every request is cancelled now.' })).toHaveProperty('checked', false);
    expect(pause).toHaveProperty('checked', false);
    expect(confirmButton()).toHaveProperty('disabled', true);

    await userEvent.click(pause);
    await userEvent.click(confirmButton());

    expect(onConfirm).toHaveBeenCalledWith('pause');
  });

  it('shows a change with no choice in its words, ready to confirm', async () => {
    const { onConfirm } = shown('mark_failed');

    expect(await screen.findByText('Marking this payment failed frees it.')).toBeDefined();
    expect(screen.queryByRole('radio')).toBeNull();
    await userEvent.click(confirmButton());

    expect(onConfirm).toHaveBeenCalledWith('confirm');
  });

  it.each([
    ['words that fail to load', 'freeze', () => Promise.resolve(new Response('{}', { status: 503 }))],
    ['a set the API doesn’t serve', 'unknown', () => Promise.resolve(new Response(JSON.stringify(STATEMENTS)))],
  ])('confirms nothing with %s, saying so', async (_what, statement, failing) => {
    answer = failing;
    shown(statement);

    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      expect.stringContaining("can't be confirmed yet"),
    );
    expect(confirmButton()).toHaveProperty('disabled', true);
  });

  it('reads the words again on each opening, and shows none after a failed read', async () => {
    const queries = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    shown('mark_failed', false, queries);
    expect(await screen.findByText('Marking this payment failed frees it.')).toBeDefined();
    cleanup();
    answer = () => Promise.resolve(new Response('{}', { status: 503 }));

    shown('mark_failed', false, queries);

    expect(await screen.findByRole('alert')).toBeDefined();
    expect(screen.queryByText('Marking this payment failed frees it.')).toBeNull();
    expect(confirmButton()).toHaveProperty('disabled', true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('cancels by its button or Escape, and starts on Cancel', async () => {
    const { onCancel } = shown('mark_failed');

    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Cancel' }));
    await userEvent.keyboard('{Escape}');
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalledTimes(2);
  });

  it('can’t be pressed twice while the change is being sent', async () => {
    const { onCancel } = shown('mark_failed', true);

    await screen.findByText('Marking this payment failed frees it.');
    await userEvent.keyboard('{Escape}');

    expect(confirmButton()).toHaveProperty('disabled', true);
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveProperty('disabled', true);
    expect(onCancel).not.toHaveBeenCalled();
  });
});
