// 6A1: the entry puts the console in the page's #root, and refuses a page without one.
import { cleanup, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  cleanup();
  document.getElementById('root')?.remove();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe('the console’s entry (6A1)', () => {
  it('renders the console into #root', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('{}', { status: 401 }))),
    );
    const root = document.createElement('div');
    root.id = 'root';
    document.body.append(root);
    await import('./main.tsx');
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeDefined();
  });

  it('refuses a page with no #root', async () => {
    await expect(import('./main.tsx')).rejects.toThrow('The console page has no #root');
  });
});
