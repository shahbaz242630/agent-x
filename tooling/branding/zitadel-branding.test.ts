// CO11: the sign-in pages' branding comes from the console's own colours, is
// sent as the admin API's label policy then activated, refuses half-given
// settings, and is the local stack's default too (compose), so the three agree.
import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import { applyBranding, ASSETS, labelPolicy, main, palettes, type Send } from './zitadel-branding.ts';

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
const picture = () => PNG;

const CSS = readFileSync(new URL('../../apps/console/src/styles.css', import.meta.url), 'utf8');
const COMPOSE = readFileSync(new URL('../../deploy/compose/compose.yaml', import.meta.url), 'utf8');

const ok = () => Promise.resolve(new Response('{}', { status: 200 }));

describe('the sign-in pages’ branding (CO11)', () => {
  it('takes the console’s Calm Ledger colours, light and dark', () => {
    expect(palettes(CSS)).toEqual({
      light: { accent: '#0e5c57', paper: '#f5f4f1', danger: '#ae281f', ink: '#1b1a18' },
      dark: { accent: '#5cc0b3', paper: '#121211', danger: '#f08a7e', ink: '#edebe6' },
    });
  });

  it('refuses a stylesheet missing a colour or a theme', () => {
    expect(() => palettes(':root { --paper: #ffffff; }')).toThrow(/no light or dark :root/);
    expect(() =>
      palettes(':root { --paper: #ffffff; } @media (prefers-color-scheme: dark) { :root { --paper: #000000; } }'),
    ).toThrow(/no --accent colour/);
  });

  it('sets the label policy, then activates it, in that order', async () => {
    const send = vi.fn<Send>(ok);
    await applyBranding(send, CSS, picture);
    expect(send.mock.calls.map(([method, path]) => `${method} ${path}`)).toEqual([
      'PUT /admin/v1/policies/label',
      'POST /assets/v1/instance/policy/label/logo',
      'POST /assets/v1/instance/policy/label/logo/dark',
      'POST /assets/v1/instance/policy/label/icon',
      'POST /assets/v1/instance/policy/label/icon/dark',
      'POST /admin/v1/policies/label/_activate',
    ]);
    const form = send.mock.calls[1]?.[2];
    if (!(form instanceof FormData)) throw new Error('the logo was not sent as a form');
    const sent = form.get('file');
    if (!(sent instanceof File)) throw new Error('the form holds no file');
    expect(sent.name).toBe('logo.png');
    expect(sent.type).toBe('image/png');
    expect(new Uint8Array(await sent.arrayBuffer())).toEqual(PNG);
    expect(send.mock.calls[0]?.[2]).toEqual(labelPolicy(palettes(CSS)));
    expect(send.mock.calls[0]?.[2]).toMatchObject({ themeMode: 'THEME_MODE_AUTO', hideLoginNameSuffix: false });
  });

  it('stops at a refusal, saying it whole, and activates nothing', async () => {
    const send = vi.fn<Send>(() => Promise.resolve(new Response('no permission', { status: 403 })));
    await expect(applyBranding(send, CSS, picture)).rejects.toThrow(
      'Zitadel refused PUT /admin/v1/policies/label: 403 no permission',
    );
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('sends the token from the environment to the origin given, and says what it did', async () => {
    const fetcher = vi.fn<typeof fetch>(ok);
    const said = await main(['https://auth.example'], { ZITADEL_ADMIN_TOKEN: 'secret' }, fetcher);
    expect(said).toContain('https://auth.example');
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe('https://auth.example/admin/v1/policies/label');
    expect(init?.method).toBe('PUT');
    expect(new Headers(init?.headers).get('authorization')).toBe('Bearer secret');
    expect(new Headers(init?.headers).get('content-type')).toBe('application/json');
    // The pictures go as forms, the repository's own PNGs, their content type left to the form.
    const [, logo] = fetcher.mock.calls[1] ?? [];
    expect(logo?.body).toBeInstanceOf(FormData);
    expect(new Headers(logo?.headers).get('content-type')).toBeNull();
    expect(new Headers(logo?.headers).get('authorization')).toBe('Bearer secret');
    expect(fetcher).toHaveBeenCalledTimes(2 + ASSETS.length);
  });

  it('refuses a missing or pathed origin, or no token, before sending anything', async () => {
    const fetcher = vi.fn<typeof fetch>(ok);
    await expect(main([], { ZITADEL_ADMIN_TOKEN: 'x' }, fetcher)).rejects.toThrow(/auth host/);
    await expect(main(['https://auth.example/ui'], { ZITADEL_ADMIN_TOKEN: 'x' }, fetcher)).rejects.toThrow(/auth host/);
    await expect(main(['https://auth.example'], {}, fetcher)).rejects.toThrow(/ZITADEL_ADMIN_TOKEN/);
    await expect(main(['https://auth.example'], { ZITADEL_ADMIN_TOKEN: '' }, fetcher)).rejects.toThrow(
      /ZITADEL_ADMIN_TOKEN/,
    );
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('has every picture it uploads in the repository, each a PNG', () => {
    for (const { file } of ASSETS) {
      const bytes = readFileSync(new URL(file, new URL('./zitadel-branding.ts', import.meta.url)));
      expect([...bytes.subarray(0, 4)]).toEqual([0x89, 0x50, 0x4e, 0x47]);
    }
  });

  it('is the local stack’s default branding too (compose), colour for colour', () => {
    const policy = labelPolicy(palettes(CSS));
    const env = (name: string) =>
      new RegExp(`ZITADEL_DEFAULTINSTANCE_LABELPOLICY_${name}: '([^']*)'`).exec(COMPOSE)?.[1];
    expect({
      primaryColor: env('PRIMARYCOLOR'),
      backgroundColor: env('BACKGROUNDCOLOR'),
      warnColor: env('WARNCOLOR'),
      fontColor: env('FONTCOLOR'),
      primaryColorDark: env('PRIMARYCOLORDARK'),
      backgroundColorDark: env('BACKGROUNDCOLORDARK'),
      warnColorDark: env('WARNCOLORDARK'),
      fontColorDark: env('FONTCOLORDARK'),
      disableWatermark: env('DISABLEWATERMARK') === 'true',
    }).toEqual({
      primaryColor: policy.primaryColor,
      backgroundColor: policy.backgroundColor,
      warnColor: policy.warnColor,
      fontColor: policy.fontColor,
      primaryColorDark: policy.primaryColorDark,
      backgroundColorDark: policy.backgroundColorDark,
      warnColorDark: policy.warnColorDark,
      fontColorDark: policy.fontColorDark,
      disableWatermark: policy.disableWatermark,
    });
  });
});
