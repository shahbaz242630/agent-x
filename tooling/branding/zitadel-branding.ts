// CO11 (S216): Zitadel's own sign-in pages (password, second factor, passkey,
// forgot and change password) in the console's Calm Ledger colours. Those
// pages are Zitadel's Login V2, which we run unmodified (ADR-003 §12): its
// look is set by the instance's branding (the label policy), not by our code.
// The colours are read from the console's own stylesheet, so the two never
// drift. Run by a person with an instance admin's token, once per instance:
//
//   ZITADEL_ADMIN_TOKEN=… node tooling/branding/zitadel-branding.ts https://auth.example
//
// The token is read from the environment alone, never an argument, so it is
// kept out of the shell's history. It sets the policy, then activates it.
import { readFileSync } from 'node:fs';

/** The console's stylesheet, whose light and dark tokens the sign-in pages take. */
const STYLES = new URL('../../apps/console/src/styles.css', import.meta.url);

export interface Palette {
  readonly accent: string;
  readonly paper: string;
  readonly danger: string;
  readonly ink: string;
}

/** One token's value in a block of the stylesheet: `--name: #rrggbb;`. */
function token(block: string, name: string): string {
  const found = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})\\s*;`).exec(block)?.[1];
  if (found === undefined) throw new Error(`The console's stylesheet has no --${name} colour here`);
  return found.toLowerCase();
}

const palette = (block: string): Palette => ({
  accent: token(block, 'accent'),
  paper: token(block, 'paper'),
  danger: token(block, 'danger'),
  ink: token(block, 'ink'),
});

/** The light palette (the first `:root`) and the dark one (`:root` inside the dark media query). */
export function palettes(css: string): { readonly light: Palette; readonly dark: Palette } {
  const light = /:root\s*\{([^}]*)\}/.exec(css)?.[1];
  const dark = /prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{([^}]*)\}/.exec(css)?.[1];
  if (light === undefined || dark === undefined) throw new Error("The console's stylesheet has no light or dark :root");
  return { light: palette(light), dark: palette(dark) };
}

/** The admin API's label policy (PUT /admin/v1/policies/label) for these palettes. */
export function labelPolicy({ light, dark }: { readonly light: Palette; readonly dark: Palette }) {
  return {
    primaryColor: light.accent,
    backgroundColor: light.paper,
    warnColor: light.danger,
    fontColor: light.ink,
    primaryColorDark: dark.accent,
    backgroundColorDark: dark.paper,
    warnColorDark: dark.danger,
    fontColorDark: dark.ink,
    // The login name is shown whole: a person checks it is their own account they are signing in to.
    hideLoginNameSuffix: false,
    // The pages are ours to the person signing in; Zitadel stays credited in our notices.
    disableWatermark: true,
    // Light or dark as the device is set, as the console does.
    themeMode: 'THEME_MODE_AUTO',
  } as const;
}

/** The instance's label policy, and the ID of Zitadel's refusal of one that changes nothing. */
const LABEL_POLICY = '/admin/v1/policies/label';
const UNCHANGED = 'INSTANCE-28fHe';

export type Send = (method: string, path: string, body: unknown) => Promise<Response>;

/** The pictures the sign-in pages show (rendered from the console's mark, light and dark), and where each goes. */
export const ASSETS = [
  { file: 'logo.png', path: '/assets/v1/instance/policy/label/logo' },
  { file: 'logo-dark.png', path: '/assets/v1/instance/policy/label/logo/dark' },
  { file: 'icon.png', path: '/assets/v1/instance/policy/label/icon' },
  { file: 'icon-dark.png', path: '/assets/v1/instance/policy/label/icon/dark' },
] as const;

/** One picture as the assets API takes it: a form with the PNG under `file`. */
export function pictureForm(file: string, bytes: Uint8Array<ArrayBuffer>): FormData {
  const form = new FormData();
  form.append('file', new Blob([bytes], { type: 'image/png' }), file);
  return form;
}

/**
 * Sets the instance's label policy to the console's palettes and uploads its pictures (each lands in the policy's
 * preview), then activates it all at once; a refusal is said whole and stops the rest, so nothing half-made goes live.
 */
export async function applyBranding(
  send: Send,
  css: string,
  picture: (file: string) => Uint8Array<ArrayBuffer>,
): Promise<void> {
  const steps: readonly (readonly [string, string, unknown])[] = [
    ['PUT', LABEL_POLICY, labelPolicy(palettes(css))],
    ...ASSETS.map(({ file, path }) => ['POST', path, pictureForm(file, picture(file))] as const),
    ['POST', '/admin/v1/policies/label/_activate', {}],
  ];
  for (const [method, path, body] of steps) {
    const response = await send(method, path, body);
    if (response.ok) continue;
    const said = await response.text();
    // A run again (after a picture failed, or on a stack already given these colours by compose): Zitadel refuses a
    // policy that changes nothing (v4.20.5 instance_policy_label.go, INSTANCE-28fHe). The colours are already set,
    // so the pictures and the activation still go on.
    if (path === LABEL_POLICY && response.status === 400 && said.includes(UNCHANGED)) continue;
    throw new Error(`Zitadel refused ${method} ${path}: ${String(response.status)} ${said}`);
  }
}

/** The command line: the auth host's origin as its one argument, the token from ZITADEL_ADMIN_TOKEN. */
export async function main(args: readonly string[], env: NodeJS.ProcessEnv, fetcher: typeof fetch): Promise<string> {
  const origin = args[0];
  const adminToken = env.ZITADEL_ADMIN_TOKEN;
  if (origin === undefined || !/^https?:\/\/[^/]+$/.test(origin)) {
    throw new Error('Give the auth host as https://host (no path), and the token in ZITADEL_ADMIN_TOKEN.');
  }
  if (adminToken === undefined || adminToken === '')
    throw new Error('Set ZITADEL_ADMIN_TOKEN to an instance admin token.');
  await applyBranding(
    (method, path, body) =>
      fetcher(`${origin}${path}`, {
        method,
        // A picture's form sets its own content type (multipart, with its boundary); the rest are JSON.
        headers:
          body instanceof FormData
            ? { authorization: `Bearer ${adminToken}`, accept: 'application/json' }
            : { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json', accept: 'application/json' },
        body: body instanceof FormData ? body : JSON.stringify(body),
      }),
    readFileSync(STYLES, 'utf8'),
    (file) => new Uint8Array(readFileSync(new URL(file, import.meta.url))),
  );
  return `Branding set and activated on ${origin}: the sign-in pages follow the console's Calm Ledger colours.`;
}

if (import.meta.main) {
  try {
    console.log(await main(process.argv.slice(2), process.env, fetch));
  } catch (error) {
    console.error(`Branding not changed: ${(error as Error).message}`);
    process.exitCode = 1;
  }
}
