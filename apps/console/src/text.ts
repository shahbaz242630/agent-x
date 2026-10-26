// The console's words (ADR-010: in a translation file, English first). Each
// is read by its key, so a missing word is a type error, never a blank on
// screen; `{name}` in a word is filled from `values`.
import en from './text/en.json';

export type TextKey = keyof typeof en;

export function t(key: TextKey, values: Readonly<Record<string, string>> = {}): string {
  return en[key].replace(/\{(\w+)\}/g, (whole, name: string) => values[name] ?? whole);
}
