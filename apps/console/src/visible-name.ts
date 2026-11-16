// The API's own rules for a name or a note a person types, as
// packages/core/src/shared-kernel/visible-name.ts has them, checked in the
// browser before anything is sent so what the API would refuse is said in
// place (6D1's agent name; 6D2's supplier name, account holder and call-back
// note). The API checks again whatever is sent.

// What may not show anywhere; a joiner allowed only where a script needs it to shape a word; something readable; no
// mark first nor five piled up.
const INVISIBLE = /[\p{C}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Script=Braille}]/u;
const JOINER_IN_A_WORD =
  /(?<=\p{M})\p{Join_Control}(?=[\p{L}\p{M}])|(?<=[\p{L}\p{M}])\p{Join_Control}(?=\p{M})|(?<=\p{Script=Arabic})\p{Join_Control}(?=\p{Script=Arabic})/gu;
const JOINERS = /\p{Join_Control}/gu;
const READABLE = /[\p{L}\p{N}]/u;
const STACKED = /(?:^\p{M})|\p{M}{5}/u;
/** Seven digits or more in a run, of any script, spaces, dots, dashes, slashes or brackets between: a phone or account number. */
const LONG_NUMBER = /\p{Nd}(?:[\s./()-]*\p{Nd}){6}/u;

/**
 * The most UTF-16 units `most` characters can take, which a field's maxLength counts: two for a character beyond the
 * basic plane (an emoji), so a valid text of `most` such characters can still be typed; the `most` is checked in code.
 */
export const unitsMost = (most: number): number => most * 2;

/**
 * Whether text keeps the API's rules for a visible name (visibleName): 1 to
 * `most` characters once composed (NFC), a letter or digit, no space at either
 * end, nothing invisible, no pile of marks.
 */
export function isVisibleName(text: string, most: number): boolean {
  const composed = text.normalize('NFC');
  const length = Array.from(composed).length;
  return (
    length > 0 &&
    length <= most &&
    composed.trim() === composed &&
    READABLE.test(composed) &&
    !INVISIBLE.test(composed.replace(JOINER_IN_A_WORD, '')) &&
    !STACKED.test(composed.replace(JOINERS, ''))
  );
}

/** Whether a note kept for good keeps the API's rules (keptNote): a visible name with no long number in it. */
export const isKeptNote = (text: string, most: number): boolean =>
  isVisibleName(text, most) && !LONG_NUMBER.test(text.normalize('NFC'));
