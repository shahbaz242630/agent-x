// A name people read, such as an organisation's or an agent's: shown to the
// organisation's own members, never logged or put in an audit event, and not
// an authority field (it grants nothing). It is kept in Unicode's composed
// form (NFC), so a name typed composed or decomposed is kept as the same
// text, and it must be something a person can see and read. (NFC doesn't
// merge letters that merely look alike, such as a Latin and a Cyrillic "a": a
// name is shown only to its own organisation's members.)

/**
 * What a name may not hold, anywhere: Unicode's "other" category (controls;
 * format characters, which reorder or hide text so one name reads as
 * another; unpaired surrogates; private-use and unassigned code points), the
 * line and paragraph separators, the code points Unicode says are shown as
 * nothing (the Hangul fillers, variation selectors), and braille, whose blank
 * pattern renders as a space.
 */
const INVISIBLE = /[\p{C}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\p{Script=Braille}]/u;

/**
 * The zero-width non-joiner and joiner where a script needs them to shape a
 * word: after a mark (the Indic scripts' virama: Devanagari, Bengali, Sinhala)
 * or before one, within a word, and between two Arabic-script letters
 * (Persian, Urdu). Anywhere else, between two Latin or Han letters say, they
 * change nothing a person sees, so they are as invisible as any other format
 * character.
 */
const JOINER_IN_A_WORD =
  /(?<=\p{M})\p{Join_Control}(?=[\p{L}\p{M}])|(?<=[\p{L}\p{M}])\p{Join_Control}(?=\p{M})|(?<=\p{Script=Arabic})\p{Join_Control}(?=\p{Script=Arabic})/gu;

/** Every joiner, taken out before marks are counted, so none can split a stack. */
const JOINERS = /\p{Join_Control}/gu;

/** Something a person reads: a letter or a digit. */
const READABLE = /[\p{L}\p{N}]/u;

/** A name that starts with a combining mark, or five marks in a row: more than one character carries. */
const STACKED = /^\p{M}|\p{M}{5}/u;

/**
 * The name as it is kept (composed, NFC), with the problems that keep it from
 * being one: it must be 1 to `most` visible characters (code points, as a
 * table's char_length counts them), with a letter or digit, no space at
 * either end, and no more than four combining marks on one character. The
 * problems say why, never what it was.
 */
export function visibleName(name: string, most: number): { readonly name: string; readonly problems: string[] } {
  const composed = name.normalize('NFC');
  const problems: string[] = [];
  const length = Array.from(composed).length;
  if (length === 0 || length > most) problems.push(`the name is 1 to ${String(most)} characters`);
  if (INVISIBLE.test(composed.replace(JOINER_IN_A_WORD, ''))) {
    problems.push('the name holds a control, format, invisible or unassigned character');
  }
  if (composed.trim() !== composed) problems.push('the name starts or ends with a space');
  if (!READABLE.test(composed)) problems.push('the name has no letter or digit');
  if (STACKED.test(composed.replace(JOINERS, '')))
    problems.push('the name starts with a combining mark, or stacks more than 4 on one');
  return { name: composed, problems };
}
