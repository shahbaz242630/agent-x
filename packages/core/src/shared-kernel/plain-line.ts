// Text kept from outside to stand in a log line (decision 25: people's names;
// L4: cities): one line of plain text, never markup or control. Control
// characters and the ones that reorder text on screen (bidi marks, U+061C
// too, embeddings, overrides and isolates) become spaces, so the text can't
// hide or rearrange the line it stands in.

/** Control characters, and every bidi control. */
const NOT_TEXT = /[\p{Cc}\p{Bidi_Control}]/gu;

/** The text as one line with single spaces, or undefined for none, one that isn't text, or one over `most` UTF-16 units. */
export function plainLine(value: unknown, most: number): string | undefined {
  if (typeof value !== 'string' || !value.isWellFormed()) return undefined;
  const line = value.replace(NOT_TEXT, ' ').replace(/\s+/g, ' ').trim();
  return line.length === 0 || line.length > most ? undefined : line;
}
