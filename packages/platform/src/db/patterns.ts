/** A UUID in its canonical form, which is how every organisation and row ID is written (ADR-007). */
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Schema and table in lower-case words: names from our migrations, never from
 * input. Checked on every call anyway, since the name goes into the SQL as a
 * name, quoted, rather than as a bound value.
 */
export const TABLE = /^[a-z][a-z0-9_]{0,62}\.[a-z][a-z0-9_]{0,62}$/;
