// Kysely's handles typed covariant in their tables (CQ8, TypeScript 4.7's
// variance annotations). Without this the compiler can't measure how
// Kysely<DB> varies with DB, so each time a handle with more tables is passed
// where one with fewer is wanted (a use case's transaction handed to a
// module's read) it compares Kysely's whole structure: ~0.5M type
// instantiations and hundreds of depth-limit hits for each pair of table
// sets, ending at the limit unproven and let through either way. Declared
// covariant, the compiler compares the table sets alone: a handle with every
// table the callee names is let through; one missing a table is refused,
// which the structural comparison let through.
//
// The annotation can't be proven against Kysely's structure (its callbacks
// take the handle back, so the compiler's own check of it reports TS2636),
// which is why it lives in a declaration file, read without that check
// (skipLibCheck). It is a claim about types only: a handle with more tables
// is the same object, and a query on fewer of its tables is one it can run.
export {};

declare module 'kysely' {
  /* eslint-disable @typescript-eslint/no-empty-object-type, @typescript-eslint/no-unused-vars -- the declarations merge with Kysely's classes: only `out` is added. */
  interface Kysely<out DB> {}
  interface Transaction<out DB> {}
  /* eslint-enable @typescript-eslint/no-empty-object-type, @typescript-eslint/no-unused-vars */
}
