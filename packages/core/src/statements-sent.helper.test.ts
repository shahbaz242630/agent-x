// Counts the statements a read sends, for the tests that hold a read to a
// fixed number however many rows it covers (the partner's no-per-row-loops
// rule, S62/S97). A helper, not a test: Vitest leaves `*.helper.test.ts` out
// (vitest.config.ts). Typed by the one method it uses, as only a module's
// infrastructure may import the query builder (.dependency-cruiser.js).

/** The part of a Kysely plugin the count needs: each statement passes through untouched. */
interface Counter {
  transformQuery(args: { readonly node: unknown }): unknown;
  transformResult(args: { readonly result: unknown }): Promise<unknown>;
}

/** What `read` gives, with the statements it sent through `tx`, each counted as Kysely sends it. */
export async function statementsSent<Tx extends { withPlugin(plugin: Counter): Tx }, T>(
  tx: Tx,
  read: (counted: Tx) => Promise<T>,
): Promise<{ readonly sent: number; readonly result: T }> {
  let sent = 0;
  const result = await read(
    tx.withPlugin({
      transformQuery: ({ node }) => {
        sent += 1;
        return node;
      },
      transformResult: ({ result: rows }) => Promise.resolve(rows),
    }),
  );
  return { sent, result };
}
