// Reading an answer from the login service (B5-3, B6-2b): its body as text,
// refused past a bound however the answer declares its length, so a login
// service gone wrong can't hold the API's memory. The address book and the
// event feed share it.

/** The body as text; `tooLarge` is thrown once it passes `most` bytes. */
export async function boundedText(response: Response, most: number, tooLarge: () => Error): Promise<string> {
  const reader = (response.body as ReadableStream<Uint8Array> | null)?.getReader();
  if (reader === undefined) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > most) {
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}
