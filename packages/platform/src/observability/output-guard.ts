// ADR-013, SEC-DATA-01: a runtime backstop behind the lint rules. Lint keeps
// our own code from writing to stdout or stderr except through the logger,
// but it can't see every spelling, and a dependency, a Node warning or Node's
// own debug output can write there too. So at start-up the app wraps both
// streams' write methods: whatever passes through them is cleaned the same way
// as a log line. The logger itself writes straight to file descriptor 1, so its
// lines don't pass through here twice.
import { redactLine } from './redact.ts';
import { scrub } from './scrub.ts';

type Callback = (error?: Error | null) => void;

/** The write method of process.stdout and process.stderr. */
export interface Output {
  write(chunk: string | Uint8Array, encoding?: BufferEncoding | Callback, callback?: Callback): boolean;
}

const GUARDED = Symbol('agentx.outputGuarded');

function isJson(line: string): boolean {
  try {
    JSON.parse(line);
    return true;
  } catch {
    return false;
  }
}

/** Each JSON line is redacted like a log line; any other text is scrubbed. Line breaks are kept. */
export function cleanOutput(text: string, now: () => number): string {
  return text
    .split('\n')
    .map((line) =>
      line.trimStart().startsWith('{') && isJson(line) ? redactLine(line, now).slice(0, -1) : scrub(line),
    )
    .join('\n');
}

function guard(output: Output & { [GUARDED]?: true }, now: () => number): void {
  if (output[GUARDED] === true) return;
  const write = output.write.bind(output);
  output.write = (chunk, encoding, callback) => {
    const text = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    const cleaned = cleanOutput(text, now);
    return typeof encoding === 'function' ? write(cleaned, encoding) : write(cleaned, 'utf8', callback);
  };
  output[GUARDED] = true;
}

/** Called once at start-up with `process`. Guarding twice changes nothing. */
export function guardOutputs(target: { stdout: Output; stderr: Output }, now: () => number = Date.now): void {
  guard(target.stdout, now);
  guard(target.stderr, now);
}
