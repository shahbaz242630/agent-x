// Where the operator's audit export for a case puts its file (Phase 3 E10c,
// ADR-005 §6): written once, never changed, never to the run's log. Deployed,
// the write-once container in the UAE (E10c-3); in development and test, a
// local folder standing in for it, each file made once (`wx`).
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/** How a write went: the file written now, or one of its name there already (an earlier run's, its answer lost). */
type StoreWrite = 'written' | 'there_already';

export interface EvidenceStore {
  /** Writes `content` as `name` (`<organisation ID>/<export ID>.ndjson`), once: never over a file already there. */
  put(name: string, content: Buffer): Promise<StoreWrite>;
}

/** Whether an error is the file system's own, with its code (ENOENT, EEXIST…). */
const fileSystemError = (error: unknown): error is Error & { readonly code: unknown } =>
  error instanceof Error && 'code' in error;

/** The local folder standing in for the write-once container (development and test alone, AGENTX_EVIDENCE_DIR). */
export function folderStore(directory: string): EvidenceStore {
  return {
    async put(name, content) {
      const path = join(directory, name);
      await mkdir(dirname(path), { recursive: true });
      try {
        await writeFile(path, content, { flag: 'wx' });
        return 'written';
      } catch (error) {
        if (fileSystemError(error) && error.code === 'EEXIST') return 'there_already';
        throw error;
      }
    },
  };
}
