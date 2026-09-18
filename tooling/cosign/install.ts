// `corepack pnpm tools:cosign`: installs the pinned cosign into .tools/, once,
// on a machine that deploys, and in CI's release job (tooling/cosign/cosign.ts).
import { ensureCosign } from './cosign.ts';

try {
  process.stdout.write('Downloading cosign (about 200 MB on Windows), checked against its pin as it arrives...\n');
  const installed = await ensureCosign();
  process.stdout.write(`cosign: ${installed}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
