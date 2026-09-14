// ADR-013: the public up-check. The uptime monitors read it (UptimeRobot, and
// Azure's availability test in production), and the container platform probes
// it. Anyone can read it, so it says only `ok` or `unavailable`: nothing about
// the build or which check failed. The failure goes to the log. Each condition
// the API needs to be up is a HealthCheck; the first is the worker's heartbeat,
// added with the worker (Phase 4).
import type { EventName, Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';

const HEALTH_PATH = '/health';
export const CHECK_FAILED: EventName = 'health.check_failed';

export interface HealthCheck {
  /** Names the check in the log, e.g. `worker_heartbeat`. */
  readonly name: string;
  /** Resolves true while the condition holds. False, a rejection or a throw all mean unavailable. */
  readonly check: () => Promise<boolean>;
}

interface HealthBody {
  readonly status: 'ok' | 'unavailable';
}

interface Outcome {
  readonly name: string;
  readonly passed: boolean;
  readonly err?: unknown;
}

async function run({ name, check }: HealthCheck): Promise<Outcome> {
  try {
    return { name, passed: await check() };
  } catch (error) {
    // A check that throws or rejects has failed; allPass logs its error.
    return { name, passed: false, err: error };
  }
}

/** Runs every check at once, and logs each failure with the check's name. */
async function allPass(checks: readonly HealthCheck[], log: Logger): Promise<boolean> {
  const failed = (await Promise.all(checks.map(run))).filter((outcome) => !outcome.passed);
  for (const { name, err } of failed) {
    log.warn(CHECK_FAILED, err === undefined ? { check: name } : { check: name, err });
  }
  return failed.length === 0;
}

export function registerHealth(app: FastifyInstance, checks: readonly HealthCheck[], logger: Logger): void {
  app.get(HEALTH_PATH, async (request, reply) => {
    const ok = await allPass(checks, logger.child({ correlationId: request.id }));
    const body: HealthBody = { status: ok ? 'ok' : 'unavailable' };
    return reply.code(ok ? 200 : 503).send(body);
  });
}
