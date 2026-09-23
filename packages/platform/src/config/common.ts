// What every settings module shares: the environments, the log levels, the
// error a refused start throws, and the shape of the environment it reads.
export const ENVIRONMENTS = ['development', 'test', 'staging', 'production'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

/** Where nothing real is at stake, so a local stack may talk plain http and needs no release name, nor a job run's name. */
export const LOCAL_ONLY: readonly Environment[] = ['development', 'test'];

/** The logging standard's levels, most to least severe. */
export const LOG_LEVELS = ['error', 'warn', 'info', 'debug'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** The log settings when none are set; also what the start-up logger writes with before the config is read. */
export const DEFAULT_LOG: { readonly level: LogLevel; readonly eventCapPerMinute: number } = Object.freeze({
  level: 'info',
  eventCapPerMinute: 600,
});

export class ConfigError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Refusing to start: ${problems.length} config problem(s).\n- ${problems.join('\n- ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

export type Env = Readonly<Record<string, string | undefined>>;
