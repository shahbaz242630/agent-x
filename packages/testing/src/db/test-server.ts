/** A user name and password for one role on the throwaway test server. */
export interface TestLogin {
  readonly user: string;
  readonly password: string;
}

/**
 * The throwaway Postgres server a test run uses. The global setup
 * (tooling/test-db) starts one per Postgres version, bootstraps the roles with
 * db/bootstrap, applies db/migrations to a template database, and passes this
 * to the tests, which read it with `inject('postgres')`.
 */
export interface TestPostgresServer {
  /** The Postgres version, e.g. `16.15`, for test names and failure messages. */
  readonly version: string;
  readonly host: string;
  readonly port: number;
  /** The server's superuser. Tests use it only to create databases and to play the attacker. */
  readonly admin: TestLogin;
  readonly roles: {
    readonly owner: TestLogin;
    readonly app: TestLogin;
    readonly backup: TestLogin;
  };
  /** A database with every migration applied, copied for each test file. */
  readonly templateDatabase: string;
}
