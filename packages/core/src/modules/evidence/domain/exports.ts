// What one download of the audit log may hold, in one place for an admin's
// own download (E10b) and the operator's export for a case (E10c, ADR-005
// §6), so the two can't drift apart (partner decision 24; S121).

/** The action a download records about the log, on the organisation's own chain. */
export const AUDIT_LOG_EXPORTED = 'audit_log.exported';

/** The most events one download holds (partner, S121): a longer range is downloaded in parts. */
export const MOST_EXPORTED_EVENTS = 10_000;

/** The longest range one download covers (decision 24: 12 months, a leap year's included). */
export const MOST_EXPORT_DAYS = 366;

/** How many events one read of a download takes. */
export const EXPORT_BATCH = 500;

/** The action a download of the activity log records about it, on the organisation's own chain (L5). */
export const ACTIVITY_LOG_EXPORTED = 'access_log.exported';

/**
 * The most requests one download of the activity log holds (partner decision
 * 31, S129): a busy day whole. A longer range is a background download (L5c).
 */
export const MOST_EXPORTED_REQUESTS = 50_000;
