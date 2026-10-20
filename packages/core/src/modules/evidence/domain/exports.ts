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

/** The actions of a background download of the activity log (L5c), on the organisation's own chain. */
export const ACTIVITY_EXPORT_REQUESTED = 'access_log.export_requested';
/** One month's file made: its count, size and SHA-256, so the file a download is given can be checked. */
export const ACTIVITY_EXPORT_FILE_MADE = 'access_log.export_file_made';
/** The download given up, after a month failed too often. */
export const ACTIVITY_EXPORT_FAILED = 'access_log.export_failed';
/** A month's file downloaded (L5c-4): each one on the audit log. */
export const ACTIVITY_EXPORT_DOWNLOADED = 'access_log.export_downloaded';
