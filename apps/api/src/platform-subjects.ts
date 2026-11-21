// The platform events that are some object's signed state, for the signed states' digest (AT13c): the hand-off
// pause's moves (platform-controls) and the sessions' signed ends (identity). Kept here, where both modules are known,
// for the anchor check's platform chain walks (job-list.ts).
import { signedEndSubjectOf } from '@agentx/core/modules/identity';
import { pauseSubjectOf, type PlatformSubjectOf } from '@agentx/core/modules/platform-controls';

/** The object a platform event is a signed state of, if any: its type and ID as the digest keys it. */
export const platformSubjectOf: PlatformSubjectOf = (action, details) =>
  pauseSubjectOf(action) ?? signedEndSubjectOf(action, details);
