// What the people screens share (6D4b): a member named as the console can
// name them (the API gives a role and IDs, never a name: "Admin (you)" and
// the membership ID, as 6D1), and the notice a dialog shows once what it was
// opened on has moved since.
// Each dialog is pinned to what it showed: it keeps the member, contact or
// reset as read when it opened, shows and sends that alone, and if a re-read
// finds it changed (its role, status or count) says so and can't be
// confirmed, so a passkey never signs what the admin didn't read. The API
// binds the rest: a step-up's challenge to the exact change asked.
import type { Member } from '../agents.ts';
import { t } from '../text.ts';
import { memberText } from './agent.tsx';

/** A member by role, "(you)" for the person signed in, and their membership ID. */
export function MemberName({
  member,
  id,
  me,
}: {
  readonly member: Member | undefined;
  readonly id: string;
  readonly me: string;
}) {
  return (
    <>
      {memberText(member, me)} <span className="mono">{id}</span>
    </>
  );
}

/** Said in a dialog whose subject changed since it opened: it can't be confirmed. */
export function Moved({ moved }: { readonly moved: boolean }) {
  return moved ? (
    <p className="notice" role="alert">
      {t('members.movedSince')}
    </p>
  ) : null;
}

/** Whether what a dialog showed (`seen`) is no longer what was read now (`now`, none if gone), by `stateOf`. */
export const movedSince = <T,>(seen: T, now: T | undefined, stateOf: (one: T) => string): boolean =>
  now === undefined || stateOf(seen) !== stateOf(now);
