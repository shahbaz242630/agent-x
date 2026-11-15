// A one-line text field with its label and its rule in plain words under it
// (6B2's unfreeze reason, 6B1's reject reason, 6C1's bank reference): one
// line, at most what the API takes, so nothing is typed that it would refuse
// for length. A rule broken is said in place once the person has been told.
import { useId } from 'react';

/** The most characters a note kept for good may have, as the API takes it (keptNote): a reject's reason, an unfreeze's. */
export const NOTE_MOST = 200;

export function LineField({
  label,
  hint,
  most,
  value,
  onChange,
  broken,
}: {
  readonly label: string;
  /** The API's rule for it, in plain words. */
  readonly hint: string;
  readonly most: number;
  readonly value: string;
  readonly onChange: (value: string) => void;
  /** What is wrong with what was typed, once said; none while it is fine or not yet checked. */
  readonly broken?: string | undefined;
}) {
  const id = useId();
  return (
    <>
      <label className="field" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        type="text"
        maxLength={most}
        aria-describedby={`${id}-hint`}
        aria-invalid={broken !== undefined}
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
      <p id={`${id}-hint`} className="fine">
        {hint}
      </p>
      {broken !== undefined && (
        <p className="notice" role="alert">
          {broken}
        </p>
      )}
    </>
  );
}
