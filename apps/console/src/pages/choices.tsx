// A choice a form asks (6D2), each option in plain words and none picked for
// the person (Rule Book §1.9): the radios in the confirm's own look
// (`.options`), with what is wrong said in place once checked (on submit);
// and a tick, the same way.
import { useId } from 'react';

export function Choices<T extends string>({
  legend,
  options,
  chosen,
  onChoose,
  broken,
  disabled = false,
}: {
  readonly legend: string;
  /** Each option and its words, in the order offered. */
  readonly options: readonly (readonly [T, string])[];
  readonly chosen: T | null;
  readonly onChoose: (choice: T) => void;
  readonly broken?: string | undefined;
  /** Read-only for now (a pass-through waiting to be asked again, 6D2). */
  readonly disabled?: boolean;
}) {
  const name = useId();
  return (
    <>
      <fieldset className="options" aria-invalid={broken !== undefined} disabled={disabled}>
        <legend>{legend}</legend>
        {options.map(([value, words]) => (
          <label key={value} className="option">
            <input
              type="radio"
              name={name}
              value={value}
              checked={chosen === value}
              onChange={() => {
                onChoose(value);
              }}
            />
            <span>{words}</span>
          </label>
        ))}
      </fieldset>
      <Broken said={broken} />
    </>
  );
}

/** What is wrong with a field, said in place once checked. */
function Broken({ said }: { readonly said: string | undefined }) {
  return said === undefined ? null : (
    <p className="notice" role="alert">
      {said}
    </p>
  );
}

/** A statement the person ticks to say it is true of them (a call made), never ticked for them. */
export function Tick({
  label,
  ticked,
  onTick,
  broken,
}: {
  readonly label: string;
  readonly ticked: boolean;
  readonly onTick: (ticked: boolean) => void;
  readonly broken?: string | undefined;
}) {
  return (
    <>
      <label className="option">
        <input
          type="checkbox"
          checked={ticked}
          aria-invalid={broken !== undefined}
          onChange={(event) => {
            onTick(event.target.checked);
          }}
        />
        <span>{label}</span>
      </label>
      <Broken said={broken} />
    </>
  );
}
