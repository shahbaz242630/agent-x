// Saving a file the API answered with (6C1's payment history, 6C2's evidence
// and log downloads), the same way on every screen: made in the browser from
// what is already in hand, so nothing more is asked of the API.

/** Saves `parts` as a file named `name`, of type `type`, as the browser saves a download. */
export function saveFile(name: string, parts: readonly BlobPart[], type: string): void {
  const file = new Blob([...parts], { type });
  const address = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = address;
  link.download = name;
  link.click();
  // Freed once the click has been handled: some browsers (older Safari, Firefox) cancel a download freed at once.
  setTimeout(() => {
    URL.revokeObjectURL(address);
  }, 0);
}

/** Saves `value` as the API answered it, as readable JSON. */
export const saveJson = (name: string, value: unknown): void => {
  saveFile(name, [JSON.stringify(value, null, 2)], 'application/json');
};
