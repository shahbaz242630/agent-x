/** Sends the browser to another address (sign-in, or a fresh start after signing out): one place, so tests can see it. */
export function goTo(address: string): void {
  window.location.assign(address);
}
