// The console's tests run in jsdom, which has no modal dialog: HTMLDialogElement
// has neither showModal nor close (jsdom 30). This stand-in opens and closes one
// as a browser does, so the shared confirm (CO12b, the browser's own <dialog>)
// renders in its tests. What only a real browser gives (the page behind inert,
// focus kept inside, Escape sent as a `cancel` event) the tests send themselves.

HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement): void {
  this.setAttribute('open', '');
};

HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement): void {
  if (!this.open) return;
  this.removeAttribute('open');
  this.dispatchEvent(new Event('close'));
};
