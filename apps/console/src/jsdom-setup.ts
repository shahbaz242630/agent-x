// The console's tests run in jsdom, which has no modal dialog: HTMLDialogElement
// has neither showModal nor close (jsdom 30). This stand-in opens and closes one
// as a browser does, so the shared confirm (CO12b, the browser's own <dialog>)
// renders in its tests. What only a real browser gives (the page behind inert,
// focus kept inside, Escape sent as a `cancel` event) the tests send themselves.

import { configure } from '@testing-library/react';

HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement): void {
  this.setAttribute('open', '');
};

HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement): void {
  if (!this.open) return;
  this.removeAttribute('open');
  this.dispatchEvent(new Event('close'));
};

// The first render of a test file draws the whole shell (CO11: a sidebar of
// router links) and, under CI's coverage instrumentation, took ~1.4 s against
// testing-library's 1 s wait (S216). A wait is only the longest a `findBy`
// keeps looking: a passing test is no slower for it.
configure({ asyncUtilTimeout: 3000 });
