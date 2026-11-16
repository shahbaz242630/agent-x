// A token an emailed or handed-over link carries in its fragment (6D4b): an
// invitation's (`/invitations/accept#token=…`) or a registered contact's for a
// factor reset (`/factor-resets/confirm#token=…`, CO9). Browsers never send a
// fragment to a server or in a Referer. It is read once, on arrival, into the
// reading page's memory alone, and the address is cleaned of it at once
// (replaced, so Back never shows it either). It is never put in storage, the
// query cache, a log or an error report (report-errors.ts sends a page's path
// alone), and goes nowhere but the one API call its page makes with it.
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

/** What arrived: a token of the page's own form, a fragment holding something else (`malformed`), or nothing. */
export type Arrived = { readonly token: string } | 'malformed' | 'none';

/** The `token` in a fragment (as the router gives it, without its `#`), checked against the page's own form. */
export function arrivedIn(hash: string, form: RegExp): Arrived {
  const token = new URLSearchParams(hash.replace(/^#/, '')).get('token');
  if (token === null) return 'none';
  return form.test(token) ? { token } : 'malformed';
}

/** The token this page arrived with, kept for the page's life; the address cleaned of it straight away. */
export function useArrivedToken(form: RegExp): Arrived {
  const hash = useRouterState({ select: ({ location }) => location.hash });
  const pathname = useRouterState({ select: ({ location }) => location.pathname });
  const navigate = useNavigate();
  const [arrived] = useState(() => arrivedIn(hash, form));
  useEffect(() => {
    if (hash !== '') void navigate({ href: pathname, replace: true });
  }, [hash, pathname, navigate]);
  return arrived;
}
