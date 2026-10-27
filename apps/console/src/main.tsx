// The console's entry (6A1): the fonts and styles, then the app in #root,
// with its errors reported to the API (6A2).
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './styles.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App, createConsoleRouter, createQueries } from './app.tsx';
import { RENDER_ERRORS, reportErrors } from './report-errors.ts';

const element = document.getElementById('root');
if (element === null) throw new Error('The console page has no #root');
reportErrors();
createRoot(element, RENDER_ERRORS).render(
  <StrictMode>
    <App queries={createQueries()} router={createConsoleRouter()} />
  </StrictMode>,
);
