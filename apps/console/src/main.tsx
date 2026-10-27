// The console's entry (6A1): the fonts and styles, then the app in #root.
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './styles.css';

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App, createConsoleRouter, createQueries } from './app.tsx';

const element = document.getElementById('root');
if (element === null) throw new Error('The console page has no #root');
createRoot(element).render(
  <StrictMode>
    <App queries={createQueries()} router={createConsoleRouter()} />
  </StrictMode>,
);
