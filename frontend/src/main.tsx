import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router';
import { App } from './App';
import './styles.css';

// Hash routing supports static hosting without a backend or rewrite rules.
createRoot(document.getElementById('root')!).render(<StrictMode><HashRouter><App/></HashRouter></StrictMode>);
