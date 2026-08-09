import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'

// Vitest runs without global hooks here (globals: false in vite.config.js),
// so @testing-library/react cannot register its own auto-cleanup — do it
// explicitly or rendered DOM leaks between tests.
afterEach(() => cleanup())
