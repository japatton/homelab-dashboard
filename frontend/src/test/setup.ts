/**
 * Vitest global setup.
 *
 * Runs once per test worker before any test file is loaded. We:
 *
 *   1. Extend Vitest's `expect` with jest-dom matchers (toBeInTheDocument,
 *      toHaveClass, etc). Without this the assertions exist but don't
 *      show helpful diffs when they fail.
 *   2. Ensure `afterEach` unmounts rendered components — testing-library
 *      normally calls cleanup() automatically when it detects jest/vitest
 *      globals, but we pin it explicitly so a future vitest upgrade
 *      doesn't silently regress into leaky DOM state.
 *   3. Polyfill the bits of `window` that framer-motion + lucide-react
 *      probe at import time and that jsdom doesn't ship: `matchMedia`,
 *      `ResizeObserver`, `IntersectionObserver`.
 */
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

afterEach(() => {
  cleanup()
})

// ─── matchMedia ────────────────────────────────────────────────────────
// Tailwind + framer-motion check `prefers-reduced-motion` on mount. jsdom
// doesn't implement matchMedia, so we return a stub that always reports
// "not matching" — effectively pretending the user isn't in reduced-motion
// mode. Tests that care can override per-case.
if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(), // deprecated but still referenced
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  })
}

// ─── ResizeObserver ────────────────────────────────────────────────────
// reactflow, three.js, framer-motion, and our own topology canvas touch
// ResizeObserver during mount. jsdom doesn't implement it either.
if (typeof window !== 'undefined' && !window.ResizeObserver) {
  class ResizeObserverStub {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  ;(window as unknown as { ResizeObserver: typeof ResizeObserverStub }).ResizeObserver =
    ResizeObserverStub
  ;(globalThis as unknown as { ResizeObserver: typeof ResizeObserverStub }).ResizeObserver =
    ResizeObserverStub
}

// ─── IntersectionObserver ─────────────────────────────────────────────
// framer-motion lazy-loads animations via an IntersectionObserver when
// elements scroll into view. Same story: jsdom doesn't have it.
if (typeof window !== 'undefined' && !window.IntersectionObserver) {
  class IntersectionObserverStub {
    observe() {}
    unobserve() {}
    disconnect() {}
    takeRecords() {
      return []
    }
    root = null
    rootMargin = ''
    thresholds = []
  }
  ;(window as unknown as { IntersectionObserver: typeof IntersectionObserverStub }).IntersectionObserver =
    IntersectionObserverStub
  ;(globalThis as unknown as { IntersectionObserver: typeof IntersectionObserverStub }).IntersectionObserver =
    IntersectionObserverStub
}
