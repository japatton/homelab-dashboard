/**
 * Smoke test for the Vitest bootstrap.
 *
 * If this passes, the test runner is wired up correctly: jsdom is the
 * environment, globals are enabled, jest-dom matchers are loaded, and
 * the stubbed window observers are available on globalThis.
 *
 * Component tests live next to their components; this file is the
 * single check that the test harness itself works end-to-end.
 */
import { describe, expect, it } from 'vitest'

describe('vitest bootstrap', () => {
  it('runs under jsdom with a document', () => {
    expect(typeof window).toBe('object')
    expect(document.body).toBeTruthy()
  })

  it('has jest-dom matchers attached', () => {
    const el = document.createElement('div')
    el.textContent = 'hello'
    document.body.appendChild(el)
    expect(el).toBeInTheDocument()
    expect(el).toHaveTextContent('hello')
  })

  it('provides ResizeObserver + IntersectionObserver stubs', () => {
    expect(typeof ResizeObserver).toBe('function')
    expect(typeof IntersectionObserver).toBe('function')
    // And matchMedia doesn't explode when probed.
    expect(window.matchMedia('(prefers-reduced-motion: reduce)').matches).toBe(false)
  })
})
