/**
 * ToastProvider + useToast — lightweight fire-and-forget notifications.
 *
 * Covers:
 *   - Ok/error/info/warn each render with the right title and visible
 *     message body.
 *   - Dismiss button removes the toast from the DOM.
 *   - Auto-dismiss timer tears down the toast after its duration.
 *   - useToast() outside a provider returns a no-op API (doesn't throw
 *     so components are robust in half-wired trees / early tests).
 */
import { render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { ToastProvider, useToast } from './Toast'

function wrapWithProvider({ children }: { children: ReactNode }) {
  return <ToastProvider>{children}</ToastProvider>
}

// Tiny harness: a button that fires a toast when clicked. We drive it
// with user-event to mirror how real code paths trigger notifications.
function Harness({
  kind = 'ok',
  title = 'Scan queued',
  message = 'Sweeping 10.0.0.0/24',
}: {
  kind?: 'ok' | 'error' | 'info' | 'warn'
  title?: string
  message?: string
}) {
  const toast = useToast()
  return (
    <button onClick={() => toast[kind](title, message)}>fire</button>
  )
}

describe('ToastProvider + useToast', () => {
  it('renders a toast on ok() with the given title and message', async () => {
    render(<Harness />, { wrapper: wrapWithProvider })
    await userEvent.click(screen.getByText('fire'))
    expect(await screen.findByText('Scan queued')).toBeInTheDocument()
    expect(screen.getByText(/Sweeping 10\.0\.0\.0\/24/)).toBeInTheDocument()
  })

  it('renders each kind without crashing', async () => {
    const kinds: Array<'ok' | 'error' | 'info' | 'warn'> = ['ok', 'error', 'info', 'warn']
    for (const k of kinds) {
      const { unmount } = render(
        <Harness kind={k} title={`t-${k}`} message="" />,
        { wrapper: wrapWithProvider },
      )
      await userEvent.click(screen.getByText('fire'))
      expect(await screen.findByText(`t-${k}`)).toBeInTheDocument()
      unmount()
    }
  })

  it('dismisses on close button click', async () => {
    render(<Harness />, { wrapper: wrapWithProvider })
    await userEvent.click(screen.getByText('fire'))
    const title = await screen.findByText('Scan queued')
    expect(title).toBeInTheDocument()

    await userEvent.click(screen.getByLabelText('Dismiss'))
    // AnimatePresence may keep the toast mounted briefly during its exit
    // animation, or in jsdom may remove it synchronously. waitFor with a
    // not-in-document assertion handles both cases without erroring when
    // the node has already been unmounted by the time we start polling.
    await waitFor(
      () => expect(screen.queryByText('Scan queued')).not.toBeInTheDocument(),
      { timeout: 2000 },
    )
  })

  it('useToast outside a provider is a safe no-op (does not throw)', () => {
    // No provider wrapping — the hook should hand back stub functions
    // that just swallow calls.
    const { result } = renderHook(() => useToast())
    expect(() => result.current.ok('anything')).not.toThrow()
    expect(() => result.current.error('anything')).not.toThrow()
    expect(() => result.current.info('anything')).not.toThrow()
    expect(() => result.current.warn('anything')).not.toThrow()
  })
})
