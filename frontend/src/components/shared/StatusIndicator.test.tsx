/**
 * StatusIndicator — tiny pure component with no side effects.
 *
 * Covers:
 *   - Label visibility toggle (showLabel=false is the default)
 *   - Pulse-ring animation only for online / scanning states
 *   - Unknown status is the fallback for unrecognised strings — we
 *     never render a broken config even when the backend returns a
 *     new DeviceStatus we haven't mapped yet.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { StatusIndicator } from './StatusIndicator'

describe('StatusIndicator', () => {
  it('hides label by default and shows it when showLabel=true', () => {
    const { rerender } = render(<StatusIndicator status="online" />)
    expect(screen.queryByText(/online/i)).not.toBeInTheDocument()

    rerender(<StatusIndicator status="online" showLabel />)
    expect(screen.getByText(/online/i)).toBeInTheDocument()
  })

  it('renders the animated ping for online and scanning states', () => {
    const { container, rerender } = render(<StatusIndicator status="online" />)
    // The ping span is rendered as a sibling with the animate-ping class.
    expect(container.querySelector('.animate-ping')).not.toBeNull()

    rerender(<StatusIndicator status="scanning" />)
    expect(container.querySelector('.animate-ping')).not.toBeNull()
  })

  it('does not animate offline or unknown states', () => {
    const { container, rerender } = render(<StatusIndicator status="offline" />)
    expect(container.querySelector('.animate-ping')).toBeNull()

    rerender(<StatusIndicator status="unknown" />)
    expect(container.querySelector('.animate-ping')).toBeNull()
  })

  it('falls back to the "unknown" palette for unrecognised values', () => {
    // Passing an arbitrary string must not crash or render an empty
    // pill — it should show the "unknown" label and greyed-out dot.
    render(<StatusIndicator status="fabricated-status" showLabel />)
    expect(screen.getByText(/unknown/i)).toBeInTheDocument()
  })

  it('accepts a size prop that resizes the dot', () => {
    const { container, rerender } = render(<StatusIndicator status="online" size="sm" />)
    expect(container.querySelector('.w-2')).not.toBeNull()
    expect(container.querySelector('.w-3')).toBeNull()

    rerender(<StatusIndicator status="online" size="lg" />)
    expect(container.querySelector('.w-3')).not.toBeNull()
  })
})
