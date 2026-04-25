/**
 * Sidebar — navigation rail with alarm badge + Analysis gate.
 *
 * Covers:
 *   - Always-visible nav items (Network, Devices, Vulnerabilities,
 *     Audit, Security, Settings) render.
 *   - Analysis link appears only when Ollama settings are configured.
 *   - Alarm badge shows numeric unread count, renders "99+" beyond 99.
 *   - Badge is skipped when unacknowledged === 0.
 *
 * Approach: mock the api client and useSocket hook so tests don't
 * touch the network or socket.io. React Query is fed via
 * renderWithProviders.
 */
import { screen } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderWithProviders } from '../../test/helpers'

// ─── Mock hoisting ───────────────────────────────────────────────────
// vi.mock runs before the file imports the mocked module — this is what
// lets us swap out the socket hook cleanly without a shim layer.
vi.mock('../../hooks/useSocket', () => ({
  useSocket: () => ({
    socket: { on: vi.fn(), off: vi.fn(), emit: vi.fn() },
    on: () => () => {},  // subscribe → unsubscribe no-op
    emit: vi.fn(),
  }),
}))

// The api client is mocked per-test via mockedGet below.
vi.mock('../../api/client', () => ({
  default: { get: vi.fn() },
}))

import clientMod from '../../api/client'
import { Sidebar } from './Sidebar'

const mockedGet = clientMod.get as unknown as ReturnType<typeof vi.fn>

function primeClient({
  settings = {},
  summary = { total: 0, unacknowledged: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
}: {
  settings?: Record<string, unknown>
  summary?: { unacknowledged: number } & Record<string, number>
} = {}) {
  mockedGet.mockImplementation((url: string) => {
    if (url === '/settings') return Promise.resolve({ data: settings })
    if (url === '/alarms/summary') return Promise.resolve({ data: summary })
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

describe('Sidebar', () => {
  beforeEach(() => {
    mockedGet.mockReset()
  })

  it('renders the always-visible nav items', async () => {
    primeClient()
    renderWithProviders(<Sidebar />)
    // We rely on the NavLink `title` attribute, which is more stable
    // than searching by tooltip text (that's inside a hover-only span).
    expect(screen.getByTitle('Network Map')).toBeInTheDocument()
    expect(screen.getByTitle('Devices')).toBeInTheDocument()
    expect(screen.getByTitle('Vulnerabilities')).toBeInTheDocument()
    expect(screen.getByTitle('Audit Log')).toBeInTheDocument()
    expect(screen.getByTitle('Settings')).toBeInTheDocument()
    // Security nav is always visible regardless of integration state.
    expect(screen.getByTitle(/Security/)).toBeInTheDocument()
  })

  it('does NOT render the Analysis link when Ollama is unconfigured', async () => {
    primeClient({ settings: { ollama: { enabled: false, host: '' } } })
    renderWithProviders(<Sidebar />)
    // The sidebar only renders nav items synchronously — the ollama
    // flag defaults to disabled, so Analysis shouldn't appear even
    // before /settings resolves.
    expect(screen.queryByTitle('AI Analysis')).not.toBeInTheDocument()
  })

  it('renders the Analysis link when Ollama is configured', async () => {
    primeClient({
      settings: { ollama: { enabled: true, host: 'http://ollama:11434' } },
    })
    renderWithProviders(<Sidebar />)
    // findBy — react-query resolves asynchronously.
    expect(await screen.findByTitle('AI Analysis')).toBeInTheDocument()
  })

  it('shows the unread count badge when there are unacknowledged alarms', async () => {
    primeClient({
      summary: { total: 5, unacknowledged: 3, critical: 1, high: 2, medium: 0, low: 0, info: 0 },
    })
    renderWithProviders(<Sidebar />)
    // Sidebar sets aria-label on the badge — deterministic locator
    // even though the badge text is "3" (which could collide with
    // other digits elsewhere in the tree).
    const badge = await screen.findByLabelText(/3 unacknowledged alarms/i)
    expect(badge).toHaveTextContent('3')
  })

  it('renders "99+" when the unread count exceeds 99', async () => {
    primeClient({
      summary: { total: 500, unacknowledged: 123, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    })
    renderWithProviders(<Sidebar />)
    const badge = await screen.findByLabelText(/123 unacknowledged alarms/i)
    expect(badge).toHaveTextContent('99+')
  })

  it('omits the alarm badge entirely when unread is zero', async () => {
    primeClient()  // default summary has unacknowledged=0
    renderWithProviders(<Sidebar />)
    // Using queryBy — the badge element should not exist.
    // The Security tooltip label still renders as "Security" without "(N new)".
    expect(screen.queryByLabelText(/unacknowledged alarm/i)).not.toBeInTheDocument()
  })
})
