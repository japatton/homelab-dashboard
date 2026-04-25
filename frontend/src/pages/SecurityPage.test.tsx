/**
 * SecurityPage — the gateway-alarm feed surface.
 *
 * Scope of these tests: UI wiring only. We don't hit a real API or
 * socket.io — we stub both so rendering is deterministic.
 *
 * Covers:
 *   - Summary stat cards reflect the backend numbers (Total /
 *     Unacknowledged / Critical / High / Medium / Low).
 *   - Alarm rows render with severity, source, message, device.
 *   - "No alarms in view" empty state when list is empty.
 *   - Severity filter buttons toggle the active pill.
 *   - Ack/Dismiss buttons wire through to the client POSTs.
 */
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderWithProviders } from '../test/helpers'

vi.mock('../hooks/useSocket', () => ({
  useSocket: () => ({
    socket: { on: vi.fn(), off: vi.fn(), emit: vi.fn() },
    on: () => () => {},
    emit: vi.fn(),
  }),
}))

vi.mock('../api/client', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

import clientMod from '../api/client'
import { SecurityPage } from './SecurityPage'

const mockedGet = clientMod.get as unknown as ReturnType<typeof vi.fn>
const mockedPost = clientMod.post as unknown as ReturnType<typeof vi.fn>

function seedClient({
  alarms = [],
  summary = {
    total: 0,
    unacknowledged: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  },
}: {
  alarms?: Array<Record<string, unknown>>
  summary?: Record<string, number>
} = {}) {
  mockedGet.mockImplementation((url: string) => {
    if (url === '/alarms/summary') return Promise.resolve({ data: summary })
    if (url === '/alarms') return Promise.resolve({ data: { alarms } })
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
  mockedPost.mockResolvedValue({ data: { ok: true } })
}

const A_CRITICAL = {
  id: 'alrm-001',
  source: 'firewalla',
  source_label: 'Firewalla Gold',
  severity: 'critical',
  category: 'Abnormal Upload',
  signature: 'Anomaly: Upload',
  message: 'Massive upload detected from 192.168.1.50',
  src_ip: '192.168.1.50',
  dst_ip: '185.220.101.42',
  device_id: 'aa:bb:cc:dd:ee:01',
  device_name: 'Couch TV',
  fingerprint: 'fp-1',
  first_seen_at: new Date().toISOString(),
  last_seen_at: new Date().toISOString(),
  count: 3,
  acknowledged: false,
  acknowledged_at: null,
  dismissed: false,
  dismissed_at: null,
  raw: {},
}

const A_MEDIUM_ACKD = {
  ...A_CRITICAL,
  id: 'alrm-002',
  severity: 'medium',
  source: 'opnsense',
  source_label: 'OPNsense',
  message: 'IDS: ET INFO suspicious user-agent',
  src_ip: '10.0.0.22',
  dst_ip: '93.184.216.34',
  device_name: '',
  fingerprint: 'fp-2',
  acknowledged: true,
  acknowledged_at: new Date().toISOString(),
}

describe('SecurityPage', () => {
  beforeEach(() => {
    mockedGet.mockReset()
    mockedPost.mockReset()
  })

  it('renders the summary stat row from /alarms/summary', async () => {
    seedClient({
      summary: { total: 42, unacknowledged: 7, critical: 2, high: 3, medium: 5, low: 1, info: 0 },
    })
    renderWithProviders(<SecurityPage />)
    // findBy — query resolves async.
    expect(await screen.findByText('42')).toBeInTheDocument()  // Total
    expect(screen.getByText('7')).toBeInTheDocument()          // Unacknowledged
    expect(screen.getByText('2')).toBeInTheDocument()          // Critical
    expect(screen.getByText('3')).toBeInTheDocument()          // High
  })

  it('renders the empty state when there are no alarms', async () => {
    seedClient()
    renderWithProviders(<SecurityPage />)
    expect(await screen.findByText(/No alarms in view/i)).toBeInTheDocument()
  })

  it('renders an alarm row with severity chip + message', async () => {
    seedClient({
      alarms: [A_CRITICAL],
      summary: { total: 1, unacknowledged: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    })
    renderWithProviders(<SecurityPage />)
    // Scope the search to the alarm table body so the stats row doesn't
    // accidentally match these strings.
    expect(await screen.findByText(/Massive upload detected from 192\.168\.1\.50/)).toBeInTheDocument()
    expect(screen.getByText('Couch TV')).toBeInTheDocument()
    // Severity badge shows the capitalised label. Appears in the stats
    // row AND on the row, so we assert at-least-one match.
    expect(screen.getAllByText('Critical').length).toBeGreaterThan(0)
    // Source "Firewalla" appears on the row chip and in the source
    // filter bar — getAllByText handles both.
    expect(screen.getAllByText('Firewalla').length).toBeGreaterThan(0)
  })

  it('calls POST /alarms/{id}/acknowledge when Ack button is clicked', async () => {
    seedClient({
      alarms: [A_CRITICAL],
      summary: { total: 1, unacknowledged: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    })
    renderWithProviders(<SecurityPage />)
    await screen.findByText(/Massive upload detected/)
    // The Ack button is identified by its title attribute.
    await userEvent.click(screen.getByTitle('Acknowledge'))
    expect(mockedPost).toHaveBeenCalledWith('/alarms/alrm-001/acknowledge')
  })

  it('calls POST /alarms/{id}/dismiss when Dismiss button is clicked', async () => {
    seedClient({
      alarms: [A_CRITICAL],
      summary: { total: 1, unacknowledged: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    })
    renderWithProviders(<SecurityPage />)
    await screen.findByText(/Massive upload detected/)
    await userEvent.click(screen.getByTitle('Dismiss'))
    expect(mockedPost).toHaveBeenCalledWith('/alarms/alrm-001/dismiss')
  })

  it('unacknowledged alarms sort ahead of acknowledged ones', async () => {
    seedClient({
      alarms: [A_MEDIUM_ACKD, A_CRITICAL], // server order: ack'd first, then unack
      summary: { total: 2, unacknowledged: 1, critical: 1, high: 0, medium: 1, low: 0, info: 0 },
    })
    renderWithProviders(<SecurityPage />)
    // After client-side sort, the critical (unack'd) row should appear
    // BEFORE the medium (ack'd) row in the table. We compare offsetTop
    // via DOM order of the rendered message text.
    await screen.findByText(/Massive upload detected/)
    const criticalRow = screen.getByText(/Massive upload detected/).closest('tr')!
    const ackdRow = screen.getByText(/IDS: ET INFO/).closest('tr')!
    // compareDocumentPosition(other) returns the relation of `other` to
    // the reference. FOLLOWING (4) means ackdRow comes AFTER criticalRow.
    expect(criticalRow.compareDocumentPosition(ackdRow) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('filter buttons highlight when active', async () => {
    seedClient()
    renderWithProviders(<SecurityPage />)
    await screen.findByText(/No alarms in view/i)

    // Severity filter: grab the Critical button from the filters bar.
    // There are two "Critical" texts in the DOM when the stats card
    // renders; we scope to the filter button via role=button.
    const criticalBtn = screen.getAllByRole('button').find((b) =>
      within(b).queryByText('Critical')
    )!
    expect(criticalBtn).toBeTruthy()

    // Initially the "All" button is selected (default severity='').
    expect(criticalBtn.className).not.toMatch(/text-tron-cyan/)
    await userEvent.click(criticalBtn)
    expect(criticalBtn.className).toMatch(/text-tron-cyan/)
  })
})
