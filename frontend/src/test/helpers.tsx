/**
 * Shared test helpers.
 *
 * `renderWithProviders` wraps a UI under test in the minimal context the
 * real app provides — React Query (for data fetching) and React Router
 * (for navigation). We don't wrap in ToastProvider here because most
 * tests mount components that don't call useToast; pass your own
 * provider tree when you need one.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, type RenderOptions } from '@testing-library/react'
import type { ReactElement, ReactNode } from 'react'
import { MemoryRouter } from 'react-router-dom'

interface ProviderOpts {
  /** Starting path for MemoryRouter. Defaults to "/". */
  initialEntries?: string[]
  /** Override the default QueryClient — useful if a test wants to seed
   *  the cache before render. */
  queryClient?: QueryClient
}

export function makeQueryClient(): QueryClient {
  // retries off in tests so failures surface fast, not after 3 retries.
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

export function renderWithProviders(
  ui: ReactElement,
  {
    initialEntries = ['/'],
    queryClient,
    ...rtlOpts
  }: ProviderOpts & Omit<RenderOptions, 'wrapper'> = {},
) {
  const qc = queryClient ?? makeQueryClient()
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
    </QueryClientProvider>
  )
  return {
    queryClient: qc,
    ...render(ui, { wrapper: Wrapper, ...rtlOpts }),
  }
}
