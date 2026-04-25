import axios, { AxiosError } from 'axios'

const client = axios.create({
  baseURL: '/api',
  timeout: 15_000,
  headers: { 'Content-Type': 'application/json' },
})

// Opt-in: attach the DASHBOARD_TOKEN from localStorage to every request.
// Stays an empty no-op in setups where the backend isn't token-gated.
client.interceptors.request.use((cfg) => {
  try {
    const tok = localStorage.getItem('dashboard_token')
    if (tok) {
      cfg.headers = cfg.headers ?? {}
      ;(cfg.headers as Record<string, string>)['Authorization'] = `Bearer ${tok}`
    }
  } catch {
    /* localStorage disabled (private mode) — ignore */
  }
  return cfg
})

/**
 * Shape we throw to the UI. Extends Error with the HTTP status and parsed
 * response body so components can distinguish 401 (show login), 404
 * (empty-state), 5xx (retry prompt) without re-checking the axios error
 * the old interceptor was flattening into a bare `Error(msg)`.
 */
export interface ApiError extends Error {
  status?: number
  data?: unknown
}

client.interceptors.response.use(
  (res) => res,
  (err: AxiosError<{ detail?: string }>) => {
    const msg =
      (err.response?.data as { detail?: string } | undefined)?.detail ||
      err.message ||
      'Request failed'
    const out = new Error(msg) as ApiError
    out.status = err.response?.status
    out.data = err.response?.data
    return Promise.reject(out)
  },
)

export default client
