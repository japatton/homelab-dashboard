import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Kept off because socket.io pushes fresh data on change already —
      // window-focus refetches would re-hit the backend for no new info
      // every time the user alt-tabs, and the dashboard is often
      // secondary-tabbed beside scan progress. 30s staleTime already
      // covers the "user just came back and clicked something" case.
      refetchOnWindowFocus: false,
      retry: 2,
      staleTime: 30_000,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
