import { useRef, useCallback } from 'react'
import { io, Socket } from 'socket.io-client'

let _socket: Socket | null = null

function _readToken(): string {
  // Read every connect attempt — the user might have set the token
  // in another tab via devtools and we want a reconnect to pick it up
  // without a page reload. Falls back to "" so the auth payload always
  // exists; the backend treats empty == not-supplied.
  try {
    return localStorage.getItem('dashboard_token') ?? ''
  } catch {
    // localStorage disabled (private mode) — no auth available.
    return ''
  }
}

function getSocket(): Socket {
  if (!_socket) {
    _socket = io('/', {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
      // F-001: send the dashboard token in the WebSocket handshake's
      // `auth` payload so the backend's @sio.event connect handler can
      // gate the upgrade. The auth field is a function so it re-reads
      // localStorage on every reconnect, not just the first connect —
      // covers the "operator rotated the token mid-session" case.
      auth: (cb) => cb({ token: _readToken() }),
    })
  }
  return _socket
}

export function useSocket() {
  const socket = useRef<Socket>(getSocket())

  const on = useCallback(<T>(event: string, handler: (data: T) => void) => {
    socket.current.on(event, handler)
    return () => { socket.current.off(event, handler) }
  }, [])

  const emit = useCallback((event: string, data?: unknown) => {
    socket.current.emit(event, data)
  }, [])

  return { socket: socket.current, on, emit }
}
