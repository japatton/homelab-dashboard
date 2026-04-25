import { useRef, useCallback } from 'react'
import { io, Socket } from 'socket.io-client'

let _socket: Socket | null = null

function getSocket(): Socket {
  if (!_socket) {
    _socket = io('/', {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: Infinity,
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
