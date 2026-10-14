// Custom hook for WebSocket connection management

import { useEffect, useRef, useState, useCallback } from 'react';
import { getAuthToken, getAnalysisStatus, isValidProgressJobId } from '../api/client';
import type { AnalysisJob } from '../types';

interface UseWebSocketOptions {
  onMessage?: (job: AnalysisJob) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onOpen?: () => void;
  reconnectAttempts?: number;
  reconnectInterval?: number;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  isConnecting: boolean;
  error: Error | null;
  connect: () => void;
  disconnect: () => void;
  lastMessage: AnalysisJob | null;
}

export function useWebSocket(
  jobId: string | null,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    reconnectAttempts = 3,
    reconnectInterval = 2000,
  } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [lastMessage, setLastMessage] = useState<AnalysisJob | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  // Each lifecycle owns exactly one socket. Cleanup invalidates its callbacks
  // and reconnect timers even if the browser delivers onclose asynchronously.
  const connectionGenerationRef = useRef(0);
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastStatusRef = useRef<string | null>(null);
  const jobIdRef = useRef<string | null>(jobId);
  const usingPollingRef = useRef(false);

  // Store callbacks in refs to avoid dependency churn
  const onMessageRef = useRef(options.onMessage);
  const onErrorRef = useRef(options.onError);
  const onCloseRef = useRef(options.onClose);
  const onOpenRef = useRef(options.onOpen);
  onMessageRef.current = options.onMessage;
  onErrorRef.current = options.onError;
  onCloseRef.current = options.onClose;
  onOpenRef.current = options.onOpen;
  jobIdRef.current = jobId;

  // Start HTTP polling as fallback when WebSocket is unavailable
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return; // already polling
    const currentJobId = jobIdRef.current;
    if (!currentJobId) return;

    usingPollingRef.current = true;
    console.log('[WS] Falling back to HTTP polling');

    const poll = async () => {
      const jid = jobIdRef.current;
      if (!jid) return;
      try {
        const status = await getAnalysisStatus(jid);
        if (!usingPollingRef.current || jobIdRef.current !== jid) return;
        setLastMessage(status);
        onMessageRef.current?.(status);
        if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') {
          console.log(`[POLL] Job ${status.status}, stopping poll`);
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
        }
      } catch {
        // ignore poll errors, will retry
      }
    };

    // Poll immediately, then every 2 seconds
    poll();
    pollIntervalRef.current = setInterval(poll, 2000);
  }, []);

  const disconnect = useCallback(() => {
    // Invalidate pending socket events before calling close(), so an abnormal
    // close after a route change or StrictMode cleanup cannot reconnect.
    connectionGenerationRef.current++;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    
    const currentSocket = wsRef.current;
    wsRef.current = null;
    if (currentSocket) {
      currentSocket.close(1000, 'Client disconnected');
    }

    usingPollingRef.current = false;
    setIsConnected(false);
    setIsConnecting(false);
  }, []);

  const connect = useCallback(() => {
    const currentJobId = jobIdRef.current;
    if (!currentJobId) return;

    // Don't reconnect if already open or connecting
    if (wsRef.current?.readyState === WebSocket.OPEN ||
        wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    if (!isValidProgressJobId(currentJobId)) {
      setError(new Error('Invalid analysis job identifier'));
      return;
    }
    // An explicit reconnect cancels any timer left by the previous socket.
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    const generation = ++connectionGenerationRef.current;
    setIsConnecting(true);
    setError(null);

    const token = getAuthToken();
    // Relative WebSocket URLs resolve to the current origin automatically,
    // so neither caller input nor a query parameter controls the endpoint.
    const wsUrl = '/api/ws/' + encodeURIComponent(currentJobId);
    console.log('[WS] Connecting to ' + wsUrl);
    const ws = new WebSocket(wsUrl, token ? ['tracesleuth.jwt.' + token] : []);
    const isCurrentSocket = () =>
      connectionGenerationRef.current === generation && wsRef.current === ws;

    ws.onopen = () => {
      if (!isCurrentSocket()) return;
      // An explicit reconnect after HTTP fallback must not leave two active
      // progress channels updating the same React state.
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      usingPollingRef.current = false;
      console.log('[WS] Connected');
      setIsConnected(true);
      setIsConnecting(false);
      reconnectCountRef.current = 0;
      onOpenRef.current?.();
    };

    ws.onmessage = (event) => {
      if (!isCurrentSocket()) return;
      try {
        const job = JSON.parse(event.data) as AnalysisJob;
        lastStatusRef.current = job.status;
        setLastMessage(job);
        onMessageRef.current?.(job);

        // Auto-close on completion
        if (
          job.status === 'completed' ||
          job.status === 'failed' ||
          job.status === 'cancelled'
        ) {
          console.log(`[WS] Job ${job.status}, closing`);
          ws.close(1000, 'Job finished');
        }
      } catch (err) {
        console.error('[WS] Failed to parse message:', err);
      }
    };

    ws.onerror = () => {
      if (!isCurrentSocket()) return;
      const err = new Error('WebSocket connection error');
      setError(err);
      onErrorRef.current?.(err);
    };

    ws.onclose = (event) => {
      if (!isCurrentSocket()) return;
      console.log(`[WS] Closed: code=${event.code}, reason=${event.reason}`);
      setIsConnected(false);
      setIsConnecting(false);
      wsRef.current = null;
      onCloseRef.current?.();

      // Only reconnect if job is still analyzing and we haven't exceeded attempts
      if (
        (lastStatusRef.current === null || lastStatusRef.current === 'analyzing') &&
        event.code !== 1000 // Don't reconnect on normal close
      ) {
        if (reconnectCountRef.current < reconnectAttempts) {
          reconnectCountRef.current++;
          console.log(`[WS] Reconnecting (attempt ${reconnectCountRef.current}/${reconnectAttempts})...`);
          reconnectTimeoutRef.current = setTimeout(() => {
            if (connectionGenerationRef.current !== generation) return;
            reconnectTimeoutRef.current = null;
            connect();
          }, reconnectInterval);
        } else {
          // All reconnect attempts exhausted — fall back to HTTP polling
          startPolling();
        }
      }
    };

    wsRef.current = ws;
  }, [reconnectAttempts, reconnectInterval, startPolling]);

  // Auto-connect when jobId changes
  useEffect(() => {
    if (jobId) {
      reconnectCountRef.current = 0;
      lastStatusRef.current = null;
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    isConnected,
    isConnecting,
    error,
    connect,
    disconnect,
    lastMessage,
  };
}
