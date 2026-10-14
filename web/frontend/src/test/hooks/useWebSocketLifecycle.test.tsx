import { StrictMode, type ReactNode } from 'react';
import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useWebSocket } from '../../hooks/useWebSocket';

// Browser close callbacks may arrive AFTER React has unmounted or replaced the socket.
const sockets: FakeWebSocket[] = [];
class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 3;

  readyState = FakeWebSocket.CONNECTING;
  onopen: (() => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  closeCode: number | undefined;

  constructor(readonly url: string, readonly protocols: string[]) {
    sockets.push(this);
  }

  close(code?: number) {
    this.closeCode = code;
    this.readyState = FakeWebSocket.CLOSED;
  }

  fireOpen() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.();
  }

  fireClose(code = 1006) {
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code, reason: 'test' } as CloseEvent);
  }

  fireMessage(status: string) {
    this.onmessage?.({ data: JSON.stringify({ status }) } as MessageEvent);
  }
}

const JOB_A = '11111111-1111-4111-8111-111111111111';
const JOB_B = '22222222-2222-4222-8222-222222222222';

beforeEach(() => {
  sockets.length = 0;
  vi.useFakeTimers();
  vi.stubGlobal('WebSocket', FakeWebSocket);
});

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('useWebSocket lifecycle', () => {
  it('does not reconnect or update after intentional unmount', () => {
    const onClose = vi.fn();
    const { unmount } = renderHook(() =>
      useWebSocket(JOB_A, { reconnectAttempts: 2, reconnectInterval: 50, onClose })
    );
    expect(sockets).toHaveLength(1);
    const first = sockets[0];

    unmount();
    expect(first.closeCode).toBe(1000);
    act(() => first.fireClose());
    act(() => vi.advanceTimersByTime(200));

    expect(sockets).toHaveLength(1);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('ignores a superseded socket without damaging its replacement', () => {
    const { result, rerender, unmount } = renderHook(
      ({ id }: { id: string }) => useWebSocket(id, { reconnectInterval: 50 }),
      { initialProps: { id: JOB_A } }
    );
    const oldSocket = sockets[0];
    rerender({ id: JOB_B });
    expect(sockets).toHaveLength(2);

    const currentSocket = sockets[1];
    act(() => currentSocket.fireOpen());
    act(() => oldSocket.fireClose());
    act(() => oldSocket.fireMessage('failed'));
    expect(result.current.isConnected).toBe(true);
    expect(result.current.lastMessage).toBeNull();

    act(() => result.current.connect());
    act(() => vi.advanceTimersByTime(200));
    expect(sockets).toHaveLength(2);
    unmount();
  });

  it('reconnects on a genuine unexpected close before any status', () => {
    const { unmount } = renderHook(() =>
      useWebSocket(JOB_A, { reconnectAttempts: 1, reconnectInterval: 50 })
    );
    expect(sockets).toHaveLength(1);
    act(() => sockets[0].fireClose());
    act(() => vi.advanceTimersByTime(50));
    expect(sockets).toHaveLength(2);
    unmount();
  });

  it('does not revive sockets discarded by React StrictMode', () => {
    const wrapper = ({ children }: { children: ReactNode }) =>
      <StrictMode>{children}</StrictMode>;
    const { unmount } = renderHook(
      () => useWebSocket(JOB_A, { reconnectAttempts: 1, reconnectInterval: 50 }),
      { wrapper }
    );
    expect(sockets).toHaveLength(2);
    act(() => sockets[0].fireClose());
    act(() => vi.advanceTimersByTime(100));
    expect(sockets).toHaveLength(2);
    unmount();
  });
});
