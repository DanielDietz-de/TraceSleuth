import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearAuthToken, createProgressWebSocket, setAuthToken } from '../../api/client';

describe('progress WebSocket authentication transport', () => {
  afterEach(() => {
    clearAuthToken();
    vi.unstubAllGlobals();
  });

  it('sends the bearer as a handshake subprotocol, never in the URL', () => {
    const calls: Array<{ url: string; protocols?: string[] }> = [];
    class RecordingWebSocket {
      constructor(url: string, protocols?: string[]) {
        calls.push({ url, protocols });
      }
    }
    vi.stubGlobal('WebSocket', RecordingWebSocket);
    const bearer = 'header.payload.signature';
    setAuthToken(bearer);
    createProgressWebSocket('test-job', () => {}, () => {}, () => {});

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain('/api/ws/test-job');
    expect(calls[0].url).not.toContain('?');
    expect(calls[0].url).not.toContain(bearer);
    expect(calls[0].protocols).toEqual(['tracesleuth.jwt.' + bearer]);
  });
});
