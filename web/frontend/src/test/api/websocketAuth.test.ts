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
    createProgressWebSocket('f3cb151c-4b8c-4ed2-9caf-453ca2508e73', () => {}, () => {}, () => {});

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain('/api/ws/f3cb151c-4b8c-4ed2-9caf-453ca2508e73');
    expect(calls[0].url).toBe('/api/ws/f3cb151c-4b8c-4ed2-9caf-453ca2508e73');
    expect(calls[0].url).not.toContain('?');
    expect(calls[0].url).not.toContain(bearer);
    expect(calls[0].protocols).toEqual(['tracesleuth.jwt.' + bearer]);
    expect(() =>
      createProgressWebSocket('evil?redirect=wss://attacker.test', () => {}, () => {}, () => {})
    ).toThrow('Invalid analysis job identifier');
  });
});
