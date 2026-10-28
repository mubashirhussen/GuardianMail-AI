import { apiClient } from '../api/client';

export type SessionDevice = {
  session_id: string;
  token_id?: string;
  fingerprint_hash?: string;
  device_name?: string;
  browser?: string;
  os?: string;
  ip_address?: string;
  location?: string;
  created_at: string;
  last_active_at?: string;
  is_current?: boolean;
  is_trusted?: boolean;
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH';
};

type RawSession = {
  _id?: string;
  id?: string;
  session_id?: string;
  token_id?: string;
  fingerprint_hash?: string;
  device_name?: string;
  browser?: string;
  os?: string;
  user_agent?: string;
  ip_address?: string;
  location?: string;
  created_at?: string;
  last_activity?: string;
  last_active_at?: string;
  is_current?: boolean;
  is_trusted?: boolean;
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH';
};

const parseJwtPayload = (token: string | null): Record<string, unknown> | null => {
  if (!token) return null;
  const [, payload] = token.split('.');
  if (!payload) return null;

  try {
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
};

const currentTokenId = (): string | undefined => {
  const payload = parseJwtPayload(localStorage.getItem('access_token'));
  return typeof payload?.jti === 'string' ? payload.jti : undefined;
};

const parseBrowser = (userAgent = ''): string => {
  if (/edg/i.test(userAgent)) return 'Edge';
  if (/chrome|chromium/i.test(userAgent)) return 'Chrome';
  if (/firefox/i.test(userAgent)) return 'Firefox';
  if (/safari/i.test(userAgent)) return 'Safari';
  return 'Unknown Browser';
};

const parseOs = (userAgent = ''): string => {
  if (/windows/i.test(userAgent)) return 'Windows';
  if (/mac os|macintosh/i.test(userAgent)) return 'macOS';
  if (/android/i.test(userAgent)) return 'Android';
  if (/iphone|ipad|ios/i.test(userAgent)) return 'iOS';
  if (/linux/i.test(userAgent)) return 'Linux';
  return 'Unknown OS';
};

const normalizeSession = (session: RawSession, activeTokenId?: string): SessionDevice => {
  const userAgent = session.user_agent ?? '';
  const tokenId = session.token_id;

  return {
    session_id: session._id ?? session.id ?? session.session_id ?? tokenId ?? '',
    token_id: tokenId,
    fingerprint_hash: session.fingerprint_hash,
    device_name: session.device_name,
    browser: session.browser ?? parseBrowser(userAgent),
    os: session.os ?? parseOs(userAgent),
    ip_address: session.ip_address,
    location: session.location,
    created_at: session.created_at ?? new Date().toISOString(),
    last_active_at: session.last_active_at ?? session.last_activity ?? session.created_at,
    is_current: session.is_current ?? (Boolean(activeTokenId) && tokenId === activeTokenId),
    is_trusted: session.is_trusted ?? false,
    risk_level: session.risk_level ?? (session.is_trusted ? 'LOW' : 'MEDIUM'),
  };
};

export const sessionsService = {
  async listSessions(): Promise<SessionDevice[]> {
    const response = await apiClient.get<RawSession[]>('/auth/sessions');
    const activeTokenId = currentTokenId();
    return response.data.map((session) => normalizeSession(session, activeTokenId));
  },

  async revokeSession(sessionId: string): Promise<void> {
    await apiClient.delete(`/auth/session/${sessionId}`);
  },

  async revokeAllOtherSessions(): Promise<{ detail: string; revoked_count?: number }> {
    const response = await apiClient.post<{ detail: string }>('/auth/logout-other-devices');
    const match = response.data.detail.match(/revoked\s+(\d+)/i);
    return {
      detail: response.data.detail,
      revoked_count: match ? Number(match[1]) : undefined,
    };
  },

  async trustDevice(fingerprintHash: string): Promise<void> {
    await apiClient.post(`/devices/trust/${encodeURIComponent(fingerprintHash)}`);
  },
};
