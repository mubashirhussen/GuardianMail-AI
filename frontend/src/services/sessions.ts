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

export type RegisteredDevice = {
  _id: string;
  device_id: string;
  fingerprint_hash: string;
  device_name: string;
  device_type: string;
  browser?: string;
  os?: string;
  last_login_ip: string;
  location?: string;
  is_trusted: boolean;
  created_at?: string;
  last_used_at?: string;
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
  return 'Chrome';
};

const parseOs = (userAgent = ''): string => {
  if (/windows/i.test(userAgent)) return 'Windows';
  if (/mac os|macintosh/i.test(userAgent)) return 'macOS';
  if (/android/i.test(userAgent)) return 'Android';
  if (/iphone|ipad|ios/i.test(userAgent)) return 'iOS';
  if (/linux/i.test(userAgent)) return 'Linux';
  return 'Windows';
};

const normalizeSession = (session: RawSession, activeTokenId?: string): SessionDevice => {
  const userAgent = session.user_agent ?? '';
  const tokenId = session.token_id;
  const isCurrent = session.is_current ?? (Boolean(activeTokenId) && tokenId === activeTokenId);
  const isTrusted = session.is_trusted ?? false;

  // Calibrate risk level: never leave unassessed
  let computedRisk: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM';
  if (session.risk_level) {
    computedRisk = session.risk_level;
  } else if (isTrusted || isCurrent || session.ip_address === '127.0.0.1' || session.ip_address === '::1') {
    computedRisk = 'LOW';
  }

  return {
    session_id: session._id ?? session.id ?? session.session_id ?? tokenId ?? '',
    token_id: tokenId,
    fingerprint_hash: session.fingerprint_hash,
    device_name: session.device_name ?? `${parseBrowser(userAgent)} on ${parseOs(userAgent)}`,
    browser: session.browser ?? parseBrowser(userAgent),
    os: session.os ?? parseOs(userAgent),
    ip_address: session.ip_address ?? '127.0.0.1',
    location: session.location ?? (session.ip_address === '127.0.0.1' ? 'Local / Dev Session' : 'Authorized Network'),
    created_at: session.created_at ?? new Date().toISOString(),
    last_active_at: session.last_active_at ?? session.last_activity ?? session.created_at,
    is_current: isCurrent,
    is_trusted: isTrusted,
    risk_level: computedRisk,
  };
};

export const sessionsService = {
  async listSessions(): Promise<SessionDevice[]> {
    const response = await apiClient.get<RawSession[]>('/auth/sessions');
    const activeTokenId = currentTokenId();
    return response.data.map((session) => normalizeSession(session, activeTokenId));
  },

  async listRegisteredDevices(): Promise<RegisteredDevice[]> {
    const res = await apiClient.get('/devices');
    return res.data || [];
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

  async untrustDevice(fingerprintHash: string): Promise<void> {
    await apiClient.post(`/devices/untrust/${encodeURIComponent(fingerprintHash)}`);
  },

  async registerCompanionSession(payload: { os: string; browser: string; device_type: string }): Promise<any> {
    const res = await apiClient.post('/devices/register-companion-session', payload);
    return res.data;
  }
};
