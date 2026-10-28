import { apiClient } from '../api/client';
import type { User, UserResponse } from '../types';

export const authService = {
  async register(payload: any): Promise<UserResponse> {
    const response = await apiClient.post<UserResponse>('/auth/register', payload);
    return response.data;
  },

  async login(payload: any): Promise<{ access_token: string; refresh_token: string }> {
    const response = await apiClient.post<{ access_token: string; refresh_token: string }>('/auth/login', payload);
    return response.data;
  },

  async getMe(): Promise<User> {
    const response = await apiClient.get<User>('/auth/me');
    return response.data;
  },

  async updateProfile(payload: any): Promise<User> {
    const response = await apiClient.put<User>('/auth/profile', payload);
    return response.data;
  },

  async getSessions(): Promise<any[]> {
    const response = await apiClient.get<any[]>('/auth/sessions');
    return response.data;
  },

  async revokeSession(sessionId: string): Promise<void> {
    await apiClient.delete(`/auth/session/${sessionId}`);
  },

  async logout(): Promise<void> {
    await apiClient.post('/auth/logout').catch(() => {});
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_info');
    // Disable GIS auto-select on application sign-out
    if (typeof window !== 'undefined' && (window as any).google?.accounts?.id?.disableAutoSelect) {
      try {
        (window as any).google.accounts.id.disableAutoSelect();
      } catch {
        // Ignore if GIS not initialized
      }
    }
  },

  async getGoogleConfig(): Promise<{ client_id: string }> {
    const response = await apiClient.get<{ client_id: string }>('/auth/google/config');
    return response.data;
  },

  async getGoogleAuthUrl(): Promise<{ auth_url: string; client_id?: string; state?: string }> {
    const response = await apiClient.get<{ auth_url: string; client_id?: string; state?: string }>('/auth/google/login');
    return response.data;
  },

  async verifyGoogleToken(credential: string): Promise<{ access_token: string; refresh_token: string; is_new_user?: boolean; user?: any }> {
    const response = await apiClient.post('/auth/google/verify-token', { credential });
    return response.data;
  },

  async verifyGoogleCredential(payload: { email?: string; name?: string; credential?: string }): Promise<{ access_token: string; refresh_token: string; is_new_user?: boolean; user?: any }> {
    const response = await apiClient.post('/auth/google/verify-credential', payload);
    return response.data;
  },

  async sendEmailCode(email: string, purpose: string = 'registration'): Promise<{ status: string; destination: string; cooldown_seconds: number; expires_in_seconds?: number }> {
    const response = await apiClient.post('/auth/email/send-code', { email, purpose });
    return response.data;
  },

  async verifyEmailCode(email: string, code: string, purpose: string = 'registration'): Promise<{ status: string; message: string }> {
    const response = await apiClient.post('/auth/email/verify', { email, code, purpose });
    return response.data;
  },

  async sendPhoneCode(phoneNumber: string, purpose: string = 'phone_verification'): Promise<{ status: string; destination: string; cooldown_seconds: number; expires_in_seconds?: number }> {
    const response = await apiClient.post('/auth/phone/send-code', { phone_number: phoneNumber, purpose });
    return response.data;
  },

  async verifyPhoneCode(phoneNumber: string, code: string, purpose: string = 'phone_verification'): Promise<{ status: string; message: string }> {
    const response = await apiClient.post('/auth/phone/verify', { phone_number: phoneNumber, code, purpose });
    return response.data;
  },

  async forgotPassword(email: string): Promise<{ status: string; message: string }> {
    const response = await apiClient.post('/auth/password/forgot', { email });
    return response.data;
  },

  async resetPassword(payload: { email: string; code: string; new_password: string }): Promise<{ status: string; message: string }> {
    const response = await apiClient.post('/auth/password/reset', payload);
    return response.data;
  },

  async logoutAll(): Promise<void> {
    await apiClient.post('/auth/logout-all').catch(() => {});
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_info');
    if (typeof window !== 'undefined' && (window as any).google?.accounts?.id?.disableAutoSelect) {
      try {
        (window as any).google.accounts.id.disableAutoSelect();
      } catch {
        // Ignore
      }
    }
  }
};
