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
  },

  async getGoogleAuthUrl(): Promise<{ auth_url: string }> {
    const response = await apiClient.get<{ auth_url: string }>('/auth/google/login');
    return response.data;
  }
};
