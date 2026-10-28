import { apiClient } from '../api/client';

export const gmailService = {
  async getPermissions(): Promise<{
    scope: string;
    scope_name: string;
    data_accessed: string[];
    purpose: string;
    data_retention: string;
    user_control: string;
  }> {
    const response = await apiClient.get('/gmail/permissions');
    return response.data;
  },

  async getAuthUrl(): Promise<{ auth_url: string; state: string; scope: string }> {
    const response = await apiClient.get('/gmail/auth-url');
    return response.data;
  },

  async connectAccount(authCode: string, state?: string): Promise<any> {
    const response = await apiClient.post('/gmail/connect', { code: authCode, state });
    return response.data;
  },

  async disconnectAccount(email: string): Promise<any> {
    const response = await apiClient.delete('/gmail/disconnect', {
      params: { email }
    });
    return response.data;
  },

  async listAccounts(): Promise<any[]> {
    const response = await apiClient.get<any[]>('/gmail/accounts');
    return response.data;
  },

  async triggerSync(email: string): Promise<any> {
    const response = await apiClient.post('/gmail/sync', null, {
      params: { email }
    });
    return response.data;
  },

  async getSyncStatus(): Promise<any> {
    const response = await apiClient.get('/gmail/sync/status');
    return response.data;
  },

  async retrySync(): Promise<any> {
    const response = await apiClient.post('/gmail/sync/retry');
    return response.data;
  }
};
