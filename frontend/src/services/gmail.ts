import { apiClient } from '../api/client';

export const gmailService = {
  async connectAccount(authCode: string): Promise<any> {
    const response = await apiClient.post('/gmail/connect', { code: authCode });
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
