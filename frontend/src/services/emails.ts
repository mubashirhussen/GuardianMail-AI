import { apiClient } from '../api/client';
import type { EmailRecord } from '../types';

export const emailsService = {
  async listEmails(skip = 0, limit = 50): Promise<EmailRecord[]> {
    const response = await apiClient.get<EmailRecord[]>('/emails/', {
      params: { skip, limit }
    });
    return response.data;
  },

  async getEmail(id: string): Promise<EmailRecord> {
    const response = await apiClient.get<EmailRecord>(`/emails/${id}`);
    return response.data;
  },

  async parseEmailFile(file: File): Promise<any> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          const arrayBuffer = reader.result as ArrayBuffer;
          const uint8 = new Uint8Array(arrayBuffer);
          let hexString = '';
          for (let i = 0; i < uint8.length; i++) {
            hexString += uint8[i].toString(16).padStart(2, '0');
          }
          const response = await apiClient.post('/parser/process', { raw_hex: hexString });
          resolve(response.data);
        } catch (err) {
          reject(err);
        }
      };
      reader.onerror = (err) => reject(err);
      reader.readAsArrayBuffer(file);
    });
  },

  async reprocessEmail(id: string): Promise<any> {
    const response = await apiClient.post(`/parser/reprocess`, null, {
      params: { email_id: id }
    });
    return response.data;
  },

  async getOcrResult(attachmentId: string): Promise<any> {
    const response = await apiClient.get(`/attachments/${attachmentId}`);
    return response.data;
  },

  async markSafe(id: string): Promise<any> {
    const response = await apiClient.post(`/emails/${id}/mark-safe`);
    return response.data;
  }
};
