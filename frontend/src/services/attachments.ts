import { apiClient } from '../api/client';

export interface AttachmentScanResult {
  attachment_id?: string;
  filename: string;
  file_size_bytes: number;
  mime_type?: string;
  sha256_hash?: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  risk_score?: number;
  malware_detected?: boolean;
  malware_family?: string;
  indicators?: string[];
  ocr_content?: string;
  scan_timestamp?: string;
}

export const attachmentsService = {
  async scanAttachment(file: File): Promise<AttachmentScanResult> {
    const formData = new FormData();
    formData.append('file', file);
    const response = await apiClient.post<AttachmentScanResult>(
      '/attachments/scan',
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    );
    return response.data;
  },

  async getAttachment(id: string): Promise<AttachmentScanResult> {
    const response = await apiClient.get<AttachmentScanResult>(`/attachments/${id}`);
    return response.data;
  },

  async listAttachments(skip = 0, limit = 50): Promise<AttachmentScanResult[]> {
    const response = await apiClient.get<AttachmentScanResult[]>('/attachments/', {
      params: { skip, limit },
    });
    return response.data;
  },
};
