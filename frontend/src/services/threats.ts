import { apiClient } from '../api/client';

export interface ThreatRecord {
  _id?: string;
  id?: string;
  email_id?: string;
  subject?: string;
  from_address?: string;
  verdict: 'PHISHING' | 'MALWARE' | 'BEC' | 'SPAM' | 'SUSPICIOUS' | 'SAFE';
  risk_score: number;
  confidence_score?: number;
  threat_category?: string;
  indicators?: Array<{
    indicator: string;
    severity: string;
    detail: string;
    type: string;
  }>;
  explanation?: string;
  detected_at?: string;
  created_at?: string;
  status?: string;
}

export interface DetectThreatPayload {
  sender: string;
  subject: string;
  body: string;
  headers?: Record<string, string>;
  attachments?: string[];
  urls?: string[];
}

export interface DetectThreatResponse {
  verdict: 'PHISHING' | 'MALWARE' | 'BEC' | 'SPAM' | 'SUSPICIOUS' | 'SAFE';
  risk_score: number;
  confidence_score: number;
  explanation?: string;
  indicators?: Array<{
    indicator: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    detail: string;
    type: string;
  }>;
  recommendations?: {
    next_steps?: string[];
    security_tips?: string[];
  };
  detector_sources?: string[];
  processing_time_ms?: number;
}

export const threatsService = {
  async listThreats(
    skip = 0,
    limit = 50,
    filters?: { verdict?: string; min_risk?: number; max_risk?: number }
  ): Promise<ThreatRecord[]> {
    const response = await apiClient.get<ThreatRecord[]>('/threats/', {
      params: { skip, limit, ...filters },
    });
    return response.data;
  },

  async getThreat(id: string): Promise<ThreatRecord> {
    const response = await apiClient.get<ThreatRecord>(`/threats/${id}`);
    return response.data;
  },

  async detectThreat(payload: DetectThreatPayload): Promise<DetectThreatResponse> {
    const response = await apiClient.post<DetectThreatResponse>('/threats/detect', payload);
    return response.data;
  },

  async getThreatStats(): Promise<any> {
    const response = await apiClient.get('/threats/stats');
    return response.data;
  },

  async getThreatsTimeline(days = 7): Promise<any[]> {
    const response = await apiClient.get('/threats/timeline', {
      params: { days },
    });
    return response.data;
  },
};
