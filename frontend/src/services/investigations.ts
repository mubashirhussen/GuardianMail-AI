import { apiClient } from '../api/client';

export interface Investigation {
  id: string;
  _id?: string;
  title: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'CLOSED' | 'ARCHIVED';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  threat_category?: string;
  risk_score?: number;
  affected_entities?: string[];
  indicators?: string[];
  created_at: string;
  updated_at?: string;
  analyst?: string;
  summary?: string;
}

export const investigationsService = {
  async listInvestigations(skip = 0, limit = 50): Promise<Investigation[]> {
    const response = await apiClient.get<Investigation[]>('/investigations/', {
      params: { skip, limit },
    });
    return response.data;
  },

  async getInvestigation(id: string): Promise<Investigation> {
    const response = await apiClient.get<Investigation>(`/investigations/${id}`);
    return response.data;
  },

  async createInvestigation(payload: Partial<Investigation>): Promise<Investigation> {
    const response = await apiClient.post<Investigation>('/investigations/', payload);
    return response.data;
  },

  async updateInvestigation(id: string, payload: Partial<Investigation>): Promise<Investigation> {
    const response = await apiClient.patch<Investigation>(`/investigations/${id}`, payload);
    return response.data;
  },

  async closeInvestigation(id: string, notes?: string): Promise<void> {
    await apiClient.post(`/investigations/${id}/close`, { notes });
  },
};
