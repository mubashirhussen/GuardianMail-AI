import { apiClient } from '../api/client';

export interface ThreatAdvisory {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  incident_date: string;
  threat_vector: string;
  target_audience: string;
  cert_in_ref: string;
  legal_sections: string;
  summary: string;
  modus_operandi: string[];
  sample_indicators: string[];
  protection_steps: string[];
  what_to_do_if_affected: string[];
}

export interface ComplaintDraftRequest {
  incident_type: string;
  suspect_details: string;
  incident_description: string;
  financial_loss?: number;
  transaction_id?: string;
  bank_name?: string;
  evidence_urls?: string[];
}

export interface ComplaintDraftResponse {
  status: string;
  message: string;
  draft_text: string;
  submission_portals: Array<{
    name: string;
    url?: string;
    email?: string;
    helpline?: string;
    toll_free?: string;
  }>;
}

export const advisoriesService = {
  async getAdvisories(params?: { category?: string; severity?: string; search?: string }): Promise<ThreatAdvisory[]> {
    const res = await apiClient.get('/threats/advisories', { params });
    return res.data.advisories || [];
  },

  async getAdvisoryById(id: string): Promise<ThreatAdvisory> {
    const res = await apiClient.get(`/threats/advisories/${id}`);
    return res.data.advisory;
  },

  async draftCertInComplaint(payload: ComplaintDraftRequest): Promise<ComplaintDraftResponse> {
    const res = await apiClient.post('/threats/advisories/draft-complaint', payload);
    return res.data;
  }
};

