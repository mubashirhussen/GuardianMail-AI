import { apiClient } from '../api/client';

export interface SecurityProviderReport {
  provider: string;
  result: string;
  reported_detections: string | number;
  checked_at: string;
  status: 'clean' | 'suspicious' | 'malicious' | 'not_configured' | 'error';
  is_configured: boolean;
}

export interface RedirectHop {
  hop: number;
  url: string;
  status_code?: number | null;
  hostname: string;
  policy_allowed: boolean;
  note: string;
}

export interface LinkScanResult {
  investigation_id?: string;
  created_at?: string;
  url: string;
  normalized_url?: string;
  domain?: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  risk_score: number;
  confidence?: number;
  indicators?: string[];
  positive_evidence?: string[];
  contradictory_evidence?: string[];
  classifications?: Array<{ category: string; verdict: string; confidence: string }>;
  connection_security?: {
    scheme: string;
    uses_https: boolean;
    tls_inspection: {
      checked: boolean;
      valid: boolean;
      tls_version?: string | null;
      issuer?: string | null;
      subject?: string | null;
      valid_from?: string | null;
      valid_until?: string | null;
      hostname_match?: boolean;
      error?: string | null;
      critical_warning?: string;
    };
  };
  domain_registration?: {
    domain: string;
    registrar: string;
    created_date?: string | null;
    updated_date?: string | null;
    expires_date?: string | null;
    domain_age_days?: number | null;
    is_recently_registered?: boolean;
    registration_privacy?: string;
    operator_location?: string;
    nameservers?: string[];
    status?: string;
  };
  infrastructure?: {
    a_records: string[];
    aaaa_records: string[];
    mx_records: string[];
    ns_records: string[];
    primary_ip?: string | null;
    asn: string;
    organization: string;
    country: string;
    city: string;
    is_shared_infrastructure: boolean;
    disclaimer: string;
  };
  security_providers?: SecurityProviderReport[];
  community_reports?: {
    total_submissions: number;
    distinct_reporters: number;
    awaiting_review: number;
    confirmed_malicious: number;
    rejected_or_duplicate: number;
    verified_victims_statement: string;
    connected_mailbox_exposure: number;
  };
  redirect_chain?: RedirectHop[];
  relationships?: {
    nodes: Array<{ id: string; label: string; type: string }>;
    edges: Array<{ from: string; to: string; relation: string }>;
  };
}

export const linksService = {
  async scanLink(url: string): Promise<LinkScanResult> {
    const response = await apiClient.post<LinkScanResult>('/threats/scan-url', { url });
    return response.data;
  },

  async getLinkHistory(skip = 0, limit = 50): Promise<LinkScanResult[]> {
    const response = await apiClient.get<LinkScanResult[]>('/threats/url-history', {
      params: { skip, limit },
    });
    return response.data;
  },

  async submitReport(investigationId: string, category: string, explanation: string) {
    const response = await apiClient.post(`/threats/url-investigations/${investigationId}/reports`, {
      category,
      explanation,
    });
    return response.data;
  },

  async exportInvestigation(investigationId: string) {
    const response = await apiClient.get(`/threats/url-investigations/${investigationId}/export`);
    return response.data;
  },
};
