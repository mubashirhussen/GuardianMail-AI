import { apiClient } from '../api/client';

export interface LinkScanResult {
  url: string;
  normalized_url?: string;
  domain?: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  risk_score: number;
  reputation?: string;
  threat_categories?: string[];
  redirect_chain?: string[];
  tls_valid?: boolean;
  domain_age_days?: number;
  whois_registered?: string;
  scan_timestamp?: string;
  indicators?: string[];
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
};
