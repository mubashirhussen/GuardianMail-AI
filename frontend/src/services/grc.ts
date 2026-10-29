import { apiClient } from '../api/client';

export interface PostureScore {
  organization_id?: string;
  posture_score: number;
  posture_rating: string;
  penalties: string[];
  metrics: {
    total_controls: number;
    failed_controls: number;
    partial_controls: number;
    not_assessed_controls?: number;
    open_findings: number;
    total_risks: number;
    critical_risks: number;
  };
  category_posture: Record<string, number>;
  disclaimer: string;
}

export interface ControlItem {
  _id?: string;
  control_id: string;
  framework_name: string;
  description: string;
  owner_id: string;
  status: string;
  risk_level: string;
  evidence_requirement: string;
  review_frequency: string;
  last_assessment?: string;
}

export interface RiskItem {
  _id?: string;
  risk_id: string;
  title: string;
  description?: string;
  category: string;
  likelihood: number;
  impact: number;
  inherent_risk_score: number;
  residual_risk_score: number;
  status: string;
  treatment_status: string;
  treatment_plan?: string;
  owner?: string;
  last_reviewed?: string;
}

export interface EvidenceItem {
  _id?: string;
  control_id: string;
  evidence_type: string;
  source: string;
  content_hash: string;
  collected_at: string;
  status: string;
  content?: string;
  payload_data?: any;
  verification_status?: 'VERIFIED' | 'TAMPER_DETECTED' | 'NOT_VERIFIED' | 'VERIFYING';
}

export interface FindingItem {
  _id?: string;
  finding_id: string;
  severity: string;
  source: string;
  control_id: string;
  description: string;
  status: string;
  remediation_plan: string;
  due_date: string;
}

export interface AuditItem {
  _id?: string;
  audit_id: string;
  scope: string;
  framework_name: string;
  auditor: string;
  start_date: string;
  end_date: string;
  status: string;
}

export interface SyncStatusResponse {
  status: 'not_configured' | 'ready' | 'running' | 'completed' | 'completed_with_warnings' | 'failed';
  sync_id?: string;
  synced_at?: string | null;
  items_synced?: number;
  summary?: Record<string, any>;
  message: string;
}

export const grcService = {
  getPosture: async (): Promise<PostureScore> => {
    const res = await apiClient.get<PostureScore>('/grc/posture');
    return res.data;
  },

  getControls: async (): Promise<ControlItem[]> => {
    const res = await apiClient.get<ControlItem[]>('/grc/controls');
    return res.data;
  },

  getRisks: async (): Promise<RiskItem[]> => {
    const res = await apiClient.get<RiskItem[]>('/grc/risks');
    return res.data;
  },

  getEvidence: async (): Promise<EvidenceItem[]> => {
    const res = await apiClient.get<EvidenceItem[]>('/grc/evidence');
    return res.data;
  },

  getFindings: async (): Promise<FindingItem[]> => {
    const res = await apiClient.get<FindingItem[]>('/grc/findings');
    return res.data;
  },

  getAudits: async (): Promise<AuditItem[]> => {
    const res = await apiClient.get<AuditItem[]>('/grc/audits');
    return res.data;
  },

  triggerEvidenceCollection: async (): Promise<EvidenceItem[]> => {
    const res = await apiClient.post<EvidenceItem[]>('/grc/evidence/collect');
    return res.data;
  },

  verifyEvidence: async (id: string): Promise<{
    evidence_id: string;
    control_id: string;
    source: string;
    content_hash: string;
    calculated_hash: string;
    is_valid: boolean;
    status: 'VERIFIED' | 'TAMPER_DETECTED';
    verified_at: string;
    algorithm: string;
  }> => {
    const res = await apiClient.post(`/grc/evidence/${id}/verify`);
    return res.data;
  },

  triggerSystemSync: async (): Promise<SyncStatusResponse> => {
    const res = await apiClient.post<SyncStatusResponse>('/grc/sync');
    return res.data;
  },

  getSyncStatus: async (): Promise<SyncStatusResponse> => {
    const res = await apiClient.get<SyncStatusResponse>('/grc/sync/status');
    return res.data;
  },

  mitigateRisk: async (riskId: string): Promise<any> => {
    const res = await apiClient.patch(`/grc/risks/${riskId}`, {
      status: 'MITIGATED',
      treatment_status: 'MITIGATE',
    });
    return res.data;
  },

  applyRiskException: async (
    riskId: string,
    reason: string,
    compensatingControls: string,
    durationDays: number = 30
  ): Promise<any> => {
    const res = await apiClient.post(`/grc/risks/${riskId}/exception`, {
      reason,
      compensating_controls: compensatingControls,
      duration_days: durationDays,
    });
    return res.data;
  },

  uploadEvidence: async (payload: {
    control_id: string;
    evidence_type: string;
    source: string;
    content: string;
  }): Promise<EvidenceItem> => {
    const res = await apiClient.post<EvidenceItem>('/grc/evidence', payload);
    return res.data;
  },

  exportReport: async (reportType: string, format: string): Promise<Blob> => {
    const res = await apiClient.post(
      '/grc/reports',
      {
        report_type: reportType,
        export_format: format,
      },
      { responseType: 'blob' }
    );
    return res.data;
  },
};

