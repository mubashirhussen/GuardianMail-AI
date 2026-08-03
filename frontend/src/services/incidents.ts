import { apiClient } from '../api/client';
import type { IncidentRecord, TimelineEvent, RecoveryAction, ComplaintDraft } from '../types';

export const incidentsService = {
  async createIncident(payload: {
    email_id: string;
    priority?: string;
    tags?: string[];
    custom_labels?: Record<string, string>;
    investigation_notes?: string;
  }): Promise<IncidentRecord> {
    const response = await apiClient.post<IncidentRecord>('/incidents', payload);
    return response.data;
  },

  async listIncidents(skip = 0, limit = 50): Promise<IncidentRecord[]> {
    const response = await apiClient.get<IncidentRecord[]>('/incidents', {
      params: { skip, limit }
    });
    return response.data;
  },

  async searchIncidents(params: {
    incident_id?: string;
    sender?: string;
    domain?: string;
    threat_type?: string;
    severity?: string;
    status?: string;
    priority?: string;
    min_risk_score?: number;
    limit?: number;
  }): Promise<IncidentRecord[]> {
    const response = await apiClient.get<IncidentRecord[]>('/incidents/search', {
      params
    });
    return response.data;
  },

  async getIncident(id: string): Promise<IncidentRecord> {
    const response = await apiClient.get<IncidentRecord>(`/incidents/${id}`);
    return response.data;
  },

  async updateIncident(id: string, payload: any): Promise<IncidentRecord> {
    const response = await apiClient.put<IncidentRecord>(`/incidents/${id}`, payload);
    return response.data;
  },

  async getTimeline(id: string): Promise<TimelineEvent[]> {
    const response = await apiClient.get<TimelineEvent[]>(`/incidents/${id}/timeline`);
    return response.data;
  },

  async addTimelineEvent(id: string, event: string, description: string): Promise<TimelineEvent> {
    const response = await apiClient.post<TimelineEvent>(`/incidents/${id}/timeline`, null, {
      params: { event, description }
    });
    return response.data;
  },

  async getRecoveryChecklist(id: string): Promise<RecoveryAction[]> {
    const response = await apiClient.get<RecoveryAction[]>(`/incidents/${id}/recovery`);
    return response.data;
  },

  async toggleRecoveryAction(actionId: string, isCompleted: boolean): Promise<RecoveryAction> {
    const response = await apiClient.post<RecoveryAction>(`/incidents/recovery/${actionId}/toggle`, null, {
      params: { is_completed: isCompleted }
    });
    return response.data;
  },

  async getNotes(id: string): Promise<any[]> {
    const response = await apiClient.get<any[]>(`/incidents/${id}/notes`);
    return response.data;
  },

  async addNote(id: string, noteText: string): Promise<any> {
    const response = await apiClient.post(`/incidents/${id}/notes`, null, {
      params: { note_content: noteText }
    });
    return response.data;
  },

  async generateEvidencePackage(id: string): Promise<any> {
    const response = await apiClient.post(`/incidents/${id}/evidence`);
    return response.data;
  },

  async generateComplaintDraft(id: string, recipientEntity: string, templateType: string): Promise<ComplaintDraft> {
    const response = await apiClient.post<ComplaintDraft>(`/incidents/${id}/complaint`, null, {
      params: { recipient_entity: recipientEntity, template_type: templateType }
    });
    return response.data;
  },

  async downloadForensicBundle(id: string): Promise<Blob> {
    const response = await apiClient.get(`/incidents/${id}/download`, {
      responseType: 'blob'
    });
    return response.data;
  }
};
