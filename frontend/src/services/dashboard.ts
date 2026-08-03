import { apiClient } from '../api/client';
import type { SystemHealthMetrics } from '../types';

export const dashboardService = {
  async getOverview(): Promise<any> {
    const response = await apiClient.get('/dashboard/overview');
    return response.data;
  },

  async getThreats(): Promise<any> {
    const response = await apiClient.get('/dashboard/threats');
    return response.data;
  },

  async getEmails(): Promise<any> {
    const response = await apiClient.get('/dashboard/emails');
    return response.data;
  },

  async getIncidents(): Promise<any> {
    const response = await apiClient.get('/dashboard/incidents');
    return response.data;
  },

  async getTrends(): Promise<any> {
    const response = await apiClient.get('/dashboard/trends');
    return response.data;
  },

  async getReportsList(skip = 0, limit = 50): Promise<any[]> {
    const response = await apiClient.get<any[]>('/dashboard/reports', {
      params: { skip, limit }
    });
    return response.data;
  },

  async getSystemHealth(): Promise<SystemHealthMetrics> {
    const response = await apiClient.get<SystemHealthMetrics>('/dashboard/system');
    return response.data;
  },

  async getAdminStats(): Promise<any> {
    const response = await apiClient.get('/dashboard/admin');
    return response.data;
  },

  async exportReport(reportType: string, format: string, start?: string, end?: string): Promise<Blob> {
    const response = await apiClient.post('/dashboard/export', null, {
      params: {
        report_type: reportType,
        export_format: format,
        start_date: start || undefined,
        end_date: end || undefined
      },
      responseType: 'blob'
    });
    return response.data;
  }
};
