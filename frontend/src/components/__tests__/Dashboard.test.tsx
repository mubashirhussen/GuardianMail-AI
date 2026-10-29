import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { Dashboard } from '../../pages/Dashboard';
import { dashboardService } from '../../services/dashboard';

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({
    user: {
      email: 'analyst@example.com',
      full_name: 'Security Analyst',
    },
  }),
}));

vi.mock('../../services/dashboard', () => ({
  dashboardService: {
    getOverview: vi.fn(),
    getThreats: vi.fn(),
    getIncidents: vi.fn(),
  },
}));

const renderDashboard = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    </QueryClientProvider>
  );
};

describe('Dashboard Component Unit Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(dashboardService.getOverview).mockResolvedValue({
      total_emails: 8521,
      safe_emails: 8100,
      suspicious_emails: 122,
      phishing_emails: 45,
      spam_emails: 10,
      bec_emails: 3,
      malicious_attachments: 5,
      malicious_urls: 7,
      resolved_incidents: 8,
      open_incidents: 14,
      avg_protection_score: 94,
      avg_risk_score: 6,
      detection_accuracy: 99.4,
    });
    vi.mocked(dashboardService.getThreats).mockResolvedValue({
      severity_distribution: {
        PHISHING: 45,
        BEC: 3,
      },
      daily_threat_trends: [
        { date: new Date().toISOString(), count: 12 },
      ],
      top_threat_campaigns: [
        { campaign_domain: 'paypal-spoof.com', volume: 4, risk: 92.5 },
      ],
      attack_categories: {
        phishing: 45,
        bec: 3,
      },
      average_detection_confidence: 91.2,
    });
    vi.mocked(dashboardService.getIncidents).mockResolvedValue({
      status_distribution: {
        Detected: 14,
      },
      severity_distribution: {
        CRITICAL: 4,
      },
      average_resolution_hours: 6.2,
      evidence_packages_generated: 9,
      complaint_drafts_created: 2,
    });
  });

  it('renders backend overview greeting and protection score', async () => {
    renderDashboard();

    expect(await screen.findByText(/Welcome back, Security/i)).toBeInTheDocument();
    expect(screen.getByText(/Live security posture/i)).toBeInTheDocument();
    expect(await screen.findByText(/Protection Score/i)).toBeInTheDocument();
    expect(await screen.findByText('94')).toBeInTheDocument();
  });

  it('renders backend KPI metrics and chart sections', async () => {
    renderDashboard();

    expect(await screen.findByText(/Emails Scanned/i)).toBeInTheDocument();
    expect(screen.getByText(/Threats Detected/i)).toBeInTheDocument();
    expect(screen.getByText(/Suspicious Emails/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Open Investigations/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Threat Activity/i)).toBeInTheDocument();
    expect(screen.getByText(/Threat Distribution/i)).toBeInTheDocument();
    expect(screen.getByText('8,521')).toBeInTheDocument();
    expect(screen.getByText('70')).toBeInTheDocument();
  });

  it('refreshes backend dashboard queries on demand', async () => {
    renderDashboard();

    const refreshButton = await screen.findByRole('button', { name: /Refresh Metrics/i });
    fireEvent.click(refreshButton);

    await waitFor(() => {
      expect(dashboardService.getOverview).toHaveBeenCalledTimes(2);
      expect(dashboardService.getThreats).toHaveBeenCalledTimes(2);
      expect(dashboardService.getIncidents).toHaveBeenCalledTimes(2);
    });
  });
});
