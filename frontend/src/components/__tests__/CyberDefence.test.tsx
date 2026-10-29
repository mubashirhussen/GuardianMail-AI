import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CertInCyberDefense } from '../CertInCyberDefense';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
  },
});

describe('CertInCyberDefense Component', () => {
  it('renders official CERT-In headings, helplines, and government links', () => {
    render(
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <CertInCyberDefense />
        </BrowserRouter>
      </QueryClientProvider>
    );

    // Verify Title
    expect(screen.getByText(/India CERT-In — Cyber Defence/i)).toBeInTheDocument();

    // Verify Description
    expect(screen.getByText(/Indian Computer Emergency Response Team \(CERT-In\)/i)).toBeInTheDocument();

    // Verify National helpline 1930
    expect(screen.getByText('1930')).toBeInTheDocument();
    expect(screen.getByText('1930').closest('a')).toHaveAttribute('href', 'tel:1930');

    // Verify CERT-In Helpdesk 1800-11-4949
    expect(screen.getByText('1800-11-4949')).toBeInTheDocument();
    expect(screen.getByText('1800-11-4949').closest('a')).toHaveAttribute('href', 'tel:1800114949');

    // Verify Phishing Email
    expect(screen.getByText('report@phishing.gov.in')).toBeInTheDocument();
    expect(screen.getByText('report@phishing.gov.in').closest('a')).toHaveAttribute('href', 'mailto:report@phishing.gov.in');

    // Verify Incident Email
    expect(screen.getByText('incident@cert-in.org.in')).toBeInTheDocument();
    expect(screen.getByText('incident@cert-in.org.in').closest('a')).toHaveAttribute('href', 'mailto:incident@cert-in.org.in');

    // Verify Complaint Portals
    expect(screen.getByText('cybercrime.gov.in')).toBeInTheDocument();
    expect(screen.getByText('report anonymously')).toBeInTheDocument();
    expect(screen.getByText('cert-in.org.in')).toBeInTheDocument();
    expect(screen.getByText('sachet.rbi.org.in')).toBeInTheDocument();
  });
});
