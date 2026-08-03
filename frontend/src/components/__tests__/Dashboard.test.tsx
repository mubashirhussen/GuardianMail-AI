import React from 'react';
import { render, screen } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { Dashboard } from '../../pages/Dashboard';
import { MemoryRouter } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';

vi.mock('@tanstack/react-query', () => ({
  useQuery: vi.fn(),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
  };
});

describe('Dashboard Component Unit Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders skeletal cards during metrics load states', () => {
    vi.mocked(useQuery).mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    } as any);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    // Render loaders/skeletons when loading
    expect(screen.queryByText('Security Command Console')).not.toBeInTheDocument();
  });

  it('renders dashboard metrics and widgets correctly when loaded', () => {
    vi.mocked(useQuery).mockImplementation(({ queryKey }) => {
      if (queryKey[1] === 'overview') {
        return {
          data: {
            protection_score: 92,
            stats: {
              total_scanned: 1250,
              flagged_threats: 48,
              active_incidents: 12,
            },
          },
          isLoading: false,
          error: null,
        } as any;
      }
      return {
        data: {
          daily_threat_trends: [],
          severity_distribution: {},
        },
        isLoading: false,
        error: null,
      } as any;
    });

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    expect(screen.getByText('Security Command Console')).toBeInTheDocument();
    expect(screen.getByText('92%')).toBeInTheDocument();
    expect(screen.getByText('1250')).toBeInTheDocument();
    expect(screen.getByText('48')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });

  it('renders sync error state when API triggers failures', () => {
    vi.mocked(useQuery).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error('Network error'),
    } as any);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    expect(screen.getByText('Observability Sync Loss')).toBeInTheDocument();
  });
});
