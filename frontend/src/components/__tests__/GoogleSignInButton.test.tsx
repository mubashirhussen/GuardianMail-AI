import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { GoogleSignInButton } from '../GoogleSignInButton';
import { authService } from '../../services/auth';

vi.mock('../../services/auth', () => ({
  authService: {
    getGoogleConfig: vi.fn().mockResolvedValue({
      client_id: 'test-google-client-id.apps.googleusercontent.com'
    }),
    getGoogleAuthUrl: vi.fn().mockResolvedValue({
      auth_url: 'https://accounts.google.com/o/oauth2/v2/auth?mock=true'
    }),
    verifyGoogleToken: vi.fn(),
  }
}));

describe('GoogleSignInButton Unit Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete (window as any).google;
  });

  it('renders Google sign-in container and account switcher controls', async () => {
    render(<GoogleSignInButton onSuccess={vi.fn()} />);

    expect(screen.getByText(/Continue with/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Google/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Use any Google account in this browser/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Switch account/i })).toBeInTheDocument();
  });

  it('initializes Google Identity Services when window.google is available', async () => {
    const mockInitialize = vi.fn();
    const mockRenderButton = vi.fn();
    const mockPrompt = vi.fn();

    (window as any).google = {
      accounts: {
        id: {
          initialize: mockInitialize,
          renderButton: mockRenderButton,
          prompt: mockPrompt,
        }
      }
    };

    render(<GoogleSignInButton onSuccess={vi.fn()} />);

    await waitFor(() => {
      expect(mockInitialize).toHaveBeenCalled();
      expect(mockRenderButton).toHaveBeenCalled();
      expect(mockPrompt).toHaveBeenCalled();
    });
  });

  it('calls onSuccess when credential is submitted', async () => {
    const mockOnSuccess = vi.fn();
    let capturedCallback: any = null;

    (window as any).google = {
      accounts: {
        id: {
          initialize: vi.fn((opts) => {
            capturedCallback = opts.callback;
          }),
          renderButton: vi.fn(),
          prompt: vi.fn(),
        }
      }
    };

    render(<GoogleSignInButton onSuccess={mockOnSuccess} />);

    await waitFor(() => {
      expect(capturedCallback).not.toBeNull();
    });

    // Simulate GIS returning valid token credential
    await capturedCallback({ credential: 'mock_test_token_123' });

    expect(mockOnSuccess).toHaveBeenCalledWith('mock_test_token_123');
  });

  it('displays error message when verification fails', async () => {
    const mockOnSuccess = vi.fn().mockRejectedValue(new Error('Invalid token audience'));

    let capturedCallback: any = null;

    (window as any).google = {
      accounts: {
        id: {
          initialize: vi.fn((opts) => {
            capturedCallback = opts.callback;
          }),
          renderButton: vi.fn(),
          prompt: vi.fn(),
        }
      }
    };

    render(<GoogleSignInButton onSuccess={mockOnSuccess} />);

    await waitFor(() => {
      expect(capturedCallback).not.toBeNull();
    });

    await capturedCallback({ credential: 'bad_token' });

    await waitFor(() => {
      expect(screen.getByText(/Invalid token audience/i)).toBeInTheDocument();
    });
  });

  it('triggers Google prompt when Switch Account is clicked', async () => {
    const mockPrompt = vi.fn();

    (window as any).google = {
      accounts: {
        id: {
          initialize: vi.fn(),
          renderButton: vi.fn(),
          prompt: mockPrompt,
        }
      }
    };

    render(<GoogleSignInButton onSuccess={vi.fn()} />);

    await waitFor(() => {
      expect(mockPrompt).toHaveBeenCalled();
    });

    const switchBtn = screen.getByRole('button', { name: /Switch account/i });
    fireEvent.click(switchBtn);

    expect(mockPrompt).toHaveBeenCalledTimes(2);
  });
});
