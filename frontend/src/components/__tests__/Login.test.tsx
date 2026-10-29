import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { Login } from '../../pages/Login';
import { MemoryRouter } from 'react-router-dom';

const mockNavigate = vi.fn();
const mockLogin = vi.fn();

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => ({
      state: { from: { pathname: '/' } }
    }),
  };
});

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({
    login: mockLogin,
    loginWithGoogle: vi.fn(),
    user: null,
  }),
}));

describe('Login Component Unit Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders MailGuard branding, subtitle, Google button, and segmented tabs', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /MailGuard/i })).toBeInTheDocument();
    expect(screen.getByText(/Sign in to your dashboard/i)).toBeInTheDocument();
    expect(screen.getByText('GMAIL VERIFY')).toBeInTheDocument();
    expect(screen.getByText('SIGN IN')).toBeInTheDocument();
    expect(screen.getByText('NEW ACCOUNT')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Email')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('••••••••••••')).toBeInTheDocument();
    expect(screen.getByTestId('signin-submit-btn')).toBeInTheDocument();
  });

  it('submits correctly when email and password are provided', async () => {
    mockLogin.mockResolvedValueOnce({ status: 'success' });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    const emailInput = screen.getByPlaceholderText('Email');
    const passwordInput = screen.getByPlaceholderText('••••••••••••');
    const submitBtn = screen.getByTestId('signin-submit-btn');

    fireEvent.change(emailInput, { target: { value: 'mubashir@example.com' } });
    fireEvent.change(passwordInput, { target: { value: 'SecurePass123!' } });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith({
        identifier: 'mubashir@example.com',
        password: 'SecurePass123!',
      });
      expect(mockNavigate).toHaveBeenCalledWith('/');
    });
  });

  it('switches between GMAIL VERIFY, SIGN IN, and NEW ACCOUNT tabs', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    // Switch to GMAIL VERIFY
    const gmailTab = screen.getByText(/GMAIL VERIFY/i);
    fireEvent.click(gmailTab);
    expect(screen.getByText(/EMAIL OR PHONE FOR VERIFICATION/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Send Verification Code/i })).toBeInTheDocument();

    // Switch to NEW ACCOUNT
    const newAccountTab = screen.getByText(/NEW ACCOUNT/i);
    fireEvent.click(newAccountTab);
    expect(screen.getByText(/FULL NAME/i)).toBeInTheDocument();
    expect(screen.getByText(/WORK EMAIL ADDRESS/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Create Account & Verify/i })).toBeInTheDocument();
  });

  it('displays Google SSO option with account switcher and footer note', () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    expect(screen.getAllByText(/Continue with/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/Google/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Switch account/i)).toBeInTheDocument();
    expect(screen.getByText(/Your account is stored securely in MailGuard Cloud/i)).toBeInTheDocument();
  });
});
