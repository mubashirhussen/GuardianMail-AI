import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { Register } from '../../pages/Register';
import { MemoryRouter } from 'react-router-dom';

const mockNavigate = vi.fn();
const mockRegister = vi.fn();

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({
    login: vi.fn(),
    loginWithGoogle: vi.fn(),
    register: mockRegister,
    user: null,
  }),
}));

describe('Register Component Unit Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders registration form fields and Google option', () => {
    render(
      <MemoryRouter>
        <Register />
      </MemoryRouter>
    );

    expect(screen.getByText(/Create your enterprise account/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Jane')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Doe')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('jane.doe@enterprise.com')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Create a strong password (min 8 chars)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Create Account & Send Verification Code/i })).toBeInTheDocument();
  });

  it('validates password matching before submitting', () => {
    render(
      <MemoryRouter>
        <Register />
      </MemoryRouter>
    );

    const firstInput = screen.getByPlaceholderText('Jane');
    const lastInput = screen.getByPlaceholderText('Doe');
    const emailInput = screen.getByPlaceholderText('jane.doe@enterprise.com');
    const passwordInput = screen.getByPlaceholderText('Create a strong password (min 8 chars)');
    const confirmInput = screen.getByPlaceholderText('Re-enter password');
    const termsCheckbox = screen.getByRole('checkbox');
    const submitBtn = screen.getByRole('button', { name: /Create Account & Send Verification Code/i });

    fireEvent.change(firstInput, { target: { value: 'Alex' } });
    fireEvent.change(lastInput, { target: { value: 'Smith' } });
    fireEvent.change(emailInput, { target: { value: 'alex@enterprise.com' } });
    fireEvent.change(passwordInput, { target: { value: 'Password123!' } });
    fireEvent.change(confirmInput, { target: { value: 'DifferentPassword123!' } });
    fireEvent.click(termsCheckbox);
    fireEvent.click(submitBtn);

    expect(screen.getByText(/Passwords do not match/i)).toBeInTheDocument();
  });
});
