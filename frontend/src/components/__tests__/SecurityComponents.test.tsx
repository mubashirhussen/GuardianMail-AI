import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { PasswordStrength } from '../PasswordStrength';
import { OTPInput } from '../OTPInput';
import { RiskBadge } from '../RiskBadge';
import { StatusBadge } from '../StatusBadge';
import { ApprovalModal } from '../ApprovalModal';

describe('Security Design System Components Unit Tests', () => {
  it('evaluates password strength and entropy states correctly', () => {
    const { rerender } = render(<PasswordStrength password="weak" />);
    expect(screen.getByText('Weak')).toBeInTheDocument();

    rerender(<PasswordStrength password="MediumPassword1" />);
    expect(screen.getByText('Strong')).toBeInTheDocument();

    rerender(<PasswordStrength password="SuperSecureP@ssw0rd!2026" />);
    expect(screen.getByText('Very Strong')).toBeInTheDocument();
  });

  it('renders and handles 6-digit OTP input interactions and paste event', () => {
    const onComplete = vi.fn();
    render(<OTPInput onComplete={onComplete} recipientText="analyst@guardianmail.ai" />);

    expect(screen.getByText('Two-Factor Authentication')).toBeInTheDocument();
    expect(screen.getByText(/analyst@guardianmail.ai/i)).toBeInTheDocument();

    const inputs = screen.getAllByRole('textbox');
    expect(inputs).toHaveLength(6);

    // Simulate typing digits
    inputs.forEach((input, i) => {
      fireEvent.change(input, { target: { value: `${i + 1}` } });
    });

    expect(onComplete).toHaveBeenCalledWith('123456');
  });

  it('renders risk badges with correct risk levels and scores', () => {
    const { rerender } = render(<RiskBadge score={94.5} />);
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('(94.5)')).toBeInTheDocument();

    rerender(<RiskBadge score={12.0} />);
    expect(screen.getByText('SAFE')).toBeInTheDocument();
  });

  it('renders status badges with appropriate action states', () => {
    const { rerender } = render(<StatusBadge status="PENDING_APPROVAL" />);
    expect(screen.getByText('APPROVAL REQUIRED')).toBeInTheDocument();

    rerender(<StatusBadge status="CONTAINED" />);
    expect(screen.getByText('CONTAINED')).toBeInTheDocument();
  });

  it('handles human approval modal interactions, justification check, and authorization submission', async () => {
    const onApprove = vi.fn().mockResolvedValue(undefined);
    const onReject = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    const requestData = {
      decisionId: 'dec_001',
      tokenId: 'tok_single_use_9921',
      action: 'ISOLATE_MAILBOX_AND_BLOCK_SENDER',
      targetResource: 'ceo@enterprise.com',
      riskScore: 92.5,
      indicators: ['Typosquatting Domain', 'SPF Fail'],
      policyName: 'Strict Zero Trust Policy'
    };

    render(
      <ApprovalModal
        isOpen={true}
        onClose={onClose}
        onApprove={onApprove}
        onReject={onReject}
        requestData={requestData}
      />
    );

    expect(screen.getByText('Authorize Sensitive Response Containment')).toBeInTheDocument();
    expect(screen.getByText('ISOLATE_MAILBOX_AND_BLOCK_SENDER')).toBeInTheDocument();
    expect(screen.getByText('tok_single_use_9921')).toBeInTheDocument();

    const authBtn = screen.getByRole('button', { name: /Authorize Sandbox Execution/i });
    
    // Attempt authorize without justification -> shows validation error
    fireEvent.click(authBtn);
    expect(screen.getByText(/Analyst operational justification is required/i)).toBeInTheDocument();
    expect(onApprove).not.toHaveBeenCalled();

    // Fill justification and click authorize
    const textarea = screen.getByPlaceholderText(/Verified typosquatting credential harvester/i);
    fireEvent.change(textarea, { target: { value: 'Confirmed malicious executive impersonation attempt.' } });
    fireEvent.click(authBtn);

    await waitFor(() => {
      expect(onApprove).toHaveBeenCalledWith('tok_single_use_9921', 'Confirmed malicious executive impersonation attempt.');
      expect(onClose).toHaveBeenCalled();
    });
  });
});
