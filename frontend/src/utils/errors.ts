/**
 * Centralized API error message mapping.
 * Maps HTTP status codes and backend error shapes to user-friendly messages.
 * Never exposes raw stack traces or internal error details.
 */

import type { AxiosError } from 'axios';

export interface AppError {
  message: string;
  status?: number;
  code?: string;
}

/**
 * Extract a user-friendly error message from an Axios error or generic error.
 */
export function getErrorMessage(error: unknown): string {
  if (!error) return 'An unexpected error occurred.';

  const axiosErr = error as AxiosError<{ detail?: string; message?: string }>;

  if (axiosErr.response) {
    const status = axiosErr.response.status;
    const detail =
      axiosErr.response.data?.detail ||
      axiosErr.response.data?.message;

    switch (status) {
      case 400:
        return detail || 'Invalid request. Please check your input and try again.';
      case 401:
        return 'Your session has expired. Please sign in again.';
      case 403:
        return 'You do not have permission to perform this action.';
      case 404:
        return detail || 'The requested resource was not found.';
      case 409:
        return detail || 'A conflict occurred. The resource may already exist.';
      case 413:
        return 'The uploaded file is too large. Please reduce the file size and try again.';
      case 422:
        return detail || 'The request could not be processed. Please verify the provided data.';
      case 429:
        return 'Too many requests. Please wait a moment before trying again.';
      case 500:
        return 'GuardianMail encountered an internal error. Please try again later.';
      case 502:
      case 503:
        return 'GuardianMail services are temporarily unavailable. Please try again shortly.';
      case 504:
        return 'The request timed out. Please check your connection and try again.';
      default:
        return detail || `An error occurred (${status}). Please try again.`;
    }
  }

  if (axiosErr.code === 'ECONNABORTED' || axiosErr.message?.includes('timeout')) {
    return 'The request timed out. Please check your connection and try again.';
  }

  if (axiosErr.message === 'Network Error') {
    return 'Unable to reach GuardianMail services. Please check your network connection.';
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'An unexpected error occurred. Please try again.';
}

/**
 * Parse an Axios error into a structured AppError object.
 */
export function parseError(error: unknown): AppError {
  const axiosErr = error as AxiosError<{ detail?: string; message?: string }>;
  return {
    message: getErrorMessage(error),
    status: axiosErr?.response?.status,
    code: axiosErr?.code,
  };
}
