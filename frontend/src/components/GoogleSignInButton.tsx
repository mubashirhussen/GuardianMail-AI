import React, { useEffect, useRef, useState, useCallback } from 'react';
import { authService } from '../services/auth';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface GoogleSignInButtonProps {
  onSuccess: (credential: string) => Promise<void> | void;
  onError?: (error: string) => void;
  disabled?: boolean;
  className?: string;
  text?: 'signin_with' | 'signup_with' | 'continue_with';
}

declare global {
  interface Window {
    google?: {
      accounts?: {
        id?: {
          initialize: (config: any) => void;
          renderButton: (parent: HTMLElement, options: any) => void;
          prompt: (notificationCallback?: (notification: any) => void) => void;
          disableAutoSelect: () => void;
        };
      };
    };
  }
}

const isRealGoogleClientId = (id: string | undefined): boolean => {
  if (!id) return false;
  const trimmed = id.trim();
  if (trimmed.startsWith('your-') || trimmed.includes('mailguard-app') || trimmed.length < 25) {
    return false;
  }
  return trimmed.endsWith('.apps.googleusercontent.com');
};

export const GoogleSignInButton: React.FC<GoogleSignInButtonProps> = ({
  onSuccess,
  onError,
  disabled = false,
  className = '',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [clientId, setClientId] = useState<string>(
    (import.meta.env.VITE_GOOGLE_CLIENT_ID as string) || ''
  );
  const [gisLoaded, setGisLoaded] = useState<boolean>(false);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // Fetch client ID from backend if not provided via Vite env
  useEffect(() => {
    let mounted = true;
    if (!isRealGoogleClientId(clientId)) {
      authService
        .getGoogleConfig()
        .then((config: any) => {
          if (mounted && config.client_id && isRealGoogleClientId(config.client_id)) {
            setClientId(config.client_id);
          }
        })
        .catch(() => {
          // Do not inject fake placeholder IDs that produce Google 401 invalid_client
        });
    }
    return () => {
      mounted = false;
    };
  }, [clientId]);

  // Handle successful Google credential returned from official GIS
  const handleCredentialResponse = useCallback(
    async (response: { credential?: string }) => {
      if (!response.credential) {
        const errMsg = 'No credential returned by Google Identity Services.';
        setAuthError(errMsg);
        onError?.(errMsg);
        return;
      }

      setAuthError(null);
      setIsVerifying(true);
      try {
        await onSuccess(response.credential);
      } catch (err: any) {
        const msg =
          err?.response?.data?.detail ||
          err?.message ||
          'Failed to authenticate with Google. Please try again.';
        setAuthError(msg);
        onError?.(msg);
      } finally {
        setIsVerifying(false);
      }
    },
    [onSuccess, onError]
  );

  // Initialize and render the official Google Identity Services button
  useEffect(() => {
    if (!isRealGoogleClientId(clientId)) return;

    let checkInterval: any = null;
    let attempts = 0;

    const tryInitGIS = () => {
      if (window.google?.accounts?.id && containerRef.current) {
        clearInterval(checkInterval);
        setGisLoaded(true);

        try {
          window.google.accounts.id.initialize({
            client_id: clientId,
            callback: handleCredentialResponse,
            auto_select: false,
            cancel_on_tap_outside: true,
            itp_support: true,
            context: 'signin',
          });

          // Clear previous render before re-rendering
          containerRef.current.innerHTML = '';

          window.google.accounts.id.renderButton(containerRef.current, {
            type: 'standard',
            theme: 'filled_black',
            size: 'large',
            text: 'continue_with',
            shape: 'rectangular',
            logo_alignment: 'left',
            width: containerRef.current.offsetWidth || 380,
          });

          // Also trigger official One-Tap / Account Chooser prompt if eligible
          window.google.accounts.id.prompt((notification) => {
            if (notification.isNotDisplayed()) {
              // Notification wasn't displayed (e.g., suppressed by browser, 3rd party cookies disabled)
            } else if (notification.isSkippedMoment()) {
              // User dismissed or skipped
            }
          });
        } catch (e: any) {
          // If renderButton fails, set fallback
          setGisLoaded(false);
        }
      } else {
        attempts++;
        if (attempts > 30) {
          clearInterval(checkInterval);
          // Script did not load in 3 seconds (likely offline or adblocker)
          setGisLoaded(false);
        }
      }
    };

    // If script is already loaded
    if (window.google?.accounts?.id) {
      tryInitGIS();
    } else {
      checkInterval = setInterval(tryInitGIS, 100);
    }

    return () => {
      if (checkInterval) clearInterval(checkInterval);
    };
  }, [clientId, handleCredentialResponse]);

  // Fallback handler if GIS script is blocked or user clicks custom button
  const handleFallbackGoogleLogin = async () => {
    setAuthError(null);
    if (!isRealGoogleClientId(clientId)) {
      const msg =
        'Google Sign-In is not configured yet. Please configure a valid GOOGLE_CLIENT_ID from Google Cloud Console in your .env file.';
      setAuthError(msg);
      onError?.(msg);
      return;
    }
    setIsVerifying(true);
    try {
      if (window.google?.accounts?.id) {
        window.google.accounts.id.prompt();
      } else {
        const data = await authService.getGoogleAuthUrl();
        if (data?.auth_url) {
          window.location.href = data.auth_url;
        } else {
          throw new Error('Google authorization service unavailable.');
        }
      }
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Google Sign-In is unavailable. Please check your connection.';
      setAuthError(msg);
      onError?.(msg);
      setIsVerifying(false);
    }
  };

  return (
    <div className={`space-y-2 w-full ${className}`}>
      {/* Official Google Identity Services Container */}
      <div className="relative w-full flex flex-col items-center justify-center min-h-[44px]">
        {/* GIS Official Render Target */}
        <div
          ref={containerRef}
          id="google-signin-btn-container"
          className={`w-full flex justify-center [&>div]:w-full [&>div>iframe]:!w-full [&>div>iframe]:!mx-auto ${
            isVerifying || disabled ? 'opacity-50 pointer-events-none' : ''
          }`}
        />

        {/* Fallback button if GIS script hasn't rendered yet or is blocked */}
        {!gisLoaded && (
          <button
            type="button"
            onClick={handleFallbackGoogleLogin}
            disabled={disabled || isVerifying}
            className="w-full py-2.5 px-4 bg-[#0d1424] hover:bg-[#141e33] border border-[#1b273d] rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-center gap-2.5 transition active:scale-[0.99] disabled:opacity-50 shadow-sm"
          >
            {isVerifying ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin text-blue-400" />
                <span>Verifying Google Identity...</span>
              </>
            ) : (
              <>
                <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>
                  Continue with <strong className="text-white">Google</strong>
                </span>
              </>
            )}
          </button>
        )}
      </div>

      {/* Account Switching Note / Switch prompt trigger */}
      <div className="flex items-center justify-between px-1 text-[11px] text-slate-500">
        <span>Use any Google account in this browser</span>
        <button
          type="button"
          onClick={() => {
            if (window.google?.accounts?.id) {
              window.google.accounts.id.prompt();
            } else {
              handleFallbackGoogleLogin();
            }
          }}
          className="text-blue-400 hover:text-blue-300 font-medium transition"
        >
          Switch account
        </button>
      </div>

      {/* Error state display */}
      {authError && (
        <div className="p-2.5 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{authError}</span>
        </div>
      )}
    </div>
  );
};
