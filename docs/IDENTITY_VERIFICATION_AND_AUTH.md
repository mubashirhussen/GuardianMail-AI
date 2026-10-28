# GuardianMail AI — Production-Grade Authentication & Identity Verification System

## Architecture Overview

GuardianMail AI provides an enterprise-grade, multi-channel authentication and identity verification platform combining:
1. **Google Identity Services (GIS)** with OpenID Connect (OIDC) server-side ID token cryptographic verification (`google.oauth2.id_token.verify_oauth2_token`).
2. **Dedicated Gmail Authorization Separation**: Google authentication scopes are strictly restricted to `openid email profile`. Reading Gmail messages requires explicit, secondary consent via `/api/v1/gmail/auth-url` (`https://www.googleapis.com/auth/gmail.readonly`).
3. **Multi-Channel One-Time Password (OTP) Challenge System**: 6-digit cryptographically generated numeric codes protected via HMAC-SHA256, expiration windows, attempt limits, and resend cooldowns.
4. **Real Transactional Delivery Integrations**: Configurable Email (Resend, SendGrid, SMTP) and Mobile SMS (Twilio SMS, Twilio Verify) with strict E.164 phone normalization.
5. **Anti-Enumeration Protection**: Generic responses on public authentication and recovery endpoints to eliminate user enumeration.
6. **Session Revocation & Device Fingerprinting**: Per-device session records, JWT `jti` revocation, Redis session blacklisting, and `logout-all` capabilities.

---

## 1. Authentication Endpoints Reference

| Method | Endpoint | Description | Security Controls |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Register new user account | Dispatches email verification OTP; validates passwords. |
| `POST` | `/api/v1/auth/login` | Authenticate credentials | Supports email or E.164 phone; lockout after 5 failures. |
| `GET` | `/api/v1/auth/google/config` | Client ID for GIS | Returns authorized Google OAuth Web Client ID. |
| `POST` | `/api/v1/auth/google/verify-token` | Validate GIS OIDC ID token | Verifies signature, issuer (`accounts.google.com`), audience, expiry, and email verification claim. |
| `POST` | `/api/v1/auth/email/send-code` | Dispatch email OTP code | 60s cooldown, 10 min TTL, invalidates prior active challenges. |
| `POST` | `/api/v1/auth/email/verify` | Verify email OTP code | Max 5 attempts, single-use invalidation, constant-time HMAC check. |
| `POST` | `/api/v1/auth/phone/send-code` | Dispatch SMS OTP code | Strict E.164 phone normalization, 60s cooldown, provider delivery. |
| `POST` | `/api/v1/auth/phone/verify` | Verify SMS OTP code | Max 5 attempts, marks `phone_verified: True` on success. |
| `POST` | `/api/v1/auth/password/forgot` | Initiate password recovery | Anti-enumeration: returns generic message whether user exists or not. |
| `POST` | `/api/v1/auth/password/reset` | Complete password recovery | Single-use reset code, updates password hash, revokes all active sessions. |
| `POST` | `/api/v1/auth/logout` | Revoke current session | Blacklists current session `jti` in Redis cache. |
| `POST` | `/api/v1/auth/logout-other-devices` | Revoke other sessions | Blacklists all other active sessions while preserving current. |
| `POST` | `/api/v1/auth/logout-all` | Revoke all sessions | Blacklists all user sessions across all devices in Redis & DB. |
| `GET` | `/api/v1/auth/me` | Fetch authenticated profile | Enforces active JWT bearer token; returns user attributes. |

---

## 2. Environment Configuration

### Base Settings

```bash
ENVIRONMENT=production
SECRET_KEY=at-least-32-character-cryptographically-secure-key
FRONTEND_URL=https://guardianmail.ai
BACKEND_URL=https://api.guardianmail.ai

# Database & Cache
MONGODB_URL=mongodb+srv://<cluster>.mongodb.net
MONGODB_DB_NAME=guardianmail
REDIS_URL=rediss://default:<password>@<host>:6379/0

# Verification Challenge Parameters
AUTH_CODE_TTL_SECONDS=600         # 10 minutes
AUTH_RESEND_COOLDOWN_SECONDS=60    # 1 minute
AUTH_MAX_VERIFICATION_ATTEMPTS=5   # Invalidation after 5 failed tries
```

### Google Identity Services (GIS)

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://api.guardianmail.ai/api/v1/auth/google/callback
```

### Email Delivery Provider

Configure one of the supported email delivery backends:

```bash
# 1. Resend
EMAIL_PROVIDER=resend
EMAIL_API_KEY=re_1234567890abcdef
EMAIL_FROM_ADDRESS=security@guardianmail.ai

# 2. SendGrid
EMAIL_PROVIDER=sendgrid
EMAIL_API_KEY=SG.1234567890abcdef
EMAIL_FROM_ADDRESS=security@guardianmail.ai

# 3. Standard SMTP
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USERNAME=postmaster@guardianmail.ai
SMTP_PASSWORD=smtp-password
SMTP_USE_TLS=True

# 4. Local Development Console Mode (logs masked destination, dev only)
EMAIL_PROVIDER=console
```

### SMS Verification Provider

```bash
# 1. Twilio SMS
SMS_PROVIDER=twilio
TWILIO_ACCOUNT_SID=ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_FROM_NUMBER=+18005550199

# 2. Twilio Verify
SMS_PROVIDER=twilio_verify
TWILIO_ACCOUNT_SID=ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_VERIFY_SERVICE_SID=VAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# 3. Local Development Console Mode (logs masked destination, dev only)
SMS_PROVIDER=console
```

---

## 3. Google Cloud Console Setup

1. Navigate to **Google Cloud Console** > **APIs & Services** > **Credentials**.
2. Click **Create Credentials** > **OAuth client ID**.
3. Select Application type: **Web application**.
4. **Authorized JavaScript origins**:
   - Development: `http://localhost:5173`, `http://localhost:8000`, `http://localhost`
   - Production: `https://guardianmail.ai`
5. **Authorized redirect URIs**:
   - `https://api.guardianmail.ai/api/v1/auth/google/callback`
   - `http://localhost:8000/api/v1/auth/google/callback`
6. Under **OAuth consent screen**:
   - User Type: External or Internal (Workspace).
   - Scopes: `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile`.
   - Ensure `gmail.readonly` is NOT added to the sign-in consent screen. It is requested separately on demand.

---

## 4. Verification Challenge Engine Details

- **Cryptographic Hashing**: Codes are never stored in plaintext. They are protected via keyed HMAC-SHA256 (`identifier + ":" + purpose + ":" + code`) with `settings.SECRET_KEY`.
- **Brute-Force Resistance**: Even with a 6-digit space (1,000,000 possibilities), the keyed HMAC prevents offline rainbow table attacks without the server's private secret key.
- **Replay Protection**: Verifying a challenge marks `consumed_at = now`. Subsequent attempts return a 400 error.
- **Single Active Challenge**: Requesting a new code automatically supersedes and invalidates prior unconsumed codes for that destination.

---

## 5. Automated Test Verification

Run all authentication, identity verification, and frontend tests:

```bash
# Backend pytest suite (20 tests)
cd backend
python -m pytest tests/test_google_auth.py tests/test_identity_verification.py -v

# Frontend vitest suite (19 tests)
npm run test:frontend

# Production frontend bundle compilation
npm run build
```
