# GuardianMail AI — Google Identity Services & OAuth 2.0 Integration Guide

This guide provides instructions for configuring Google Identity Services (GIS), OpenID Connect token verification, and separate Gmail API access in GuardianMail AI.

---

## 1. Architectural Overview

GuardianMail AI uses a modern, zero-trust authentication design:

1. **Authentication (Sign-In & Account Chooser):**
   - Utilizes Google's official **Google Identity Services (GIS)** SDK (`https://accounts.google.com/gsi/client`).
   - When a user chooses **Continue with Google**, Google's official account chooser displays accounts available in the user's browser session.
   - The user does not need to retype their email when selecting an account offered by Google.
   - The frontend receives an OpenID Connect ID token (`credential`) and sends it to `POST /api/v1/auth/google/verify-token`.
   - **Scopes requested for sign-in:** `openid`, `email`, `profile` only.
   - **NO Gmail permissions are requested during initial sign-in.**

2. **Backend Cryptographic Verification:**
   - The backend validates the ID token signature against Google's public JWKS certificates (`https://www.googleapis.com/oauth2/v3/certs`) using `google.oauth2.id_token.verify_oauth2_token`.
   - Checks issuer (`accounts.google.com` or `https://accounts.google.com`).
   - Checks audience (`aud` matches configured `GOOGLE_CLIENT_ID`).
   - Checks expiration (`exp`).
   - Enforces `email_verified == True`.
   - Uses Google's stable subject identifier (`sub`) as the primary identity key (`google_id`).

3. **Account Linking Safeguards:**
   - Returning users with matching `google_id` authenticate directly.
   - If user exists by email, linking only occurs if the Google email is verified (`email_verified == True`).
   - If an existing account is already bound to a different Google ID, conflicting account linking is rejected (HTTP 409) to prevent account hijacking.
   - Deactivated or locked accounts are blocked (HTTP 403).

4. **Separate Gmail Integration:**
   - Gmail mailbox access requires explicit authorization under `https://www.googleapis.com/auth/gmail.readonly`.
   - Users trigger this explicitly in **Profile & Settings** -> **Connect Gmail**.
   - A permissions disclosure modal details:
     - Exact scopes requested.
     - Data accessed (headers, bodies, attachments for threat detection).
     - Purpose and retention policies.
     - Revocation control: users can disconnect anytime via `DELETE /api/v1/gmail/disconnect`, immediately purging tokens and halting mailbox synchronization.

---

## 2. Google Cloud Console Configuration

### Step 1: Create or Select a Google Cloud Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Select your organization or click **New Project**.
3. Name your project (e.g., `GuardianMail AI Defense`).

### Step 2: Configure the OAuth Consent Screen
1. Go to **APIs & Services** > **OAuth consent screen**.
2. Select User Type:
   - **Internal:** If restricted to users in your Google Workspace organization.
   - **External:** If allowing any Google identity.
3. Fill in required App Information:
   - **App name:** `GuardianMail AI`
   - **User support email:** Your security contact or admin email.
   - **App logo:** GuardianMail AI shield logo.
   - **Application home page:** `http://localhost:5173` (development) or `https://app.guardianmail.ai` (production).
   - **Application privacy policy link:** `https://guardianmail.ai/privacy`
   - **Application terms of service link:** `https://guardianmail.ai/terms`
   - **Authorized domains:** Add your top-level domain (e.g., `guardianmail.ai`).
4. Click **Save and Continue**.

### Step 3: Configure Identity Scopes
Under the **Scopes** step:
1. Click **Add or Remove Scopes**.
2. Select the non-sensitive identity scopes:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
   - `openid`
3. Click **Update** and **Save and Continue**.

*(Note: Gmail scope `.../auth/gmail.readonly` is configured separately under APIs & Services > Enabled APIs for mailbox ingestion).*

### Step 4: Create OAuth 2.0 Web Client ID
1. Go to **APIs & Services** > **Credentials**.
2. Click **Create Credentials** > **OAuth client ID**.
3. Select Application Type: **Web application**.
4. Name: `GuardianMail AI Web Client`.
5. **Authorized JavaScript origins:**
   - Development:
     - `http://localhost:5173`
     - `http://localhost:3000`
     - `http://localhost:8000`
     - `http://127.0.0.1:5173`
     - `http://127.0.0.1:8000`
   - Production:
     - `https://app.guardianmail.ai`
     - `https://api.guardianmail.ai`
6. **Authorized redirect URIs:**
   - Development:
     - `http://localhost:8000/api/v1/auth/google/callback`
     - `http://localhost:5173/login`
   - Production:
     - `https://api.guardianmail.ai/api/v1/auth/google/callback`
     - `https://app.guardianmail.ai/login`
7. Click **Create**.
8. Copy the generated **Client ID** and **Client Secret**.

---

## 3. Environment Variable Setup

### Backend Configuration (`backend/.env` or root `.env`)
```bash
# Google Identity Services & OAuth 2.0
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback

# Security & Sessions
SECRET_KEY=at-least-32-characters-cryptographically-secure-random-secret
ENVIRONMENT=development   # Set to 'production' in deployed environments
```

### Frontend Configuration (`frontend/.env`)
```bash
# Backend API Base URL
VITE_API_BASE_URL=http://localhost:8000/api/v1

# Google Identity Services Client ID
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
```

*(Note: If `VITE_GOOGLE_CLIENT_ID` is omitted, the frontend automatically queries `/api/v1/auth/google/config` at runtime to obtain the public client ID).*

---

## 4. API Endpoints Reference

| Method | Endpoint | Description | Protected |
|---|---|---|---|
| `GET` | `/api/v1/auth/google/config` | Returns public Google Client ID for GIS button initialization | No |
| `GET` | `/api/v1/auth/google/login` | Returns OAuth authorization URL with identity scopes | No |
| `POST` | `/api/v1/auth/google/verify-token` | Verifies OpenID Connect ID token and returns session tokens | No (Rate-limited) |
| `GET` | `/api/v1/auth/google/callback` | Standard OAuth code exchange callback | No |
| `GET` | `/api/v1/gmail/permissions` | Discloses Gmail read-only scopes, data accessed & purpose | No |
| `GET` | `/api/v1/gmail/auth-url` | Builds isolated Gmail consent authorization URL | Yes (Bearer JWT) |
| `POST` | `/api/v1/gmail/connect` | Links Gmail mailbox tokens to authenticated account | Yes (Bearer JWT) |
| `DELETE` | `/api/v1/gmail/disconnect` | Revokes Gmail access and purges stored OAuth tokens | Yes (Bearer JWT) |

---

## 5. Security & Threat Model Mitigations

1. **Token Forgery & Replay Attacks:**
   - Every Google ID token is verified against Google's public cryptographic keys (`google.oauth2.id_token`).
   - Audience matching prevents tokens issued for other applications from being accepted.
   - Expiration timestamps prevent replaying old credentials.

2. **Account Takeover via Email Impersonation:**
   - Only Google accounts with `email_verified == True` are accepted.
   - Linking by email requires verified status.
   - If an account is already bound to a different Google `sub`, re-linking is rejected (HTTP 409).

3. **Separation of Privileges (Sign-In vs. Mailbox Reading):**
   - GuardianMail AI does not request inbox access during login.
   - Email read permissions (`https://www.googleapis.com/auth/gmail.readonly`) are only requested upon explicit user opt-in in the Settings panel.

4. **Session Hardening:**
   - Application sessions are issued as GuardianMail AI JWTs with unique `jti` identifiers.
   - Active sessions are recorded in the device repository with device fingerprinting and IP address tracking.
   - Session revocation invalidates tokens immediately across the enterprise.
