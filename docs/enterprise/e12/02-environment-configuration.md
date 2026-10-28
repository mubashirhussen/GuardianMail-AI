# E12.2 — Environment Configuration

## Production Variables (`.env`)
```ini
APP_ENV=production
APP_NAME="GuardianMail AI"
APP_VERSION="1.0.0"
LOG_LEVEL=INFO
DEBUG=False

MONGODB_URI=mongodb://mongo_user:strong_password@mongo:27017/guardianmail?authSource=admin
MONGODB_DATABASE=guardianmail

REDIS_URL=redis://redis:6379/0

CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2
CELERY_WORKER_CONCURRENCY=4

SECRET_KEY=enterprise-super-secure-cryptographic-secret-2026-must-be-rotated-frequently
JWT_ISSUER=guardianmail.com
JWT_AUDIENCE=guardianmail-app

GOOGLE_CLIENT_ID=prod_google_client_id
GOOGLE_CLIENT_SECRET=prod_google_client_secret
GOOGLE_REDIRECT_URI=https://guardianmail.com/api/v1/auth/callback
```\n