# E12.5 — TLS & Reverse Proxy

## Header Configuration
* **HSTS**: Force HTTPS protocols (`max-age=63072000; includeSubDomains; preload`).
* **Frame Protection**: `X-Frame-Options: DENY` prevents clickjacking.
* **CSP**: Implemented Content-Security-Policy rules restricting unsafe scripts/styles.
* **Correlation Propagation**: Generates `$request_id` and sets `X-Request-ID` header.\n