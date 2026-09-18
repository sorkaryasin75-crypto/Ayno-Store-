# AYNO STORE — PRODUCTION V4 / FIREBASE EDITION

Railway and PostgreSQL have been removed from this deployment architecture.

## Runtime

- Firebase Hosting
- Firebase Cloud Functions
- Firebase Authentication
- Cloud Firestore
- Firebase Storage
- Firebase App Check (configuration-ready)

## Included

- Existing Ayno Store V4 frontend
- Firebase Hosting configuration
- Firestore rules/indexes
- Storage rules
- Firebase Cloud Function API gateway
- Telegram Web App server-side validation
- Firebase Custom Token → ID Token authentication flow
- User/order/wallet/withdrawal/transfer/review/error-log foundations
- Secure provider-secret pattern
- `.env.example`

## No fake provider data

Provider endpoints that are not implemented in the supplied source are not replaced with fake success responses. Configure the real provider credentials/API contracts before enabling those operations.

See `FIREBASE_SETUP.md`.
