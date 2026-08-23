# Ecosystem Integration

**Role:** authentication/token boundary.

**Foundation:** JWT standards and the established `jsonwebtoken` library. Cryptographic primitives must not be custom-built here.

**Provides:** short-lived service/user tokens and token verification.

**Production requirements:** OIDC/OAuth integration where appropriate, key rotation, issuer/audience validation, revocation strategy, secure cookie/session boundaries, audit events, and secret-manager integration.
