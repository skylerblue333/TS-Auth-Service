# SKYCOIN4444 Ecosystem Integration

**Wave-2 slot:** #62 SkyAuth  
**Lane:** 02  
**Role:** credential authentication and short-lived token boundary.

## Provides

- local username/password registration against a pluggable user store;
- bcrypt password verification;
- bounded HS256 access tokens;
- token verification;
- health/readiness endpoints;
- an injected `IdentityResolver` contract for mapping an authenticated local username to bounded SkyIdentity identifiers.

## Integration direction

`SkyIdentity (#61) -> SkyAuth (#62) -> SkyMFA (#63) -> SkyPermissions (#64)` is the intended identity/security chain.

SkyAuth deliberately does not import SkyIdentity implementation code. A consuming composition root supplies an adapter implementing `IdentityResolver`. This keeps authentication independent of a particular transport or deployment topology while making the identity boundary testable.

A successful resolver mapping sets `identityLinked: true` but always reports `identityVerificationPerformed: false`. Mapping identifiers is not identity proofing.

## Production requirements not established here

Persistent credential storage, external IdP/OIDC integration, MFA, token revocation, asymmetric signing/key rotation, durable audit events, rate limiting, secure session-cookie/CSRF policy, tenant isolation, secret-manager integration, HA, deployment evidence, and operational monitoring remain separate integration requirements.
