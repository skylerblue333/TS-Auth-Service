# SkyAuth Security Boundaries

## Supported controls

- bcrypt password hashing for the current local credential store;
- bounded username/password inputs;
- explicit JWT algorithm restriction to HS256;
- one-hour token lifetime;
- fail-closed production JWT secret configuration;
- bearer-token parsing with single-token syntax;
- bounded JSON request bodies;
- validation of caller-supplied identity-directory mappings;
- non-root runtime container verification in CI.

## Not security guarantees

SkyAuth is not an identity-proofing service. `IdentityResolver` output is treated as a mapping from a separately trusted integration boundary and every response explicitly states `identityVerificationPerformed: false`.

The repository does not establish MFA, OAuth/OIDC provider compliance, credential breach detection, account recovery, brute-force/rate-limit controls, refresh-token rotation, revocation, asymmetric signing, key rotation, durable security audit logs, tenant isolation, secure ingress/TLS termination, WAF behavior, HA, or production deployment.

## Integration responsibilities

A production composition must authenticate and authorize access to any SkyIdentity adapter, protect transport confidentiality/integrity, validate adapter freshness/availability, maintain durable user and audit state, rotate secrets/keys, enforce rate limits, and independently review the complete deployed authentication flow.
