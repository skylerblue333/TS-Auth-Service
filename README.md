# TypeScript Authentication Service

A small Express service implementing registration, password hashing, login, and JWT verification. It is an authentication component with an in-memory development store—not a complete identity platform or production user database.

## Implemented behavior

The service validates usernames and minimum password length, hashes passwords with bcrypt, rejects duplicate registrations, issues HS256 JWTs with a one-hour expiry, requires an explicit `JWT_SECRET` in production, restricts accepted JWT algorithms, returns only a minimal identity on verification, limits JSON request bodies to 16 KB, and disables the Express fingerprint header.

```bash
pnpm install
JWT_SECRET="replace-with-a-managed-secret" NODE_ENV=production pnpm run build
JWT_SECRET="replace-with-a-managed-secret" pnpm start
```

The API endpoints are `POST /register`, `POST /login`, and `GET /verify` with an `Authorization: Bearer <token>` header.

## Validation

```bash
pnpm run build
pnpm test --runInBand
```

The current suite covers registration and login, weak-credential rejection, duplicate registration, minimal verified identity, and invalid-token rejection.

## Scope and limitations

The default store is process-local memory and loses users on restart. This repository does not provide persistent storage, refresh tokens, revocation, multi-factor authentication, account recovery, rate limiting, audit logging, CSRF policy, key rotation, or a deployed identity provider. It must not be used as a production authentication service until those controls and an external persistent store are implemented and reviewed.

The former “OAuth2,” “professional-grade,” “scalable,” and “cloud-native” language was removed because the current implementation issues local JWTs and does not implement an OAuth2 authorization server.
