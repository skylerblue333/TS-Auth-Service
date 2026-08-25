# SkyAuth — TypeScript Authentication Boundary

Wave-2 slot **#62** / Lane **02**.

SkyAuth is a small Express authentication component that preserves the repository's existing registration, bcrypt password hashing, login, and HS256 JWT verification behavior while adding an explicit integration contract for a separate SkyIdentity directory.

## Implemented behavior

The service validates usernames and minimum password length, hashes passwords with bcrypt, rejects duplicate registrations, issues one-hour HS256 JWTs, requires a strong `JWT_SECRET` in production, rejects explicitly configured weak secrets in every environment, restricts accepted JWT algorithms, limits JSON request bodies to 16 KB, and disables the Express fingerprint header.

Wave 2 adds `GET /identity-context`. After a valid bearer token is authenticated, an injected `IdentityResolver` may map the local username to bounded opaque `subjectId` / `profileId` identifiers. Resolver output is validated before it is returned. Missing resolvers, unavailable resolvers, and malformed mappings fail closed.

Every identity-context response explicitly reports `identityVerificationPerformed: false`. A directory mapping is not proof of a person's real-world identity.

## API

- `GET /healthz`
- `GET /readyz`
- `POST /register`
- `POST /login`
- `GET /verify`
- `GET /identity-context`

Authenticated endpoints require `Authorization: Bearer <token>`.

## SkyIdentity integration contract

Consumers inject an adapter rather than coupling SkyAuth to a network endpoint:

```ts
import { createApp, type IdentityResolver } from "./src/index";

const resolver: IdentityResolver = {
  async resolve(username) {
    // Call a separately authenticated/authorized SkyIdentity adapter here.
    return { subjectId: `sky:${username}`, profileId: `profile:${username}`, source: "skyidentity" };
  },
};

const app = createApp(undefined, process.env.JWT_SECRET, resolver);
```

The adapter remains responsible for transport security, authorization, freshness, availability, and proving that returned identifiers are legitimate. SkyAuth only validates the shape and bounds of the mapping.

## Validation

```bash
pnpm install --frozen-lockfile
pnpm run build
pnpm exec jest --runInBand
pnpm audit --prod --audit-level high
docker build -t sky-ts-auth:ci .
```

CI additionally verifies that the runtime image uses the non-root `node` user.

## Secret configuration

Generate and inject a deployment secret rather than committing one:

```bash
openssl rand -hex 32
```

Production startup fails if `JWT_SECRET` is absent or shorter than 32 characters.

## Status and limitations

**Engineering beta / authentication boundary.**

The default user store is process-local memory and loses users on restart. This repository does not provide persistent identity storage, OAuth/OIDC authorization-server behavior, refresh tokens, revocation, MFA, account recovery, rate limiting, durable audit logging, CSRF/session-cookie policy, asymmetric signing/key rotation, tenant isolation, HA, or verified production deployment.

SkyAuth authenticates credentials that exist in its configured user store. The optional SkyIdentity resolver links identifiers only; it does not perform identity proofing or verification. No external provider is represented as connected unless a consumer supplies and verifies its own adapter.
