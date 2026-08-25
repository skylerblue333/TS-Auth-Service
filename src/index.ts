import bcrypt from "bcryptjs";
import express, { type Express, type Request, type Response } from "express";
import jwt, { type JwtPayload } from "jsonwebtoken";

const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,64}$/;
const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$/;
const SOURCE_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/;
const PASSWORD_MIN_LENGTH = 12;
const TOKEN_TTL_SECONDS = 60 * 60;

type UserRecord = { username: string; passwordHash: string };
type UserStore = { find(username: string): UserRecord | undefined; save(user: UserRecord): void };

export interface IdentityLink {
  readonly subjectId: string;
  readonly profileId?: string;
  readonly source: string;
}

/**
 * Integration boundary for SkyIdentity or another trusted identity directory.
 * Returning a link does not prove or verify a person's real-world identity.
 */
export interface IdentityResolver {
  resolve(username: string): IdentityLink | undefined | Promise<IdentityLink | undefined>;
}

export class InMemoryUserStore implements UserStore {
  private readonly users = new Map<string, UserRecord>();

  find(username: string): UserRecord | undefined {
    return this.users.get(username);
  }

  save(user: UserRecord): void {
    this.users.set(user.username, user);
  }
}

export function configuredSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (secret !== undefined) {
    if (secret.length < 32) {
      throw new Error("JWT_SECRET must contain at least 32 characters when configured");
    }
    return secret;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("JWT_SECRET with at least 32 characters is required in production");
  }
  return "development-only-secret-change-me-32chars";
}

function credentials(body: unknown): { username: string; password: string } | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const value = body as Record<string, unknown>;
  if (typeof value.username !== "string" || typeof value.password !== "string") return undefined;
  return { username: value.username.trim(), password: value.password };
}

function bearerToken(request: Request): string | undefined {
  const header = request.header("authorization");
  if (!header) return undefined;
  const [scheme, token, ...extra] = header.split(" ");
  return scheme?.toLowerCase() === "bearer" && token && extra.length === 0 ? token : undefined;
}

function tokenSubject(token: string, secret: string): string | undefined {
  try {
    const decoded = jwt.verify(token, secret, { algorithms: ["HS256"] }) as JwtPayload;
    return typeof decoded.sub === "string" && USERNAME_PATTERN.test(decoded.sub) ? decoded.sub : undefined;
  } catch {
    return undefined;
  }
}

function normalizeIdentityLink(link: IdentityLink): IdentityLink | undefined {
  const subjectId = link.subjectId.trim();
  const profileId = link.profileId?.trim();
  const source = link.source.trim();
  if (!ID_PATTERN.test(subjectId) || !SOURCE_PATTERN.test(source)) return undefined;
  if (profileId !== undefined && !ID_PATTERN.test(profileId)) return undefined;
  return profileId === undefined ? { subjectId, source } : { subjectId, profileId, source };
}

export function createApp(
  store: UserStore = new InMemoryUserStore(),
  secret = configuredSecret(),
  identityResolver?: IdentityResolver,
): Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "16kb" }));

  app.get("/healthz", (_request: Request, response: Response) => {
    response.json({ status: "ok", service: "sky-ts-auth" });
  });

  app.get("/readyz", (_request: Request, response: Response) => {
    response.json({ status: "ready" });
  });

  app.post("/register", async (request: Request, response: Response) => {
    const input = credentials(request.body);
    if (!input || !USERNAME_PATTERN.test(input.username) || input.password.length < PASSWORD_MIN_LENGTH) {
      return response.status(400).json({ error: "username or password does not meet requirements" });
    }
    if (store.find(input.username)) return response.status(409).json({ error: "user already exists" });
    const passwordHash = await bcrypt.hash(input.password, 12);
    store.save({ username: input.username, passwordHash });
    return response.status(201).json({ username: input.username });
  });

  app.post("/login", async (request: Request, response: Response) => {
    const input = credentials(request.body);
    const user = input ? store.find(input.username) : undefined;
    const valid = Boolean(user && input && (await bcrypt.compare(input.password, user.passwordHash)));
    if (!valid || !user) return response.status(401).json({ error: "invalid credentials" });
    const token = jwt.sign({ sub: user.username }, secret, {
      algorithm: "HS256",
      expiresIn: TOKEN_TTL_SECONDS,
    });
    return response.json({ token, expiresIn: TOKEN_TTL_SECONDS });
  });

  app.get("/verify", (request: Request, response: Response) => {
    const token = bearerToken(request);
    if (!token) return response.status(401).json({ error: "bearer token required" });
    const subject = tokenSubject(token, secret);
    if (!subject) return response.status(401).json({ error: "invalid token" });
    return response.json({ valid: true, user: { username: subject } });
  });

  app.get("/identity-context", async (request: Request, response: Response) => {
    const token = bearerToken(request);
    if (!token) return response.status(401).json({ error: "bearer token required" });
    const username = tokenSubject(token, secret);
    if (!username) return response.status(401).json({ error: "invalid token" });

    if (!identityResolver) {
      return response.status(503).json({
        authenticated: true,
        user: { username },
        identityLinked: false,
        identityVerificationPerformed: false,
        error: "identity resolver not configured",
      });
    }

    try {
      const rawLink = await identityResolver.resolve(username);
      if (!rawLink) {
        return response.json({
          authenticated: true,
          user: { username },
          identityLinked: false,
          identityVerificationPerformed: false,
        });
      }
      const identity = normalizeIdentityLink(rawLink);
      if (!identity) {
        return response.status(502).json({
          authenticated: true,
          user: { username },
          identityLinked: false,
          identityVerificationPerformed: false,
          error: "identity resolver returned invalid mapping",
        });
      }
      return response.json({
        authenticated: true,
        user: { username },
        identityLinked: true,
        identityVerificationPerformed: false,
        identity,
      });
    } catch {
      return response.status(503).json({
        authenticated: true,
        user: { username },
        identityLinked: false,
        identityVerificationPerformed: false,
        error: "identity resolver unavailable",
      });
    }
  });

  return app;
}

const app = createApp();
if (require.main === module) {
  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, () => console.log(`Auth service listening on port ${port}`));
}
export default app;
