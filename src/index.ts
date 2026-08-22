import bcrypt from "bcryptjs";
import express, { type Express, type Request, type Response } from "express";
import jwt, { type JwtPayload } from "jsonwebtoken";

const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,64}$/;
const PASSWORD_MIN_LENGTH = 12;
const TOKEN_TTL_SECONDS = 60 * 60;

type UserRecord = { username: string; passwordHash: string };
type UserStore = { find(username: string): UserRecord | undefined; save(user: UserRecord): void };

export class InMemoryUserStore implements UserStore {
  private readonly users = new Map<string, UserRecord>();
  find(username: string): UserRecord | undefined { return this.users.get(username); }
  save(user: UserRecord): void { this.users.set(user.username, user); }
}

function configuredSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (secret) return secret;
  if (process.env.NODE_ENV === "production") throw new Error("JWT_SECRET is required in production");
  return "development-only-secret-change-me";
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

export function createApp(store: UserStore = new InMemoryUserStore(), secret = configuredSecret()): Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "16kb" }));

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
    const valid = Boolean(user && input && await bcrypt.compare(input.password, user.passwordHash));
    if (!valid || !user) return response.status(401).json({ error: "invalid credentials" });
    const token = jwt.sign({ sub: user.username }, secret, { algorithm: "HS256", expiresIn: TOKEN_TTL_SECONDS });
    return response.json({ token, expiresIn: TOKEN_TTL_SECONDS });
  });

  app.get("/verify", (request: Request, response: Response) => {
    const token = bearerToken(request);
    if (!token) return response.status(401).json({ error: "bearer token required" });
    try {
      const decoded = jwt.verify(token, secret, { algorithms: ["HS256"] }) as JwtPayload;
      if (typeof decoded.sub !== "string") return response.status(401).json({ error: "invalid token" });
      return response.json({ valid: true, user: { username: decoded.sub } });
    } catch {
      return response.status(401).json({ error: "invalid token" });
    }
  });

  return app;
}

const app = createApp();
if (require.main === module) app.listen(3000, () => console.log("Auth service listening on port 3000"));
export default app;
