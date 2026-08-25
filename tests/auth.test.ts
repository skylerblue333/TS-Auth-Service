import request from "supertest";
import { configuredSecret, createApp, InMemoryUserStore, type IdentityResolver } from "../src/index";

const password = "correct-horse-battery-staple";

async function authenticatedToken(app: ReturnType<typeof createApp>): Promise<string> {
  await request(app).post("/register").send({ username: "test", password });
  const { body } = await request(app).post("/login").send({ username: "test", password });
  return body.token as string;
}

describe("Auth API", () => {
  it("registers and logs in a user without exposing a password hash", async () => {
    const app = createApp(new InMemoryUserStore(), "test-secret");
    const register = await request(app).post("/register").send({ username: "test", password });
    expect(register.status).toBe(201);
    expect(register.body).toEqual({ username: "test" });

    const login = await request(app).post("/login").send({ username: "test", password });
    expect(login.status).toBe(200);
    expect(login.body.token).toEqual(expect.any(String));
  });

  it("rejects weak credentials and duplicate registration", async () => {
    const app = createApp(new InMemoryUserStore(), "test-secret");
    expect((await request(app).post("/register").send({ username: "ab", password: "short" })).status).toBe(400);
    await request(app).post("/register").send({ username: "test", password });
    expect((await request(app).post("/register").send({ username: "test", password })).status).toBe(409);
  });

  it("verifies only a valid bearer token and returns a minimal identity", async () => {
    const app = createApp(new InMemoryUserStore(), "test-secret");
    const token = await authenticatedToken(app);
    const verified = await request(app).get("/verify").set("Authorization", `Bearer ${token}`);
    expect(verified.status).toBe(200);
    expect(verified.body).toEqual({ valid: true, user: { username: "test" } });
    expect((await request(app).get("/verify").set("Authorization", "Bearer invalid")).status).toBe(401);
  });
});

describe("SkyIdentity integration contract", () => {
  it("returns a bounded linked identity context without claiming identity verification", async () => {
    const resolver: IdentityResolver = {
      resolve: (username) => ({
        subjectId: `sky:${username}`,
        profileId: `profile:${username}`,
        source: "skyidentity",
      }),
    };
    const app = createApp(new InMemoryUserStore(), "test-secret", resolver);
    const token = await authenticatedToken(app);
    const result = await request(app).get("/identity-context").set("Authorization", `Bearer ${token}`);

    expect(result.status).toBe(200);
    expect(result.body).toEqual({
      authenticated: true,
      user: { username: "test" },
      identityLinked: true,
      identityVerificationPerformed: false,
      identity: {
        subjectId: "sky:test",
        profileId: "profile:test",
        source: "skyidentity",
      },
    });
  });

  it("fails closed when no identity resolver is configured", async () => {
    const app = createApp(new InMemoryUserStore(), "test-secret");
    const token = await authenticatedToken(app);
    const result = await request(app).get("/identity-context").set("Authorization", `Bearer ${token}`);

    expect(result.status).toBe(503);
    expect(result.body.identityLinked).toBe(false);
    expect(result.body.identityVerificationPerformed).toBe(false);
  });

  it("rejects malformed resolver output instead of trusting it", async () => {
    const resolver: IdentityResolver = {
      resolve: () => ({ subjectId: "../bad", profileId: "ok-profile", source: "skyidentity" }),
    };
    const app = createApp(new InMemoryUserStore(), "test-secret", resolver);
    const token = await authenticatedToken(app);
    const result = await request(app).get("/identity-context").set("Authorization", `Bearer ${token}`);

    expect(result.status).toBe(502);
    expect(result.body.identityLinked).toBe(false);
    expect(result.body.identity).toBeUndefined();
  });

  it("reports a valid authenticated user with no mapping as unlinked", async () => {
    const resolver: IdentityResolver = { resolve: () => undefined };
    const app = createApp(new InMemoryUserStore(), "test-secret", resolver);
    const token = await authenticatedToken(app);
    const result = await request(app).get("/identity-context").set("Authorization", `Bearer ${token}`);

    expect(result.status).toBe(200);
    expect(result.body).toEqual({
      authenticated: true,
      user: { username: "test" },
      identityLinked: false,
      identityVerificationPerformed: false,
    });
  });
});

describe("JWT secret configuration", () => {
  const originalSecret = process.env.JWT_SECRET;
  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    if (originalSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = originalSecret;

    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
  });

  it("rejects an explicitly configured short JWT secret outside production", () => {
    process.env.NODE_ENV = "development";
    process.env.JWT_SECRET = "short";
    expect(() => configuredSecret()).toThrow(/at least 32 characters/);
  });

  it("uses the development fallback only when JWT_SECRET is absent", () => {
    process.env.NODE_ENV = "development";
    delete process.env.JWT_SECRET;
    expect(configuredSecret()).toBe("development-only-secret-change-me-32chars");
  });
});
