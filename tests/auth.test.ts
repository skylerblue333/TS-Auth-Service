import request from "supertest";
import { configuredSecret, createApp, InMemoryUserStore } from "../src/index";

const password = "correct-horse-battery-staple";

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
    await request(app).post("/register").send({ username: "test", password });
    const { body } = await request(app).post("/login").send({ username: "test", password });
    const verified = await request(app).get("/verify").set("Authorization", `Bearer ${body.token}`);
    expect(verified.status).toBe(200);
    expect(verified.body).toEqual({ valid: true, user: { username: "test" } });
    expect((await request(app).get("/verify").set("Authorization", "Bearer invalid")).status).toBe(401);
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
