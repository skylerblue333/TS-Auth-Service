import jwt from "jsonwebtoken";

const secret = process.env.JWT_SECRET;
if (!secret) throw new Error("JWT_SECRET must be configured");

export function issueToken(subject: string, claims: Record<string, unknown> = {}) {
  return jwt.sign({ ...claims }, secret, { subject, expiresIn: "1h" });
}

export function verifyToken(token: string) {
  return jwt.verify(token, secret);
}
