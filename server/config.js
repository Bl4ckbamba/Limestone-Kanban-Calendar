import path from "node:path";
import process from "node:process";

const isProduction = process.env.NODE_ENV === "production";
const DEFAULT_LOGIN_BAN_ATTEMPT_LIMIT = 15;
const DEFAULT_LOGIN_BAN_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_LOGIN_BAN_DURATION_MS = 15 * 60 * 1000;

function readIntegerEnv(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const rawValue = process.env[name];
  if (rawValue === undefined || rawValue === "") return fallback;

  const value = Number(rawValue);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }

  return value;
}

function parseTrustProxy(value) {
  if (value === undefined || value.trim() === "") return false;

  const trimmedValue = value.trim();
  const normalizedValue = trimmedValue.toLowerCase();

  if (/^\d+$/.test(trimmedValue)) {
    return Number(trimmedValue);
  }
  if (normalizedValue === "true") return true;
  if (normalizedValue === "false") return false;

  const entries = trimmedValue
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (!entries.length) return false;
  return entries.length === 1 ? entries[0] : entries;
}

function parseSessionCookieSecure(value) {
  if (value === undefined || value.trim() === "") return isProduction ? "auto" : false;

  const normalizedValue = value.trim().toLowerCase();
  if (normalizedValue === "auto") return "auto";
  if (normalizedValue === "true") return true;
  if (normalizedValue === "false") return false;

  throw new Error("SESSION_COOKIE_SECURE must be auto, true, or false");
}

export const config = {
  isProduction,
  port: readIntegerEnv("PORT", 3000, { min: 1, max: 65535 }),
  databasePath: process.env.DATABASE_PATH || path.resolve("data", "limestone.sqlite"),
  sessionSecret: process.env.SESSION_SECRET || (isProduction ? "" : "dev-session-secret-change-me"),
  sessionCookieSecure: parseSessionCookieSecure(process.env.SESSION_COOKIE_SECURE),
  adminUsername: process.env.ADMIN_USERNAME || "admin",
  adminPassword: process.env.ADMIN_PASSWORD || (isProduction ? "" : "admin"),
  clientOrigin: process.env.CLIENT_ORIGIN || (isProduction ? undefined : "http://localhost:3000"),
  trustProxy: parseTrustProxy(process.env.TRUST_PROXY),
  loginBanAttemptLimit: readIntegerEnv("LOGIN_BAN_ATTEMPT_LIMIT", DEFAULT_LOGIN_BAN_ATTEMPT_LIMIT, { min: 1 }),
  loginBanWindowMs: readIntegerEnv("LOGIN_BAN_WINDOW_MS", DEFAULT_LOGIN_BAN_WINDOW_MS, { min: 1000 }),
  loginBanDurationMs: readIntegerEnv("LOGIN_BAN_DURATION_MS", DEFAULT_LOGIN_BAN_DURATION_MS, { min: 1000 })
};

if (isProduction && !config.sessionSecret) {
  throw new Error("SESSION_SECRET is required in production");
}
