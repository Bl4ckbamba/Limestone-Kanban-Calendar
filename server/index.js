import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import argon2 from "argon2";
import express from "express";
import helmet from "helmet";
import http from "node:http";
import session from "express-session";
import { Server } from "socket.io";
import { config } from "./config.js";
import {
  db,
  serializeAction,
  serializeCalendarEvent,
  serializeCard,
  serializeNote,
  serializeProject,
  serializeUser
} from "./db.js";
import { SqliteSessionStore } from "./session-store.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const USERNAME_PATTERN = /^[a-z0-9._-]{3,40}$/;
const DEFAULT_PROJECT_COLOR = "#bef264";
const CALENDAR_GROUP_ID_PREFIX = "project-";
const CALENDAR_DURATION_UNITS = new Set(["minute", "hour", "day"]);
const CALENDAR_REPEAT_UNITS = new Set(["none", "day", "week", "year"]);
const CALENDAR_REPEAT_END_MODES = new Set(["never", "on", "after"]);
const CARD_UPDATE_ACTION_COALESCE_SECONDS = 5 * 60;
const LOGIN_BAN_ERROR = "Too many failed login attempts. Try again later.";
const TEMPORARY_ADMIN_PASSWORD = "admin";
const PASSWORD_CHANGE_REQUIRED_ERROR = "Password change required";
const PRE_LOGIN_CSRF_TOKEN_MAX_AGE_MS = 60 * 60 * 1000;
const devConnectSrc = ["'self'", "ws:", config.clientOrigin, `http://localhost:${config.port}`].filter(Boolean);

app.set("trust proxy", config.trustProxy);
app.disable("x-powered-by");

const sessionMiddleware = session({
  name: "limestone.sid",
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: new SqliteSessionStore(),
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: config.sessionCookieSecure,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(
  helmet({
    hsts: config.isProduction,
    contentSecurityPolicy: config.isProduction
      ? undefined
      : {
          directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "connect-src": devConnectSrc,
            "script-src": ["'self'", "'unsafe-inline'"]
          }
        }
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(sessionMiddleware);

io.engine.use(sessionMiddleware);

app.use(["/auth", "/api"], (req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

function getUserById(id) {
  return db
    .prepare(
      "SELECT id, username, is_admin, password_change_required, deleted_at, created_at FROM users WHERE id = ? AND deleted_at IS NULL"
    )
    .get(id);
}

function publicUser(user) {
  return user ? serializeUser(user) : null;
}

function authenticatedUser(req) {
  if (!req.session.userId) return null;

  const user = getUserById(req.session.userId);
  if (!user) {
    req.session.destroy(() => {});
    return null;
  }

  return user;
}

function requireAuth(req, res, next) {
  const user = authenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: "Authentication required" });
  }

  req.user = user;
  next();
}

function requireProtectedApp(req, res, next) {
  const user = authenticatedUser(req);
  if (user) {
    req.user = user;
    return next();
  }

  if (req.originalUrl === "/app" || req.originalUrl === "/app/" || req.originalUrl === "/app/index.html") {
    return res.redirect(302, "/login/");
  }

  return res.status(401).type("text/plain").send("Authentication required");
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

function requireCompletedSetup(req, res, next) {
  if (req.user?.password_change_required) {
    return res.status(403).json({ error: PASSWORD_CHANGE_REQUIRED_ERROR });
  }
  next();
}

function validateUsername(username) {
  return USERNAME_PATTERN.test(username);
}

function validatePassword(password) {
  return password.length >= 10;
}

function normalizeIp(ip) {
  return String(ip || "unknown").replace(/^::ffff:/, "");
}

function clientIp(req) {
  return normalizeIp(req.ip || req.socket?.remoteAddress);
}

function parseStoredTimestamp(value) {
  if (!value) return null;
  const normalizedValue = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
    ? `${value.replace(" ", "T")}Z`
    : value;
  const timestamp = Date.parse(normalizedValue);
  return Number.isNaN(timestamp) ? null : timestamp;
}

function ipLoginRecord(ip) {
  return db.prepare("SELECT * FROM login_ip_attempts WHERE ip = ?").get(ip);
}

function clearFailedLogins(ip) {
  db.prepare("DELETE FROM login_ip_attempts WHERE ip = ?").run(ip);
}

function activeIpBan(ip, now = new Date()) {
  const record = ipLoginRecord(ip);
  if (!record?.banned_until) return null;

  const bannedUntil = parseStoredTimestamp(record.banned_until);
  if (bannedUntil && bannedUntil > now.getTime()) {
    return { record, bannedUntil };
  }

  clearFailedLogins(ip);
  return null;
}

function sendLoginBanResponse(res, ban) {
  if (ban?.bannedUntil) {
    const retryAfterSeconds = Math.max(1, Math.ceil((ban.bannedUntil - Date.now()) / 1000));
    res.set("Retry-After", String(retryAfterSeconds));
  }

  return res.status(429).json({ error: LOGIN_BAN_ERROR });
}

function recordFailedLogin(ip) {
  const now = new Date();
  const nowMs = now.getTime();
  const nowIso = now.toISOString();
  const existing = ipLoginRecord(ip);
  const firstFailedAt = parseStoredTimestamp(existing?.first_failed_at || existing?.last_failed_at);
  const isExistingWindow = firstFailedAt && firstFailedAt <= nowMs && nowMs - firstFailedAt <= config.loginBanWindowMs;
  const failedAttempts = isExistingWindow ? Number(existing.failed_attempts || 0) + 1 : 1;
  const windowStartedAt = isExistingWindow ? existing.first_failed_at || existing.last_failed_at : nowIso;
  const isBanned = failedAttempts >= config.loginBanAttemptLimit;
  const bannedAt = isBanned ? nowIso : null;
  const bannedUntil = isBanned ? new Date(nowMs + config.loginBanDurationMs).toISOString() : null;

  db.prepare(
    `
    INSERT INTO login_ip_attempts (ip, failed_attempts, first_failed_at, banned_at, banned_until, last_failed_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      failed_attempts = excluded.failed_attempts,
      first_failed_at = excluded.first_failed_at,
      banned_at = excluded.banned_at,
      banned_until = excluded.banned_until,
      last_failed_at = excluded.last_failed_at
    `
  ).run(ip, failedAttempts, windowStartedAt, bannedAt, bannedUntil, nowIso);

  return ipLoginRecord(ip);
}

function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
  }
  return req.session.csrfToken;
}

function csrfTokenDigest(value) {
  return crypto.createHmac("sha256", config.sessionSecret).update(value).digest("base64url");
}

function createPreLoginCsrfToken(now = Date.now()) {
  const timestamp = String(now);
  const nonce = crypto.randomBytes(32).toString("base64url");
  const payload = `${timestamp}.${nonce}`;
  return `${payload}.${csrfTokenDigest(payload)}`;
}

function safeEqualText(left, right) {
  const leftBuffer = Buffer.from(String(left || ""));
  const rightBuffer = Buffer.from(String(right || ""));
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function isValidPreLoginCsrfToken(token, now = Date.now()) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return false;

  const [timestamp, nonce, digest] = parts;
  if (!/^\d+$/.test(timestamp) || !/^[A-Za-z0-9_-]{32,}$/.test(nonce)) return false;

  const createdAt = Number(timestamp);
  if (!Number.isSafeInteger(createdAt) || createdAt > now || now - createdAt > PRE_LOGIN_CSRF_TOKEN_MAX_AGE_MS) {
    return false;
  }

  return safeEqualText(csrfTokenDigest(`${timestamp}.${nonce}`), digest);
}

function validateCsrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const actual = String(req.get("x-csrf-token") || "");
  if (!req.session.userId && req.path === "/auth/login") {
    if (isValidPreLoginCsrfToken(actual)) return next();
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  if (!req.session.userId) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  if (!safeEqualText(ensureCsrfToken(req), actual)) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  next();
}

app.use(validateCsrf);

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function cleanText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseJsonObject(value, fallback = {}) {
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    return isPlainObject(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function mergeJsonPatch(base, patch) {
  if (!isPlainObject(patch)) return base;
  const source = isPlainObject(base) ? base : {};
  const merged = { ...source };

  for (const [key, value] of Object.entries(patch)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    if (isPlainObject(value) && isPlainObject(source[key])) {
      merged[key] = mergeJsonPatch(source[key], value);
    } else {
      merged[key] = value;
    }
  }

  return merged;
}

function userPreferences(userId) {
  const row = db.prepare("SELECT preferences_json FROM user_preferences WHERE user_id = ?").get(userId);
  return parseJsonObject(row?.preferences_json);
}

function saveUserPreferences(userId, preferences) {
  const preferencesJson = JSON.stringify(isPlainObject(preferences) ? preferences : {});
  if (Buffer.byteLength(preferencesJson, "utf8") > 100_000) {
    const error = new Error("Preferences payload is too large");
    error.status = 413;
    throw error;
  }

  db.prepare(
    `
    INSERT INTO user_preferences (user_id, preferences_json, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET
      preferences_json = excluded.preferences_json,
      updated_at = CURRENT_TIMESTAMP
    `
  ).run(userId, preferencesJson);

  return userPreferences(userId);
}

function cleanHexColor(value, fallback = DEFAULT_PROJECT_COLOR) {
  const rawValue = String(value || "").trim();
  const withHash = rawValue.startsWith("#") ? rawValue : `#${rawValue}`;
  const shortMatch = withHash.match(/^#([0-9a-f]{3})$/i);
  if (shortMatch) return `#${shortMatch[1].split("").map((char) => `${char}${char}`).join("")}`.toLowerCase();
  if (/^#[0-9a-f]{6}$/i.test(withHash)) return withHash.toLowerCase();
  return fallback;
}

function assertStatus(status) {
  if (!["planned", "ongoing", "finished"].includes(status)) {
    const error = new Error("Invalid card status");
    error.status = 400;
    throw error;
  }
}

function getProject(projectId) {
  return db.prepare("SELECT * FROM projects WHERE id = ?").get(projectId);
}

function getNote(noteId) {
  return db
    .prepare(
      `
      SELECT n.*, u.username AS creator_name
      FROM notes n
      LEFT JOIN users u ON u.id = n.created_by
      WHERE n.id = ?
      `
    )
    .get(noteId);
}

function getCard(cardId) {
  return db
    .prepare(
      `
      SELECT c.*, u.username AS creator_name
      FROM cards c
      LEFT JOIN users u ON u.id = c.created_by
      WHERE c.id = ?
      `
    )
    .get(cardId);
}

function listBoard(projectId) {
  const project = getProject(projectId);
  if (!project) return null;
  const cards = db
    .prepare(
      `
      SELECT c.*, u.username AS creator_name
      FROM cards c
      LEFT JOIN users u ON u.id = c.created_by
      WHERE c.project_id = ? AND c.flushed_at IS NULL
      ORDER BY c.status, c.position, c.id
      `
    )
    .all(projectId)
    .map(serializeCard);

  return {
    project: serializeProject(project),
    cards
  };
}

function listActions(projectId) {
  return db
    .prepare(
      `
      SELECT ca.*, u.username AS actor_name
      FROM card_actions ca
      JOIN users u ON u.id = ca.actor_id
      WHERE ca.project_id = ?
      ORDER BY ca.created_at DESC, ca.id DESC
      LIMIT 500
      `
    )
    .all(projectId)
    .map(serializeAction);
}

function projectCalendarGroupId(projectId) {
  return `${CALENDAR_GROUP_ID_PREFIX}${projectId}`;
}

function isValidDateKey(value) {
  const text = String(value || "");
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function normalizeOptionalDateKey(value, fallback, message) {
  if (value === undefined) return fallback;

  const dateKey = String(value ?? "").trim();
  if (!dateKey) return null;
  if (isValidDateKey(dateKey)) return dateKey;

  const error = new Error(message);
  error.status = 400;
  throw error;
}

function isValidTime(value) {
  const text = String(value || "");
  const match = text.match(/^(\d{2}):(\d{2})$/);
  if (!match) return false;

  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  return hours >= 0 && hours <= 23 && minutes >= 0 && minutes <= 59;
}

function cleanInteger(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.trunc(number), min), max);
}

function parseCalendarRepeatCount(value) {
  if (typeof value === "number") {
    return Number.isInteger(value) && value >= 1 && value <= 9999 ? value : null;
  }

  if (typeof value === "string") {
    const text = value.trim();
    if (!/^\d+$/.test(text)) return null;

    const number = Number(text);
    return number >= 1 && number <= 9999 ? number : null;
  }

  return null;
}

function assertCalendarChoice(value, allowedValues, message) {
  if (!allowedValues.has(value)) {
    const error = new Error(message);
    error.status = 400;
    throw error;
  }
}

function normalizeCalendarEventInput(body, projectId, existingEvent = null) {
  const groupId = cleanText(body.groupId ?? existingEvent?.group_id ?? projectCalendarGroupId(projectId), 80);
  if (groupId !== projectCalendarGroupId(projectId)) {
    const error = new Error("Calendar event group must match the selected project");
    error.status = 400;
    throw error;
  }

  const startDate = cleanText(body.startDate ?? existingEvent?.start_date, 10);
  if (!isValidDateKey(startDate)) {
    const error = new Error("Calendar event start date must be YYYY-MM-DD");
    error.status = 400;
    throw error;
  }

  const startTime = cleanText(body.startTime ?? existingEvent?.start_time, 5);
  if (!isValidTime(startTime)) {
    const error = new Error("Calendar event start time must be HH:MM");
    error.status = 400;
    throw error;
  }

  const durationUnit = cleanText(body.durationUnit ?? existingEvent?.duration_unit ?? "hour", 10);
  const repeatUnit = cleanText(body.repeatUnit ?? existingEvent?.repeat_unit ?? "none", 10);
  const repeatEndMode = cleanText(body.repeatEndMode ?? existingEvent?.repeat_end_mode ?? "never", 10);
  assertCalendarChoice(durationUnit, CALENDAR_DURATION_UNITS, "Invalid calendar event duration unit");
  assertCalendarChoice(repeatUnit, CALENDAR_REPEAT_UNITS, "Invalid calendar event repeat unit");
  assertCalendarChoice(repeatEndMode, CALENDAR_REPEAT_END_MODES, "Invalid calendar event repeat end mode");

  const repeatEndDate = String(body.repeatEndDate ?? existingEvent?.repeat_end_date ?? "").trim();
  if (repeatEndDate && !isValidDateKey(repeatEndDate)) {
    const error = new Error("Calendar event repeat end date must be YYYY-MM-DD");
    error.status = 400;
    throw error;
  }

  const repeatCountValue = body.repeatCount ?? existingEvent?.repeat_count;
  const parsedRepeatCount = parseCalendarRepeatCount(repeatCountValue);
  let normalizedRepeatEndMode = repeatEndMode;
  let normalizedRepeatEndDate = null;
  let normalizedRepeatCount = parsedRepeatCount ?? 1;

  if (repeatUnit === "none") {
    normalizedRepeatEndMode = "never";
  } else if (repeatEndMode === "on") {
    if (!repeatEndDate) {
      const error = new Error("Calendar event repeat end date is required when repeat end mode is on");
      error.status = 400;
      throw error;
    }
    normalizedRepeatEndDate = repeatEndDate;
  } else if (repeatEndMode === "after") {
    if (parsedRepeatCount === null) {
      const error = new Error("Calendar event repeat count must be an integer between 1 and 9999");
      error.status = 400;
      throw error;
    }
    normalizedRepeatCount = parsedRepeatCount;
  }

  return {
    groupId,
    name: cleanText(body.name ?? existingEvent?.name ?? "", 96),
    color: cleanHexColor(body.color ?? existingEvent?.color ?? DEFAULT_PROJECT_COLOR),
    hidden: body.hidden === undefined ? Boolean(existingEvent?.hidden) : Boolean(body.hidden),
    startDate,
    startTime,
    durationAmount: cleanInteger(body.durationAmount ?? existingEvent?.duration_amount, 1, 1, 525600),
    durationUnit,
    repeatAmount: cleanInteger(body.repeatAmount ?? existingEvent?.repeat_amount, 1, 1, 999),
    repeatUnit,
    repeatEndMode: normalizedRepeatEndMode,
    repeatEndDate: normalizedRepeatEndDate,
    repeatCount: normalizedRepeatCount
  };
}

function getCalendarEvent(projectId, eventId) {
  return db
    .prepare(
      `
      SELECT *
      FROM calendar_events
      WHERE project_id = ? AND id = ?
      `
    )
    .get(projectId, eventId);
}

function listCalendarEvents(projectId) {
  return db
    .prepare(
      `
      SELECT *
      FROM calendar_events
      WHERE project_id = ?
      ORDER BY start_date ASC, start_time ASC, created_at DESC, id ASC
      `
    )
    .all(projectId)
    .map(serializeCalendarEvent);
}

function listAllCalendarEvents() {
  return db
    .prepare(
      `
      SELECT *
      FROM calendar_events
      ORDER BY project_id ASC, start_date ASC, start_time ASC, created_at DESC, id ASC
      `
    )
    .all()
    .map(serializeCalendarEvent);
}

function listAllActions() {
  return db
    .prepare(
      `
      SELECT ca.*, u.username AS actor_name
      FROM card_actions ca
      JOIN users u ON u.id = ca.actor_id
      ORDER BY ca.created_at DESC, ca.id DESC
      LIMIT 500
      `
    )
    .all()
    .map(serializeAction);
}

function logAction({ projectId, cardId, action, actorId, cardTitle, fromStatus, toStatus, metadata = {} }) {
  db.prepare(
    `
    INSERT INTO card_actions
      (project_id, card_id, action, actor_id, card_title, from_status, to_status, metadata_json)
    VALUES
      (@projectId, @cardId, @action, @actorId, @cardTitle, @fromStatus, @toStatus, @metadataJson)
    `
  ).run({
    projectId,
    cardId,
    action,
    actorId,
    cardTitle,
    fromStatus: fromStatus || null,
    toStatus: toStatus || null,
    metadataJson: JSON.stringify(metadata)
  });
}

function parseActionMetadata(action) {
  try {
    const metadata = JSON.parse(action?.metadata_json || "{}");
    return metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {};
  } catch {
    return {};
  }
}

function metadataHas(metadata, key) {
  return Object.prototype.hasOwnProperty.call(metadata, key);
}

function changedCardContentFields(previousCard, nextCard) {
  return [
    previousCard.title !== nextCard.title ? "title" : null,
    previousCard.description !== nextCard.description ? "description" : null,
    previousCard.event_date !== nextCard.event_date ? "eventDate" : null
  ].filter(Boolean);
}

function logCardUpdateAction({ previousCard, nextCard, actorId }) {
  const changedFields = changedCardContentFields(previousCard, nextCard);
  if (!changedFields.length) return;

  const lastAction = db
    .prepare(
      `
      SELECT ca.*, ca.created_at >= datetime('now', ?) AS is_recent
      FROM card_actions ca
      WHERE ca.project_id = ? AND ca.card_id = ?
      ORDER BY ca.created_at DESC, ca.id DESC
      LIMIT 1
      `
    )
    .get(`-${CARD_UPDATE_ACTION_COALESCE_SECONDS} seconds`, previousCard.project_id, previousCard.id);

  if (lastAction?.action === "updated" && lastAction.actor_id === actorId && Number(lastAction.is_recent)) {
    const metadata = parseActionMetadata(lastAction);
    const existingFields = Array.isArray(metadata.changedFields) ? metadata.changedFields : [];
    const updateCount = Number.isFinite(Number(metadata.updateCount)) ? Number(metadata.updateCount) : 1;
    const nextMetadata = {
      ...metadata,
      previousTitle: metadataHas(metadata, "previousTitle") ? metadata.previousTitle : previousCard.title,
      previousDescription: metadataHas(metadata, "previousDescription")
        ? metadata.previousDescription
        : previousCard.description,
      previousEventDate: metadataHas(metadata, "previousEventDate")
        ? metadata.previousEventDate
        : previousCard.event_date,
      changedFields: [...new Set([...existingFields, ...changedFields])],
      updateCount: updateCount + 1,
      coalesced: true
    };

    db.prepare(
      `
      UPDATE card_actions
      SET card_title = ?,
          from_status = ?,
          to_status = ?,
          metadata_json = ?,
          created_at = CURRENT_TIMESTAMP
      WHERE id = ?
      `
    ).run(nextCard.title, previousCard.status, nextCard.status, JSON.stringify(nextMetadata), lastAction.id);
    return;
  }

  logAction({
    projectId: previousCard.project_id,
    cardId: previousCard.id,
    action: "updated",
    actorId,
    cardTitle: nextCard.title,
    fromStatus: previousCard.status,
    toStatus: nextCard.status,
    metadata: {
      previousTitle: previousCard.title,
      previousDescription: previousCard.description,
      previousEventDate: previousCard.event_date,
      changedFields,
      updateCount: 1
    }
  });
}

function renumberStatus(projectId, status) {
  const cards = db
    .prepare(
      "SELECT id FROM cards WHERE project_id = ? AND status = ? AND flushed_at IS NULL ORDER BY position, id"
    )
    .all(projectId, status);
  const update = db.prepare("UPDATE cards SET position = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
  cards.forEach((card, index) => update.run(index, card.id));
}

function emitProjectChanged(projectId) {
  io.to(`project:${projectId}`).emit("board:changed", { projectId });
  io.to(`project:${projectId}`).emit("calendar:changed", { projectId });
}

app.get("/auth/csrf", (req, res) => {
  res.json({ csrfToken: req.session.userId ? ensureCsrfToken(req) : createPreLoginCsrfToken() });
});

app.get("/auth/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  res.json({ user: publicUser(getUserById(req.session.userId)) });
});

app.post(
  "/auth/login",
  asyncRoute(async (req, res, next) => {
    const ip = clientIp(req);
    const currentBan = activeIpBan(ip);
    if (currentBan) {
      return sendLoginBanResponse(res, currentBan);
    }

    const username = cleanText(req.body.username, 40).toLowerCase();
    const password = String(req.body.password || "");
    const user = db.prepare("SELECT * FROM users WHERE username = ? AND deleted_at IS NULL").get(username);

    if (!user || !(await argon2.verify(user.password_hash, password))) {
      recordFailedLogin(ip);
      const newBan = activeIpBan(ip);
      if (newBan) {
        return sendLoginBanResponse(res, newBan);
      }
      return res.status(401).json({ error: "Invalid username or password" });
    }

    req.session.regenerate((error) => {
      if (error) return next(error);
      clearFailedLogins(ip);
      req.session.userId = user.id;
      ensureCsrfToken(req);
      res.json({ user: publicUser(user) });
    });
  })
);

app.post("/auth/logout", requireAuth, (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ error: "Could not log out" });
    res.clearCookie("limestone.sid");
    res.status(204).end();
  });
});

app.get("/api/users", requireAuth, requireAdmin, (req, res) => {
  if (req.user.password_change_required) {
    return res.status(403).json({ error: PASSWORD_CHANGE_REQUIRED_ERROR });
  }

  const users = db
    .prepare(
      "SELECT id, username, is_admin, password_change_required, deleted_at, created_at FROM users WHERE deleted_at IS NULL ORDER BY is_admin DESC, username ASC"
    )
    .all();
  const safeUsers = users.filter(Boolean).map(serializeUser);
  res.json({ users: safeUsers });
});

app.patch(
  "/api/profile",
  requireAuth,
  asyncRoute(async (req, res) => {
    const username = cleanText(req.body.username ?? req.user.username, 40).toLowerCase();
    const password = String(req.body.password || "");

    if (!validateUsername(username)) {
      return res.status(400).json({ error: "Username must be 3-40 letters, numbers, dots, dashes, or underscores" });
    }
    if (password && !validatePassword(password)) {
      return res.status(400).json({ error: "Password must be at least 10 characters" });
    }
    if (req.user.password_change_required && !password) {
      return res.status(400).json({ error: PASSWORD_CHANGE_REQUIRED_ERROR });
    }

    try {
      if (password) {
        const passwordHash = await argon2.hash(password);
        db.prepare("UPDATE users SET username = ?, password_hash = ?, password_change_required = 0 WHERE id = ?").run(
          username,
          passwordHash,
          req.user.id
        );
      } else {
        db.prepare("UPDATE users SET username = ? WHERE id = ?").run(username, req.user.id);
      }
      res.json({ user: serializeUser(getUserById(req.user.id)) });
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        return res.status(409).json({ error: "Username is already taken" });
      }
      throw error;
    }
  })
);

app.get("/api/preferences", requireAuth, (req, res) => {
  res.json({ preferences: userPreferences(req.user.id) });
});

app.patch("/api/preferences", requireAuth, (req, res) => {
  const patch = req.body?.preferences;
  if (!isPlainObject(patch)) {
    return res.status(400).json({ error: "Preferences must be an object" });
  }

  const nextPreferences = mergeJsonPatch(userPreferences(req.user.id), patch);
  res.json({ preferences: saveUserPreferences(req.user.id, nextPreferences) });
});

app.use("/api", requireAuth, requireCompletedSetup);

app.post(
  "/api/users",
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const username = cleanText(req.body.username, 40).toLowerCase();
    const password = String(req.body.password || "");

    if (!validateUsername(username)) {
      return res.status(400).json({ error: "Username must be 3-40 letters, numbers, dots, dashes, or underscores" });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({ error: "Password must be at least 10 characters" });
    }

    const passwordHash = await argon2.hash(password);
    try {
      const result = db
        .prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)")
        .run(username, passwordHash);
      res.status(201).json({ user: serializeUser(getUserById(result.lastInsertRowid)) });
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        return res.status(409).json({ error: "Username is already taken" });
      }
      throw error;
    }
  })
);

app.patch(
  "/api/users/:userId",
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const targetUserId = Number(req.params.userId);
    const targetUser = getUserById(targetUserId);
    if (!targetUser) return res.status(404).json({ error: "Account not found" });

    const username = cleanText(req.body.username ?? targetUser.username, 40).toLowerCase();
    const password = String(req.body.password || "");

    if (!validateUsername(username)) {
      return res.status(400).json({ error: "Username must be 3-40 letters, numbers, dots, dashes, or underscores" });
    }
    if (password && !validatePassword(password)) {
      return res.status(400).json({ error: "Password must be at least 10 characters" });
    }

    try {
      if (password) {
        const passwordHash = await argon2.hash(password);
        db.prepare("UPDATE users SET username = ?, password_hash = ?, password_change_required = 0 WHERE id = ?").run(
          username,
          passwordHash,
          targetUserId
        );
      } else {
        db.prepare("UPDATE users SET username = ? WHERE id = ?").run(username, targetUserId);
      }
      res.json({ user: serializeUser(getUserById(targetUserId)) });
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        return res.status(409).json({ error: "Username is already taken" });
      }
      throw error;
    }
  })
);

app.delete("/api/users/:userId", requireAuth, requireAdmin, (req, res) => {
  const targetUserId = Number(req.params.userId);
  const targetUser = getUserById(targetUserId);
  if (!targetUser) return res.status(404).json({ error: "Account not found" });
  if (String(targetUserId) === String(req.user.id)) {
    return res.status(400).json({ error: "You cannot delete your own account" });
  }

  if (targetUser.is_admin) {
    const activeAdminCount = db
      .prepare("SELECT COUNT(*) AS total FROM users WHERE is_admin = 1 AND deleted_at IS NULL")
      .get().total;
    if (activeAdminCount <= 1) {
      return res.status(400).json({ error: "Cannot delete the last admin account" });
    }
  }

  db.prepare("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL").run(targetUserId);
  res.status(204).end();
});

app.get("/api/projects", requireAuth, (req, res) => {
  const projects = db
    .prepare(`
      SELECT
        p.*,
        SUM(CASE WHEN c.flushed_at IS NULL THEN 1 ELSE 0 END) AS total_cards,
        SUM(CASE WHEN c.status = 'finished' AND c.flushed_at IS NULL THEN 1 ELSE 0 END) AS completed_cards,
        SUM(CASE WHEN c.status = 'ongoing' AND c.flushed_at IS NULL THEN 1 ELSE 0 END) AS ongoing_cards
      FROM projects p
      LEFT JOIN cards c ON c.project_id = p.id
      GROUP BY p.id
      ORDER BY p.updated_at DESC, p.id DESC
    `)
    .all()
    .map(serializeProject);
  res.json({ projects });
});

app.post("/api/projects", requireAuth, (req, res) => {
  const name = cleanText(req.body.name, 80);
  if (!name) return res.status(400).json({ error: "Project name is required" });
  const color = cleanHexColor(req.body.color);

  const result = db
    .prepare("INSERT INTO projects (name, color, created_by) VALUES (?, ?, ?)")
    .run(name, color, req.user.id);
  res.status(201).json({ project: serializeProject(getProject(result.lastInsertRowid)) });
});

app.patch("/api/projects/:projectId", requireAuth, (req, res) => {
  const project = getProject(Number(req.params.projectId));
  if (!project) return res.status(404).json({ error: "Project not found" });

  const name = cleanText(req.body.name ?? project.name, 80);
  if (!name) return res.status(400).json({ error: "Project name is required" });
  const color = cleanHexColor(req.body.color ?? project.color);

  db.prepare(
    `
    UPDATE projects
    SET name = ?, color = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  ).run(name, color, project.id);

  emitProjectChanged(project.id);
  res.json({ project: serializeProject(getProject(project.id)) });
});

app.delete("/api/projects/:projectId", requireAuth, (req, res) => {
  const project = getProject(Number(req.params.projectId));
  if (!project) return res.status(404).json({ error: "Project not found" });

  db.prepare("DELETE FROM projects WHERE id = ?").run(project.id);
  emitProjectChanged(project.id);
  res.status(204).end();
});

app.get("/api/notes", requireAuth, (req, res) => {
  const notes = db
    .prepare(
      `
      SELECT n.*, u.username AS creator_name
      FROM notes n
      LEFT JOIN users u ON u.id = n.created_by
      ORDER BY n.updated_at DESC, n.id DESC
      `
    )
    .all()
    .map(serializeNote);
  res.json({ notes });
});

app.post("/api/notes", requireAuth, (req, res) => {
  const name = cleanText(req.body.name, 120);
  if (!name) return res.status(400).json({ error: "Note name is required" });

  const result = db
    .prepare("INSERT INTO notes (name, content, created_by) VALUES (?, '', ?)")
    .run(name, req.user.id);
  res.status(201).json({ note: serializeNote(getNote(result.lastInsertRowid)) });
});

app.get("/api/notes/:noteId", requireAuth, (req, res) => {
  const note = getNote(Number(req.params.noteId));
  if (!note) return res.status(404).json({ error: "Note not found" });
  res.json({ note: serializeNote(note) });
});

app.patch("/api/notes/:noteId", requireAuth, (req, res) => {
  const note = getNote(Number(req.params.noteId));
  if (!note) return res.status(404).json({ error: "Note not found" });

  const name = cleanText(req.body.name ?? note.name, 120);
  const content = String(req.body.content ?? note.content ?? "").slice(0, 500000);
  if (!name) return res.status(400).json({ error: "Note name is required" });

  db.prepare(
    `
    UPDATE notes
    SET name = ?, content = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `
  ).run(name, content, note.id);

  res.json({ note: serializeNote(getNote(note.id)) });
});

app.delete("/api/notes/:noteId", requireAuth, (req, res) => {
  const note = getNote(Number(req.params.noteId));
  if (!note) return res.status(404).json({ error: "Note not found" });

  db.prepare("DELETE FROM notes WHERE id = ?").run(note.id);
  res.status(204).end();
});

app.get("/api/projects/:projectId/board", requireAuth, (req, res) => {
  const board = listBoard(Number(req.params.projectId));
  if (!board) return res.status(404).json({ error: "Project not found" });
  res.json(board);
});

app.get("/api/calendar", requireAuth, (req, res) => {
  res.json({
    actions: listAllActions(),
    events: listAllCalendarEvents()
  });
});

app.get("/api/projects/:projectId/calendar", requireAuth, (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!getProject(projectId)) return res.status(404).json({ error: "Project not found" });
  res.json({
    actions: listActions(projectId),
    events: listCalendarEvents(projectId)
  });
});

app.post("/api/projects/:projectId/calendar/events", requireAuth, (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!getProject(projectId)) return res.status(404).json({ error: "Project not found" });

  const eventId = crypto.randomUUID();
  const event = normalizeCalendarEventInput(req.body, projectId);

  db.prepare(
    `
    INSERT INTO calendar_events (
      id,
      project_id,
      group_id,
      name,
      color,
      hidden,
      start_date,
      start_time,
      duration_amount,
      duration_unit,
      repeat_amount,
      repeat_unit,
      repeat_end_mode,
      repeat_end_date,
      repeat_count,
      created_by
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  ).run(
    eventId,
    projectId,
    event.groupId,
    event.name,
    event.color,
    event.hidden ? 1 : 0,
    event.startDate,
    event.startTime,
    event.durationAmount,
    event.durationUnit,
    event.repeatAmount,
    event.repeatUnit,
    event.repeatEndMode,
    event.repeatEndDate,
    event.repeatCount,
    req.user.id
  );

  db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(projectId);
  emitProjectChanged(projectId);
  res.status(201).json({ event: serializeCalendarEvent(getCalendarEvent(projectId, eventId)) });
});

app.patch("/api/projects/:projectId/calendar/events/:eventId", requireAuth, (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!getProject(projectId)) return res.status(404).json({ error: "Project not found" });

  const existingEvent = getCalendarEvent(projectId, String(req.params.eventId || ""));
  if (!existingEvent) return res.status(404).json({ error: "Calendar event not found" });

  const event = normalizeCalendarEventInput(req.body, projectId, existingEvent);
  db.prepare(
    `
    UPDATE calendar_events
    SET group_id = ?,
        name = ?,
        color = ?,
        hidden = ?,
        start_date = ?,
        start_time = ?,
        duration_amount = ?,
        duration_unit = ?,
        repeat_amount = ?,
        repeat_unit = ?,
        repeat_end_mode = ?,
        repeat_end_date = ?,
        repeat_count = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE project_id = ? AND id = ?
    `
  ).run(
    event.groupId,
    event.name,
    event.color,
    event.hidden ? 1 : 0,
    event.startDate,
    event.startTime,
    event.durationAmount,
    event.durationUnit,
    event.repeatAmount,
    event.repeatUnit,
    event.repeatEndMode,
    event.repeatEndDate,
    event.repeatCount,
    projectId,
    existingEvent.id
  );

  db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(projectId);
  emitProjectChanged(projectId);
  res.json({ event: serializeCalendarEvent(getCalendarEvent(projectId, existingEvent.id)) });
});

app.delete("/api/projects/:projectId/calendar/events/:eventId", requireAuth, (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!getProject(projectId)) return res.status(404).json({ error: "Project not found" });

  const existingEvent = getCalendarEvent(projectId, String(req.params.eventId || ""));
  if (!existingEvent) return res.status(404).json({ error: "Calendar event not found" });

  db.prepare("DELETE FROM calendar_events WHERE project_id = ? AND id = ?").run(projectId, existingEvent.id);
  db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(projectId);
  emitProjectChanged(projectId);
  res.status(204).end();
});

app.post("/api/projects/:projectId/cards", requireAuth, (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!getProject(projectId)) return res.status(404).json({ error: "Project not found" });

  const title = cleanText(req.body.title, 120);
  const description = cleanText(req.body.description, 2000);
  const eventDate = normalizeOptionalDateKey(req.body.eventDate, null, "Card event date must be YYYY-MM-DD");
  const status = req.body.status || "planned";
  assertStatus(status);
  if (!title) return res.status(400).json({ error: "Card title is required" });

  const createCard = db.transaction(() => {
    const maxPosition =
      db
        .prepare(
          "SELECT COALESCE(MAX(position), -1) AS max_position FROM cards WHERE project_id = ? AND status = ? AND flushed_at IS NULL"
        )
        .get(projectId, status).max_position + 1;
    const result = db
      .prepare(
        `
        INSERT INTO cards (project_id, title, description, status, position, event_date, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `
      )
      .run(projectId, title, description, status, maxPosition, eventDate, req.user.id);
    const card = getCard(result.lastInsertRowid);
    logAction({
      projectId,
      cardId: card.id,
      action: "created",
      actorId: req.user.id,
      cardTitle: card.title,
      toStatus: card.status
    });
    db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(projectId);
    return card;
  });

  const card = createCard();
  emitProjectChanged(projectId);
  res.status(201).json({ card: serializeCard(card) });
});

app.post("/api/projects/:projectId/flush-finished", requireAuth, (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!getProject(projectId)) return res.status(404).json({ error: "Project not found" });

  const flushFinishedCards = db.transaction(() => {
    const finishedCards = db
      .prepare(
        `
        SELECT * FROM cards
        WHERE project_id = ? AND status = 'finished' AND flushed_at IS NULL
        ORDER BY position, id
        `
      )
      .all(projectId);

    const flush = db.prepare("UPDATE cards SET flushed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
    finishedCards.forEach((card) => {
      flush.run(card.id);
      logAction({
        projectId,
        cardId: card.id,
        action: "flushed",
        actorId: req.user.id,
        cardTitle: card.title,
        fromStatus: "finished",
        toStatus: "finished",
        metadata: { flushed: true }
      });
    });

    renumberStatus(projectId, "finished");
    db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(projectId);
    return finishedCards.length;
  });

  const flushedCount = flushFinishedCards();
  emitProjectChanged(projectId);
  res.json({ flushedCount });
});

app.patch("/api/cards/:cardId", requireAuth, (req, res) => {
  const card = getCard(Number(req.params.cardId));
  if (!card || card.flushed_at) return res.status(404).json({ error: "Card not found" });

  const title = cleanText(req.body.title ?? card.title, 120);
  const description = cleanText(req.body.description ?? card.description, 2000);
  const eventDate = normalizeOptionalDateKey(req.body.eventDate, card.event_date, "Card event date must be YYYY-MM-DD");
  if (!title) return res.status(400).json({ error: "Card title is required" });

  const updateCard = db.transaction(() => {
    if (card.title === title && card.description === description && card.event_date === eventDate) {
      return { card, changed: false };
    }

    db.prepare(
      `
      UPDATE cards
      SET title = ?, description = ?, event_date = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
      `
    ).run(title, description, eventDate, card.id);
    const nextCard = getCard(card.id);
    logCardUpdateAction({ previousCard: card, nextCard, actorId: req.user.id });
    db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(card.project_id);
    return { card: nextCard, changed: true };
  });

  const result = updateCard();
  if (result.changed) emitProjectChanged(card.project_id);
  res.json({ card: serializeCard(result.card) });
});

app.post("/api/cards/:cardId/move", requireAuth, (req, res) => {
  const card = getCard(Number(req.params.cardId));
  if (!card || card.flushed_at) return res.status(404).json({ error: "Card not found" });

  const status = req.body.status || card.status;
  assertStatus(status);
  const requestedPosition = Number.isFinite(Number(req.body.position)) ? Number(req.body.position) : 0;

  const moveCard = db.transaction(() => {
    const targetCards = db
      .prepare(
        `
        SELECT id FROM cards
        WHERE project_id = ? AND status = ? AND flushed_at IS NULL AND id != ?
        ORDER BY position, id
        `
      )
      .all(card.project_id, status, card.id);
    const insertAt = Math.max(0, Math.min(requestedPosition, targetCards.length));
    targetCards.splice(insertAt, 0, { id: card.id });

    db.prepare(
      "UPDATE cards SET status = ?, position = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(status, insertAt, card.id);

    const updatePosition = db.prepare(
      "UPDATE cards SET position = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    );
    targetCards.forEach((targetCard, index) => updatePosition.run(index, targetCard.id));
    if (card.status !== status) renumberStatus(card.project_id, card.status);

    const nextCard = getCard(card.id);
    logAction({
      projectId: card.project_id,
      cardId: card.id,
      action: "moved",
      actorId: req.user.id,
      cardTitle: card.title,
      fromStatus: card.status,
      toStatus: status,
      metadata: { fromPosition: card.position, toPosition: nextCard.position }
    });
    db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(card.project_id);
    return nextCard;
  });

  const nextCard = moveCard();
  emitProjectChanged(card.project_id);
  res.json({ card: serializeCard(nextCard) });
});

app.post("/api/cards/:cardId/flush", requireAuth, (req, res) => {
  const card = getCard(Number(req.params.cardId));
  if (!card || card.flushed_at) return res.status(404).json({ error: "Card not found" });
  if (card.status !== "finished") return res.status(400).json({ error: "Only finished cards can be flushed" });

  const flushCard = db.transaction(() => {
    db.prepare("UPDATE cards SET flushed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(card.id);
    renumberStatus(card.project_id, "finished");
    logAction({
      projectId: card.project_id,
      cardId: card.id,
      action: "flushed",
      actorId: req.user.id,
      cardTitle: card.title,
      fromStatus: "finished",
      toStatus: "finished",
      metadata: { flushed: true }
    });
    db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(card.project_id);
    return getCard(card.id);
  });

  const nextCard = flushCard();
  emitProjectChanged(card.project_id);
  res.json({ card: serializeCard(nextCard) });
});

app.delete("/api/cards/:cardId", requireAuth, (req, res) => {
  const card = getCard(Number(req.params.cardId));
  if (!card || card.flushed_at) return res.status(404).json({ error: "Card not found" });

  db.transaction(() => {
    db.prepare("UPDATE cards SET flushed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(card.id);
    db.prepare("DELETE FROM card_actions WHERE card_id = ?").run(card.id);
    renumberStatus(card.project_id, card.status);
    db.prepare("UPDATE projects SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(card.project_id);
  })();

  emitProjectChanged(card.project_id);
  res.status(204).end();
});

io.use((socket, next) => {
  const user = socket.request.session?.userId ? getUserById(socket.request.session.userId) : null;
  if (!user) {
    return next(new Error("Authentication required"));
  }
  if (user.password_change_required) {
    return next(new Error(PASSWORD_CHANGE_REQUIRED_ERROR));
  }
  next();
});

io.on("connection", (socket) => {
  socket.on("project:join", (projectId) => {
    const project = getProject(Number(projectId));
    if (project) socket.join(`project:${project.id}`);
  });

  socket.on("project:leave", (projectId) => {
    socket.leave(`project:${Number(projectId)}`);
  });
});

if (config.isProduction || process.env.SERVE_DIST === "1") {
  const distPath = path.resolve(__dirname, "..", "dist");
  const appDistPath = path.join(distPath, "app");
  const publicFiles = ["app-icon.svg", "favicon.svg", "limestone-logo.svg"];

  app.get(["/", "/index.html"], (req, res) => res.redirect(302, "/login/"));
  app.use("/assets", express.static(path.join(distPath, "assets")));
  app.use("/login/assets", express.static(path.join(distPath, "login", "assets")));
  app.get(["/login", "/login/", "/login/index.html"], (req, res) => res.sendFile(path.join(distPath, "login", "index.html")));

  for (const fileName of publicFiles) {
    app.get(`/${fileName}`, (req, res) => res.sendFile(path.join(distPath, fileName)));
  }

  app.use("/app/assets", requireProtectedApp, express.static(path.join(appDistPath, "assets")));
  app.use("/app/assets", requireProtectedApp, (req, res) => res.status(404).type("text/plain").send("Not found"));
  app.use("/app", requireProtectedApp, express.static(appDistPath, { index: false }));
  app.get(/^\/app(?:\/.*)?$/, requireProtectedApp, (req, res) => {
    res.sendFile(path.join(appDistPath, "index.html"));
  });
}

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  console.error(error);
  const status = Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : 500;
  const isExpectedClientError = status >= 400 && status < 500;
  const message =
    isExpectedClientError || !config.isProduction ? error.message || "Internal server error" : "Internal server error";
  res.status(status).json({ error: message });
});

async function ensureAdminAccount() {
  const adminCount = db.prepare("SELECT COUNT(*) AS total FROM users WHERE is_admin = 1 AND deleted_at IS NULL").get().total;
  if (adminCount > 0) return;

  const username = cleanText(config.adminUsername, 40).toLowerCase();
  const password = String(config.adminPassword || "");

  if (!validateUsername(username)) {
    throw new Error("ADMIN_USERNAME must be 3-40 letters, numbers, dots, dashes, or underscores");
  }
  const isTemporaryAdminPassword = password === TEMPORARY_ADMIN_PASSWORD;

  if (config.isProduction && !password) {
    throw new Error("ADMIN_PASSWORD must be set before creating the first production admin");
  }

  if (config.isProduction && isTemporaryAdminPassword) {
    throw new Error("ADMIN_PASSWORD must be set to a non-default value before creating the first production admin");
  }

  if (!isTemporaryAdminPassword && !validatePassword(password)) {
    throw new Error("ADMIN_PASSWORD must be at least 10 characters");
  }

  const passwordHash = await argon2.hash(password);
  const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(username);

  if (existing) {
    db.prepare("UPDATE users SET password_hash = ?, is_admin = 1, password_change_required = ?, deleted_at = NULL WHERE id = ?").run(
      passwordHash,
      isTemporaryAdminPassword ? 1 : 0,
      existing.id
    );
  } else {
    db.prepare(
      "INSERT INTO users (username, password_hash, is_admin, password_change_required) VALUES (?, ?, 1, ?)"
    ).run(username, passwordHash, isTemporaryAdminPassword ? 1 : 0);
  }

  console.log(`Created admin account "${username}".`);
}

ensureAdminAccount()
  .then(() => {
    server.listen(config.port, () => {
      console.log(`Limestone server listening on http://localhost:${config.port}`);
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
