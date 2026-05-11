import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { config } from "./config.js";

fs.mkdirSync(path.dirname(config.databasePath), { recursive: true });

export const db = new Database(config.databasePath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    password_change_required INTEGER NOT NULL DEFAULT 0,
    deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_ip_attempts (
    ip TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    first_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    banned_at TEXT,
    banned_until TEXT,
    last_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_preferences (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    preferences_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    color TEXT,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('planned', 'ongoing', 'finished')),
    position INTEGER NOT NULL DEFAULT 0,
    event_date TEXT,
    flushed_at TEXT,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS card_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    card_id INTEGER REFERENCES cards(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (action IN ('created', 'moved', 'updated', 'deleted', 'flushed')),
    actor_id INTEGER NOT NULL REFERENCES users(id),
    card_title TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS calendar_events (
    id TEXT PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL,
    hidden INTEGER NOT NULL DEFAULT 0,
    start_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    duration_amount INTEGER NOT NULL DEFAULT 1,
    duration_unit TEXT NOT NULL CHECK (duration_unit IN ('minute', 'hour', 'day')),
    repeat_amount INTEGER NOT NULL DEFAULT 1,
    repeat_unit TEXT NOT NULL CHECK (repeat_unit IN ('none', 'day', 'week', 'year')),
    repeat_end_mode TEXT NOT NULL CHECK (repeat_end_mode IN ('never', 'on', 'after')),
    repeat_end_date TEXT,
    repeat_count INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expire INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at);
  CREATE INDEX IF NOT EXISTS idx_cards_project_status_position ON cards(project_id, status, position);
  CREATE INDEX IF NOT EXISTS idx_card_actions_project_created ON card_actions(project_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_calendar_events_project_start ON calendar_events(project_id, start_date, start_time);
  CREATE INDEX IF NOT EXISTS idx_notes_updated_at ON notes(updated_at);
  CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
  CREATE INDEX IF NOT EXISTS idx_login_ip_attempts_banned ON login_ip_attempts(banned_at);
  CREATE INDEX IF NOT EXISTS idx_user_preferences_updated ON user_preferences(updated_at);
`);

function hasColumn(table, column) {
  return db.pragma(`table_info(${table})`).some((info) => info.name === column);
}

function parseStoredTimestamp(value) {
  if (!value) return null;
  const normalizedValue = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
    ? `${value.replace(" ", "T")}Z`
    : value;
  const timestamp = Date.parse(normalizedValue);
  return Number.isNaN(timestamp) ? null : timestamp;
}

function migrateLegacyLoginBanExpiries() {
  const legacyBans = db
    .prepare(
      `
      SELECT ip, banned_at
      FROM login_ip_attempts
      WHERE banned_at IS NOT NULL AND banned_until IS NULL
      `
    )
    .all();

  if (!legacyBans.length) return;

  const updateBanExpiry = db.prepare("UPDATE login_ip_attempts SET banned_until = ? WHERE ip = ?");
  const clearInvalidBan = db.prepare(
    `
    UPDATE login_ip_attempts
    SET failed_attempts = 0,
        banned_at = NULL,
        banned_until = NULL
    WHERE ip = ?
    `
  );

  for (const ban of legacyBans) {
    const bannedAt = parseStoredTimestamp(ban.banned_at);
    if (!bannedAt) {
      clearInvalidBan.run(ban.ip);
      continue;
    }

    updateBanExpiry.run(new Date(bannedAt + config.loginBanDurationMs).toISOString(), ban.ip);
  }
}

function removeDeletedCardActions() {
  db.prepare(
    `
    DELETE FROM card_actions
    WHERE action = 'deleted'
       OR card_id IN (
        SELECT card_id
        FROM card_actions
        WHERE action = 'deleted'
          AND card_id IS NOT NULL
      )
    `
  ).run();
}

if (!hasColumn("users", "is_admin")) {
  db.exec("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0");
}

if (!hasColumn("users", "password_change_required")) {
  db.exec("ALTER TABLE users ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0");
}

if (!hasColumn("users", "deleted_at")) {
  db.exec("ALTER TABLE users ADD COLUMN deleted_at TEXT");
}

if (!hasColumn("projects", "color")) {
  db.exec("ALTER TABLE projects ADD COLUMN color TEXT");
}

if (!hasColumn("login_ip_attempts", "first_failed_at")) {
  db.exec("ALTER TABLE login_ip_attempts ADD COLUMN first_failed_at TEXT");
  db.exec(
    `
    UPDATE login_ip_attempts
    SET first_failed_at = COALESCE(last_failed_at, banned_at, CURRENT_TIMESTAMP)
    WHERE first_failed_at IS NULL
    `
  );
}

if (!hasColumn("login_ip_attempts", "banned_until")) {
  db.exec("ALTER TABLE login_ip_attempts ADD COLUMN banned_until TEXT");
}

migrateLegacyLoginBanExpiries();
removeDeletedCardActions();

db.exec("CREATE INDEX IF NOT EXISTS idx_login_ip_attempts_banned_until ON login_ip_attempts(banned_until)");

export function serializeProject(row) {
  return {
    id: row.id,
    name: row.name,
    color: row.color || "",
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    totalCards: Number(row.total_cards || 0),
    completedCards: Number(row.completed_cards || 0),
    ongoingCards: Number(row.ongoing_cards || 0)
  };
}

export function serializeUser(row) {
  return {
    id: row.id,
    username: row.username,
    isAdmin: Boolean(row.is_admin),
    mustChangePassword: Boolean(row.password_change_required),
    deletedAt: row.deleted_at || null,
    createdAt: row.created_at
  };
}

export function serializeNote(row) {
  return {
    id: row.id,
    name: row.name,
    content: row.content ?? "",
    createdBy: row.created_by,
    creatorName: row.creator_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function serializeCard(row) {
  return {
    id: row.id,
    projectId: row.project_id,
    title: row.title,
    description: row.description,
    status: row.status,
    position: row.position,
    eventDate: row.event_date,
    flushedAt: row.flushed_at,
    createdBy: row.created_by,
    creatorName: row.creator_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function serializeAction(row) {
  return {
    id: row.id,
    projectId: row.project_id,
    cardId: row.card_id,
    action: row.action,
    actorId: row.actor_id,
    actorName: row.actor_name,
    cardTitle: row.card_title,
    fromStatus: row.from_status,
    toStatus: row.to_status,
    metadata: JSON.parse(row.metadata_json || "{}"),
    createdAt: row.created_at
  };
}

export function serializeCalendarEvent(row) {
  return {
    id: row.id,
    projectId: row.project_id,
    groupId: row.group_id,
    name: row.name ?? "",
    color: row.color,
    hidden: Boolean(row.hidden),
    startDate: row.start_date,
    startTime: row.start_time,
    durationAmount: row.duration_amount,
    durationUnit: row.duration_unit,
    repeatAmount: row.repeat_amount,
    repeatUnit: row.repeat_unit,
    repeatEndMode: row.repeat_end_mode,
    repeatEndDate: row.repeat_end_date || "",
    repeatCount: row.repeat_count,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}
