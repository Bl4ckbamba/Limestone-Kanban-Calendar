import session from "express-session";
import { db } from "./db.js";

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

export class SqliteSessionStore extends session.Store {
  constructor() {
    super();
    this.getStmt = db.prepare("SELECT sess FROM sessions WHERE sid = ? AND expire > ?");
    this.setStmt = db.prepare(`
      INSERT INTO sessions (sid, sess, expire)
      VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire
    `);
    this.destroyStmt = db.prepare("DELETE FROM sessions WHERE sid = ?");
    this.touchStmt = db.prepare("UPDATE sessions SET expire = ? WHERE sid = ?");
    this.clearExpiredStmt = db.prepare("DELETE FROM sessions WHERE expire <= ?");
  }

  get(sid, callback) {
    try {
      this.clearExpiredStmt.run(Date.now());
      const row = this.getStmt.get(sid, Date.now());
      callback(null, row ? JSON.parse(row.sess) : null);
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sess, callback) {
    try {
      const maxAge = sess.cookie?.maxAge || 7 * ONE_DAY_MS;
      this.setStmt.run(sid, JSON.stringify(sess), Date.now() + maxAge);
      callback?.(null);
    } catch (error) {
      callback?.(error);
    }
  }

  destroy(sid, callback) {
    try {
      this.destroyStmt.run(sid);
      callback?.(null);
    } catch (error) {
      callback?.(error);
    }
  }

  touch(sid, sess, callback) {
    try {
      const maxAge = sess.cookie?.maxAge || 7 * ONE_DAY_MS;
      this.touchStmt.run(Date.now() + maxAge, sid);
      callback?.(null);
    } catch (error) {
      callback?.(error);
    }
  }
}
