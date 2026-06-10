#!/usr/bin/env python3
"""
pxtunnel_db — SQLite-backed identity, sessions and RBAC for the PX Tunnel UI.

Self-contained: one SQLite file on the host (no external database).
One SQLite file holds login accounts, tenant grants, descriptions and revocable sessions.
Replaces the old store.json, which kept only authz metadata with NO passwords / NO login.
The first run migrates store.json -> SQLite (idempotent, gated by a flag in `meta`).

Zero pip deps (sqlite3, hashlib, hmac, secrets, base64 — all stdlib).

Security model:
  - Passwords: PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023). Self-describing hash string
    `pbkdf2_sha256$<iter>$<salt_b64>$<hash_b64>` so the cost can be raised later without
    breaking existing hashes. Verified with hmac.compare_digest (constant time).
  - Sessions: server-side + revocable. The cookie carries only an opaque random token; the DB
    row is the single source of truth, so logout / delete-user / role-change take effect
    immediately (no stale signed tokens to outlive a revocation).
  - Roles: superadmin (all tenants) / admin (operate within assigned tenants) / viewer (read
    assigned tenants). Grants live in user_tenants; superadmin ignores them (sees everything).
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

DB_PATH = os.environ.get("PXTUNNEL_DB", "/etc/pxtunnel/pxtunnel.db")
STORE_PATH = os.environ.get("PXTUNNEL_STORE", "/etc/pxtunnel/store.json")
PBKDF2_ITERATIONS = int(os.environ.get("PXTUNNEL_PBKDF2_ITER", "600000"))
SESSION_TTL = int(os.environ.get("PXTUNNEL_SESSION_TTL", str(7 * 24 * 3600)))  # 7 days
MIN_PASSWORD_LEN = int(os.environ.get("PXTUNNEL_MIN_PW", "8"))
ROLES = ("superadmin", "admin", "viewer")
NODE_TYPES = ("server", "cloud-server", "computer", "router", "phone", "vpn-exit", "mesh", "other")
SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS users (
  username    TEXT PRIMARY KEY,
  pw_hash     TEXT,                 -- NULL = account exists but cannot log in yet
  role        TEXT NOT NULL,        -- superadmin | admin | viewer
  description TEXT DEFAULT '',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_tenants (
  username TEXT NOT NULL,
  tenant   TEXT NOT NULL,
  PRIMARY KEY (username, tenant),
  FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tenants (
  name        TEXT PRIMARY KEY,
  description TEXT DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnel_meta (
  link_id     TEXT PRIMARY KEY,
  description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS node_meta (
  key       TEXT PRIMARY KEY,   -- a link_id, OR "host:<hostname>" for an add-time pending type
  node_type TEXT DEFAULT '',
  label     TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  username   TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
"""


# ── connection ────────────────────────────────────────────────────────────────
def _connect():
    """One connection per call (sqlite3 connections are not thread-safe to share)."""
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _meta_get(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def _meta_set(conn, key, value):
    conn.execute("INSERT INTO meta(key, value) VALUES (?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


# ── init + one-time migration ──────────────────────────────────────────────────
def init_db(store_path=None):
    """Create tables if missing and (once) migrate an existing store.json. Idempotent."""
    if store_path is None:
        store_path = STORE_PATH
    conn = _connect()
    try:
        conn.executescript(SCHEMA_SQL)
        if _meta_get(conn, "schema_version") is None:
            _meta_set(conn, "schema_version", str(SCHEMA_VERSION))
        if _meta_get(conn, "store_migrated") != "1":
            _migrate_store(conn, store_path)
            _meta_set(conn, "store_migrated", "1")
        conn.commit()
    finally:
        conn.close()


def _migrate_store(conn, store_path):
    """Import the legacy store.json. Users come over WITHOUT passwords (pw_hash NULL) —
    the old store had no credentials, so a superadmin must set them before they can log in."""
    if not store_path or not os.path.exists(store_path):
        return
    try:
        with open(store_path) as fh:
            d = json.load(fh)
    except Exception:  # noqa: BLE001 - never block startup on a bad legacy file
        return
    now = int(time.time())
    for name, meta in (d.get("tenants") or {}).items():
        conn.execute("INSERT OR IGNORE INTO tenants(name, description, created_at) VALUES (?,?,?)",
                     (name, (meta or {}).get("description", ""), now))
    for lid, meta in (d.get("tunnel_meta") or {}).items():
        conn.execute("INSERT OR IGNORE INTO tunnel_meta(link_id, description) VALUES (?,?)",
                     (lid, (meta or {}).get("description", "")))
    for name, meta in (d.get("access_users") or {}).items():
        meta = meta or {}
        role = meta.get("role", "viewer")
        if role not in ROLES:
            role = "viewer"
        conn.execute(
            "INSERT OR IGNORE INTO users(username, pw_hash, role, description, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)", (name, None, role, meta.get("description", ""), now, now))
        if role != "superadmin":
            for t in (meta.get("tenants") or []):
                if isinstance(t, str) and t and t != "*":
                    conn.execute("INSERT OR IGNORE INTO user_tenants(username, tenant) VALUES (?,?)",
                                 (name, t))


# ── passwords ──────────────────────────────────────────────────────────────────
def hash_password(password):
    # Single choke-point: every code path that sets a password (API, set_password, upsert_user,
    # bootstrap CLI) hashes here, so the minimum-length policy is enforced once for all of them.
    if not password or len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password, stored):
    if not stored or not password:
        return False
    try:
        algo, iter_s, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 base64.b64decode(salt_b64), int(iter_s))
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except Exception:  # noqa: BLE001
        return False


# ── users + grants ───────────────────────────────────────────────────────────
def _user_tenants(conn, username, role):
    if role == "superadmin":
        return ["*"]
    rows = conn.execute("SELECT tenant FROM user_tenants WHERE username=? ORDER BY tenant",
                        (username,)).fetchall()
    return [r["tenant"] for r in rows]


def get_user(username):
    """Full user record INCLUDING pw_hash (internal use: login). Do not serialize directly."""
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return None
        u = dict(row)
        u["tenants"] = _user_tenants(conn, username, u["role"])
        return u
    finally:
        conn.close()


def list_users():
    """Public-safe listing (no pw_hash)."""
    conn = _connect()
    try:
        out = []
        for row in conn.execute("SELECT username, role, description, pw_hash FROM users ORDER BY username"):
            out.append({
                "name": row["username"],
                "role": row["role"],
                "description": row["description"] or "",
                "tenants": _user_tenants(conn, row["username"], row["role"]),
                "has_password": bool(row["pw_hash"]),
            })
        return out
    finally:
        conn.close()


def upsert_user(username, role, description="", tenants=None, password=None):
    """Create or update a login account. Password is only changed when provided (truthy)."""
    if role not in ROLES:
        raise ValueError("invalid role")
    tenants = tenants or []
    now = int(time.time())
    conn = _connect()
    try:
        existing = conn.execute("SELECT pw_hash FROM users WHERE username=?", (username,)).fetchone()
        pw_hash = existing["pw_hash"] if existing else None
        if password:
            pw_hash = hash_password(password)
        conn.execute(
            "INSERT INTO users(username, pw_hash, role, description, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET role=excluded.role, "
            "description=excluded.description, pw_hash=excluded.pw_hash, updated_at=excluded.updated_at",
            (username, pw_hash, role, description, now, now))
        conn.execute("DELETE FROM user_tenants WHERE username=?", (username,))
        if role != "superadmin":
            for t in tenants:
                if isinstance(t, str) and t:
                    conn.execute("INSERT OR IGNORE INTO user_tenants(username, tenant) VALUES (?,?)",
                                 (username, t))
        conn.commit()
    finally:
        conn.close()


def set_password(username, password):
    conn = _connect()
    try:
        cur = conn.execute("UPDATE users SET pw_hash=?, updated_at=? WHERE username=?",
                           (hash_password(password), int(time.time()), username))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_user(username):
    """Delete a user; ON DELETE CASCADE removes their grants and sessions too."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()


def count_superadmins():
    """Active superadmins (with a usable password) — used to prevent lock-out."""
    conn = _connect()
    try:
        return conn.execute(
            "SELECT COUNT(*) c FROM users WHERE role='superadmin' AND pw_hash IS NOT NULL"
        ).fetchone()["c"]
    finally:
        conn.close()


# ── tenant + tunnel descriptions ───────────────────────────────────────────────
def list_tenant_meta():
    conn = _connect()
    try:
        return {r["name"]: r["description"] or "" for r in conn.execute("SELECT name, description FROM tenants")}
    finally:
        conn.close()


def set_tenant_desc(name, description):
    now = int(time.time())
    conn = _connect()
    try:
        conn.execute("INSERT INTO tenants(name, description, created_at) VALUES (?,?,?) "
                     "ON CONFLICT(name) DO UPDATE SET description=excluded.description",
                     (name, description, now))
        conn.commit()
    finally:
        conn.close()


def delete_tenant_meta(name):
    conn = _connect()
    try:
        conn.execute("DELETE FROM tenants WHERE name=?", (name,))
        conn.execute("DELETE FROM user_tenants WHERE tenant=?", (name,))
        conn.commit()
    finally:
        conn.close()


def get_tunnel_descriptions():
    conn = _connect()
    try:
        return {r["link_id"]: r["description"] or "" for r in conn.execute("SELECT link_id, description FROM tunnel_meta")}
    finally:
        conn.close()


def set_tunnel_desc(link_id, description):
    conn = _connect()
    try:
        conn.execute("INSERT INTO tunnel_meta(link_id, description) VALUES (?,?) "
                     "ON CONFLICT(link_id) DO UPDATE SET description=excluded.description",
                     (link_id, description))
        conn.commit()
    finally:
        conn.close()


# ── node typing (per-endpoint type + friendly name) + local node identity ──────
def get_node_meta():
    """{key -> {type, label}} where key is a link_id or 'host:<hostname>'."""
    conn = _connect()
    try:
        return {r["key"]: {"type": r["node_type"] or "", "label": r["label"] or ""}
                for r in conn.execute("SELECT key, node_type, label FROM node_meta")}
    finally:
        conn.close()


def set_node_meta(key, node_type, label):
    conn = _connect()
    try:
        conn.execute("INSERT INTO node_meta(key, node_type, label) VALUES (?,?,?) "
                     "ON CONFLICT(key) DO UPDATE SET node_type=excluded.node_type, label=excluded.label",
                     (key, node_type or "", label or ""))
        conn.commit()
    finally:
        conn.close()


def get_local_node():
    """The host this dashboard runs on, shown as the near end of every tunnel."""
    conn = _connect()
    try:
        return {"name": _meta_get(conn, "local_node_name") or "this-node",
                "type": _meta_get(conn, "local_node_type") or "cloud-server"}
    finally:
        conn.close()


def set_local_node(name, node_type):
    conn = _connect()
    try:
        _meta_set(conn, "local_node_name", name)
        _meta_set(conn, "local_node_type", node_type)
        conn.commit()
    finally:
        conn.close()


# ── sessions ────────────────────────────────────────────────────────────────
def create_session(username):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = _connect()
    try:
        conn.execute("INSERT INTO sessions(token, username, created_at, expires_at) VALUES (?,?,?,?)",
                     (token, username, now, now + SESSION_TTL))
        conn.commit()
        return token
    finally:
        conn.close()


def get_session_user(token):
    """Live user dict for a valid, non-expired session, else None. Joins users so a deleted
    or role-changed account is reflected immediately."""
    if not token:
        return None
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT u.username, u.role, u.description FROM sessions s "
            "JOIN users u ON u.username = s.username "
            "WHERE s.token=? AND s.expires_at > ?", (token, int(time.time()))).fetchone()
        if not row:
            return None
        u = dict(row)
        u["tenants"] = _user_tenants(conn, u["username"], u["role"])
        return u
    finally:
        conn.close()


def delete_session(token):
    conn = _connect()
    try:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
    finally:
        conn.close()


def delete_user_sessions(username):
    conn = _connect()
    try:
        conn.execute("DELETE FROM sessions WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()


def purge_expired_sessions():
    conn = _connect()
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
        conn.commit()
    finally:
        conn.close()


# ── RBAC helpers ────────────────────────────────────────────────────────────
def is_superadmin(user):
    return bool(user) and user.get("role") == "superadmin"


def visible_tenants(user):
    """None = sees ALL (superadmin); else the explicit set of tenant names (may be empty)."""
    if user and user.get("role") == "superadmin":
        return None
    return set(user.get("tenants") or []) if user else set()


def can_see_tenant(user, tenant):
    vis = visible_tenants(user)
    return vis is None or tenant in vis


def can_act(user, tenant):
    """Write/action permission on a tenant: superadmin anywhere; admin on assigned; viewer never."""
    if not user:
        return False
    if user.get("role") == "superadmin":
        return True
    if user.get("role") == "admin":
        return tenant in (user.get("tenants") or [])
    return False


# ── bootstrap ────────────────────────────────────────────────────────────────
def bootstrap_admin(username, password=None):
    """Create or promote a superadmin. Returns the plaintext password (generated if not given)
    so the caller can show it ONCE — only the hash is ever persisted."""
    init_db()
    if not password:
        password = secrets.token_urlsafe(18)  # ~24 url-safe chars
    upsert_user(username, "superadmin", description="Owner / platform superadmin", password=password)
    return password
