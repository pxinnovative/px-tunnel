#!/usr/bin/env python3
"""
pxtunnel-api — aggregator + admin API + static server for the PX Tunnel UI.

Read path: merges the collector snapshot (data plane) + Headscale CLI (control plane) +
the SQLite store (descriptions, login accounts, roles) into the dashboard view.
Admin path: CRUD for tenants (= Headscale users), access-users (login accounts), and
tunnel/node actions (rename, exit-node, approve routes, disconnect, remove, describe).

Auth: every request needs a valid session (opaque cookie -> server-side session row) except
`/login`, `POST /api/login` and `/api/health`. RBAC is enforced SERVER-SIDE here (the UI only
hides controls — cosmetic): superadmin = all; admin = operate within assigned tenants only;
viewer = read assigned tenants. State + tenant listings are filtered to the caller's tenants.

Two data layers:
  - Headscale  = source of truth for tenants (users), tunnels (nodes), routes, ACL.
  - SQLite     = login accounts + roles + tenant grants + human descriptions (pxtunnel_db).

Zero pip deps (stdlib only). Binds loopback; front it with a TLS reverse proxy for remote access.
All shell calls use an argument list (no shell=True); node ids validated as integers.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pxtunnel_db as db

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.environ.get("PXTUNNEL_STATE", "/run/pxtunnel/state.json")
COLLECT = os.environ.get("PXTUNNEL_COLLECT", os.path.join(HERE, "..", "collector", "pxtunnel_collect.py"))
WEB = os.environ.get("PXTUNNEL_WEB", os.path.join(HERE, "..", "web"))
MAX_AGE = int(os.environ.get("PXTUNNEL_MAX_AGE", "15"))
# Headscale server_url used in device join commands (e.g. https://headscale.example.com).
# Empty -> the UI shows a configure-me placeholder in the join command.
LOGIN_SERVER = os.environ.get("PXTUNNEL_LOGIN_SERVER", "")
_bind = os.environ.get("PXTUNNEL_BIND", "127.0.0.1:8807")
BIND_HOST, BIND_PORT = _bind.rsplit(":", 1)

COOKIE_NAME = os.environ.get("PXTUNNEL_COOKIE_NAME", "pxtunnel_session")
# Secure flag off by default for loopback / SSH-tunnel access over http://localhost.
# Set PXTUNNEL_COOKIE_SECURE=1 once a TLS reverse proxy fronts the dashboard.
COOKIE_SECURE = os.environ.get("PXTUNNEL_COOKIE_SECURE", "0") == "1"

# Branding (white-label): product name shown in the UI.
BRAND = os.environ.get("PXTUNNEL_BRAND", "PX Tunnel")
# Reserved "infrastructure" tenant: raw WireGuard / system links are grouped here; it cannot be
# deleted or granted to non-superadmins. Rename via PXTUNNEL_INFRA_TENANT.
INFRA_TENANT = os.environ.get("PXTUNNEL_INFRA_TENANT", "system")

APP_VERSION = "0.3.0"
# \Z (not $) anchors the very end of string — $ also matches before a trailing newline.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,30}\Z")
RESERVED_TENANTS = {INFRA_TENANT, "system", "default"}
MAX_BODY = int(os.environ.get("PXTUNNEL_MAX_BODY", str(1 << 20)))  # 1 MiB request-body cap

# in-memory login throttle (keyed by username; the only client is loopback so IP is useless)
LOGIN_WINDOW = 300
LOGIN_MAX_FAILS = 5
_LOGIN_FAILS = {}


# ── shell + headscale helpers ─────────────────────────────────────────────────
def hs(args, timeout=10):
    """Run a headscale CLI subcommand, no shell (injection-safe). -> (rc, out, err)."""
    try:
        p = subprocess.run(["headscale"] + args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


# Cap on a submitted policy document so a runaway paste can't exhaust memory / disk.
MAX_POLICY_BYTES = 256 * 1024


def hs_policy(content, apply=False):
    """Validate (and optionally apply) a HuJSON ACL policy via the headscale CLI.

    `headscale policy check`/`set` read the policy from a file, so we write the submitted
    document to a private temp file, run the CLI against it, and always remove it. Nothing is
    persisted by us — headscale itself owns the policy store (database mode). Returns
    (ok: bool, detail: str). On apply=True a successful `set` implies the policy is live.
    """
    if not content or not content.strip():
        return False, "empty policy"
    if len(content.encode("utf-8")) > MAX_POLICY_BYTES:
        return False, "policy too large"
    fd, tmp = tempfile.mkstemp(prefix="pxtunnel-policy-", suffix=".hujson")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(tmp, 0o600)
        # Always check first; only `set` when applying and the check passed.
        rc, _out, err = hs(["policy", "check", "-f", tmp])
        if rc != 0:
            return False, (err.strip() or "policy failed validation")[:600]
        if apply:
            rc, _out, err = hs(["policy", "set", "-f", tmp])
            if rc != 0:
                return False, (err.strip() or "policy set failed")[:600]
        return True, "applied" if apply else "valid"
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def hs_users():
    rc, out, _ = hs(["users", "list", "--output", "json"])
    try:
        return json.loads(out) or [] if rc == 0 else []
    except Exception:  # noqa: BLE001
        return []


def _user_id(name):
    for u in hs_users():
        if u.get("name") == name:
            return u.get("id")
    return None


def ensure_user(name):
    """Create the tenant user if missing; return its numeric id (v0.28 needs the ID)."""
    uid = _user_id(name)
    if uid is None:
        hs(["users", "create", name])
        uid = _user_id(name)
    return uid


def node_counts_by_user():
    rc, out, _ = hs(["nodes", "list", "--output", "json"])
    counts = {}
    try:
        nodes = json.loads(out) if rc == 0 else []
        for n in (nodes if isinstance(nodes, list) else []):
            u = (n.get("user") or {}).get("name") or "default"
            counts[u] = counts.get(u, 0) + 1
    except Exception:  # noqa: BLE001
        pass
    return counts


def node_tenant(nid):
    """Resolve a Headscale node id -> the tenant (user) it belongs to, for per-tenant authz."""
    rc, out, _ = hs(["nodes", "list", "--output", "json"])
    try:
        nodes = json.loads(out) if rc == 0 else []
    except Exception:  # noqa: BLE001
        nodes = []
    for n in (nodes if isinstance(nodes, list) else []):
        if str(n.get("id")) == str(nid):
            # No "default" fallback: an orphaned node (missing user) must NOT become actionable
            # via a tenant grant. Return None -> the caller treats it as not-found (404).
            return (n.get("user") or {}).get("name") or None
    return None


# ── state (collector snapshot, enriched with descriptions, filtered by role) ──────
def snapshot_age():
    try:
        return time.time() - os.path.getmtime(STATE)
    except OSError:
        return 1e9


def refresh_if_stale():
    if snapshot_age() <= MAX_AGE:
        return
    try:
        subprocess.run(["python3", COLLECT, "--out", STATE], timeout=12, capture_output=True, check=False)
    except Exception:  # noqa: BLE001
        pass


def _default_peer_type(link):
    return {"nordvpn": "vpn-exit", "app-tailnet": "mesh",
            "raw-wg": "server", "headscale-node": "computer"}.get(link.get("layer"), "other")


def _default_peer_label(link):
    b = link.get("endpoint_b") or {}
    fp = b.get("pubkey_fp")
    return b.get("label") or b.get("public_endpoint") or b.get("addr") or (fp and fp + "…") or "peer"


def _peer_identity(link, nmeta):
    """Resolve a link's far-end (type, label): explicit per-link meta, else the add-time pending
    type keyed by hostname, else a sensible default from the layer."""
    m = nmeta.get(link.get("id")) or {}
    if not (m.get("type") or m.get("label")):
        name = (link.get("endpoint_b") or {}).get("label")
        if name and ("host:" + name) in nmeta:
            m = nmeta["host:" + name]
    return (m.get("type") or _default_peer_type(link)), (m.get("label") or _default_peer_label(link))


def load_state():
    refresh_if_stale()
    try:
        with open(STATE) as fh:
            state = json.load(fh)
    except Exception as e:  # noqa: BLE001
        return None, str(e)
    descs = db.get_tunnel_descriptions()
    nmeta = db.get_node_meta()
    for l in state.get("links", []):
        if descs.get(l.get("id")):
            l["description"] = descs[l["id"]]
        l["peer_type"], l["peer_label"] = _peer_identity(l, nmeta)
    state["local_node"] = db.get_local_node()
    state["app_version"] = APP_VERSION
    return state, None


def link_tenant(lid):
    """Tenant that owns a given link id (for describe authz)."""
    state, _ = load_state()
    for l in (state or {}).get("links", []):
        if l.get("id") == lid:
            return l.get("tenant") or INFRA_TENANT
    return None


def _recompute_posture(links):
    return {
        "total": len(links),
        "online": sum(1 for l in links if l.get("online")),
        "unexpected": [l["id"] for l in links if not l.get("expected", True)],
        "exit_nodes": [l["id"] for l in links if l.get("exit_node")],
        "stale": [l["id"] for l in links if "stale_handshake" in (l.get("security", {}).get("flags") or [])],
        "tenants": sorted(set(l.get("tenant") or INFRA_TENANT for l in links)),
    }


def state_for(user):
    """The snapshot, with links filtered to the tenants this user may see (superadmin = all)."""
    state, err = load_state()
    if not state:
        return None, err
    vis = db.visible_tenants(user)  # None = all
    if vis is not None:
        links = [l for l in state.get("links", []) if (l.get("tenant") or INFRA_TENANT) in vis]
        state = dict(state)
        state["links"] = links
        state["posture"] = _recompute_posture(links)
    return state, None


def list_tenants_for(user):
    meta = db.list_tenant_meta()
    counts = node_counts_by_user()
    vis = db.visible_tenants(user)
    out = []
    for u in hs_users():
        name = u.get("name")
        if vis is not None and name not in vis:
            continue
        out.append({"name": name, "id": u.get("id"),
                    "description": meta.get(name, ""), "nodes": counts.get(name, 0)})
    return sorted(out, key=lambda t: t["name"])


# ── login throttle ─────────────────────────────────────────────────────────────
def _throttled(username):
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(username, []) if now - t < LOGIN_WINDOW]
    _LOGIN_FAILS[username] = fails
    return len(fails) >= LOGIN_MAX_FAILS


def _record_fail(username):
    _LOGIN_FAILS.setdefault(username, []).append(time.time())


# ── HTTP handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "pxtunnel-api/0.4"
    timeout = 30  # bound slow-body / slowloris reads so a stuck socket can't pin a thread forever

    # ---- low-level senders ----
    def _send(self, code, body, ctype="application/json", extra_headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra_headers or {}):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _cookie_header(self, value, max_age):
        sec = "; Secure" if COOKIE_SECURE else ""
        return ("Set-Cookie",
                f"{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{sec}")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n <= 0 or n > MAX_BODY:  # reject oversized/declared-huge bodies without reading them
                return {}
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:  # noqa: BLE001
            return {}

    def _get_cookie(self, name):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _current_user(self):
        return db.get_session_user(self._get_cookie(COOKIE_NAME))

    def log_message(self, fmt, *args):  # quieter logs
        pass

    # ── GET ──
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        # public routes
        if path == "/api/health":
            # brand is public on purpose: the (pre-auth) login page uses it to label itself.
            return self._send(200, {"status": "pass", "snapshot_age_s": round(snapshot_age(), 1),
                                    "brand": BRAND})
        if path in ("/login", "/login.html"):
            return self._serve_file(os.path.join(WEB, "login.html"), "text/html; charset=utf-8")

        user = self._current_user()
        if not user:
            if path.startswith("/api/"):
                return self._send(401, {"error": "unauthenticated"})
            return self._redirect("/login")

        # authenticated routes
        if path == "/api/me":
            return self._send(200, {"username": user["username"], "role": user["role"],
                                    "tenants": user["tenants"], "node_types": list(db.NODE_TYPES),
                                    "brand": BRAND, "infra_tenant": INFRA_TENANT,
                                    "login_server_set": bool(LOGIN_SERVER)})
        if path == "/api/state":
            state, err = state_for(user)
            return self._send(200, state) if state else self._send(503, {"error": "no snapshot", "detail": err})
        if path == "/api/tenants":
            return self._send(200, list_tenants_for(user))
        if path == "/api/access-users":
            if not db.is_superadmin(user):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, db.list_users())
        # access-control policy (the mesh ACL) — read; superadmin only
        if path == "/api/policy":
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can view the access policy"})
            rc, out, err = hs(["policy", "get"])
            if rc != 0:
                return self._send(503, {"error": "could not read policy", "detail": err[:300]})
            return self._send(200, {"policy": out})
        if path in ("/", "/index.html"):
            return self._serve_file(os.path.join(WEB, "index.html"), "text/html; charset=utf-8")

        # static (authenticated)
        safe = os.path.normpath(path).lstrip("/")
        target = os.path.join(WEB, safe)
        if os.path.commonpath([os.path.abspath(target), os.path.abspath(WEB)]) == os.path.abspath(WEB) \
                and os.path.isfile(target):
            ctype = "text/css" if target.endswith(".css") else \
                    "application/javascript" if target.endswith(".js") else "text/plain"
            return self._serve_file(target, ctype)
        return self._send(404, {"error": "not found"})

    # ── POST ──
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        body = self._body()

        # ---- public: login ----
        if path == "/api/login":
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            if not username or not password:
                return self._send(400, {"error": "username and password required"})
            if _throttled(username):
                return self._send(429, {"error": "too many attempts — wait a minute"})
            rec = db.get_user(username)
            if not rec or not db.verify_password(password, rec.get("pw_hash")):
                _record_fail(username)
                return self._send(401, {"error": "invalid credentials"})
            _LOGIN_FAILS.pop(username, None)
            token = db.create_session(username)
            return self._send(200, {"ok": True, "username": username, "role": rec["role"]},
                              extra_headers=[self._cookie_header(token, db.SESSION_TTL)])

        # ---- everything else needs a session ----
        user = self._current_user()
        if not user:
            return self._send(401, {"error": "unauthenticated"})

        if path == "/api/logout":
            tok = self._get_cookie(COOKIE_NAME)
            if tok:
                db.delete_session(tok)
            return self._send(200, {"ok": True}, extra_headers=[self._cookie_header("", 0)])

        # self / admin password change
        m = re.match(r"^/api/access-users/([a-z0-9][a-z0-9_-]{1,30})/password$", path)
        if m:
            return self._set_user_password(user, m.group(1), body)

        # add a device to a tenant -> join command
        if path == "/api/device/add":
            tenant = (body.get("tenant") or "").strip()
            if not tenant:
                return self._send(400, {"error": "no tenant — create one in Manage first"})
            if not NAME_RE.match(tenant):
                return self._send(400, {"error": "invalid tenant name"})
            if not db.can_act(user, tenant):
                return self._send(403, {"error": "forbidden for this tenant"})
            uid = ensure_user(tenant)
            if uid is None:
                return self._send(500, {"error": f"could not resolve tenant '{tenant}'"})
            args = ["preauthkeys", "create", "--user", str(uid), "--expiration", "1h"]
            if body.get("reusable"):
                args.append("--reusable")
            rc, out, err = hs(args)
            key = out.strip().splitlines()[-1].strip() if rc == 0 and out.strip() else ""
            if rc != 0 or not key:
                return self._send(500, {"error": "preauthkey create failed", "detail": err[:200]})
            srv = LOGIN_SERVER or "<set-PXTUNNEL_LOGIN_SERVER>"
            cmd = f"tailscale up --login-server {srv} --authkey {key} --accept-routes"
            # Optional device name + type: name -> --hostname so it self-identifies on join;
            # type is stored keyed by hostname and applied when the node appears (icon/label).
            name = (body.get("name") or "").strip()
            ntype = body.get("node_type") or ""
            if name and NAME_RE.match(name):
                cmd += f" --hostname={name}"
                if ntype in db.NODE_TYPES:
                    db.set_node_meta("host:" + name, ntype, name)
            return self._send(200, {
                "authkey": key, "tenant": tenant, "expires_in": "1h", "login_command": cmd,
            })

        # create a tenant (Headscale user) + store its description — superadmin only
        if path == "/api/tenants":
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can create tenants"})
            name = (body.get("name") or "").strip()
            if not NAME_RE.match(name) or name in RESERVED_TENANTS:
                return self._send(400, {"error": "invalid or reserved tenant name"})
            if _user_id(name) is not None:
                return self._send(409, {"error": "tenant already exists"})
            rc, _o, err = hs(["users", "create", name])
            if rc != 0:
                return self._send(500, {"error": "create failed", "detail": err[:200]})
            db.set_tenant_desc(name, (body.get("description") or "").strip())
            return self._send(200, {"ok": True, "tenant": name})

        # set a tenant's description — act permission on that tenant
        if path == "/api/tenants/describe":
            name = (body.get("name") or "").strip()
            if not NAME_RE.match(name):
                return self._send(400, {"error": "invalid tenant name"})
            if not db.can_act(user, name):
                return self._send(403, {"error": "forbidden for this tenant"})
            db.set_tenant_desc(name, (body.get("description") or "").strip())
            return self._send(200, {"ok": True})

        # create / update an access-user (login account) — superadmin only
        if path == "/api/access-users":
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can manage users"})
            return self._upsert_access_user(user, body)

        # tunnel description (any link the user may act on)
        if path == "/api/tunnel/describe":
            lid = body.get("id", "")
            if not lid:
                return self._send(400, {"error": "id required"})
            tenant = link_tenant(lid)
            if tenant is None:  # unknown link id -> 404, never fall back to the infra tenant
                return self._send(404, {"error": "no such tunnel"})
            if not db.can_act(user, tenant):
                return self._send(403, {"error": "forbidden for this tunnel"})
            db.set_tunnel_desc(lid, (body.get("description") or "").strip())
            return self._send(200, {"ok": True})

        # tunnel peer identity (type + friendly name) + optional description
        if path == "/api/tunnel/meta":
            lid = body.get("id", "")
            if not lid:
                return self._send(400, {"error": "id required"})
            tenant = link_tenant(lid)
            if tenant is None:
                return self._send(404, {"error": "no such tunnel"})
            if not db.can_act(user, tenant):
                return self._send(403, {"error": "forbidden for this tunnel"})
            ntype = body.get("node_type") or ""
            if ntype and ntype not in db.NODE_TYPES:
                return self._send(400, {"error": "invalid node type"})
            db.set_node_meta(lid, ntype, (body.get("label") or "").strip())
            if "description" in body:
                db.set_tunnel_desc(lid, (body.get("description") or "").strip())
            return self._send(200, {"ok": True})

        # local node identity (the host this dashboard runs on) — superadmin only
        if path == "/api/settings/local-node":
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can set the local node"})
            name = (body.get("name") or "").strip()
            ntype = body.get("type") or "cloud-server"
            if not NAME_RE.match(name) or ntype not in db.NODE_TYPES:
                return self._send(400, {"error": "invalid name or type"})
            db.set_local_node(name, ntype)
            return self._send(200, {"ok": True})

        # access-control policy (the mesh ACL) — validate or apply; superadmin only
        if path in ("/api/policy", "/api/policy/check"):
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can change the access policy"})
            apply = path == "/api/policy"
            ok, detail = hs_policy(body.get("policy", ""), apply=apply)
            if not ok:
                return self._send(400, {"error": "invalid policy", "detail": detail})
            return self._send(200, {"ok": True, "detail": detail})

        # node actions: /api/node/<id>/<action>
        m = re.match(r"^/api/node/(\d+)/(expire|delete|approve|exit-node|rename)$", path)
        if m:
            return self._node_action(user, m.group(1), m.group(2), body)

        return self._send(404, {"error": "not found"})

    # ── DELETE ──
    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        user = self._current_user()
        if not user:
            return self._send(401, {"error": "unauthenticated"})

        m = re.match(r"^/api/tenants/([a-z0-9][a-z0-9_-]{1,30})$", path)
        if m:
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can delete tenants"})
            name = m.group(1)
            if name in RESERVED_TENANTS:
                return self._send(400, {"error": "cannot delete reserved tenant"})
            uid = _user_id(name)
            if uid is not None:
                rc, _o, err = hs(["users", "destroy", "--identifier", str(uid), "--force"])
                if rc != 0:
                    return self._send(500, {"error": "destroy failed", "detail": err[:200]})
            db.delete_tenant_meta(name)
            return self._send(200, {"ok": True, "deleted": name})

        m = re.match(r"^/api/access-users/([a-z0-9][a-z0-9_-]{1,30})$", path)
        if m:
            if not db.is_superadmin(user):
                return self._send(403, {"error": "only a superadmin can delete users"})
            name = m.group(1)
            target = db.get_user(name)
            if not target:
                return self._send(404, {"error": "no such user"})
            if target["role"] == "superadmin" and db.count_superadmins() <= 1:
                return self._send(400, {"error": "cannot delete the last superadmin"})
            db.delete_user(name)
            return self._send(200, {"ok": True, "deleted": name})

        return self._send(404, {"error": "not found"})

    # ── handlers split out for clarity ──
    def _set_user_password(self, user, target, body):
        new = body.get("password") or ""
        if len(new) < db.MIN_PASSWORD_LEN:
            return self._send(400, {"error": f"password must be at least {db.MIN_PASSWORD_LEN} characters"})
        self_change = (target == user["username"])
        if db.is_superadmin(user):
            if not db.get_user(target):
                return self._send(404, {"error": "no such user"})
        elif self_change:
            rec = db.get_user(user["username"])
            if not db.verify_password(body.get("current_password") or "", (rec or {}).get("pw_hash")):
                return self._send(403, {"error": "current password is wrong"})
        else:
            return self._send(403, {"error": "forbidden"})
        db.set_password(target, new)
        # A password change must revoke ALL existing sessions (incl. any stolen token), not just
        # prove knowledge of the old one. Applies to self-change AND superadmin reset alike.
        db.delete_user_sessions(target)
        if self_change:  # keep the acting user signed in with a fresh, post-change session
            token = db.create_session(user["username"])
            return self._send(200, {"ok": True}, extra_headers=[self._cookie_header(token, db.SESSION_TTL)])
        return self._send(200, {"ok": True})

    def _upsert_access_user(self, user, body):
        name = (body.get("name") or "").strip()
        if not NAME_RE.match(name):
            return self._send(400, {"error": "invalid user name"})
        tenants = body.get("tenants", [])
        if not isinstance(tenants, list) or not all(isinstance(x, str) for x in tenants):
            return self._send(400, {"error": "tenants must be a list of names"})
        role = body.get("role", "viewer")
        if role not in db.ROLES:
            return self._send(400, {"error": "role must be superadmin|admin|viewer"})
        # An admin/viewer must never be granted a reserved/infra tenant (the reserved infra tenant)
        # — that would let them act on owner infrastructure and orphaned nodes.
        if role != "superadmin":
            reserved = sorted(set(tenants) & RESERVED_TENANTS)
            if reserved:
                return self._send(400, {"error": "cannot assign reserved tenant(s) to a "
                                                 "non-superadmin: " + ", ".join(reserved)})
        password = body.get("password") or None
        if password is not None and len(password) < 8:
            return self._send(400, {"error": "password must be at least 8 characters"})
        # guard: don't let the only superadmin demote themselves into lock-out
        existing = db.get_user(name)
        if existing and existing["role"] == "superadmin" and role != "superadmin" \
                and db.count_superadmins() <= 1:
            return self._send(400, {"error": "cannot demote the last superadmin"})
        db.upsert_user(name, role, description=(body.get("description") or "").strip(),
                       tenants=([] if role == "superadmin" else tenants), password=password)
        return self._send(200, {"ok": True, "user": name, "has_password": bool(password) or
                                bool((existing or {}).get("pw_hash"))})

    def _node_action(self, user, nid, action, body):
        tenant = node_tenant(nid)
        if tenant is None:
            return self._send(404, {"error": "no such node"})
        if not db.can_act(user, tenant):
            return self._send(403, {"error": "forbidden for this node's tenant"})
        if action == "expire":
            rc, _o, err = hs(["nodes", "expire", "-i", nid])
        elif action == "delete":
            rc, _o, err = hs(["nodes", "delete", "-i", nid, "--force"])
        elif action == "exit-node":
            rc, _o, err = hs(["nodes", "approve-routes", "-i", nid, "-r", "0.0.0.0/0,::/0"])
        elif action == "rename":
            new = (body.get("name") or "").strip()
            if not NAME_RE.match(new):
                return self._send(400, {"error": "invalid node name"})
            rc, _o, err = hs(["nodes", "rename", "-i", nid, new])
        else:  # approve given routes
            routes = body.get("routes", [])
            if not isinstance(routes, list) or not all(isinstance(r, str) for r in routes):
                return self._send(400, {"error": "routes must be a list of strings"})
            for r in routes:
                try:
                    ipaddress.ip_network(r, strict=False)
                except ValueError:
                    return self._send(400, {"error": ("invalid CIDR route: " + r)[:120]})
            args = ["nodes", "approve-routes", "-i", nid]
            if routes:
                args += ["-r", ",".join(routes)]
            rc, _o, err = hs(args)
        if rc != 0:
            return self._send(500, {"error": f"{action} failed", "detail": err[:200]})
        return self._send(200, {"ok": True, "node": int(nid), "action": action})

    def _serve_file(self, fpath, ctype):
        try:
            with open(fpath, "rb") as fh:
                return self._send(200, fh.read().decode("utf-8", "replace"), ctype)
        except OSError:
            return self._send(404, {"error": "not found"})


def _bootstrap_cli(argv):
    if len(argv) < 1:
        print("usage: pxtunnel_api.py bootstrap-admin <username> [password]")
        return 2
    username = argv[0]
    if not NAME_RE.match(username):
        print("error: username must match", NAME_RE.pattern)
        return 2
    pw = argv[1] if len(argv) > 1 else None
    if pw is not None and len(pw) < db.MIN_PASSWORD_LEN:
        print(f"error: password must be at least {db.MIN_PASSWORD_LEN} characters")
        return 2
    try:
        pw = db.bootstrap_admin(username, pw)
    except ValueError as e:
        print("error:", e)
        return 2
    print(f"superadmin '{username}' is ready.")
    print(f"password: {pw}")
    print("Store it now (password manager / SOPS) — it is shown only once.")
    return 0


def main():
    args = sys.argv[1:]
    if args and args[0] == "bootstrap-admin":
        sys.exit(_bootstrap_cli(args[1:]))
    db.init_db()
    db.purge_expired_sessions()
    httpd = ThreadingHTTPServer((BIND_HOST, int(BIND_PORT)), Handler)
    print(f"pxtunnel-api on http://{BIND_HOST}:{BIND_PORT}  (state={STATE} db={db.DB_PATH})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
