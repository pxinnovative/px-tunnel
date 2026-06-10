#!/usr/bin/env python3
"""Headscale-free auth + RBAC test for pxtunnel-api. Runnable anywhere (Mac / CI).

Spawns the API against a TEMP sqlite db + temp state snapshot (no headscale needed) and asserts
the authentication gate, session lifecycle, server-side RBAC and password flows on the
headscale-free endpoints. Tenant/node paths need a live headscale and are covered by
tests/smoke.py on the host. Stdlib only; exits non-zero on any failure.
"""
import http.cookiejar
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
API = os.path.join(HERE, "..", "api", "pxtunnel_api.py")
PORT = int(os.environ.get("PXTUNNEL_TEST_PORT", "8899"))
BASE = f"http://127.0.0.1:{PORT}"

_tmp = tempfile.mkdtemp(prefix="pxtunnel-test-")
_db = os.path.join(_tmp, "test.db")
_state = os.path.join(_tmp, "state.json")
with open(_state, "w") as fh:
    json.dump({"host": "testhost", "generated_at": 0, "links": [
        {"id": "headscale-node:1", "layer": "headscale-node", "tenant": "acme",
         "online": True, "status": "online", "expected": True, "security": {"flags": []}},
        {"id": "raw-wg:wg0:abcd1234", "layer": "raw-wg", "tenant": "system",
         "online": True, "status": "online", "expected": True, "security": {"flags": []}},
    ], "posture": {}, "versions": []}, fh)

_env = dict(os.environ, PXTUNNEL_DB=_db, PXTUNNEL_STATE=_state,
            PXTUNNEL_WEB=os.path.join(HERE, "..", "web"),
            PXTUNNEL_BIND=f"127.0.0.1:{PORT}", PXTUNNEL_MAX_AGE="999999",
            PXTUNNEL_PBKDF2_ITER="50000")  # lower cost = faster test only

_passed, _failed = 0, 0


def check(name, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failed += 1
        print(f"  FAIL {name}")


def call(method, path, data=None, jar=None):
    op = (urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
          if jar is not None else urllib.request.build_opener())
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(BASE + path, data=body, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        r = op.open(req, timeout=8)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


def login(jar, user, pw):
    return call("POST", "/api/login", {"username": user, "password": pw}, jar)


proc = None
try:
    bs = subprocess.run([sys.executable, API, "bootstrap-admin", "owner", "owner-pass-123"],
                        env=_env, capture_output=True, text=True)
    check("bootstrap superadmin", "ready" in bs.stdout)
    weak = subprocess.run([sys.executable, API, "bootstrap-admin", "weakuser", "x"],
                          env=_env, capture_output=True, text=True)
    check("bootstrap rejects weak password", weak.returncode != 0 and "at least" in (weak.stdout + weak.stderr))

    proc = subprocess.Popen([sys.executable, API], env=_env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    up = False
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=1)
            up = True
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    check("server is up", up)

    # ── gate ──
    check("unauth /api/me -> 401", call("GET", "/api/me")[0] == 401)
    check("unauth /api/state -> 401", call("GET", "/api/state")[0] == 401)
    check("health is public", call("GET", "/api/health")[0] == 200)
    check("bad login -> 401", login(http.cookiejar.CookieJar(), "owner", "nope")[0] == 401)

    # ── superadmin session ──
    owner = http.cookiejar.CookieJar()
    sc, sb = login(owner, "owner", "owner-pass-123")
    check("owner login -> 200 superadmin", sc == 200 and sb.get("role") == "superadmin")
    me = call("GET", "/api/me", jar=owner)[1]
    check("owner /api/me", me.get("username") == "owner" and me.get("role") == "superadmin")
    check("owner sees both links", len(call("GET", "/api/state", jar=owner)[1].get("links", [])) == 2)

    # ── node typing (Phase 1) ──
    _st = call("GET", "/api/state", jar=owner)[1]
    check("state carries local_node", isinstance(_st.get("local_node"), dict) and bool(_st["local_node"].get("name")))
    check("links carry peer_type/label", all(l.get("peer_type") and l.get("peer_label") for l in _st.get("links", [])))
    check("me lists node_types", isinstance(call("GET", "/api/me", jar=owner)[1].get("node_types"), list))
    check("set tunnel meta", call("POST", "/api/tunnel/meta",
          {"id": "headscale-node:1", "node_type": "router", "label": "gateway-1"}, jar=owner)[0] == 200)
    _hn = [l for l in call("GET", "/api/state", jar=owner)[1]["links"] if l["id"] == "headscale-node:1"]
    check("tunnel meta applied to render", bool(_hn) and _hn[0]["peer_type"] == "router" and _hn[0]["peer_label"] == "gateway-1")
    check("reject bad node type", call("POST", "/api/tunnel/meta",
          {"id": "headscale-node:1", "node_type": "bogus"}, jar=owner)[0] == 400)
    check("set local node", call("POST", "/api/settings/local-node",
          {"name": "this-node", "type": "cloud-server"}, jar=owner)[0] == 200)

    # ── create scoped accounts ──
    check("create admin1", call("POST", "/api/access-users",
          {"name": "admin1", "role": "admin", "tenants": ["acme"], "password": "admin-pass-1"},
          jar=owner)[0] == 200)
    check("create viewer1", call("POST", "/api/access-users",
          {"name": "viewer1", "role": "viewer", "tenants": ["acme"], "password": "viewer-pass-1"},
          jar=owner)[0] == 200)
    check("reject short password", call("POST", "/api/access-users",
          {"name": "shorty", "role": "viewer", "tenants": ["acme"], "password": "x"},
          jar=owner)[0] == 400)
    check("reject reserved tenant for admin", call("POST", "/api/access-users",
          {"name": "badadmin", "role": "admin", "tenants": ["system"], "password": "badadmin-12"},
          jar=owner)[0] == 400)

    # ── admin RBAC ──
    adm = http.cookiejar.CookieJar()
    check("admin1 login", login(adm, "admin1", "admin-pass-1")[0] == 200)
    check("admin1 cannot list users (403)", call("GET", "/api/access-users", jar=adm)[0] == 403)
    check("admin1 cannot create users (403)", call("POST", "/api/access-users",
          {"name": "x2", "role": "viewer", "tenants": ["acme"]}, jar=adm)[0] == 403)

    # ── viewer RBAC ──
    vw = http.cookiejar.CookieJar()
    check("viewer1 login", login(vw, "viewer1", "viewer-pass-1")[0] == 200)
    vlinks = call("GET", "/api/state", jar=vw)[1].get("links", [])
    check("viewer1 sees only acme link", len(vlinks) == 1 and vlinks[0]["tenant"] == "acme")
    check("viewer1 cannot create users (403)", call("POST", "/api/access-users",
          {"name": "x3", "role": "viewer"}, jar=vw)[0] == 403)
    check("viewer1 cannot add device (403)", call("POST", "/api/device/add",
          {"tenant": "acme"}, jar=vw)[0] == 403)

    # ── self password change (revokes other sessions, keeps the acting one) ──
    vw2 = http.cookiejar.CookieJar()
    login(vw2, "viewer1", "viewer-pass-1")
    check("viewer1 second session alive", call("GET", "/api/me", jar=vw2)[0] == 200)
    check("viewer1 wrong current -> 403", call("POST", "/api/access-users/viewer1/password",
          {"password": "newpass-12", "current_password": "wrong"}, jar=vw)[0] == 403)
    check("viewer1 good current -> 200", call("POST", "/api/access-users/viewer1/password",
          {"password": "newpass-12", "current_password": "viewer-pass-1"}, jar=vw)[0] == 200)
    check("viewer1 OTHER session revoked after self pw change", call("GET", "/api/me", jar=vw2)[0] == 401)
    check("viewer1 acting session still alive (fresh cookie)", call("GET", "/api/me", jar=vw)[0] == 200)
    check("old viewer1 password rejected", login(http.cookiejar.CookieJar(), "viewer1", "viewer-pass-1")[0] == 401)
    check("new viewer1 password works", login(http.cookiejar.CookieJar(), "viewer1", "newpass-12")[0] == 200)

    # ── superadmin reset revokes sessions ──
    check("superadmin reset admin1 pw", call("POST", "/api/access-users/admin1/password",
          {"password": "admin-pass-2"}, jar=owner)[0] == 200)
    check("admin1 old session revoked after reset", call("GET", "/api/me", jar=adm)[0] == 401)

    # ── lock-out guards ──
    check("cannot delete last superadmin", call("DELETE", "/api/access-users/owner", jar=owner)[0] == 400)
    check("cannot demote last superadmin", call("POST", "/api/access-users",
          {"name": "owner", "role": "admin", "tenants": ["acme"]}, jar=owner)[0] == 400)

    # ── logout revokes session ──
    check("owner logout", call("POST", "/api/logout", jar=owner)[0] == 200)
    check("owner session dead after logout", call("GET", "/api/me", jar=owner)[0] == 401)

    print(f"\n{_passed} passed, {_failed} failed")
finally:
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            proc.kill()
    shutil.rmtree(_tmp, ignore_errors=True)

sys.exit(1 if _failed else 0)
