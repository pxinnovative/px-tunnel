#!/usr/bin/env python3
"""
pxtunnel-collect — read-only data-plane collector for the PX Tunnel dashboard.

Reads the host's real mesh/tunnel state and emits ONE normalized JSON snapshot (a `Link[]`
model). Runs on the Headscale host; needs root or CAP_NET_ADMIN for `wg show`. Takes NO
arguments beyond `--out <file>` and opens NO socket — it only reads host state and writes JSON.

Sources merged:
  - `headscale nodes list -o json` -> the mesh devices (the primary data: enrolled nodes).
  - `wg show all dump`             -> raw kernel WireGuard tunnels (non-Headscale), shown as
                                      "system" infrastructure. Optional; absent on most hosts.
  - `headscale version` / `wg --version` -> version panel input.
  - purposes file (PXTUNNEL_PURPOSES) -> operator annotation (purpose / criticality / expected).

Config (env):
  PXTUNNEL_INFRA_TENANT  reserved tenant that owns raw WireGuard links (default "system").
  PXTUNNEL_PURPOSES      path to a HuJSON/YAML purposes file (default /etc/pxtunnel/purposes.yaml).

Security: never emits private keys; peer public keys are truncated to an 8-char fingerprint.
`expected` defaults to False so any un-annotated raw tunnel flags for review.
"""
import json
import os
import subprocess
import sys
import time

INFRA_TENANT = os.environ.get("PXTUNNEL_INFRA_TENANT", "system")
PURPOSES_PATH = os.environ.get("PXTUNNEL_PURPOSES", "/etc/pxtunnel/purposes.yaml")

# Generic interface-name hints (no deployment specifics). `nordlynx` is NordVPN's standard
# interface name; everything else relies on the operator's purposes file.
IFACE_HINTS = {
    "nordlynx": ("NordVPN full-tunnel exit", "normal", True),
}


def run(cmd, timeout=8):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001 - the collector must never crash on one bad source
        return 1, "", str(e)


def fp(pubkey):
    """8-char fingerprint of a WG/node public key (never the full key in the UI)."""
    return (pubkey or "")[:8] if pubkey and pubkey != "(none)" else None


def _keyfp(key):
    """Public node-key fingerprint for the detail view: strips the 'nodekey:' prefix and keeps the
    first 16 hex chars. Node keys are PUBLIC (safe to show); we still never emit the full value."""
    if not key:
        return None
    key = key.split(":", 1)[-1]
    return (key[:16] + "…") if len(key) > 16 else key


def parse_wg_dump():
    """`wg show all dump` -> raw-wg / nordvpn Links (non-Headscale system tunnels)."""
    rc, out, _ = run(["wg", "show", "all", "dump"])
    if rc != 0:
        return []
    links = []
    cur_iface = None
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            cur_iface = parts[0]  # interface self line
            continue
        if len(parts) >= 8 and cur_iface:
            iface = parts[0]
            peer_pub, _psk, endpoint, allowed = parts[1], parts[2], parts[3], parts[4]
            handshake = int(parts[5]) if parts[5].isdigit() else 0
            rx = int(parts[6]) if parts[6].isdigit() else 0
            tx = int(parts[7]) if parts[7].isdigit() else 0
            allowed_list = [a for a in allowed.split(",") if a] if allowed != "(none)" else []
            is_exit = any(a in ("0.0.0.0/0", "::/0") for a in allowed_list)
            layer = "nordvpn" if iface == "nordlynx" else "raw-wg"
            age = (time.time() - handshake) if handshake else None
            status = "offline"
            if handshake:
                status = "online" if age < 180 else ("idle" if age < 900 else "offline")
            links.append({
                "id": f"{layer}:{iface}:{fp(peer_pub)}",
                "layer": layer,
                "tenant": INFRA_TENANT,  # raw WireGuard / VPN = system infrastructure
                "iface": iface,
                "endpoint_b": {"public_endpoint": None if endpoint == "(none)" else endpoint,
                               "pubkey_fp": fp(peer_pub)},
                "subnet": allowed_list,
                "exit_node": is_exit,
                "online": status == "online",
                "status": status,
                "last_handshake": handshake or None,
                "handshake_age_s": int(age) if age is not None else None,
                "throughput": {"rx_bytes": rx, "tx_bytes": tx},
            })
    return links


def parse_headscale_nodes():
    """`headscale nodes list -o json` -> the mesh devices (control plane = primary data)."""
    rc, out, _ = run(["headscale", "nodes", "list", "--output", "json"])
    if rc != 0:
        return []
    try:
        nodes = json.loads(out)
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(nodes, list):  # headscale returns `null` when there are 0 nodes
        return []
    res = []
    for n in nodes:
        ips = n.get("ip_addresses") or []
        res.append({
            "id": f"headscale-node:{n.get('id')}",
            "layer": "headscale-node",
            "tenant": (n.get("user") or {}).get("name") or "default",  # the node's owning tenant
            "iface": "(mesh)",
            "endpoint_b": {"label": n.get("given_name") or n.get("name"),
                           "addr": ips[0] if ips else None, "pubkey_fp": None},
            "subnet": n.get("approved_routes") or [],
            "routes_available": n.get("available_routes") or [],
            "exit_node": any(r in ("0.0.0.0/0", "::/0") for r in (n.get("available_routes") or [])),
            "online": bool(n.get("online")),
            "status": "online" if n.get("online") else "offline",
            "last_seen": n.get("last_seen"),
            "tags": n.get("forced_tags") or n.get("tags") or [],
            "ips": ips,  # full mesh-address list (the list/card view shows only the first)
            # Phase B device-detail fields. All optional: headscale's `nodes list -o json` shape
            # varies by version (OS/client version live in Hostinfo, often absent) — read defensively.
            "node": {
                "created_at": n.get("created_at"),
                "expiry": n.get("expiry"),
                "register_method": n.get("register_method"),
                "node_key_fp": _keyfp(n.get("node_key")),
                "given_name": n.get("given_name"),
                "hostname": n.get("name"),
                "valid_tags": n.get("valid_tags") or [],
                "invalid_tags": n.get("invalid_tags") or [],
                "os": (n.get("hostinfo") or {}).get("os") or n.get("os"),
                "client_version": (n.get("hostinfo") or {}).get("ipn_version") or n.get("client_version"),
            },
        })
    return res


def versions():
    rc, out, _ = run(["headscale", "version"])
    hs = "unknown"
    if rc == 0:
        for ln in out.splitlines():
            if ln.lower().startswith("headscale version"):
                hs = ln.split()[-1]
                break
        else:
            hs = out.strip().split("\n")[0]
    rc2, out2, _ = run(["wg", "--version"])
    wg = out2.strip().split("\n")[0] if rc2 == 0 else "unknown"
    return [
        {"component": "headscale", "current": hs, "channel": "stable"},
        {"component": "wireguard-tools", "current": wg, "channel": "os"},
    ]


def load_purposes():
    """Operator annotation: {link_id: {purpose, criticality, expected, owner_note}}.
    Parsed with PyYAML if available; otherwise no annotations (zero hard pip deps)."""
    data = {"links": {}, "defaults": {"expected": False, "criticality": "normal"}}
    if not os.path.exists(PURPOSES_PATH):
        return data
    try:
        import yaml  # optional
        with open(PURPOSES_PATH) as fh:
            loaded = yaml.safe_load(fh) or {}
        data["links"] = loaded.get("links", {}) or {}
        data["defaults"] = loaded.get("defaults", data["defaults"])
    except Exception:  # noqa: BLE001
        pass
    return data


def annotate(link, purposes):
    pmap = purposes["links"]
    defaults = purposes["defaults"]
    ann = pmap.get(link["id"], {})
    hint = IFACE_HINTS.get(link.get("iface"))
    purpose = ann.get("purpose") or (hint[0] if hint else None)
    criticality = ann.get("criticality") or (hint[1] if hint else defaults.get("criticality"))
    expected = ann.get("expected")
    if expected is None:
        # Headscale-managed nodes are expected by definition; raw tunnels need annotation.
        expected = (hint[2] if hint else (link.get("layer") == "headscale-node"
                                          or defaults.get("expected", False)))
    link["purpose"] = purpose
    link["criticality"] = criticality
    link["expected"] = bool(expected)
    link["owner_note"] = ann.get("owner_note")
    flags = []
    if not expected:
        flags.append("unexpected_peer")
    if link.get("exit_node"):
        flags.append("exit_node")
    if link.get("handshake_age_s") and link["handshake_age_s"] > 900 and expected:
        flags.append("stale_handshake")
    link["security"] = {"overlay_encrypted": True, "flags": flags}
    return link


def main():
    purposes = load_purposes()
    links = []
    for src in (parse_headscale_nodes, parse_wg_dump):
        links.extend(src())
    links = [annotate(l, purposes) for l in links]

    posture = {
        "total": len(links),
        "online": sum(1 for l in links if l["online"]),
        "unexpected": [l["id"] for l in links if not l["expected"]],
        "exit_nodes": [l["id"] for l in links if l.get("exit_node")],
        "stale": [l["id"] for l in links if "stale_handshake" in l["security"]["flags"]],
        "tenants": sorted(set(l.get("tenant", INFRA_TENANT) for l in links)),
    }
    snapshot = {
        "generated_at": int(time.time()),
        "host": os.uname().nodename,
        "links": links,
        "posture": posture,
        "versions": versions(),
    }
    out = json.dumps(snapshot, indent=2)
    if len(sys.argv) > 2 and sys.argv[1] == "--out":
        target = sys.argv[2]
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = target + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(out)
        os.replace(tmp, target)  # atomic
    else:
        print(out)


if __name__ == "__main__":
    main()
