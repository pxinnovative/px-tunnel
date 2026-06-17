# PX Tunnel

### Your private WireGuard mesh shouldn't need a SaaS control plane, or a wiki of `headscale` CLI commands.

**PX Tunnel** is a free, open-source, self-hosted **admin console for [Headscale](https://github.com/juanfont/headscale) + WireGuard**: a Tailscale-style web dashboard you run entirely on your own infrastructure. Manage devices, isolate clients into tenants, set access rules and routing, all from one panel. No SaaS, no lock-in, no telemetry.

```sh
# Enroll a device from the dashboard. It hands you a one-liner to run on the machine:
tailscale up --login-server https://headscale.example.com --authkey <key> --accept-routes
```

For homelabbers, MSPs, agencies and teams who want Tailscale's convenience on a coordinator they own.

> ⭐ If a self-hosted mesh-VPN admin panel sounds useful, **star the repo**. It tells us to keep building in the open.

---

## Why PX Tunnel?

| | **PX Tunnel** | Tailscale (SaaS) | Headscale (alone) | Other Headscale UIs |
|---|---|---|---|---|
| **Cost** | Free, AGPL-3.0 | Free tier + paid | Free | Free |
| **Self-hosted control plane** | ✅ | ❌ (their cloud) | ✅ | ✅ |
| **Web dashboard** | ✅ | ✅ | ❌ (CLI only) | ✅ |
| **Multi-tenant (client/team isolation)** | ✅ built-in | Enterprise | manual | rare |
| **Auth + RBAC (superadmin/admin/viewer)** | ✅ | ✅ | ❌ | varies |
| **Deny-by-default network ACL shipped** | ✅ | ✅ | manual | manual |
| **Per-device naming & typing (icons)** | ✅ | ✅ | ❌ | varies |
| **Dependencies** | Python stdlib + SQLite | n/a | n/a | varies |

Headscale gives you a self-hosted coordinator but only a CLI. PX Tunnel is the missing control panel, built for **running a mesh for other people** (clients, teams, family), with tenant isolation and roles as first-class features.

## Features
- **Devices & tenants:** group nodes into isolated tenants (workspaces); see status, addresses, tags.
- **Add device:** generate a one-line join command (with device name + type) for any machine.
- **Access-control editor:** view, validate and apply the mesh ACL (HuJSON policy) from the console. A built-in example (admin reaches all, clients isolated) gets you a safe policy in one click.
- **Authentication + RBAC:** SQLite logins (PBKDF2-SHA256), server-side revocable sessions. Roles are `superadmin`, `admin` (operate assigned tenants) and `viewer` (read assigned).
- **Deny-by-default network isolation:** a Headscale ACL where each tenant reaches only its own nodes.
- **Node actions:** approve subnet routes, advertise/approve exit nodes, rename, expire, remove.
- **Hardened:** server-side RBAC, no `shell=True`, request-body cap, CIDR validation, least-privilege units.
- **White-label ready:** brand, coordinator URL and the reserved system tenant are all configurable.

## System Requirements
- A host running **[Headscale](https://github.com/juanfont/headscale)** (the CLI socket is reachable).
- **Python 3.11+** (standard library only, zero pip dependencies in the core).
- Linux with systemd (recommended), or any host that can run the Python aggregator + collector.

## Quick Start (systemd on the Headscale host)
```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pxtunnel
sudo usermod -aG headscale pxtunnel                 # access to the headscale CLI socket
sudo mkdir -p /opt/pxtunnel-ui && sudo cp -r api collector web /opt/pxtunnel-ui/
sudo mkdir -p /etc/pxtunnel
sudo cp .env.example /etc/pxtunnel/pxtunnel.env     # edit: set PXTUNNEL_LOGIN_SERVER
sudo chown -R pxtunnel:pxtunnel /etc/pxtunnel
sudo cp deploy/pxtunnel-api.service deploy/pxtunnel-collector.service \
        deploy/pxtunnel-collector.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pxtunnel-collector.timer pxtunnel-api.service
# bootstrap the first admin (password printed once):
sudo -u pxtunnel python3 /opt/pxtunnel-ui/api/pxtunnel_api.py bootstrap-admin <username>
```
The dashboard binds to `127.0.0.1:8807`. Put a TLS reverse proxy in front for remote access and set
`PXTUNNEL_COOKIE_SECURE=1`. Then use **Add device** in the UI and run the generated command on the machine.

## Configuration
Both systemd units load `/etc/pxtunnel/pxtunnel.env`; see [`.env.example`](.env.example). Key vars:
`PXTUNNEL_LOGIN_SERVER` (your Headscale `server_url`), `PXTUNNEL_BRAND` (white-label name),
`PXTUNNEL_INFRA_TENANT` (reserved system tenant), `PXTUNNEL_COOKIE_SECURE`, `PXTUNNEL_BIND`, `PXTUNNEL_DB`.

## Privacy & Security
PX Tunnel is self-hosted and makes **no outbound calls**: no telemetry, no analytics, nothing leaves
your host. Passwords are PBKDF2-SHA256; sessions are server-side and revocable. RBAC is enforced
**server-side**. Network isolation is a separate, deny-by-default Headscale ACL
([`deploy/headscale-acl.hujson`](deploy/headscale-acl.hujson)). See [SECURITY.md](SECURITY.md).

## Community
- ⭐ Star this repo if PX Tunnel is useful to you
- 💬 Join the conversation in [GitHub Discussions](../../discussions)
- 🐛 Report bugs or request features in [GitHub Issues](../../issues)
- 🔧 PRs welcome (see [CONTRIBUTING.md](CONTRIBUTING.md))

We're building in public and want your input. PX Tunnel is part of [PX Open Suite](https://github.com/pxinnovative): free, local-first tools for developers and creators.

## Roadmap
- [x] Auth + RBAC + tenants + deny-by-default ACL + add-device + node actions (v0.0.1)
- [x] Devices model UI: flat device list, list + card views, tenant filter, collapsed "system" infra section (v0.1.0)
- [x] Device detail view: addresses, subnets (approved/awaiting), exit-node, created/expiry/last-seen, node key, tags + actions (v0.2.0)
- [x] Access-control editor: HuJSON policy view / validate / apply, with a starter example (v0.3.0)
- [ ] Users & invites UI (roles, invite by link/email, transfer ownership)
- [ ] Audit logs, DNS & settings, light/dark theme
- [ ] Interactive flow-diagram view of the mesh
- [ ] Client onboarding helpers (one-line installers, QR enrollment)

See [Issues](../../issues) for the full list.

## Support
- **Bug reports:** [GitHub Issues](../../issues)
- **Questions & ideas:** [GitHub Discussions](../../discussions)
- **Buy me a coffee:** [buymeacoffee.com/pxinnovative](https://buymeacoffee.com/pxinnovative)
- **Star the repo:** it helps more than you think

## License
[AGPL-3.0](LICENSE), free to use, modify and distribute. If you run a modified version as a network
service, you must publish your source under the AGPL. A separate commercial license (for closed-source
or SaaS use) may be available from the maintainers.

"PX Tunnel" is a trademark of PX Innovative Solutions Inc. (see [TRADEMARK.md](TRADEMARK.md)).

---

Made with 🛡️ by [Victor Kerber](https://github.com/pxinnovative) @ [PX Innovative Solutions Inc.](https://pxinnovative.com)
