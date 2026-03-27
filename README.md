# 🔴 RedInfra Dashboard

Web UI for managing red team infrastructure built on top of [redinfra](https://github.com/hegusung/redinfra/tree/automation).  
Flask single-file app — no database, no frontend build step, just Python + YAML configs.

---

## Features

- **Dashboard** — overview of all missions (enabled/disabled), node count, quick actions
- **Mission editor** — create/edit missions with multiple AWS nodes, DNS records, ports, services
- **Services per node** — Web, Mail (Postfix + GoPhish), O365, Mythic C2, WebDAV, Responder, RedELK — each configured via YAML editor with toggle
- **Deploy panel** — one-click Deploy All / Destroy, or run individual steps (Terraform, Cloudflare, SendGrid, O365, Routing, Ansible); real-time terminal output via SSE
- **Playbook runner** — run Ansible playbooks per mission/node from the UI
- **Inventory** — live view of AWS instances, Cloudflare DNS records, SendGrid domains/senders, O365 tenants/emails
- **Settings** — configure AWS, Cloudflare, SendGrid, O365 credentials and VPN/routing parameters
- **Mock mode** — works without redinfra installed; configs are saved to `/tmp/redinfra-demo/config/`, deploy simulates output

---

## Requirements

```
Python 3.8+
Flask
PyYAML
```

Optional (for live Inventory):
```
boto3        # AWS instances
msal         # O365 token acquisition
requests     # O365 Graph API calls
```

Install:
```bash
pip install flask pyyaml
pip install boto3 msal requests   # optional, for Inventory
```

---

## Quick Start

### 1. Clone & run

```bash
cd /root/.openclaw/workspace/redinfra-dashboard
python3 app.py
```

The dashboard starts on **http://0.0.0.0:4444**.

> Without redinfra at `/opt/redinfra`, the app runs in **Mock Mode** — all config is saved to `/tmp/redinfra-demo/config/` and deploys are simulated.

### 2. With real redinfra

```bash
export REDINFRA_PATH=/opt/redinfra
python3 app.py
```

---

## Production Deployment (systemd + nginx)

### systemd service

Create `/etc/systemd/system/redinfra-dashboard.service`:

```ini
[Unit]
Description=RedInfra Dashboard (Flask)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/.openclaw/workspace/redinfra-dashboard
ExecStart=/usr/bin/python3 /root/.openclaw/workspace/redinfra-dashboard/app.py
Restart=on-failure
RestartSec=5
Environment=REDINFRA_PATH=/opt/redinfra

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable redinfra-dashboard
sudo systemctl start redinfra-dashboard
sudo systemctl status redinfra-dashboard
```

### nginx reverse proxy

Copy the bundled config:
```bash
sudo cp nginx.conf /etc/nginx/sites-available/redinfra
sudo ln -s /etc/nginx/sites-available/redinfra /etc/nginx/sites-enabled/redinfra
```

Edit `server_name` to match your IP or domain:
```nginx
server_name 192.168.1.50;   # or redinfra.yourdomain.com
```

Test and reload:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

The dashboard is now available on **port 80** (proxied to Flask on 4444).

---

## Configuration

### Environment variable

| Variable | Default | Description |
|---|---|---|
| `REDINFRA_PATH` | `/opt/redinfra` | Path to the redinfra installation. If absent → Mock Mode. |

### Config files (auto-managed)

All configs are YAML files in `$REDINFRA_PATH/config/` (or `/tmp/redinfra-demo/config/` in mock mode).

| File | Description |
|---|---|
| `main.yml` | API credentials (AWS, Cloudflare, SendGrid, O365), VPN/routing, tags |
| `<mission>.yml` | One file per mission: nodes, DNS, ports, enabled flag, Ansible playbooks |

---

## Mission Structure

Each mission YAML follows the redinfra schema:

```yaml
mission: operation-nightfall
enabled: true

c2:
  region: eu-west-1
  instance_type: t3.medium
  local_ip: 192.168.56.10
  ports: [443, 80]
  dns_A: [c2.redteamdomain.com]
  dns_proxy: []
  ansible:
    - playbook: install_mythic.yml
      args:
        mythic_password: Passw0rd!
        github_extensions:
          - https://github.com/MythicC2Profiles/httpx

phishing:
  region: eu-west-3
  instance_type: t2.small
  local_ip: 192.168.56.11
  ports: [443, 80, 25, 587]
  dns_A: [mail.redteamdomain.com]
  dns_proxy: []
  ansible:
    - playbook: install_mail.yml
      args:
        domains:
          - domain: redteamdomain.com
            users:
              - name: John Doe
                mail: john.doe
                password: admin
        sendgrid_password: SG_API_KEY
    - playbook: install_gophish.yml
      args:
        mails: [john.doe@redteamdomain.com]
        web_domains: [phish.redteamdomain.com]
        gophish_rid: token
        gophish_track_uri: /track
        gophish_uris: [/login]
```

---

## Supported Services / Playbooks

| Service | Playbooks | Description |
|---|---|---|
| 🌐 Web | `install_web.yml` | Nginx with geo-filtering, reverse proxy |
| 📧 Mail | `install_mail.yml`, `install_gophish.yml` | Postfix/Dovecot/Roundcube + GoPhish |
| 🔷 O365 | *(Graph API, no playbook)* | Azure AD domains, mailboxes, licenses |
| 💀 Mythic | `install_mythic.yml` | Mythic C2 with optional GitHub extensions |
| 📁 WebDAV | `install_webdav.yml` | Nginx WebDAV with optional Let's Encrypt |
| 🔊 Responder | `install_responder.yml` | LLMNR/NBT-NS poisoner |
| 🦌 RedELK | `install_redelk_c2.yml`, `install_redelk_redirectors.yml` | Centralized logging for C2 and redirectors |

---

## Deploy Steps (individual)

From the **Deploy** page you can run steps independently:

| Button | redinfra command |
|---|---|
| 🏗 Terraform | `redinfra.py auto --apply-terraform` |
| 🌐 Cloudflare | `redinfra.py auto --apply-cloudflare` |
| 📧 SendGrid | `redinfra.py auto --apply-sendgrid` |
| 🔷 O365 | `redinfra.py auto --apply-o365` |
| 🔀 Routing | `redinfra.py auto --apply-routing` |
| 📋 Ansible | `redinfra.py auto --apply-ansible` |
| 🚀 Deploy All | `redinfra.py auto --apply` |
| 💥 Destroy | `redinfra.py auto --destroy` |

All output is streamed live to the built-in terminal via Server-Sent Events.

---

## Project Layout

```
redinfra-dashboard/
├── app.py          # Flask application (single file, self-contained UI)
├── nginx.conf      # nginx reverse proxy config (port 80 → 4444)
└── README.md       # This file
```

---

## Notes

- The app is a **single Python file** — no templates directory, no static folder. HTML/CSS/JS are all inline.
- Tab key is supported in YAML textareas (2-space indent, shift+tab to de-indent).
- The SSE terminal supports ANSI color codes from redinfra output.
- Deleting a mission from the UI **removes the config file only** — cloud resources already deployed are not destroyed automatically. Run Destroy first if needed.

---

## License

Same as [redinfra](https://github.com/hegusung/redinfra) — for authorized red team use only.
