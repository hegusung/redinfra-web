#!/usr/bin/env python3
"""
RedInfra Dashboard - Web UI for Red Team Infrastructure Management
Based on: https://github.com/hegusung/redinfra/tree/automation

Config structure (from lib/config.py):
- mission.yml per mission: mission, enabled, c2/phishing/payloads/responder nodes
  Each node: region, instance_type, ports, local_ip, dns_A, dns_proxy, dns{MX,TXT}, mail, ansible
- main.yml: api{aws_key,aws_secret,cloudflare_key,sendgrid_api,o365[]}, tags, routing, vpn

Deploy: python3 redinfra.py auto --apply (deploys ALL enabled missions at once)
"""
import os, json, subprocess, threading, queue, glob, time
from flask import Flask, render_template_string, request, jsonify, Response
import yaml

app = Flask(__name__)

BASE_PATH = os.environ.get("REDINFRA_PATH", "/opt/redinfra")
MOCK_MODE = not os.path.exists(BASE_PATH)
CONFIG_PATH = "/tmp/redinfra-demo/config" if MOCK_MODE else os.path.join(BASE_PATH, "config")
os.makedirs(CONFIG_PATH, exist_ok=True)

AWS_REGIONS = ["eu-west-1","eu-west-2","eu-west-3","eu-north-1","eu-central-1",
               "us-east-1","us-east-2","us-west-1","us-west-2","ap-southeast-1","ap-northeast-1"]
INSTANCE_TYPES = ["","t2.micro","t2.small","t2.medium","t2.large",
                  "t3.micro","t3.small","t3.medium","t3.large","c5.large","c5.xlarge"]
INSTANCE_TYPE_LABELS = {"": "— No instance —"}
ANSIBLE_PLAYBOOKS = ["install_mail.yml","install_gophish.yml","install_mythic.yml",
                     "install_web.yml","install_webdav.yml","install_responder.yml",
                     "install_vpn.yml","install_redelk_c2.yml","install_redelk_redirectors.yml","install_node.yml"]
NODE_TYPES = ["c2","phishing","payloads","responder"]

def itype_opts(selected=""):
    return "".join(
        '<option value="%s"%s>%s</option>' % (
            t,
            ' selected' if t == selected else '',
            INSTANCE_TYPE_LABELS.get(t, t)
        ) for t in INSTANCE_TYPES
    )

# ─── Data helpers ────────────────────────────────────────────────────────────

def get_missions():
    missions = []
    for f in sorted(glob.glob(os.path.join(CONFIG_PATH, "*.yml"))):
        if os.path.basename(f) in ("main.yml", "aws.yml"):
            continue
        try:
            with open(f) as fh:
                cfg = yaml.safe_load(fh) or {}
            nodes = [k for k in NODE_TYPES if k in cfg]
            missions.append({
                "name": cfg.get("mission", os.path.basename(f).replace(".yml","")),
                "enabled": cfg.get("enabled", False),
                "nodes": nodes,
                "file": f,
            })
        except Exception:
            pass
    return missions

def get_main_config():
    f = os.path.join(CONFIG_PATH, "main.yml")
    if os.path.exists(f):
        with open(f) as fh:
            return yaml.safe_load(fh) or {}
    return {
        "api": {"aws_key":"","aws_secret":"","cloudflare_key":"","sendgrid_api":"","o365":[]},
        "tags": {"Team":"RedTeam","Owner":""},
        "routing": {"vpn_interface":"tap0","iptables_chain":"redinfra","vpn_range":"192.168.40.0/24","rule_start_table":10,"rule_priority":30000},
        "vpn": {"region":"eu-west-1","instance_type":"t2.micro"}
    }

def get_mission_config(name):
    for f in glob.glob(os.path.join(CONFIG_PATH, "*.yml")):
        if os.path.basename(f) in ("main.yml","aws.yml"): continue
        try:
            with open(f) as fh:
                cfg = yaml.safe_load(fh) or {}
            if cfg.get("mission") == name:
                return cfg
        except Exception:
            pass
    return {"mission": name, "enabled": False}

def save_mission(data):
    fname = os.path.join(CONFIG_PATH, "%s.yml" % data["mission"])
    with open(fname, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

def save_main(data):
    with open(os.path.join(CONFIG_PATH, "main.yml"), "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

# ─── Deploy runner ────────────────────────────────────────────────────────────

log_queues = {}

def run_cmd(cmd, qid):
    q = log_queues.get(qid)
    if not q: return
    if MOCK_MODE:
        steps = [
            "\033[34m[*] MOCK MODE — RedInfra not found at %s\033[0m" % BASE_PATH,
            "\033[34m[*] Command: %s\033[0m" % " ".join(cmd),
            "\033[34m[*] Reading all enabled missions from config/...\033[0m",
            "\033[32m[+] Terraform: Creating infrastructure nodes...\033[0m",
            "\033[32m[+] Terraform: apply complete! 3 added, 0 changed, 0 destroyed.\033[0m",
            "\033[34m[*] Cloudflare: Syncing DNS entries...\033[0m",
            "\033[32m[+] Cloudflare: DNS updated.\033[0m",
            "\033[34m[*] SendGrid: Configuring mail senders...\033[0m",
            "\033[32m[+] SendGrid: Done.\033[0m",
            "\033[34m[*] Routing: Applying iptables rules...\033[0m",
            "\033[32m[+] Routing: Done.\033[0m",
            "\033[34m[*] Ansible: Running playbooks...\033[0m",
            "\033[32m[+] Ansible: Playbook install_mail.yml OK\033[0m",
            "\033[32m[+] Ansible: Playbook install_gophish.yml OK\033[0m",
            "\033[32m[✓] All steps complete! (simulation)\033[0m",
        ]
        for s in steps:
            q.put(s); time.sleep(0.6)
        q.put(None); return
    try:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            cmd, cwd=BASE_PATH, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
            env=env
        )
        for line in proc.stdout:
            q.put(line.rstrip())
        proc.wait()
        rc = proc.returncode
        if rc != 0:
            q.put("\033[31m[!] Process exited with code %d\033[0m" % rc)
        q.put(None)
    except Exception as e:
        q.put("\033[31m[!] Error: %s\033[0m" % str(e))
        q.put(None)

# ─── HTML ────────────────────────────────────────────────────────────────────

CSS = """
<style>
:root{{--bg:#0a0c0f;--bg2:#111318;--bg3:#1a1d23;--border:#252930;--green:#00ff88;--red:#ff4444;--orange:#ff8800;--blue:#4488ff;--purple:#aa44ff;--text:#c8d0dc;--text2:#7a8494}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:monospace;min-height:100vh}}
a{{color:var(--green);text-decoration:none}}a:hover{{text-decoration:underline}}
nav{{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:28px;height:52px}}
nav .logo{{color:var(--red);font-size:1.1em;font-weight:bold;letter-spacing:2px;margin-right:8px}}
nav a{{color:var(--text2);font-size:.85em;padding:16px 0;border-bottom:2px solid transparent;display:inline-block}}
nav a:hover,nav a.active{{color:var(--green);border-bottom-color:var(--green);text-decoration:none}}
nav .mock{{margin-left:auto;color:var(--orange);font-size:.75em}}
.wrap{{max-width:1200px;margin:0 auto;padding:28px 24px}}
h1{{font-size:1.35em;color:var(--green);margin-bottom:22px}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:14px}}
.card-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
.card-title{{color:var(--text);font-weight:bold}}
.btn{{display:inline-flex;align-items:center;gap:5px;padding:7px 14px;border-radius:6px;border:1px solid;cursor:pointer;font-family:monospace;font-size:.8em;font-weight:bold;transition:all .15s;text-decoration:none}}
.btn-g{{background:rgba(0,255,136,.1);border-color:var(--green);color:var(--green)}}.btn-g:hover{{background:rgba(0,255,136,.2)}}
.btn-r{{background:rgba(255,68,68,.1);border-color:var(--red);color:var(--red)}}.btn-r:hover{{background:rgba(255,68,68,.2)}}
.btn-o{{background:rgba(255,136,0,.1);border-color:var(--orange);color:var(--orange)}}.btn-o:hover{{background:rgba(255,136,0,.2)}}
.btn-s{{background:rgba(122,132,148,.1);border-color:var(--text2);color:var(--text2)}}.btn-s:hover{{background:rgba(122,132,148,.2)}}
.btn-b{{background:rgba(68,136,255,.1);border-color:var(--blue);color:var(--blue)}}.btn-b:hover{{background:rgba(68,136,255,.2)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.72em;font-weight:bold}}
.bg{{background:rgba(0,255,136,.15);color:var(--green);border:1px solid rgba(0,255,136,.3)}}
.br{{background:rgba(255,68,68,.15);color:var(--red);border:1px solid rgba(255,68,68,.3)}}
.bb{{background:rgba(68,136,255,.15);color:var(--blue);border:1px solid rgba(68,136,255,.3)}}
.fg{{color:var(--text2);font-size:.8em;margin-bottom:6px;display:block;letter-spacing:.4px}}
input,select,textarea{{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);font-family:monospace;font-size:.85em;outline:none;transition:border-color .15s;margin-bottom:0}}
input:focus,select:focus,textarea:focus{{border-color:var(--green)}}
.fg-group{{margin-bottom:14px}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}}
/* Tabs */
.tabs{{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:18px}}
.tab{{padding:9px 18px;cursor:pointer;color:var(--text2);font-size:.83em;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s;user-select:none}}
.tab:hover{{color:var(--text)}}
.tab.on{{color:var(--green);border-bottom-color:var(--green)}}
.pane{{display:none}}.pane.on{{display:block}}
/* Chips */
.chips{{display:flex;flex-wrap:wrap;gap:5px;align-items:center;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:5px 10px;min-height:38px;cursor:text}}
.chips:focus-within{{border-color:var(--green)}}
.chip{{display:inline-flex;align-items:center;gap:3px;border-radius:10px;padding:2px 9px;font-size:.76em}}
.chip-g{{background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:var(--green)}}
.chip-b{{background:rgba(68,136,255,.1);border:1px solid rgba(68,136,255,.3);color:var(--blue)}}
.chip button{{background:none;border:none;cursor:pointer;padding:0;line-height:1;font-size:1em;color:inherit}}
.chips input{{background:none;border:none;outline:none;flex:1;min-width:70px;color:var(--text);font-size:.85em;padding:0;margin:0}}
/* Table */
.dt{{width:100%;border-collapse:collapse}}
.dt th{{text-align:left;color:var(--text2);font-size:.75em;padding:5px 8px;border-bottom:1px solid var(--border)}}
.dt td{{padding:5px 8px;vertical-align:top}}
.dt td input,.dt td select{{padding:5px 8px;margin:0}}
/* Terminal */
.term{{background:#000;border:1px solid var(--border);border-radius:8px;padding:14px;font-family:monospace;font-size:.82em;height:420px;overflow-y:auto;line-height:1.6}}
.tg{{color:#00ff88}}.tr{{color:#ff4444}}.tb{{color:#4488ff}}.ty{{color:#ffcc00}}.tw{{color:#c8d0dc}}
/* Mission row */
.mrow{{display:flex;align-items:center;justify-content:space-between;padding:13px 18px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin-bottom:9px}}
.mrow:hover{{border-color:#30363d}}
.ntag{{font-size:.68em;padding:1px 6px;border-radius:4px;background:var(--bg3);color:var(--text2);border:1px solid var(--border)}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}}
.stat{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:15px;text-align:center}}
.stat .n{{font-size:2em;font-weight:bold}}
.stat .l{{color:var(--text2);font-size:.74em;margin-top:3px}}
.banner{{background:rgba(255,136,0,.1);border:1px solid var(--orange);border-radius:6px;padding:9px 14px;margin-bottom:18px;color:var(--orange);font-size:.82em}}
hr{{border:none;border-top:1px solid var(--border);margin:18px 0}}
.toggle{{position:relative;display:inline-block;width:42px;height:22px}}
.toggle input{{opacity:0;width:0;height:0}}
.slider{{position:absolute;cursor:pointer;inset:0;background:#2a2d33;border-radius:22px;transition:.25s}}
.slider:before{{position:absolute;content:"";height:16px;width:16px;left:3px;bottom:3px;background:var(--text2);border-radius:50%;transition:.25s}}
input:checked+.slider{{background:rgba(0,255,136,.3)}}
input:checked+.slider:before{{transform:translateX(20px);background:var(--green)}}
.tlabel{{display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-size:.85em}}
</style>
"""

NAV_TPL = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RedInfra — {title}</title>
""" + CSS + """
</head><body>
<nav>
  <span class="logo">🔴 REDINFRA</span>
  <a href="/" {a_dash}>Dashboard</a>
  <a href="/mission/new" {a_mission}>New Mission</a>
  <a href="/deploy" {a_deploy}>Deploy</a>
  <a href="/inventory" {a_inventory}>Inventory</a>
  <a href="/settings" {a_settings}>Settings</a>
  {mock}
</nav>
<script>
function chips_add(id, cls) {{
  var c = document.getElementById(id);
  var inp = c.querySelector('input');
  var v = inp.value.trim();
  if (!v) return;
  var s = document.createElement('span');
  s.className = 'chip ' + cls;
  s.dataset.v = v;
  s.innerHTML = v + ' <button type="button" onclick="this.parentElement.remove()">×</button>';
  c.insertBefore(s, inp);
  inp.value = '';
}}
function chips_get(id) {{
  return Array.from(document.querySelectorAll('#'+id+' .chip')).map(function(c){{return c.dataset.v;}});
}}
document.addEventListener('keydown', function(e) {{
  if (e.key !== 'Enter') return;
  var inp = e.target;
  if (!inp.classList || !inp.classList.contains('chips-inp')) return;
  e.preventDefault();
  chips_add(inp.getAttribute('data-chips-id'), inp.getAttribute('data-chips-cls'));
}});
document.addEventListener('keydown', function(e) {{
  if (e.key !== 'Tab') return;
  var el = e.target;
  if (el.tagName !== 'TEXTAREA') return;
  e.preventDefault();
  var spaces = '  ';
  var start = el.selectionStart;
  var end = el.selectionEnd;
  var val = el.value;
  if (start !== end) {{
    var lineStart = val.lastIndexOf('\\n', start - 1) + 1;
    var lineEnd = val.indexOf('\\n', end);
    if (lineEnd === -1) lineEnd = val.length;
    var lines = val.substring(lineStart, lineEnd).split('\\n');
    var newLines = e.shiftKey
      ? lines.map(function(l){{ return l.startsWith(spaces) ? l.slice(2) : l; }})
      : lines.map(function(l){{ return spaces + l; }});
    var replaced = newLines.join('\\n');
    el.value = val.substring(0, lineStart) + replaced + val.substring(lineEnd);
    el.selectionStart = lineStart;
    el.selectionEnd = lineStart + replaced.length;
  }} else {{
    if (e.shiftKey) {{
      var lineStart = val.lastIndexOf('\\n', start - 1) + 1;
      if (val.substring(lineStart, lineStart + 2) === spaces) {{
        el.value = val.substring(0, lineStart) + val.substring(lineStart + 2);
        el.selectionStart = el.selectionEnd = Math.max(lineStart, start - 2);
      }}
    }} else {{
      el.value = val.substring(0, start) + spaces + val.substring(end);
      el.selectionStart = el.selectionEnd = start + 2;
    }}
  }}
}});
function tab_switch(grp, id) {{
  document.querySelectorAll('[data-grp="'+grp+'"]').forEach(function(el){{
    el.classList.toggle('on', el.dataset.tab === id);
  }});
}}
function strip_ansi(s) {{
  return s.replace(/\\x1b\[[0-9;]*m/g,'').replace(/\\033\[[0-9;]*m/g,'');
}}
function line_class(l) {{
  if (l.indexOf('[+]')>=0||l.indexOf('\\033[32m')>=0) return 'tg';
  if (l.indexOf('[!]')>=0||l.indexOf('ERROR')>=0||l.indexOf('failed')>=0) return 'tr';
  if (l.indexOf('[*]')>=0||l.indexOf('\\033[34m')>=0) return 'tb';
  if (l.indexOf('WARN')>=0||l.indexOf('\\033[33m')>=0) return 'ty';
  return 'tw';
}}
</script>
<div class="wrap">BODY_PLACEHOLDER</div>
</body></html>"""

def nav(title, page, body):
    pages = {"dash":"","mission":"","deploy":"","inventory":"","settings":""}
    pages[page] = 'class="active"'
    mock = '<span class="mock">⚠ MOCK MODE</span>' if MOCK_MODE else ''
    return (NAV_TPL
        .format(
            title=title,
            a_dash=pages["dash"], a_mission=pages["mission"],
            a_deploy=pages["deploy"], a_inventory=pages["inventory"],
            a_settings=pages["settings"],
            mock=mock,
        )
        .replace("BODY_PLACEHOLDER", body)
    )

# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    missions = get_missions()
    total_nodes = sum(len(m["nodes"]) for m in missions)
    enabled = sum(1 for m in missions if m["enabled"])
    rows = ""
    for m in missions:
        badge = '<span class="badge bg">ENABLED</span>' if m["enabled"] else '<span class="badge br">DISABLED</span>'
        rows += """
        <div class="mrow">
          <div style="font-weight:bold">%s</div>
          <div style="display:flex;align-items:center;gap:10px">
            %s
            <a href="/mission/%s/edit" class="btn btn-s">✏ Edit</a>
            <button onclick="deleteMission('%s')" class="btn btn-r">🗑 Delete</button>
          </div>
        </div>""" % (m["name"], badge, m["name"], m["name"])
    if not rows:
        rows = '<div style="text-align:center;padding:40px;color:var(--text2)">No missions yet. <a href="/mission/new">Create your first →</a></div>'

    mock_banner = '<div class="banner">⚠ Mock mode — configs saved to /tmp/redinfra-demo/config/</div>' if MOCK_MODE else ''

    modal = """
    <div id="modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;align-items:center;justify-content:center">
      <div style="background:#111318;border:1px solid #ff4444;border-radius:10px;padding:28px 32px;max-width:420px;box-shadow:0 0 40px rgba(255,68,68,.15)">
        <div style="font-size:1.4em;margin-bottom:10px">⚠️ Delete Mission</div>
        <div style="color:#c8d0dc;margin-bottom:6px;font-size:.88em">You are about to delete:</div>
        <div style="background:#1a1d23;border:1px solid #252930;border-radius:6px;padding:8px 14px;color:#00ff88;margin-bottom:14px;font-weight:bold" id="modal-name"></div>
        <div style="color:#7a8494;font-size:.82em;margin-bottom:20px;line-height:1.7">
          This will <b style="color:#ff4444">permanently remove the config file</b>.<br>
          Cloud resources already deployed will <b style="color:#ff4444">NOT be destroyed</b> automatically.<br>
          Run Destroy first if needed.
        </div>
        <div style="display:flex;gap:10px;justify-content:flex-end">
          <button class="btn btn-s" onclick="document.getElementById('modal').style.display='none'">Cancel</button>
          <button class="btn btn-r" id="modal-confirm">🗑 Confirm Delete</button>
        </div>
      </div>
    </div>"""

    delete_js = """
    <script>
    function deleteMission(name) {
      document.getElementById('modal-name').textContent = name;
      document.getElementById('modal').style.display = 'flex';
      document.getElementById('modal-confirm').onclick = function() {
        document.getElementById('modal').style.display = 'none';
        fetch('/api/mission/delete', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mission:name})}).then(function(r){return r.json();}).then(function(d){if(d.ok)window.location.reload();else alert('Error: '+d.error);});
      };
    }
    document.addEventListener('keydown', function(e){ if(e.key==='Escape') document.getElementById('modal').style.display='none'; });
    </script>"""

    body = (
        modal +
        "<h1>📡 Dashboard</h1>" +
        mock_banner +
        '<div class="stats">'
        '<div class="stat"><div class="n" style="color:var(--green)">' + str(len(missions)) + '</div><div class="l">MISSIONS</div></div>'
        '<div class="stat"><div class="n" style="color:var(--green)">' + str(enabled) + '</div><div class="l">ENABLED</div></div>'
        '<div class="stat"><div class="n" style="color:var(--red)">' + str(len(missions)-enabled) + '</div><div class="l">DISABLED</div></div>'
        '<div class="stat"><div class="n" style="color:var(--blue)">' + str(total_nodes) + '</div><div class="l">TOTAL NODES</div></div>'
        '</div>'
        '<div class="card"><div class="card-head"><span class="card-title">Missions</span>'
        '<a href="/mission/new" class="btn btn-g">+ New Mission</a></div>' +
        rows +
        '</div>'
        '<div class="card" style="font-size:.8em;color:var(--text2);line-height:1.7">'
        '<b style="color:var(--text)">ℹ Deploy behavior:</b> All <span style="color:var(--green)">enabled</span> missions are deployed together. Enable/disable them before deploying.'
        '</div>' +
        delete_js
    )
    return nav("Dashboard", "dash", body)

# ─── Services / Playbooks ─────────────────────────────────────────────────────

SERVICES = [
    {
        "id":    "web",
        "label": "🌐 Web Server",
        "playbooks": ["install_web.yml"],
        "fields": [
            ("web_domains", "WEB DOMAINS", "chips", "payload.domain.com", []),
        ],
    },
    {
        "id":    "mail",
        "label": "📧 Mail",
        "playbooks": ["install_mail.yml", "install_gophish.yml"],
        "fields": [
            ("mail_domains",      "MAIL DOMAINS & USERS",  "domains_table", "", []),
            ("mail_sendgrid_pw",  "SENDGRID API KEY",       "password",  "sg-...", ""),
            ("gophish_mails",     "GOPHISH — SENDING EMAILS",  "chips", "john@domain.com", []),
            ("gophish_webdomains","GOPHISH — WEB DOMAINS",      "chips", "phish.domain.com", []),
            ("gophish_rid",       "GOPHISH — RID PARAM",        "text",  "token", "rid"),
            ("gophish_track_uri", "GOPHISH — TRACKING URI",     "text",  "/track", "/track"),
            ("gophish_uris",      "GOPHISH — PHISHING URIs",    "chips", "/login", []),
        ],
    },
    {
        "id":    "o365",
        "label": "🔷 O365",
        "playbooks": [],
        "fields": [
            ("o365_tenant",  "TENANT ID",     "text",     "xxxxxxxx-...", ""),
            ("o365_client",  "CLIENT ID",     "text",     "xxxxxxxx-...", ""),
            ("o365_secret",  "CLIENT SECRET", "password", "",             ""),
            ("o365_domains", "DOMAINS",       "chips",    "evil.com",     []),
        ],
    },
    {
        "id":    "mythic",
        "label": "💀 Mythic",
        "playbooks": ["install_mythic.yml"],
        "fields": [
            ("mythic_password",   "ADMIN PASSWORD",    "password", "changeme", ""),
            ("mythic_extensions", "GITHUB EXTENSIONS", "chips",    "https://github.com/...", []),
        ],
    },
    {
        "id":    "webdav",
        "label": "📁 WebDAV",
        "playbooks": ["install_webdav.yml"],
        "fields": [
            ("webdav_domains", "WEBDAV DOMAINS", "chips", "webdav.domain.com", []),
        ],
    },
    {
        "id":    "responder",
        "label": "🔊 Responder",
        "playbooks": ["install_responder.yml"],
        "fields": [],
    },
    {
        "id":    "redelk",
        "label": "🦌 RedELK",
        "playbooks": ["install_redelk_c2.yml", "install_redelk_redirectors.yml"],
        "fields": [],
    },
    {
        "id":    "custom",
        "label": "⚙ Custom",
        "playbooks": ["__custom__"],
        "fields": [],
    },
]

def _svc_field_html(svc_id, field_id, label, ftype, placeholder, default, existing):
    uid = "svc_%s_%s" % (svc_id, field_id)
    val = existing.get(field_id, default)

    if ftype in ("text",):
        return (
            '<div class="fg-group"><label class="fg">%s</label>'
            '<input type="text" id="%s" value="%s" placeholder="%s"></div>'
        ) % (label, uid, val or "", placeholder)

    elif ftype == "password":
        return (
            '<div class="fg-group"><label class="fg">%s</label>'
            '<input type="password" id="%s" value="%s" placeholder="%s"></div>'
        ) % (label, uid, val or "", placeholder)

    elif ftype == "chips":
        chips = "".join(
            '<span class="chip chip-g" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">x</button></span>' % (v, v)
            for v in (val if isinstance(val, list) else [])
        )
        return (
            '<div class="fg-group"><label class="fg">%s <small>(Enter)</small></label>'
            '<div class="chips" id="%s" onclick="this.querySelector(\'input\').focus()">%s'
            '<input type="text" placeholder="%s" '
            'onkeydown="if(event.key===\'Enter\'){event.preventDefault();chips_add(\'%s\',\'chip chip-g\')}"></div></div>'
        ) % (label, uid, chips, placeholder, uid)

    elif ftype == "domains_table":
        rows = ""
        for dom in (val if isinstance(val, list) else []):
            for usr in dom.get("users", []):
                rows += (
                    '<tr>'
                    '<td><input type="text" value="%s" placeholder="domain.com"></td>'
                    '<td><input type="text" value="%s" placeholder="John Doe"></td>'
                    '<td><input type="text" value="%s" placeholder="john"></td>'
                    '<td><input type="password" value="%s" placeholder="password"></td>'
                    '<td><button type="button" onclick="this.parentElement.parentElement.remove()" '
                    'style="background:none;border:none;color:var(--red);cursor:pointer">x</button></td>'
                    '</tr>'
                ) % (dom.get("domain",""), usr.get("name",""), usr.get("mail",""), usr.get("password",""))
        return (
            '<div class="fg-group"><label class="fg">%s</label>'
            '<table class="dt"><thead><tr><th>Domain</th><th>Full Name</th><th>Mailbox</th><th>Password</th><th></th></tr></thead>'
            '<tbody id="%s">%s</tbody></table>'
            '<button type="button" class="btn btn-s" style="margin-top:6px;font-size:.76em" '
            'onclick="addRow(\'%s\',\'<td><input type=text placeholder=domain.com></td>'
            '<td><input type=text placeholder=John Doe></td>'
            '<td><input type=text placeholder=john></td>'
            '<td><input type=password placeholder=password></td>\')">+ User</button>'
            '</div>'
        ) % (label, uid, rows, uid)

    return ""

SVC_YAML_TEMPLATES = {
    "web": """\
# install_web.yml — Nginx web server
web_domains:
  - site: www.redteamdomain.com
    locations:
      - location: /payloads/
        fallback_path: /
        allow:
          country:
            - ES
          ASN: []
        disallow:
          country: []
          ASN:
            - Microsoft
            - AWS
            - Google
      - location: /c2/
        proxy: http://127.0.0.1:82
""",
    "mail": """\
# install_mail.yml — Postfix/Dovecot/Roundcube + SendGrid
domains:
  - domain: redteamdomain.com
    users:
      - name: John Doe
        mail: john.doe
        password: admin
sendgrid_password: SENDGRID_API

# install_gophish.yml — GoPhish phishing framework
mails:
  - john.doe@redteamdomain.com
web_domains:
  - test2.redteamdomain.com
gophish_rid: token
gophish_track_uri: /product
gophish_uris:
  - /login
""",
    "o365": """\
# O365 config — per node (phishing)
o365:
  tenant_id: <TENANT_UUID>
  domains:
    - domain: redteamdomain.com
      services:
        - Email
        - OfficeCommunicationsOnline
      emails:
        - name: "John Doe"
          email: john@redteamdomain.com
          password: Passw0rd!
          usageLocation: US
""",
    "mythic": """\
# install_mythic.yml — Mythic C2 framework
mythic_password: Passw0rd!
github_extensions:
  - https://github.com/MythicC2Profiles/httpx
  - https://github.com/MythicC2Profiles/smb
  - https://github.com/MythicC2Profiles/tcp
local_extensions:
  - CustomContainer
""",
    "webdav": """\
# install_webdav.yml — Nginx WebDAV server
web_domains:
  - site: webdav.domain.com
    letsencrypt: true
    letsencrypt_email: "admin@domain.com"
    backend_name: webdav
    fallback_path: https://google.com/
    allow:
      country:
        - ES
      ASN: []
    disallow:
      country: []
      ASN: []
""",
    "responder": """\
# install_responder.yml — Responder (LLMNR/NBT-NS poisoner)
# No arguments required
""",
    "redelk": """\
# install_redelk_redirectors.yml
redirector_tgz: redirs.tgz
filebeatid: c2
scenario_name: test_scenario
redelk_url: 192.168.1.52:5044

# install_redelk_c2.yml
c2_tgz: c2servers.tgz
filebeatid: c2
scenario_name: test_scenario
redelk_url: 192.168.1.52:5044
""",
    "custom": """\
# Playbooks custom — liste libre
# Ajouter autant d'entrées que nécessaire
- playbook: mon_playbook.yml
  args:
    variable: valeur
    autre_var: autre_valeur
# - playbook: second_playbook.yml
#   args: {}
""",
}

def build_services_section(cfg):
    # Collect existing ansible from all nodes
    existing_by_svc = {}
    skip = {"mission","enabled"}
    for key, val in cfg.items():
        if key in skip or not isinstance(val, dict): continue
        for pb in val.get("ansible", []):
            for svc in SERVICES:
                if pb["playbook"] in svc["playbooks"]:
                    if svc["id"] not in existing_by_svc:
                        existing_by_svc[svc["id"]] = {"_node": key, "args": {}}
                    existing_by_svc[svc["id"]]["args"].update(pb.get("args", {}))

    tabs_html = '<div class="tabs" style="margin-bottom:0">'
    panes_html = ""

    for i, svc in enumerate(SERVICES):
        on = " on" if i == 0 else ""
        tabs_html += (
            '<div class="tab%s" data-grp="svc" data-tab="%s" onclick="tab_switch(\'svc\',\'%s\')">%s</div>'
        ) % (on, svc["id"], svc["id"], svc["label"])

        existing = existing_by_svc.get(svc["id"], {})
        existing_node = existing.get("_node", "")
        existing_args = existing.get("args", {})

        # If existing args, show them; otherwise show the template
        if existing_args:
            yaml_content = yaml.dump(existing_args, default_flow_style=False, allow_unicode=True)
        else:
            yaml_content = SVC_YAML_TEMPLATES.get(svc["id"], "# No arguments\n")

        # Enable toggle
        is_enabled = bool(existing)
        enabled_checked = "checked" if is_enabled else ""
        toggle = (
            '<label class="tlabel" style="margin-bottom:14px;display:flex">'
            '<div class="toggle"><input type="checkbox" id="svc_' + svc["id"] + '_enabled" ' + enabled_checked + '>'
            '<span class="slider"></span></div>'
            '<span style="color:var(--text2);font-size:.85em"> Enable this service</span>'
            '</label>'
        )

        # Target node selector (not for O365)
        node_sel = ""
        if svc["id"] != "o365":
            node_sel = (
                '<div class="fg-group"><label class="fg">TARGET NODE <small>(server_type name)</small></label>'
                '<input type="text" id="svc_' + svc["id"] + '_node" value="' + existing_node + '" placeholder="c2 / phishing / redirector1"></div>'
            )

        # YAML textarea
        yaml_area = (
            '<div class="fg-group"><label class="fg">CONFIGURATION <small style="color:var(--text2)">(YAML)</small></label>'
            '<textarea id="svc_' + svc["id"] + '_yaml" style="height:180px;font-size:.82em;font-family:monospace;line-height:1.5">'
            + yaml_content +
            '</textarea></div>'
        )

        pane_content = toggle + node_sel + yaml_area
        panes_html += '<div class="pane%s" data-grp="svc" data-tab="%s">%s</div>' % (on, svc["id"], pane_content)

    tabs_html += '</div>'
    return tabs_html + panes_html

# ─── Mission Form ─────────────────────────────────────────────────────────────

def build_node_pane(node, cfg, color, is_new=False):
    nc = cfg.get(node, {})
    # Region select
    reg_opts = "".join('<option value="%s"%s>%s</option>' % (r, ' selected' if nc.get("region")==r else '', r) for r in AWS_REGIONS)
    # Instance type select
    it_opts = itype_opts(nc.get("instance_type",""))
    # Chips
    port_chips = "".join('<span class="chip chip-b" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">×</button></span>' % (p,p) for p in nc.get("ports",[]))
    dnsa_chips = "".join('<span class="chip chip-g" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">×</button></span>' % (d,d) for d in nc.get("dns_A",[]))
    dnsp_chips = "".join('<span class="chip chip-g" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">×</button></span>' % (d,d) for d in nc.get("dns_proxy",[]))
    # MX rows (phishing only)
    mx_rows = ""
    if node == "phishing":
        for e in nc.get("dns",{}).get("MX",[]):
            mx_rows += '<tr><td><input type="text" value="%s"></td><td><input type="text" value="%s"></td><td><button type="button" onclick="this.closest(\'tr\').remove()" style="background:none;border:none;color:var(--red);cursor:pointer;font-size:1.1em">×</button></td></tr>' % (e.get("key",""),e.get("value",""))
        mail_rows = ""
        for m in nc.get("mail",[]):
            mail_rows += '<tr><td><input type="text" value="%s"></td><td><input type="text" value="%s"></td><td><button type="button" onclick="this.closest(\'tr\').remove()" style="background:none;border:none;color:var(--red);cursor:pointer">×</button></td></tr>' % (m.get("mail",""),m.get("name",""))
    pass  # ansible handled in services section

    # New mission: C2 is visible/checked by default; edit: follow config
    default_on = is_new and node == "c2"
    active = "checked" if (nc or default_on) else ""
    show = "" if (nc or default_on) else 'style="display:none"'

    phishing_extra = ""
    if node == "phishing":
        phishing_extra = """
        <hr>
        <div class="fg-group"><label class="fg">MX DNS ENTRIES</label>
        <table class="dt"><thead><tr><th>Key (domain)</th><th>Value (mx host)</th><th></th></tr></thead>
        <tbody id="%(n)s_mx">%(mx_rows)s</tbody></table>
        <button type="button" class="btn btn-s" style="margin-top:7px;font-size:.76em" onclick="addRow('%(n)s_mx','<td><input type=text placeholder=domain.com></td><td><input type=text placeholder=mx.domain.com></td>')">+ MX</button>
        </div>
        <div class="fg-group"><label class="fg">MAIL SENDERS</label>
        <table class="dt"><thead><tr><th>Email</th><th>Name</th><th></th></tr></thead>
        <tbody id="%(n)s_mail">%(mail_rows)s</tbody></table>
        <button type="button" class="btn btn-s" style="margin-top:7px;font-size:.76em" onclick="addRow('%(n)s_mail','<td><input type=text placeholder=john@domain.com></td><td><input type=text placeholder=John Doe></td>')">+ Sender</button>
        </div>""" % {"n": node, "mx_rows": mx_rows, "mail_rows": mail_rows}

    return """
    <div class="card">
      <div class="card-head">
        <span class="card-title" style="color:%(color)s">%(emoji)s %(NODE)s Node</span>
        <label class="tlabel">
          <div class="toggle"><input type="checkbox" id="%(n)s_on" %(active)s onchange="toggleNode('%(n)s',this.checked)"><span class="slider"></span></div>
          Include
        </label>
      </div>
      <div id="%(n)s_fields" %(show)s>
        <div class="g3">
          <div class="fg-group"><label class="fg">AWS REGION</label><select id="%(n)s_region">%(reg_opts)s</select></div>
          <div class="fg-group"><label class="fg">INSTANCE TYPE</label><select id="%(n)s_itype">%(it_opts)s</select></div>
          <div class="fg-group"><label class="fg">LOCAL IP</label><input type="text" id="%(n)s_lip" value="%(lip)s" placeholder="192.168.56.110"></div>
        </div>
        <div class="g3">
          <div class="fg-group"><label class="fg">PORTS <small>(Enter)</small></label>
            <div class="chips" id="%(n)s_ports" onclick="this.querySelector('input').focus()">%(port_chips)s<input type="text" placeholder="443" onkeydown="if(event.key==='Enter'){event.preventDefault();chips_add('%(n)s_ports','chip chip-b')}"></div>
          </div>
          <div class="fg-group"><label class="fg">DNS A RECORDS <small>(Enter)</small></label>
            <div class="chips" id="%(n)s_dnsa" onclick="this.querySelector('input').focus()">%(dnsa_chips)s<input type="text" placeholder="c2.domain.com" onkeydown="if(event.key==='Enter'){event.preventDefault();chips_add('%(n)s_dnsa','chip chip-g')}"></div>
          </div>
          <div class="fg-group"><label class="fg">DNS PROXY RECORDS <small>(Enter)</small></label>
            <div class="chips" id="%(n)s_dnsp" onclick="this.querySelector('input').focus()">%(dnsp_chips)s<input type="text" placeholder="proxy.domain.com" onkeydown="if(event.key==='Enter'){event.preventDefault();chips_add('%(n)s_dnsp','chip chip-g')}"></div>
          </div>
        </div>
        %(phishing_extra)s
      </div>
    </div>""" % {
        "n": node, "NODE": node.upper(), "color": color,
        "emoji": {"c2":"💀","phishing":"🎣","payloads":"📦","responder":"🔊"}.get(node,""),
        "active": active, "show": show,
        "reg_opts": reg_opts, "it_opts": it_opts,
        "lip": nc.get("local_ip",""),
        "port_chips": port_chips, "dnsa_chips": dnsa_chips, "dnsp_chips": dnsp_chips,
        "phishing_extra": phishing_extra,
    }

@app.route("/mission/new")
def mission_new():
    return mission_form({}, False)

@app.route("/mission/<name>/edit")
def mission_edit(name):
    return mission_form(get_mission_config(name), True)

def mission_form(cfg, edit):
    # Extract existing nodes from config (all keys except mission/enabled)
    skip = {"mission","enabled"}
    existing_nodes = []
    for key, val in cfg.items():
        if key in skip: continue
        if isinstance(val, dict) and ("region" in val or "o365" in val or "ansible" in val):
            existing_nodes.append((key, val))

    # If new mission, start with one empty node
    if not existing_nodes:
        existing_nodes = [("", {})]

    enabled_checked = "checked" if cfg.get("enabled") else ""
    title_text = "Edit Mission: %s" % cfg.get("mission","") if edit else "New Mission"
    name_ro = 'readonly style="opacity:.6"' if edit else ''
    elabel_color = "var(--green)" if cfg.get("enabled") else "var(--text2)"
    elabel_text  = "ENABLED" if cfg.get("enabled") else "DISABLED"
    title_prefix = "✏ " if edit else "+ "

    # Build nodes HTML
    reg_opts_html = "".join('<option value="%s">%s</option>' % (r,r) for r in AWS_REGIONS)
    it_opts_html  = "".join('<option value="%s">%s</option>' % (t,t) for t in INSTANCE_TYPES)

    def node_services_html(idx, nc):
        """Build the services/playbooks tabs for a specific node."""
        # Get existing ansible entries for this node
        existing_by_svc = {}
        known_playbooks = {pb for svc in SERVICES for pb in svc["playbooks"] if pb != "__custom__"}
        custom_entries = []
        for pb in nc.get("ansible", []):
            matched = False
            for svc in SERVICES:
                if pb["playbook"] in svc["playbooks"]:
                    if svc["id"] not in existing_by_svc:
                        existing_by_svc[svc["id"]] = {}
                    existing_by_svc[svc["id"]].update(pb.get("args", {}))
                    matched = True
                    break
            if not matched:
                custom_entries.append(pb)
        if custom_entries:
            existing_by_svc["custom"] = custom_entries  # list — handled separately below
        # O365 is stored directly in node config, not in ansible
        if "o365" in nc:
            existing_by_svc["o365"] = {"o365": nc["o365"]}

        tabs = ""
        panes = ""
        for i, svc in enumerate(SERVICES):
            on = " on" if i == 0 else ""
            tab_id = "n%s_%s" % (idx, svc["id"])
            tabs += (
                '<div class="tab%s" data-grp="nsvc%s" data-tab="%s" onclick="tab_switch(\'nsvc%s\',\'%s\')">%s</div>'
            ) % (on, idx, tab_id, idx, tab_id, svc["label"])

            existing_args = existing_by_svc.get(svc["id"], {})
            if svc["id"] == "custom":
                if existing_args:
                    # existing_args is a list of playbook entries
                    yaml_content = yaml.dump(existing_args, default_flow_style=False, allow_unicode=True)
                else:
                    yaml_content = SVC_YAML_TEMPLATES.get("custom", "")
            elif existing_args:
                yaml_content = yaml.dump(existing_args, default_flow_style=False, allow_unicode=True)
            else:
                yaml_content = SVC_YAML_TEMPLATES.get(svc["id"], "# No arguments\n")

            is_enabled = svc["id"] in existing_by_svc
            enabled_checked = "checked" if is_enabled else ""

            pane = (
                '<label class="tlabel" style="margin-bottom:12px;display:flex">'
                '<div class="toggle"><input type="checkbox" id="svc_' + str(idx) + '_' + svc["id"] + '_enabled" ' + enabled_checked + '>'
                '<span class="slider"></span></div>'
                '<span style="color:var(--text2);font-size:.85em"> Enable</span></label>'
                '<div class="fg-group"><label class="fg">CONFIGURATION <small>(YAML)</small></label>'
                '<textarea id="svc_' + str(idx) + '_' + svc["id"] + '_yaml" style="height:140px;font-size:.8em;font-family:monospace">'
                + yaml_content + '</textarea></div>'
            )
            panes += '<div class="pane%s" data-grp="nsvc%s" data-tab="%s">%s</div>' % (on, idx, tab_id, pane)

        return (
            '<hr style="border:none;border-top:1px solid #252930;margin:14px 0">'
            '<div style="font-size:.78em;color:var(--text2);margin-bottom:8px;letter-spacing:.4px">🎭 SERVICES</div>'
            '<div class="tabs" style="margin-bottom:0">' + tabs + '</div>'
            + panes
        )

    def node_card_html(idx, node_name, nc):
        port_chips = "".join('<span class="chip chip-b" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">x</button></span>' % (p,p) for p in nc.get("ports",[]))
        dnsa_chips = "".join('<span class="chip chip-g" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">x</button></span>' % (d,d) for d in nc.get("dns_A",[]))
        dnsp_chips = "".join('<span class="chip chip-g" data-v="%s">%s <button type="button" onclick="this.parentElement.remove()">x</button></span>' % (d,d) for d in nc.get("dns_proxy",[]))
        reg_opts = "".join('<option value="%s"%s>%s</option>' % (r,' selected' if nc.get("region")==r else '',r) for r in AWS_REGIONS)
        it_opts  = itype_opts(nc.get("instance_type",""))
        i = str(idx)
        chips_html = (
            '<div class="chips" id="node_%(i)s_ports">%(pc)s<input type="text" placeholder="443" onkeydown="if(event.key===&quot;Enter&quot;){event.preventDefault();chips_add(&quot;node_%(i)s_ports&quot;,&quot;chip chip-b&quot;)}"></div></div>'
            '<div class="fg-group"><label class="fg">DNS A RECORDS <small>(Enter)</small></label>'
            '<div class="chips" id="node_%(i)s_dnsa">%(ac)s<input type="text" placeholder="c2.domain.com" onkeydown="if(event.key===&quot;Enter&quot;){event.preventDefault();chips_add(&quot;node_%(i)s_dnsa&quot;,&quot;chip chip-g&quot;)}"></div></div>'
            '</div>'
            '<div class="fg-group"><label class="fg">DNS PROXY RECORDS <small>(Enter)</small></label>'
            '<div class="chips" id="node_%(i)s_dnsp">%(dc)s<input type="text" placeholder="proxy.domain.com" onkeydown="if(event.key===&quot;Enter&quot;){event.preventDefault();chips_add(&quot;node_%(i)s_dnsp&quot;,&quot;chip chip-g&quot;)}"></div></div>'
        ) % {"i": i, "pc": port_chips, "ac": dnsa_chips, "dc": dnsp_chips}
        return (
            '<div class="card" id="node_card_' + i + '" style="border-color:rgba(68,136,255,.3)">'
            '<div class="card-head">'
            '<span class="card-title" style="color:var(--blue)">🖥 Node #' + str(idx+1) + '</span>'
            '<button type="button" class="btn btn-r" style="padding:4px 10px;font-size:.75em" onclick="removeNode(' + i + ')">✕ Remove</button>'
            '</div>'
            '<div class="g3">'
            '<div class="fg-group"><label class="fg">SERVER TYPE <small>(nom libre)</small></label>'
            '<input type="text" id="node_' + i + '_type" value="' + node_name + '" placeholder="c2 / phishing / redirector1"></div>'
            '<div class="fg-group"><label class="fg">AWS REGION</label><select id="node_' + i + '_region">' + reg_opts + '</select></div>'
            '<div class="fg-group"><label class="fg">INSTANCE TYPE</label><select id="node_' + i + '_itype">' + it_opts + '</select></div>'
            '</div>'
            '<div class="g3">'
            '<div class="fg-group"><label class="fg">LOCAL IP</label><input type="text" id="node_' + i + '_lip" value="' + nc.get("local_ip","") + '" placeholder="192.168.56.10"></div>'
            '<div class="fg-group"><label class="fg">PORTS <small>(Enter)</small></label>'
            + chips_html
            + node_services_html(idx, nc)
            + '</div>'
        )

    nodes_html = '<div id="nodes_container">'
    for i, (nname, nc) in enumerate(existing_nodes):
        nodes_html += node_card_html(i, nname, nc)
    nodes_html += '</div>'
    nodes_html += '<button type="button" class="btn btn-b" style="margin-bottom:16px" onclick="addNode()">+ Add Node</button>'

    svc_defs_js = json.dumps([{"id": s["id"], "label": s["label"], "playbooks": s["playbooks"]} for s in SERVICES])

    html_top = (
        "<h1>" + title_prefix + title_text + "</h1>"
        '<div class="card"><div class="g2">'
        '<div class="fg-group"><label class="fg">MISSION NAME</label>'
        '<input type="text" id="mname" value="' + cfg.get("mission","") + '" placeholder="operation-nightfall" ' + name_ro + '></div>'
        '<div class="fg-group"><label class="fg">STATUS</label>'
        '<label class="tlabel"><div class="toggle">'
        '<input type="checkbox" id="menabled" ' + enabled_checked + ' onchange="document.getElementById(\'elabel\').textContent=this.checked?\'ENABLED\':\'DISABLED\';document.getElementById(\'elabel\').style.color=this.checked?\'var(--green)\':\'var(--text2)\'"><span class="slider"></span>'
        '</div><span id="elabel" style="color:' + elabel_color + '">' + elabel_text + '</span></label></div>'
        '</div></div>'
        '<div class="card">'
        '<div class="card-head"><span class="card-title">🖥 AWS Nodes</span></div>'
        + nodes_html +
        '</div>'
        '<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px">'
        '<a href="/" class="btn btn-s">Cancel</a>'
        '<button type="button" class="btn btn-g" onclick="saveMission()">💾 Save Mission</button>'
        '</div>'
    )

    js = """<script>
var nodeCount = NODE_COUNT_PH;
var REGIONS = REGIONS_PH;
var ITYPES = ITYPES_PH;
var SVC_DEFS = SVC_DEFS_PH;
var SVC_YAML_TEMPLATES = SVC_YAML_PH;

// chips-inp keydown handled by global listener in NAV

function g(id) { var el = document.getElementById(id); return el ? el.value : ''; }
function gChips(id) { return Array.from(document.querySelectorAll('#'+id+' .chip')).map(function(c){return c.dataset.v;}); }

function addRow(tbodyId, tpl) {
  var tb = document.getElementById(tbodyId);
  if (!tb) return;
  var tr = document.createElement('tr');
  tr.innerHTML = tpl + '<td><button type="button" onclick="this.parentElement.parentElement.remove()" style="background:none;border:none;color:var(--red);cursor:pointer">x</button></td>';
  tb.appendChild(tr);
}

function getNodeNames() {
  var names = [];
  for (var i = 0; i < nodeCount; i++) {
    var el = document.getElementById('node_'+i+'_type');
    if (el && el.value.trim()) names.push(el.value.trim());
  }
  return names;
}

function updateNodeDropdowns() {
  var names = getNodeNames();
  SVC_DEFS.forEach(function(svc) {
    if (!svc.has_node) return;
    var sel = document.getElementById('svc_'+svc.id+'_node');
    if (!sel) return;
    var cur = sel.value;
    sel.innerHTML = names.map(function(n){
      return '<option value="'+n+'"'+(n===cur?' selected':'')+'>'+n+'</option>';
    }).join('');
  });
}

function buildSvcTabs(idx) {
  var tabs = '';
  var panes = '';
  SVC_DEFS.forEach(function(svc, i) {
    var on = i === 0 ? ' on' : '';
    var tid = 'n'+idx+'_'+svc.id;
    var grp = 'nsvc'+idx;
    tabs += '<div class="tab'+on+'" data-grp="'+grp+'" data-tab="'+tid+'" onclick="tab_switch(&quot;'+grp+'&quot;,&quot;'+tid+'&quot;)">'+svc.label+'</div>';
    var tpl = SVC_YAML_TEMPLATES[svc.id] || '# No arguments';
    panes += '<div class="pane'+on+'" data-grp="'+grp+'" data-tab="'+tid+'">'
      +'<label class="tlabel" style="margin-bottom:12px;display:flex">'
      +'<div class="toggle"><input type="checkbox" id="svc_'+idx+'_'+svc.id+'_enabled"><span class="slider"></span></div>'
      +'<span style="color:var(--text2);font-size:.85em"> Enable</span></label>'
      +'<div class="fg-group"><label class="fg">CONFIGURATION <small>(YAML)</small></label>'
      +'<textarea id="svc_'+idx+'_'+svc.id+'_yaml" style="height:140px;font-size:.8em;font-family:monospace">'+tpl+'</textarea>'
      +'</div></div>';
  });
  return '<hr style="border:none;border-top:1px solid #252930;margin:14px 0">'
    +'<div style="font-size:.78em;color:var(--text2);margin-bottom:8px;letter-spacing:.4px">&#127921; SERVICES</div>'
    +'<div class="tabs" style="margin-bottom:0">'+tabs+'</div>'+panes;
}

function addNode() {
  var idx = nodeCount;
  nodeCount++;
  var regOpts = REGIONS.map(function(r){return '<option value="'+r+'">'+r+'</option>';}).join('');
  var itOpts  = ITYPES.map(function(t){return '<option value="'+t.v+'">'+t.l+'</option>';}).join('');
  var card = document.createElement('div');
  card.className = 'card';
  card.id = 'node_card_' + idx;
  card.style.borderColor = 'rgba(68,136,255,.3)';
  card.innerHTML = (
    '<div class="card-head">'
    +'<span class="card-title" style="color:var(--blue)">&#128421; Node #'+(idx+1)+'</span>'
    +'<button type="button" class="btn btn-r" style="padding:4px 10px;font-size:.75em" onclick="removeNode('+idx+')">&#10005; Remove</button>'
    +'</div>'
    +'<div class="g3">'
    +'<div class="fg-group"><label class="fg">SERVER TYPE</label>'
    +'<input type="text" id="node_'+idx+'_type" placeholder="c2 / phishing / redirector1"></div>'
    +'<div class="fg-group"><label class="fg">AWS REGION</label><select id="node_'+idx+'_region">'+regOpts+'</select></div>'
    +'<div class="fg-group"><label class="fg">INSTANCE TYPE</label><select id="node_'+idx+'_itype">'+itOpts+'</select></div>'
    +'</div>'
    +'<div class="g3">'
    +'<div class="fg-group"><label class="fg">LOCAL IP</label><input type="text" id="node_'+idx+'_lip" placeholder="192.168.56.10"></div>'
    +'<div class="fg-group"><label class="fg">PORTS</label>'
    +'<div class="chips" id="node_'+idx+'_ports"><input type="text" placeholder="443" data-chips-id="node_'+idx+'_ports" data-chips-cls="chip chip-b" class="chips-inp"></div></div>'
    +'<div class="fg-group"><label class="fg">DNS A</label>'
    +'<div class="chips" id="node_'+idx+'_dnsa"><input type="text" placeholder="c2.domain.com" data-chips-id="node_'+idx+'_dnsa" data-chips-cls="chip chip-g" class="chips-inp"></div></div>'
    +'</div>'
    +'<div class="fg-group"><label class="fg">DNS PROXY</label>'
    +'<div class="chips" id="node_'+idx+'_dnsp"><input type="text" placeholder="proxy.domain.com" data-chips-id="node_'+idx+'_dnsp" data-chips-cls="chip chip-g" class="chips-inp"></div></div>'
    + buildSvcTabs(idx)
  );
  document.getElementById('nodes_container').appendChild(card);
}

function removeNode(idx) {
  var card = document.getElementById('node_card_'+idx);
  if (card) card.remove();
  updateNodeDropdowns();
}

function collectServices() {
  // Returns list of {node_idx, svc_id, yaml} for the API to parse server-side
  var result = [];
  for (var i = 0; i < nodeCount; i++) {
    var typeEl = document.getElementById('node_'+i+'_type');
    if (!typeEl) continue;
    SVC_DEFS.forEach(function(svc) {
      var enabledEl = document.getElementById('svc_'+i+'_'+svc.id+'_enabled');
      if (!enabledEl || !enabledEl.checked) return;
      var yamlContent = g('svc_'+i+'_'+svc.id+'_yaml');
      result.push({node_idx: i, svc_id: svc.id, yaml: yamlContent, playbooks: svc.playbooks});
    });
  }
  return result;
}

function saveMission() {
  var name = document.getElementById('mname').value.trim();
  if (!name) { alert('Mission name is required!'); return; }
  var data = { mission: name, enabled: document.getElementById('menabled').checked };
  var svcMap = collectServices();

  for (var i = 0; i < nodeCount; i++) {
    var typeEl = document.getElementById('node_'+i+'_type');
    if (!typeEl) continue;
    var ntype = typeEl.value.trim();
    if (!ntype) continue;
    var itype = g('node_'+i+'_itype');
    if (itype) {
      data[ntype] = {
        region: g('node_'+i+'_region'),
        instance_type: itype,
        local_ip: g('node_'+i+'_lip'),
        ports: gChips('node_'+i+'_ports').map(Number),
        dns_A: gChips('node_'+i+'_dnsa'),
        dns_proxy: gChips('node_'+i+'_dnsp'),
      };
    } else {
      data[ntype] = {};  // services only (e.g. O365), no AWS instance
    }
      // ansible resolved server-side
  }

  // Pass node index mapping so API can resolve node names
  var nodeNames = {};
  for (var ni = 0; ni < nodeCount; ni++) {
    var tel = document.getElementById('node_'+ni+'_type');
    if (tel && tel.value.trim()) nodeNames[ni] = tel.value.trim();
  }
  // For services on nodes without a type name (e.g. O365-only), use node field value or default
  var svcs = collectServices();
  svcs.forEach(function(svc) {
    var ni = svc.node_idx;
    if (!nodeNames[ni]) {
      var tel = document.getElementById('node_'+ni+'_type');
      var fallback = (tel && tel.value.trim()) ? tel.value.trim() : 'phishing';
      nodeNames[ni] = fallback;
      // Also create the node entry in data if missing
      if (!data[fallback]) {
        var itype = g('node_'+ni+'_itype');
        if (itype) {
          data[fallback] = {
            region: g('node_'+ni+'_region') || 'eu-west-1',
            instance_type: itype,
            local_ip: g('node_'+ni+'_lip') || '',
            ports: gChips('node_'+ni+'_ports').map(Number),
            dns_A: gChips('node_'+ni+'_dnsa'),
            dns_proxy: gChips('node_'+ni+'_dnsp'),
          };
        } else {
          data[fallback] = {};
        }
      }
    }
  });
  data._services = svcs;
  data._node_names = nodeNames;
  fetch('/api/mission/save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  }).then(function(r){return r.json();}).then(function(d){
    if (d.ok) window.location='/';
    else alert('Error: '+d.error);
  });
}
</script>""" \
    .replace("NODE_COUNT_PH", str(len(existing_nodes))) \
    .replace("REGIONS_PH", json.dumps(AWS_REGIONS)) \
    .replace("ITYPES_PH", json.dumps([{"v": t, "l": INSTANCE_TYPE_LABELS.get(t, t)} for t in INSTANCE_TYPES])) \
    .replace("SVC_DEFS_PH", svc_defs_js) \
    .replace("SVC_YAML_PH", json.dumps({s["id"]: SVC_YAML_TEMPLATES.get(s["id"],"# No arguments\n") for s in SERVICES}, ensure_ascii=False))

    body = html_top + js
    return nav(title_text, "mission", body)

# ─── Deploy ───────────────────────────────────────────────────────────────────

@app.route("/deploy")
def deploy():
    missions = get_missions()
    auto_action = request.args.get("action","")
    # Mission select options
    m_opts = "".join('<option value="%s">%s%s</option>' % (m["name"], m["name"], " ✓" if m["enabled"] else " (disabled)") for m in missions)
    # Mission->nodes map for JS (to populate server select dynamically)
    mission_nodes_js = json.dumps({m["name"]: m["nodes"] for m in missions})

    body = """
    <h1>🚀 Deploy Infrastructure</h1>
    <div class="card" style="background:rgba(68,136,255,.05);border-color:rgba(68,136,255,.3);font-size:.82em;color:var(--blue);margin-bottom:18px">
      ℹ <b>All enabled missions are deployed together</b> — redinfra reads every enabled mission from <code>config/*.yml</code>. Use the dashboard to enable/disable missions before deploying.
    </div>
    <div style="display:grid;grid-template-columns:340px 1fr;gap:16px">
    <div>
      <div class="card">
        <div class="card-head"><span class="card-title">⚡ Actions</span></div>
        <div class="fg-group"><label class="fg">SELECT MISSION (enable/disable only)</label>
          <select id="msel">%s</select>
          <div style="margin-top:8px;display:flex;gap:8px">
            <button class="btn btn-g" style="flex:1;justify-content:center" onclick="toggleMission(true)">Enable</button>
            <button class="btn btn-s" style="flex:1;justify-content:center" onclick="toggleMission(false)">Disable</button>
          </div>
        </div>
        <hr>
        <div style="margin-bottom:10px;font-size:.8em;color:var(--text2)">INDIVIDUAL STEPS</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:14px">
          <button class="btn btn-b" onclick="run('apply-terraform')">🏗 Terraform</button>
          <button class="btn btn-b" onclick="run('apply-cloudflare')">🌐 Cloudflare</button>
          <button class="btn btn-b" onclick="run('apply-sendgrid')">📧 SendGrid</button>
          <button class="btn btn-b" onclick="run('apply-o365')">🔷 O365</button>
          <button class="btn btn-b" onclick="run('apply-routing')">🔀 Routing</button>
          <button class="btn btn-b" onclick="run('apply-ansible')">📋 Ansible</button>
        </div>
        <hr>
        <div style="display:flex;gap:8px">
          <button class="btn btn-g" style="flex:1;justify-content:center;padding:10px" onclick="run('apply')">🚀 DEPLOY ALL</button>
          <button class="btn btn-r" style="flex:1;justify-content:center;padding:10px" onclick="if(confirm('Destroy ALL resources for enabled missions?'))run('destroy')">💥 DESTROY</button>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">🎭 Run Playbook</span></div>
        <div class="fg-group"><label class="fg">MISSION</label>
          <select id="pb_mission" onchange="updatePbServers()">
            <option value="">— select a mission —</option>%s
          </select>
        </div>
        <div class="fg-group"><label class="fg">SERVER</label>
          <select id="pb_srv"><option value="">— select a mission first —</option></select>
        </div>
        <button class="btn btn-o" onclick="runPlaybook()">▶ Run Playbooks</button>
      </div>
    </div>
    <div class="card" style="display:flex;flex-direction:column">
      <div class="card-head">
        <span class="card-title">🖥 Terminal</span>
        <div style="display:flex;gap:8px;align-items:center">
          <span id="sbadge" class="badge bb">IDLE</span>
          <button class="btn btn-s" style="padding:4px 9px;font-size:.75em" onclick="document.getElementById('term').innerHTML='<span class=tw>// Cleared.</span>'">Clear</button>
        </div>
      </div>
      <div class="term" id="term"><span class="tw">// Output will appear here...</span></div>
    </div>
    </div>
    <script>
    var es = null;
    function setStatus(t,c){var b=document.getElementById('sbadge');b.textContent=t;b.className='badge b'+c;}
    function addLine(text){
      var t=document.getElementById('term');
      var d=document.createElement('div');
      d.className=line_class(text);
      d.textContent=strip_ansi(text);
      t.appendChild(d);t.scrollTop=t.scrollHeight;
    }
    function startSSE(url){
      if(es)es.close();
      document.getElementById('term').innerHTML='';
      setStatus('RUNNING','b');
      es=new EventSource(url);
      es.onmessage=function(e){
        var d=JSON.parse(e.data);
        if(d.done){es.close();setStatus('DONE','g');return;}
        if(d.error){addLine(d.error);es.close();setStatus('ERROR','r');return;}
        addLine(d.line);
      };
      es.onerror=function(){es.close();setStatus('ERROR','r');};
    }
    function run(action){startSSE('/api/run?action='+action);}
    var MISSION_NODES = %s;
    function updatePbServers(){
      var m=document.getElementById('pb_mission').value;
      var sel=document.getElementById('pb_srv');
      sel.innerHTML='';
      var nodes=(MISSION_NODES[m]||[]);
      if(!m||nodes.length===0){
        sel.innerHTML='<option value="">— no servers —</option>';
        return;
      }
      nodes.forEach(function(n){
        var o=document.createElement('option');
        o.value=n;o.textContent=n;
        sel.appendChild(o);
      });
    }
    function runPlaybook(){
      var m=document.getElementById('pb_mission').value;
      var s=document.getElementById('pb_srv').value;
      if(!m){alert('Sélectionne une mission');return;}
      if(!s){alert('Aucun serveur disponible pour cette mission');return;}
      startSSE('/api/run?action=playbooks&mission='+encodeURIComponent(m)+'&server='+encodeURIComponent(s));
    }
    function toggleMission(enable){
      var m=document.getElementById('msel').value;
      fetch('/api/mission/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mission:m,enabled:enable})})
        .then(function(r){return r.json();}).then(function(d){if(d.ok)window.location.reload();else alert('Error: '+d.error);});
    }
    %s
    </script>
    """ % (m_opts, m_opts, mission_nodes_js, "setTimeout(function(){run('%s');},600);" % auto_action if auto_action else "")
    return nav("Deploy", "deploy", body)

# ─── Settings ─────────────────────────────────────────────────────────────────

@app.route("/settings")
def settings():
    cfg = get_main_config()
    api = cfg.get("api", {})
    routing = cfg.get("routing", {})
    vpn = cfg.get("vpn", {})
    tags = cfg.get("tags", {})
    o365_rows = ""
    for t in (api.get("o365") or []):
        o365_rows += '<tr><td><input type="text" value="%s"></td><td><input type="text" value="%s"></td><td><input type="password" value="%s"></td><td><button type="button" onclick="this.closest(\'tr\').remove()" style="background:none;border:none;color:var(--red);cursor:pointer">×</button></td></tr>' % (t.get("tenant_id",""), t.get("client_id",""), t.get("client_secret",""))
    reg_opts = "".join('<option value="%s"%s>%s</option>' % (r,' selected' if vpn.get("region")==r else '',r) for r in AWS_REGIONS)
    it_opts = "".join('<option value="%s"%s>%s</option>' % (t,' selected' if vpn.get("instance_type")==t else '',t) for t in INSTANCE_TYPES)
    def _e(v):
        """Escape a value for safe HTML attribute insertion."""
        return str(v).replace("&","&amp;").replace('"','&quot;').replace("<","&lt;").replace(">","&gt;")

    body = (
    '<h1>⚙ Settings — main.yml</h1>'
    '<div class="card">'
    '<div class="card-head"><span class="card-title">🔑 API Credentials</span></div>'
    '<div class="g2">'
    '<div class="fg-group"><label class="fg">AWS KEY</label><input type="text" id="aws_key" value="__AWS_KEY__"></div>'
    '<div class="fg-group"><label class="fg">AWS SECRET</label><input type="password" id="aws_secret" value="__AWS_SECRET__"></div>'
    '<div class="fg-group"><label class="fg">CLOUDFLARE API KEY</label><input type="password" id="cf_key" value="__CF_KEY__"></div>'
    '<div class="fg-group"><label class="fg">SENDGRID API KEY</label><input type="password" id="sg_key" value="__SG_KEY__"></div>'
    '</div></div>'
    '<div class="card">'
    '<div class="card-head"><span class="card-title">🔷 O365 Tenants</span></div>'
    '<table class="dt"><thead><tr><th>Tenant ID</th><th>Client ID</th><th>Client Secret</th><th></th></tr></thead>'
    '<tbody id="o365r">__O365_ROWS__</tbody></table>'
    '<button type="button" class="btn btn-s" style="margin-top:8px;font-size:.76em" onclick="addO365()">+ Add Tenant</button>'
    '</div>'
    '<div class="card">'
    '<div class="card-head"><span class="card-title">🔀 Routing &amp; VPN</span></div>'
    '<div class="g3">'
    '<div class="fg-group"><label class="fg">VPN INTERFACE</label><input type="text" id="vpn_iface" value="__VPN_IFACE__"></div>'
    '<div class="fg-group"><label class="fg">IPTABLES CHAIN</label><input type="text" id="ipt_chain" value="__IPT_CHAIN__"></div>'
    '<div class="fg-group"><label class="fg">VPN RANGE</label><input type="text" id="vpn_range" value="__VPN_RANGE__"></div>'
    '</div>'
    '<div class="g2">'
    '<div class="fg-group"><label class="fg">VPN REGION</label><select id="vpn_reg">__VPN_REG__</select></div>'
    '<div class="fg-group"><label class="fg">VPN INSTANCE TYPE</label><select id="vpn_itype">__VPN_ITYPE__</select></div>'
    '</div></div>'
    '<div class="card">'
    '<div class="card-head"><span class="card-title">🏷 Tags</span></div>'
    '<table class="dt"><thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>'
    '<tbody id="tagsr">__TAG_ROWS__</tbody></table>'
    '<button type="button" class="btn btn-s" style="margin-top:8px;font-size:.76em" onclick="addTag()">+ Add Tag</button>'
    '</div>'
    '<div style="display:flex;justify-content:flex-end">'
    '<button class="btn btn-g" onclick="saveSettings()">💾 Save Settings</button>'
    '</div>'
    '<script>'
    'function addTag(){'
    'var tb=document.getElementById("tagsr");'
    'var tr=document.createElement("tr");'
    'tr.innerHTML="<td><input type=text placeholder=Key></td><td><input type=text placeholder=Value></td><td><button type=button onclick=\\"this.closest(\'tr\').remove()\\" style=\\"background:none;border:none;color:var(--red);cursor:pointer\\">×</button></td>";'
    'tb.appendChild(tr);}'
    'function addO365(){'
    'var tb=document.getElementById("o365r");'
    'var tr=document.createElement("tr");'
    'tr.innerHTML="<td><input type=text placeholder=tenant-id></td><td><input type=text placeholder=client-id></td><td><input type=password placeholder=client-secret></td><td><button type=button onclick=\\"this.closest(\'tr\').remove()\\" style=\\"background:none;border:none;color:var(--red);cursor:pointer\\">×</button></td>";'
    'tb.appendChild(tr);}'
    'function saveSettings(){'
    'var o365=Array.from(document.querySelectorAll("#o365r tr")).map(function(tr){'
    'var ins=tr.querySelectorAll("input");'
    'return{tenant_id:ins[0].value,client_id:ins[1].value,client_secret:ins[2].value};});'
    'var tags={};'
    'Array.from(document.querySelectorAll("#tagsr tr")).forEach(function(tr){'
    'var ins=tr.querySelectorAll("input");'
    'var k=ins[0].value.trim(),v=ins[1].value;'
    'if(k)tags[k]=v;});'
    'var data={'
    'api:{aws_key:document.getElementById("aws_key").value,aws_secret:document.getElementById("aws_secret").value,cloudflare_key:document.getElementById("cf_key").value,sendgrid_api:document.getElementById("sg_key").value,o365:o365},'
    'routing:{vpn_interface:document.getElementById("vpn_iface").value,iptables_chain:document.getElementById("ipt_chain").value,vpn_range:document.getElementById("vpn_range").value,rule_start_table:10,rule_priority:30000},'
    'vpn:{region:document.getElementById("vpn_reg").value,instance_type:document.getElementById("vpn_itype").value},'
    'tags:tags};'
    'fetch("/api/settings/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)})'
    '.then(function(r){return r.json();}).then(function(d){if(d.ok)alert("✅ Saved!");else alert("Error: "+d.error);});}'
    '</script>'
    ).replace("__AWS_KEY__", _e(api.get("aws_key",""))
    ).replace("__AWS_SECRET__", _e(api.get("aws_secret",""))
    ).replace("__CF_KEY__", _e(api.get("cloudflare_key",""))
    ).replace("__SG_KEY__", _e(api.get("sendgrid_api",""))
    ).replace("__O365_ROWS__", o365_rows
    ).replace("__VPN_IFACE__", _e(routing.get("vpn_interface","tap0"))
    ).replace("__IPT_CHAIN__", _e(routing.get("iptables_chain","redinfra"))
    ).replace("__VPN_RANGE__", _e(routing.get("vpn_range","192.168.40.0/24"))
    ).replace("__VPN_REG__", reg_opts
    ).replace("__VPN_ITYPE__", it_opts
    ).replace("__TAG_ROWS__", "".join(
        '<tr><td><input type="text" value="%s"></td><td><input type="text" value="%s"></td>'
        '<td><button type="button" onclick="this.closest(\'tr\').remove()" style="background:none;border:none;color:var(--red);cursor:pointer">×</button></td></tr>'
        % (_e(k), _e(v)) for k, v in tags.items()
    ) or '<tr><td><input type="text" placeholder="Team"></td><td><input type="text" placeholder="RedTeam"></td>'
         '<td><button type="button" onclick="this.closest(\'tr\').remove()" style="background:none;border:none;color:var(--red);cursor:pointer">×</button></td></tr>'
    )
    return nav("Settings", "settings", body)

# ─── API ──────────────────────────────────────────────────────────────────────

SVC_PLAYBOOKS_MAP = {
    "web":      [("install_web.yml", lambda a: {"web_domains": a.get("web_domains", [])})],
    "mail":     [
        ("install_mail.yml",    lambda a: {"domains": a.get("domains", []), "sendgrid_password": a.get("sendgrid_password", "")}),
        ("install_gophish.yml", lambda a: {"mails": a.get("mails", []), "web_domains": a.get("web_domains", []), "gophish_rid": a.get("gophish_rid", "rid"), "gophish_track_uri": a.get("gophish_track_uri", "/track"), "gophish_uris": a.get("gophish_uris", [])}),
    ],
    "mythic":   [("install_mythic.yml", lambda a: {"mythic_password": a.get("mythic_password", ""), "github_extensions": a.get("github_extensions", [])})],
    "webdav":   [("install_webdav.yml", lambda a: {"web_domains": a.get("web_domains", [])})],
    "responder":[("install_responder.yml", lambda a: {})],
    "redelk":   [("install_redelk_c2.yml", lambda a: {}), ("install_redelk_redirectors.yml", lambda a: {})],
    "o365":     None,  # written directly into node config, not ansible
    "custom":   "__custom__",  # handled separately — raw YAML list injected as-is into ansible[]
}

@app.route("/api/mission/save", methods=["POST"])
def api_mission_save():
    try:
        data = request.json
        import sys
        print("DEBUG save payload:", json.dumps(data, ensure_ascii=False), file=sys.stderr)
        if not data.get("mission"):
            return jsonify({"ok": False, "error": "Mission name required"})

        # Process _services: parse YAML and assign ansible to nodes
        services   = data.pop("_services", [])
        node_names = data.pop("_node_names", {})
        # node_names is {str(idx): node_type_name}

        for svc in services:
            svc_id   = svc.get("svc_id", "")
            node_idx = str(svc.get("node_idx", ""))
            yaml_raw = svc.get("yaml", "")
            if not svc_id: continue

            node = node_names.get(node_idx, "").strip()
            if not node:
                continue

            try:
                args = yaml.safe_load(yaml_raw) or {}
            except Exception:
                args = {}
            if not isinstance(args, dict):
                args = {}

            playbook_builders = SVC_PLAYBOOKS_MAP.get(svc_id, [])

            # O365: write directly into node config (not ansible)
            # Node may not exist if user only configured O365 without AWS infra
            if playbook_builders is None:
                if svc_id == "o365":
                    if node not in data:
                        data[node] = {}
                    data[node]["o365"] = args.get("o365", args)
                continue

            # Custom: raw YAML list injected as-is into ansible[]
            if playbook_builders == "__custom__":
                try:
                    entries = yaml.safe_load(yaml_raw) or []
                except Exception:
                    entries = []
                if isinstance(entries, list) and entries:
                    if node not in data:
                        data[node] = {}
                    if "ansible" not in data[node]:
                        data[node]["ansible"] = []
                    data[node]["ansible"].extend(entries)
                continue

            if not playbook_builders:
                continue

            if "ansible" not in data[node]:
                data[node]["ansible"] = []
            for pb_name, pb_args_fn in playbook_builders:
                data[node]["ansible"].append({
                    "playbook": pb_name,
                    "args": pb_args_fn(args)
                })

        save_mission(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mission/delete", methods=["POST"])
def api_mission_delete():
    try:
        name = request.json.get("mission")
        for f in glob.glob(os.path.join(CONFIG_PATH, "*.yml")):
            if os.path.basename(f) in ("main.yml", "aws.yml"): continue
            try:
                with open(f) as fh:
                    cfg = yaml.safe_load(fh) or {}
                if cfg.get("mission") == name:
                    os.remove(f)
                    return jsonify({"ok": True})
            except Exception:
                pass
        return jsonify({"ok": False, "error": "Mission not found"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mission/toggle", methods=["POST"])
def api_mission_toggle():
    try:
        data = request.json
        cfg = get_mission_config(data["mission"])
        cfg["enabled"] = data["enabled"]
        save_mission(cfg)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/settings/save", methods=["POST"])
def api_settings_save():
    try:
        save_main(request.json)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/run")
def api_run():
    action = request.args.get("action","apply")
    mission = request.args.get("mission","")
    server = request.args.get("server","")

    if action == "destroy":
        cmd = ["python3", "redinfra.py", "auto", "--destroy"]
    elif action == "playbooks":
        cmd = ["python3", "redinfra.py", "auto", "--playbooks", mission, server]
    else:
        cmd = ["python3", "redinfra.py", "auto", "--%s" % action]

    qid = "%s_%d" % (action, int(time.time()*1000))
    log_queues[qid] = queue.Queue()
    threading.Thread(target=run_cmd, args=(cmd, qid), daemon=True).start()

    def generate():
        q = log_queues[qid]
        while True:
            line = q.get()
            if line is None:
                yield "data: %s\n\n" % json.dumps({"done": True})
                break
            yield "data: %s\n\n" % json.dumps({"line": line})
        log_queues.pop(qid, None)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ─── Inventory ───────────────────────────────────────────────────────────────

@app.route("/inventory")
def inventory():
    body = """
    <h1>📦 Inventory</h1>
    <div style="display:grid;grid-template-columns:1fr;gap:16px">

      <!-- AWS Instances -->
      <div class="card">
        <div class="card-head">
          <span class="card-title">☁️ AWS Instances</span>
          <div style="display:flex;align-items:center;gap:10px">
            <span id="aws_badge" class="badge bb">IDLE</span>
            <button class="btn btn-b" onclick="fetchAWS()">⟳ Fetch</button>
          </div>
        </div>
        <div id="aws_body" style="color:var(--text2);font-size:.84em">Click Fetch to load instances.</div>
      </div>

      <!-- Cloudflare DNS -->
      <div class="card">
        <div class="card-head">
          <span class="card-title">🌐 Cloudflare DNS Records</span>
          <div style="display:flex;align-items:center;gap:10px">
            <span id="cf_badge" class="badge bb">IDLE</span>
            <button class="btn btn-b" onclick="fetchCF()">⟳ Fetch</button>
          </div>
        </div>
        <div id="cf_body" style="color:var(--text2);font-size:.84em">Click Fetch to load DNS entries.</div>
      </div>

      <!-- SendGrid -->
      <div class="card">
        <div class="card-head">
          <span class="card-title">📧 SendGrid — Domains & Senders</span>
          <div style="display:flex;align-items:center;gap:10px">
            <span id="sg_badge" class="badge bb">IDLE</span>
            <button class="btn btn-b" onclick="fetchSG()">⟳ Fetch</button>
          </div>
        </div>
        <div id="sg_body" style="color:var(--text2);font-size:.84em">Click Fetch to load SendGrid data.</div>
      </div>

      <!-- O365 -->
      <div class="card">
        <div class="card-head">
          <span class="card-title">🔷 O365 — Domains & Emails</span>
          <div style="display:flex;align-items:center;gap:10px">
            <span id="o365_badge" class="badge bb">IDLE</span>
            <button class="btn btn-b" onclick="fetchO365()">⟳ Fetch</button>
          </div>
        </div>
        <div id="o365_body" style="color:var(--text2);font-size:.84em">Click Fetch to load O365 data.</div>
      </div>

    </div>
    <script>
    function setBadge(id, text, cls) {
      var b = document.getElementById(id);
      b.textContent = text;
      b.className = 'badge b' + cls;
    }

    function tableHTML(cols, rows, emptyMsg) {
      if (!rows || !rows.length) return '<div style="color:var(--text2);padding:10px 0">' + (emptyMsg||'No data.') + '</div>';
      var th = cols.map(function(c){ return '<th>'+c+'</th>'; }).join('');
      var trs = rows.map(function(r){
        var tds = r.map(function(v){
          var cls = '';
          var s = String(v||'');
          if (s==='running'||s==='active'||s==='verified') cls = ' style="color:var(--green)"';
          else if (s==='stopped'||s==='terminated'||s==='failed') cls = ' style="color:var(--red)"';
          else if (s==='pending'||s==='starting') cls = ' style="color:var(--orange)"';
          return '<td'+cls+'>'+s+'</td>';
        }).join('');
        return '<tr>'+tds+'</tr>';
      }).join('');
      return '<table class="dt"><thead><tr>'+th+'</tr></thead><tbody>'+trs+'</tbody></table>';
    }

    function fetchAWS() {
      setBadge('aws_badge','LOADING','b');
      document.getElementById('aws_body').innerHTML = '<span style="color:var(--text2)">Fetching AWS instances…</span>';
      fetch('/api/inventory/aws').then(function(r){return r.json();}).then(function(d){
        if (d.error) { setBadge('aws_badge','ERROR','r'); document.getElementById('aws_body').innerHTML='<span style="color:var(--red)">'+d.error+'</span>'; return; }
        setBadge('aws_badge','OK','g');
        var rows = (d.instances||[]).map(function(i){
          return [i.id, i.name||'—', i.region, i.type, i.state, i.public_ip||'—', i.private_ip||'—', i.mission||'—'];
        });
        document.getElementById('aws_body').innerHTML = tableHTML(
          ['Instance ID','Name','Region','Type','State','Public IP','Private IP','Mission'], rows, 'No instances found.'
        );
      }).catch(function(e){ setBadge('aws_badge','ERROR','r'); document.getElementById('aws_body').innerHTML='<span style="color:var(--red)">'+e+'</span>'; });
    }

    function fetchCF() {
      setBadge('cf_badge','LOADING','b');
      document.getElementById('cf_body').innerHTML = '<span style="color:var(--text2)">Fetching Cloudflare records…</span>';
      fetch('/api/inventory/cloudflare').then(function(r){return r.json();}).then(function(d){
        if (d.error) { setBadge('cf_badge','ERROR','r'); document.getElementById('cf_body').innerHTML='<span style="color:var(--red)">'+d.error+'</span>'; return; }
        setBadge('cf_badge','OK','g');
        // Group by zone
        var zones = d.zones || [];
        if (!zones.length) { document.getElementById('cf_body').innerHTML='<div style="color:var(--text2);padding:10px 0">No zones found.</div>'; return; }
        var html = '';
        zones.forEach(function(z) {
          var rows = (z.records||[]).map(function(r){ return [r.type, r.name, r.content, r.proxied ? '🟠 Proxied' : '⚪ DNS only', r.ttl||'auto']; });
          html += '<div style="margin-bottom:16px"><div style="color:var(--blue);font-size:.8em;margin-bottom:6px;font-weight:bold">🌐 '+z.name+'</div>'
            + tableHTML(['Type','Name','Content','Proxy','TTL'], rows, 'No records.')
            + '</div>';
        });
        document.getElementById('cf_body').innerHTML = html;
      }).catch(function(e){ setBadge('cf_badge','ERROR','r'); document.getElementById('cf_body').innerHTML='<span style="color:var(--red)">'+e+'</span>'; });
    }

    function fetchSG() {
      setBadge('sg_badge','LOADING','b');
      document.getElementById('sg_body').innerHTML = '<span style="color:var(--text2)">Fetching SendGrid data…</span>';
      fetch('/api/inventory/sendgrid').then(function(r){return r.json();}).then(function(d){
        if (d.error) { setBadge('sg_badge','ERROR','r'); document.getElementById('sg_body').innerHTML='<span style="color:var(--red)">'+d.error+'</span>'; return; }
        setBadge('sg_badge','OK','g');
        var dom_rows = (d.domains||[]).map(function(d){ return [d.domain, d.valid ? 'verified' : 'pending', d.subdomain||'—']; });
        var send_rows = (d.senders||[]).map(function(s){ return [s.email, s.nickname||'—', s.verified ? 'verified' : 'pending']; });
        var html = '<div style="margin-bottom:16px"><div style="color:var(--blue);font-size:.8em;margin-bottom:6px;font-weight:bold">📨 Authenticated Domains</div>'
          + tableHTML(['Domain','Status','Subdomain'], dom_rows, 'No domains.')
          + '</div>'
          + '<div><div style="color:var(--blue);font-size:.8em;margin-bottom:6px;font-weight:bold">👤 Verified Senders</div>'
          + tableHTML(['Email','Nickname','Status'], send_rows, 'No senders.')
          + '</div>';
        document.getElementById('sg_body').innerHTML = html;
      }).catch(function(e){ setBadge('sg_badge','ERROR','r'); document.getElementById('sg_body').innerHTML='<span style="color:var(--red)">'+e+'</span>'; });
    }

    function fetchO365() {
      setBadge('o365_badge','LOADING','b');
      document.getElementById('o365_body').innerHTML = '<span style="color:var(--text2)">Fetching O365 data…</span>';
      fetch('/api/inventory/o365').then(function(r){return r.json();}).then(function(d){
        if (d.error) { setBadge('o365_badge','ERROR','r'); document.getElementById('o365_body').innerHTML='<span style="color:var(--red)">'+d.error+'</span>'; return; }
        setBadge('o365_badge','OK','g');
        var tenants = d.tenants || [];
        if (!tenants.length) { document.getElementById('o365_body').innerHTML='<div style="color:var(--text2);padding:10px 0">No O365 tenants configured.</div>'; return; }
        var html = '';
        tenants.forEach(function(t) {
          var src = t.source === 'live' ? '<span style="color:var(--green);font-size:.72em;margin-left:8px">● LIVE</span>'
                  : t.source === 'config' ? '<span style="color:var(--orange);font-size:.72em;margin-left:8px">● CONFIG ONLY</span>'
                  : '';
          if (t.error) {
            html += '<div style="margin-bottom:16px;padding:10px;background:rgba(255,68,68,.07);border:1px solid rgba(255,68,68,.3);border-radius:6px">'
              + '<b style="color:#aa44ff">🔷 ' + t.tenant_id + '</b> <span style="color:var(--red);font-size:.82em">⚠ ' + t.error + '</span></div>';
            return;
          }
          html += '<div style="margin-bottom:20px">'
            + '<div style="color:#aa44ff;font-size:.8em;margin-bottom:8px;font-weight:bold">🔷 Tenant: ' + t.tenant_id + src + '</div>';

          // Domains
          var dom_rows = (t.domains||[]).map(function(dom){
            var vstatus = (dom.verified === null || dom.verified === undefined) ? '—' : dom.verified ? 'verified' : 'pending';
            return [dom.id, vstatus, (dom.services||[]).join(', ')||'—'];
          });
          html += '<div style="margin-bottom:10px"><div style="color:var(--blue);font-size:.78em;margin-bottom:5px">🌐 Domains</div>'
            + tableHTML(['Domain','Status','Services'], dom_rows, 'No domains.')
            + '</div>';

          // Emails
          var email_rows = (t.emails||[]).map(function(e){
            var lstatus = (e.licensed === null || e.licensed === undefined) ? '—' : e.licensed ? 'licensed' : 'unlicensed';
            return [e.email, e.name||'—', lstatus];
          });
          html += '<div><div style="color:var(--blue);font-size:.78em;margin-bottom:5px">👤 Emails</div>'
            + tableHTML(['Email','Name','License'], email_rows, 'No users.')
            + '</div>';

          html += '</div>';
        });
        document.getElementById('o365_body').innerHTML = html;
      }).catch(function(e){ setBadge('o365_badge','ERROR','r'); document.getElementById('o365_body').innerHTML='<span style="color:var(--red)">'+e+'</span>'; });
    }
    </script>
    """
    return nav("Inventory", "inventory", body)


# ─── Inventory API ────────────────────────────────────────────────────────────

@app.route("/api/inventory/aws")
def api_inventory_aws():
    if MOCK_MODE:
        return jsonify({"instances": [
            {"id":"i-0a1b2c3d4e5f","name":"c2-server","region":"eu-west-1","type":"t3.medium","state":"running","public_ip":"54.72.11.200","private_ip":"192.168.56.10","mission":"op-nightfall"},
            {"id":"i-1b2c3d4e5f6a","name":"phishing-1","region":"eu-west-3","type":"t2.small","state":"running","public_ip":"35.180.45.120","private_ip":"192.168.56.11","mission":"op-nightfall"},
            {"id":"i-2c3d4e5f6a7b","name":"payload-srv","region":"eu-central-1","type":"t2.micro","state":"stopped","public_ip":"","private_ip":"192.168.56.12","mission":"op-phantom"},
            {"id":"i-3d4e5f6a7b8c","name":"vpn-gateway","region":"eu-west-1","type":"t2.micro","state":"running","public_ip":"54.72.99.1","private_ip":"192.168.40.1","mission":"—"},
        ]})
    try:
        import boto3
        cfg = get_main_config()
        api = cfg.get("api", {})
        session = boto3.Session(
            aws_access_key_id=api.get("aws_key",""),
            aws_secret_access_key=api.get("aws_secret",""),
        )
        instances = []
        for region in AWS_REGIONS:
            try:
                ec2 = session.client("ec2", region_name=region)
                resp = ec2.describe_instances()
                for r in resp["Reservations"]:
                    for inst in r["Instances"]:
                        name = next((t["Value"] for t in inst.get("Tags",[]) if t["Key"]=="Name"), "")
                        mission = next((t["Value"] for t in inst.get("Tags",[]) if t["Key"]=="Mission"), "—")
                        instances.append({
                            "id": inst["InstanceId"],
                            "name": name,
                            "region": region,
                            "type": inst.get("InstanceType",""),
                            "state": inst["State"]["Name"],
                            "public_ip": inst.get("PublicIpAddress",""),
                            "private_ip": inst.get("PrivateIpAddress",""),
                            "mission": mission,
                        })
            except Exception:
                pass
        return jsonify({"instances": instances})
    except ImportError:
        return jsonify({"error": "boto3 not installed. Run: pip install boto3"})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/inventory/cloudflare")
def api_inventory_cloudflare():
    if MOCK_MODE:
        return jsonify({"zones": [
            {"name": "redteamdomain.com", "records": [
                {"type":"A",   "name":"c2.redteamdomain.com",       "content":"54.72.11.200", "proxied":False, "ttl":"auto"},
                {"type":"A",   "name":"mail.redteamdomain.com",      "content":"35.180.45.120","proxied":False, "ttl":"auto"},
                {"type":"MX",  "name":"redteamdomain.com",           "content":"mail.redteamdomain.com","proxied":False,"ttl":"auto"},
                {"type":"TXT", "name":"redteamdomain.com",           "content":"v=spf1 include:sendgrid.net ~all","proxied":False,"ttl":"auto"},
                {"type":"CNAME","name":"em123.redteamdomain.com",    "content":"u12345.wl.sendgrid.net","proxied":False,"ttl":"auto"},
            ]},
            {"name": "phish-domain.io", "records": [
                {"type":"A",   "name":"login.phish-domain.io",       "content":"35.180.45.120","proxied":True,  "ttl":"auto"},
                {"type":"A",   "name":"www.phish-domain.io",         "content":"35.180.45.120","proxied":True,  "ttl":"auto"},
            ]},
        ]})
    try:
        import urllib.request as urlreq
        cfg = get_main_config()
        api_key = cfg.get("api",{}).get("cloudflare_key","")
        if not api_key:
            return jsonify({"error": "No Cloudflare API key configured in Settings."})

        def cf_get(path):
            req = urlreq.Request(
                "https://api.cloudflare.com/client/v4" + path,
                headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"}
            )
            with urlreq.urlopen(req, timeout=10) as r:
                return json.loads(r.read())

        zones_resp = cf_get("/zones?per_page=50")
        zones = []
        for z in zones_resp.get("result", []):
            records_resp = cf_get("/zones/%s/dns_records?per_page=100" % z["id"])
            records = []
            for rec in records_resp.get("result", []):
                records.append({
                    "type": rec["type"],
                    "name": rec["name"],
                    "content": rec["content"],
                    "proxied": rec.get("proxied", False),
                    "ttl": rec.get("ttl", "auto"),
                })
            zones.append({"name": z["name"], "records": records})
        return jsonify({"zones": zones})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/inventory/o365")
def api_inventory_o365():
    if MOCK_MODE:
        return jsonify({"tenants": [
            {
                "tenant_id": "xxxxxxxx-0000-0000-0000-xxxxxxxxxxxx",
                "domains": [
                    {"id": "redteamdomain.com", "verified": True,  "services": ["Email", "OfficeCommunicationsOnline"]},
                    {"id": "phish-domain.io",   "verified": False, "services": ["Email"]},
                ],
                "emails": [
                    {"email": "john.doe@redteamdomain.com", "name": "John Doe", "licensed": True},
                    {"email": "jane.doe@redteamdomain.com", "name": "Jane Doe", "licensed": True},
                    {"email": "support@phish-domain.io",    "name": "Support",  "licensed": False},
                ],
            }
        ]})
    try:
        import requests as req
        import msal

        # Structure mirrors config.get_o365() from automation branch:
        # - credentials (tenant_id, client_id, client_secret) come from main.yml api.o365[]
        # - domains/emails come from mission YAMLs, node.o365.domains[]

        # Step 1: load credentials from main.yml
        main_cfg = get_main_config()
        api_o365_list = main_cfg.get("api", {}).get("o365") or []
        tenants_cfg = {}
        for entry in api_o365_list:
            tid = entry.get("tenant_id", "")
            if tid:
                tenants_cfg[tid] = {
                    "tenant_id":     tid,
                    "client_id":     entry.get("client_id", ""),
                    "client_secret": entry.get("client_secret", ""),
                    "domains": {}
                }

        # Step 2: merge domain/email data from mission YAMLs
        for f in sorted(glob.glob(os.path.join(CONFIG_PATH, "*.yml"))):
            if os.path.basename(f) in ("main.yml", "aws.yml"): continue
            try:
                with open(f) as fh:
                    mission_cfg = yaml.safe_load(fh) or {}
                skip = {"mission", "enabled"}
                for node_key, node_val in mission_cfg.items():
                    if node_key in skip or not isinstance(node_val, dict): continue
                    if "o365" not in node_val: continue
                    o365_node = node_val["o365"]
                    tenant_id = o365_node.get("tenant_id", "")
                    if not tenant_id: continue
                    # Create tenant entry if not in main.yml (credentials missing)
                    if tenant_id not in tenants_cfg:
                        tenants_cfg[tenant_id] = {
                            "tenant_id": tenant_id,
                            "client_id": "",
                            "client_secret": "",
                            "domains": {}
                        }
                    # Merge domains
                    for domain_info in (o365_node.get("domains") or []):
                        domain = domain_info.get("domain", "")
                        if not domain: continue
                        if domain not in tenants_cfg[tenant_id]["domains"]:
                            tenants_cfg[tenant_id]["domains"][domain] = {
                                "services": domain_info.get("services", ["Email"]),
                                "emails": {}
                            }
                        for user_info in (domain_info.get("emails") or []):
                            email = user_info.get("email", "")
                            if email:
                                tenants_cfg[tenant_id]["domains"][domain]["emails"][email] = user_info
            except Exception:
                pass

        if not tenants_cfg:
            return jsonify({"error": "No O365 tenants configured (check main.yml api.o365 and mission YAMLs)."})

        results = []
        for tenant_id, t_cfg in tenants_cfg.items():
            client_id     = t_cfg.get("client_id", "")
            client_secret = t_cfg.get("client_secret", "")

            if not client_id or not client_secret:
                # No live credentials — return config-based data only
                domains = [
                    {"id": d, "verified": None, "services": info.get("services", [])}
                    for d, info in t_cfg["domains"].items()
                ]
                emails = [
                    {"email": user_info.get("email", e), "name": user_info.get("name", ""), "licensed": None}
                    for d_info in t_cfg["domains"].values()
                    for e, user_info in d_info.get("emails", {}).items()
                ]
                results.append({"tenant_id": tenant_id, "source": "config", "domains": domains, "emails": emails})
                continue

            # Acquire token via MSAL (same logic as Tenant.__init__ in lib/o365.py)
            app_msal = msal.ConfidentialClientApplication(
                client_id,
                authority="https://login.microsoftonline.com/%s" % tenant_id,
                client_credential=client_secret,
            )
            token_result = app_msal.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            token = token_result.get("access_token", "")
            if not token:
                results.append({"tenant_id": tenant_id, "error": "Failed to acquire token: %s" % token_result.get("error_description", "")})
                continue

            headers = {"Authorization": "Bearer %s" % token}

            # list_domains() — mirrors Tenant.list_domains()
            domains = []
            resp = req.get("https://graph.microsoft.com/v1.0/domains", headers=headers, timeout=10)
            for d in resp.json().get("value", []):
                domains.append({
                    "id":       d.get("id", ""),
                    "verified": d.get("isVerified", False),
                    "services": d.get("supportedServices", []),
                })

            # list_users() — mirrors Tenant.list_users()
            emails = []
            resp = req.get(
                "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,displayName,assignedLicenses",
                headers=headers, timeout=10
            )
            for u in resp.json().get("value", []):
                emails.append({
                    "email":    u.get("userPrincipalName", ""),
                    "name":     u.get("displayName", ""),
                    "licensed": len(u.get("assignedLicenses", [])) > 0,
                })

            results.append({"tenant_id": tenant_id, "source": "live", "domains": domains, "emails": emails})

        return jsonify({"tenants": results})
    except ImportError as e:
        return jsonify({"error": "Missing dependency: %s. Run: pip install msal requests" % str(e)})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/api/inventory/sendgrid")
def api_inventory_sendgrid():
    if MOCK_MODE:
        return jsonify({
            "domains": [
                {"domain": "redteamdomain.com",  "valid": True,  "subdomain": "em123"},
                {"domain": "phish-domain.io",    "valid": False, "subdomain": "em456"},
            ],
            "senders": [
                {"email": "john.doe@redteamdomain.com", "nickname": "John Doe",    "verified": True},
                {"email": "noreply@redteamdomain.com",  "nickname": "No Reply",    "verified": True},
                {"email": "support@phish-domain.io",    "nickname": "Support",     "verified": False},
            ]
        })
    try:
        import urllib.request as urlreq
        cfg = get_main_config()
        sg_key = cfg.get("api",{}).get("sendgrid_api","")
        if not sg_key:
            return jsonify({"error": "No SendGrid API key configured in Settings."})

        def sg_get(path):
            req = urlreq.Request(
                "https://api.sendgrid.com/v3" + path,
                headers={"Authorization": "Bearer " + sg_key, "Content-Type": "application/json"}
            )
            with urlreq.urlopen(req, timeout=10) as r:
                return json.loads(r.read())

        # Authenticated domains
        doms_resp = sg_get("/whitelabel/domains")
        domains = []
        for d in (doms_resp if isinstance(doms_resp, list) else []):
            domains.append({
                "domain": d.get("domain",""),
                "valid":  d.get("valid", False),
                "subdomain": d.get("subdomain",""),
            })

        # Verified senders
        senders_resp = sg_get("/verified_senders")
        senders = []
        for s in senders_resp.get("results", []):
            senders.append({
                "email":    s.get("from_email",""),
                "nickname": s.get("nickname",""),
                "verified": s.get("verified", False),
            })

        return jsonify({"domains": domains, "senders": senders})
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == "__main__":
    print("🔴 RedInfra Dashboard — http://127.0.0.1:4444")
    print("   Config: %s | Mode: %s" % (CONFIG_PATH, "MOCK" if MOCK_MODE else "LIVE"))
    app.run(host="127.0.0.1", port=4444, debug=False, threaded=True)
