#!/usr/bin/env python3
"""
Security monitoring dashboard for Ubuntu (with IP address detection).

Run:   sudo python3 dashboard.py
Open:  http://localhost:8080

Needs only Python 3 (already on Ubuntu). Run with sudo so it can read
/var/log/auth.log and see which program owns each open port.

Options:
  --port 9000          change the port
  --host 0.0.0.0       let other devices on the network open the dashboard
  --log FILE           read a different log file (useful for testing)
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
from collections import Counter, deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/var/log/auth.log"
MAX_LINES = 5000
THRESHOLD = 5  # more than this many failures in 10 minutes = red alert

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
SUDO = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+)\s+:.*?COMMAND=(.*)$")


# ---------- helpers ----------
def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def parse_ts(line, now):
    """Handles both Ubuntu log styles: ISO (24.04) and 'Nov  1 13:13:48' (older)."""
    head = line.split(" ", 1)[0]
    if len(head) > 10 and head[4] == "-":
        head = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", head)
        try:
            dt = datetime.fromisoformat(head)
        except ValueError:
            return None
        return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt
    try:
        dt = datetime.strptime(" ".join(line[:15].split()), "%b %d %H:%M:%S")
    except ValueError:
        return None
    dt = dt.replace(year=now.year)
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt


def read_log():
    try:
        with open(LOG_PATH, "r", errors="replace") as f:
            return list(deque(f, maxlen=MAX_LINES))
    except PermissionError:
        return None
    except FileNotFoundError:
        out = run(["journalctl", "-t", "sshd", "-t", "sshd-session", "-t", "sudo",
                   "--no-pager", "-o", "short-iso", "-n", str(MAX_LINES)])
        return out.splitlines()


def classify_ip(ip):
    """Label an address: Local (this machine), Private (LAN) or Public (internet)."""
    try:
        a = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return "Unknown"
    if a.is_loopback:
        return "Local"
    if a.is_private or a.is_link_local:
        return "Private"
    return "Public"


def server_ips():
    """This machine's own IP addresses, per network interface."""
    found = []
    for line in run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        p = line.split()
        if len(p) >= 4 and p[1] != "lo":
            found.append({"iface": p[1], "ip": p[3].split("/")[0]})
    if not found:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            found.append({"iface": "default", "ip": s.getsockname()[0]})
            s.close()
        except OSError:
            pass
    return found


def listening_ports():
    rows = []
    for line in run(["ss", "-tulnpH"]).splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        host, _, port = p[4].rpartition(":")
        prog = re.search(r'\(\("([^"]+)"', line)
        local_only = host.startswith(("127.", "[::1"))
        rows.append({
            "proto": p[0],
            "addr": p[4],
            "prog": prog.group(1) if prog else "",
            "exposed": not local_only,
            "port": int(port) if port.isdigit() else 0,
        })
    rows.sort(key=lambda r: (not r["exposed"], r["port"]))
    return rows


def logged_in():
    users = []
    for line in run(["who"]).splitlines():
        p = line.split()
        if len(p) >= 4:
            users.append({
                "user": p[0], "tty": p[1], "since": " ".join(p[2:4]),
                "origin": p[4].strip("()") if len(p) > 4 else "local",
            })
    return users


def vitals():
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for l in f:
                k, v = l.split(":", 1)
                mem[k] = int(v.split()[0])
        mem_pct = round(100 * (1 - mem["MemAvailable"] / mem["MemTotal"]))
        disk = shutil.disk_usage("/")
        disk_pct = round(100 * disk.used / disk.total)
        with open("/proc/uptime") as f:
            secs = int(float(f.read().split()[0]))
        d, rem = divmod(secs, 86400)
        h, rem = divmod(rem, 3600)
        up = (f"{d}d " if d else "") + f"{h}h {rem // 60}m"
        return {"load": round(os.getloadavg()[0], 2), "mem": mem_pct, "disk": disk_pct, "uptime": up}
    except (OSError, KeyError, ValueError):
        return {"load": 0, "mem": 0, "disk": 0, "uptime": "unknown"}


def system_checks(log_ok):
    checks = []

    extra_root = []
    try:
        with open("/etc/passwd") as f:
            for l in f:
                parts = l.split(":")
                if len(parts) > 3 and parts[2] == "0" and parts[0] != "root":
                    extra_root.append(parts[0])
    except OSError:
        pass
    checks.append({"name": "Only root has UID 0", "critical": True,
                   "status": "Check" if extra_root else "Pass",
                   "detail": ("Also UID 0: " + ", ".join(extra_root)) if extra_root else "No extra superusers"})

    writable = [x for x in run(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"]).splitlines() if x]
    checks.append({"name": "No world-writable files in /etc", "critical": True,
                   "status": "Check" if writable else "Pass",
                   "detail": (", ".join(writable[:3]) + (" ..." if len(writable) > 3 else "")) if writable
                   else "Permissions look safe"})

    if shutil.which("ufw"):
        out = run(["ufw", "status"]).lower()
        if "inactive" in out:
            checks.append({"name": "Firewall (ufw)", "critical": False, "status": "Check",
                           "detail": "Firewall is off. Turn it on with: sudo ufw enable"})
        elif "active" in out:
            checks.append({"name": "Firewall (ufw)", "critical": False, "status": "Pass",
                           "detail": "Firewall is active"})
        else:
            checks.append({"name": "Firewall (ufw)", "critical": False, "status": "Check",
                           "detail": "Could not read status. Run the dashboard with sudo"})
    else:
        checks.append({"name": "Firewall (ufw)", "critical": False, "status": "Check",
                       "detail": "ufw is not installed. Install with: sudo apt install ufw"})

    checks.append({"name": "Authentication log readable", "critical": False,
                   "status": "Pass" if log_ok else "Check",
                   "detail": LOG_PATH if log_ok else "Start the dashboard with sudo"})
    return checks


# ---------- data collection ----------
def collect():
    now = datetime.now()
    lines = read_log()
    failed, accepted, sudo_ev = [], [], []

    for line in lines or []:
        ts = parse_ts(line, now)
        if ts is None:
            continue
        m = FAILED.search(line)
        if m:
            failed.append((ts, m.group(1), m.group(2)))
            continue
        m = ACCEPTED.search(line)
        if m:
            accepted.append((ts, m.group(2), m.group(3), m.group(1)))
            continue
        m = SUDO.search(line)
        if m:
            sudo_ev.append((ts, m.group(1), m.group(2).strip()))

    f10 = sum(1 for t, _, _ in failed if timedelta(0) <= now - t <= timedelta(minutes=10))
    f1h = sum(1 for t, _, _ in failed if timedelta(0) <= now - t <= timedelta(hours=1))

    timeline = [0] * 12
    for t, _, _ in failed:
        idx = int((now - t).total_seconds() // 300)
        if 0 <= idx < 12:
            timeline[11 - idx] += 1

    # ---- IP address detection ----
    ip_stats = {}
    for t, u, ip in failed:
        s = ip_stats.setdefault(ip, {"count": 0, "last": t, "users": set()})
        s["count"] += 1
        s["users"].add(u)
        if t > s["last"]:
            s["last"] = t
    attackers = []
    for ip, s in sorted(ip_stats.items(), key=lambda kv: kv[1]["count"], reverse=True)[:10]:
        attackers.append({
            "ip": ip,
            "count": s["count"],
            "kind": classify_ip(ip),
            "users": sorted(s["users"])[:4],
            "last": s["last"].strftime("%H:%M:%S"),
            "mins_ago": round(max(0, (now - s["last"]).total_seconds()) / 60, 1),
        })

    by_user = Counter(u for _, u, _ in failed).most_common(8)

    events = (
        [(t, "Failed login", f"{u} from {ip}", ip) for t, u, ip in failed]
        + [(t, "Login", f"{u} from {ip} ({how})", ip) for t, u, ip, how in accepted]
        + [(t, "Sudo", f"{u}: {c[:80]}", "") for t, u, c in sudo_ev]
    )
    events.sort(key=lambda e: e[0], reverse=True)

    checks = system_checks(lines is not None)
    bad = [c for c in checks if c["critical"] and c["status"] == "Check"]

    reasons = []
    if lines is None:
        level, headline = "warn", "Cannot read the authentication log"
        reasons.append("Start the dashboard with: sudo python3 dashboard.py")
    elif f10 > THRESHOLD:
        level, headline = "alert", "THREAT DETECTED"
        top = attackers[0] if attackers else None
        reasons.append(f"{f10} failed logins in the last 10 minutes")
        if top:
            reasons.append(f"Top source IP: {top['ip']} ({top['count']} attempts)")
    elif f10 > 0 or bad:
        level, headline = "warn", "Suspicious activity"
        if f10:
            reasons.append(f"{f10} failed login(s) in the last 10 minutes")
        for c in bad:
            reasons.append(f"{c['name']}: {c['detail']}")
    else:
        level, headline = "ok", "No threats detected"
        reasons.append("No recent failed logins")

    return {
        "level": level,
        "headline": headline,
        "reasons": reasons,
        "hostname": socket.gethostname(),
        "server_ips": server_ips(),
        "f10": f10,
        "f1h": f1h,
        "total_failed": len(failed),
        "timeline": timeline,
        "attackers": attackers,
        "by_user": by_user,
        "events": [{"time": t.strftime("%H:%M:%S"), "type": k, "detail": d, "ip": ip}
                   for t, k, d, ip in events[:15]],
        "ports": listening_ports(),
        "users": logged_in(),
        "vitals": vitals(),
        "checks": checks,
        "updated": now.strftime("%H:%M:%S"),
    }


# ---------- web page ----------
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Monitor</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1419;color:#e6e9ee}
header{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;background:#161c24;border-bottom:1px solid #26303c;flex-wrap:wrap;gap:8px}
header h1{margin:0;font-size:18px}
.ips{font-size:13px;color:#9fb0c3}
.ips b{color:#e6e9ee;font-family:ui-monospace,Consolas,monospace;margin:0 8px 0 4px}
#banner{margin:16px 20px;padding:18px 22px;border-radius:10px;font-size:22px;font-weight:700}
#banner small{display:block;font-size:14px;font-weight:400;margin-top:6px;opacity:.95}
.ok{background:#14532d;border:1px solid #22c55e}
.warn{background:#713f12;border:1px solid #f59e0b}
.alert{background:#7f1d1d;border:1px solid #ef4444;animation:pulse 1s infinite}
@keyframes pulse{50%{box-shadow:0 0 18px #ef4444}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px;padding:0 20px 24px}
.card{background:#161c24;border:1px solid #26303c;border-radius:10px;padding:14px 16px;overflow:auto}
.card h2{margin:0 0 10px;font-size:14px;color:#9fb0c3;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:5px 6px;border-bottom:1px solid #222c38}
th{color:#7f90a4;font-weight:600}
.mono{font-family:ui-monospace,Consolas,monospace}
.tag{padding:1px 7px;border-radius:9px;font-size:11px;font-weight:700}
.t-Local{background:#1e3a5f;color:#93c5fd}.t-Private{background:#4a3b12;color:#fcd34d}
.t-Public{background:#7f1d1d;color:#fca5a5}.t-Unknown{background:#333;color:#ccc}
.pass{color:#4ade80}.check{color:#fbbf24}
.bar{display:flex;align-items:flex-end;gap:4px;height:90px}
.bar div{flex:1;background:#ef4444;min-height:2px;border-radius:2px 2px 0 0}
.stats{display:flex;gap:18px;flex-wrap:wrap}
.stats div{font-size:12px;color:#9fb0c3}.stats b{display:block;font-size:20px;color:#e6e9ee}
canvas{width:100%;max-width:340px;display:block;margin:0 auto}
.empty{color:#7f90a4;font-size:13px}
</style></head><body>
<header>
  <h1>&#128737; Security Monitor &mdash; <span id="host"></span></h1>
  <div class="ips">Server IP: <span id="sips"></span> Updated: <b id="upd"></b></div>
</header>
<div id="banner" class="ok">Loading...</div>
<div class="grid">
  <div class="card"><h2>Radar (attacking IPs)</h2><canvas id="radar" width="340" height="340"></canvas></div>
  <div class="card"><h2>Attacker IP addresses</h2><div id="attackers"></div></div>
  <div class="card"><h2>Failed logins, last hour (5-min buckets)</h2><div class="bar" id="timeline"></div>
    <div class="stats" style="margin-top:12px"><div><b id="f10">0</b>last 10 min</div><div><b id="f1h">0</b>last hour</div><div><b id="ftot">0</b>in log</div></div></div>
  <div class="card"><h2>Recent events</h2><div id="events"></div></div>
  <div class="card"><h2>System checks</h2><div id="checks"></div></div>
  <div class="card"><h2>Open ports</h2><div id="ports"></div></div>
  <div class="card"><h2>Logged-in users</h2><div id="users"></div></div>
  <div class="card"><h2>System vitals</h2><div class="stats" id="vitals"></div></div>
</div>
<script>
let DATA = null, sweep = 0;
const $ = id => document.getElementById(id);
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function table(head, rows, empty){
  if(!rows.length) return '<div class="empty">'+empty+'</div>';
  return '<table><tr>'+head.map(h=>'<th>'+h+'</th>').join('')+'</tr>'+
    rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</table>';
}
function hash(s){let h=0;for(const ch of s)h=(h*31+ch.charCodeAt(0))>>>0;return h;}
function render(d){
  DATA = d;
  $('host').textContent = d.hostname;
  $('upd').textContent = d.updated;
  $('sips').innerHTML = d.server_ips.length ? d.server_ips.map(i=>esc(i.iface)+'<b>'+esc(i.ip)+'</b>').join('') : '<b>unknown</b>';
  const b = $('banner'); b.className = d.level;
  b.innerHTML = esc(d.headline) + '<small>' + d.reasons.map(esc).join(' &bull; ') + '</small>';
  $('attackers').innerHTML = table(['IP address','Type','Attempts','Users tried','Last'],
    d.attackers.map(a=>['<span class="mono">'+esc(a.ip)+'</span>','<span class="tag t-'+a.kind+'">'+a.kind+'</span>',a.count,esc(a.users.join(', ')),a.last]),
    'No failed logins from any IP address');
  const mx = Math.max(1, ...d.timeline);
  $('timeline').innerHTML = d.timeline.map(v=>'<div title="'+v+'" style="height:'+Math.round(v/mx*100)+'%"></div>').join('');
  $('f10').textContent = d.f10; $('f1h').textContent = d.f1h; $('ftot').textContent = d.total_failed;
  $('events').innerHTML = table(['Time','Type','Detail'],
    d.events.map(e=>[e.time,esc(e.type),'<span class="mono">'+esc(e.detail)+'</span>']), 'No events yet');
  $('checks').innerHTML = table(['Check','Result','Detail'],
    d.checks.map(c=>[esc(c.name),'<b class="'+c.status.toLowerCase()+'">'+c.status+'</b>',esc(c.detail)]), '');
  $('ports').innerHTML = table(['Proto','Address','Program','Exposed'],
    d.ports.map(p=>[p.proto,'<span class="mono">'+esc(p.addr)+'</span>',esc(p.prog),p.exposed?'<b class="check">Yes</b>':'No']), 'No listening ports found');
  $('users').innerHTML = table(['User','TTY','Since','From'],
    d.users.map(u=>[esc(u.user),esc(u.tty),esc(u.since),esc(u.origin)]), 'Nobody logged in');
  const v = d.vitals;
  $('vitals').innerHTML = '<div><b>'+v.load+'</b>load</div><div><b>'+v.mem+'%</b>memory</div><div><b>'+v.disk+'%</b>disk</div><div><b>'+esc(v.uptime)+'</b>uptime</div>';
}
function drawRadar(){
  const c = $('radar'), x = c.getContext('2d'), W = c.width, cx = W/2, R = W/2-14;
  x.clearRect(0,0,W,W);
  x.strokeStyle = '#1f6f43'; x.lineWidth = 1;
  for(let i=1;i<=4;i++){x.beginPath();x.arc(cx,cx,R*i/4,0,7);x.stroke();}
  x.beginPath();x.moveTo(cx-R,cx);x.lineTo(cx+R,cx);x.moveTo(cx,cx-R);x.lineTo(cx,cx+R);x.stroke();
  sweep += 0.03;
  const g = x.createConicGradient ? x.createConicGradient(sweep,cx,cx) : null;
  if(g){g.addColorStop(0,'rgba(34,197,94,0.45)');g.addColorStop(0.12,'rgba(34,197,94,0)');g.addColorStop(1,'rgba(34,197,94,0)');
    x.fillStyle=g;x.beginPath();x.arc(cx,cx,R,0,7);x.fill();}
  x.strokeStyle='#22c55e';x.beginPath();x.moveTo(cx,cx);x.lineTo(cx+R*Math.cos(sweep),cx+R*Math.sin(sweep));x.stroke();
  x.fillStyle='#22c55e';x.beginPath();x.arc(cx,cx,4,0,7);x.fill();
  if(DATA){
    x.font = '11px ui-monospace,monospace';
    DATA.attackers.filter(a=>a.mins_ago<=60).forEach(a=>{
      const ang = (hash(a.ip)%360)*Math.PI/180;
      const r = R*(0.2 + 0.75*Math.min(a.mins_ago,60)/60);
      const px = cx+r*Math.cos(ang), py = cx+r*Math.sin(ang);
      x.fillStyle = '#ef4444'; x.beginPath(); x.arc(px,py,5+Math.min(a.count,10)/2,0,7); x.fill();
      x.fillStyle = '#fecaca';
      x.textAlign = px > cx ? 'right' : 'left';
      x.fillText(a.ip, px + (px > cx ? -9 : 9), py - 8);
    });
  }
  requestAnimationFrame(drawRadar);
}
async function poll(){
  try{ render(await (await fetch('/api/data')).json()); }
  catch(e){ $('banner').className='warn'; $('banner').textContent='Lost connection to the dashboard server'; }
}
poll(); setInterval(poll, 5000); drawRadar();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] == "/api/data":
            body = json.dumps(collect()).encode()
            ctype = "application/json"
        elif self.path.split("?")[0] == "/":
            body = PAGE.encode()
            ctype = "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    global LOG_PATH
    ap = argparse.ArgumentParser(description="Security monitoring dashboard")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--log", default=LOG_PATH)
    args = ap.parse_args()
    LOG_PATH = args.log

    if os.geteuid() != 0:
        print("Warning: not running as root. Use: sudo python3 dashboard.py")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Dashboard running at http://localhost:{args.port}  (Ctrl+C to stop)")
    for i in server_ips():
        print(f"  Server IP: {i['ip']} ({i['iface']})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
