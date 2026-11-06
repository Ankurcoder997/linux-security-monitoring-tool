# Security Monitoring Tool (Ubuntu)

A lightweight security monitoring tool for Ubuntu, built as a Linux system administration PBL project. It has two parts:

1. **`monitoring.sh`** is a Bash script that writes a security report and prints an ALERT when too many failed logins are detected.
2. **`dashboard.py`** is a live web dashboard (Python 3 standard library only) with a status banner, attacker IP detection, and a radar view.

## Features

- Detects failed SSH login attempts and raises an alert above a threshold (more than 5)
- **IP address detection:** shows each attacking IP with its attempt count, usernames tried, last-seen time, and type (Local, Private, or Public)
- Shows this server's own IP addresses per network interface
- Live radar with one blip per attacking IP
- Recent events feed (failed logins, successful logins, sudo commands)
- System checks: only root has UID 0, no world-writable files in `/etc`, firewall status, auth log readable
- Open listening ports, currently logged-in users, and system vitals (load, memory, disk, uptime)
- Timestamped text reports saved to `~/monitoring/logs/`
- Automation with cron (runs every 5 minutes)

## Project structure

```
~/monitoring/
├── monitoring.sh      # report + alert script
├── dashboard.py       # web dashboard
├── README.md
└── logs/              # saved reports (report_YYYY-MM-DD_HH-MM.txt)
```

## Requirements

- Ubuntu Desktop or Server (tested on the Ubuntu used in lab)
- Packages: `openssh-server`, `net-tools`, `ufw`, `python3`, `nano`
- `sudo` access (needed to read the auth log)

## Installation

```bash
sudo hostnamectl set-hostname ubuntu
sudo apt update
sudo apt install -y openssh-server net-tools ufw python3 nano
sudo systemctl enable --now ssh

mkdir -p ~/monitoring/logs
cd ~/monitoring
```

Copy `monitoring.sh` and `dashboard.py` into `~/monitoring/`, then:

```bash
chmod +x monitoring.sh
python3 -m py_compile dashboard.py && echo OK
```

Enable the firewall:

```bash
sudo ufw allow ssh
sudo ufw enable
sudo ufw status
```

## Usage

### Security report script

```bash
cd ~/monitoring
./monitoring.sh
```

The report has 9 sections: failed logins, top attacking IPs, logged-in users, recent logins, open ports, sudo usage, world-writable files in `/etc`, UID 0 users, and firewall status. It ends with either:

- `OK: 0 failed login attempts. No alert.`
- `ALERT: N failed login attempts detected!`

View the latest report:

```bash
cat "$(ls -t ~/monitoring/logs/report_*.txt | head -1)"
```

### Dashboard

```bash
cd ~/monitoring
sudo python3 dashboard.py
```

Open **http://localhost:8080**. It refreshes every 5 seconds.

Options:

| Option | Description |
|---|---|
| `--port 9000` | Change the port (default 8080) |
| `--host 0.0.0.0` | Allow other devices on the network to open the dashboard |
| `--log FILE` | Read a different log file (useful for testing) |

Run with `sudo` so the dashboard can read `/var/log/auth.log` and see which program owns each port.

### Dashboard status levels

| Banner | Meaning |
|---|---|
| Green: No threats detected | No recent failed logins |
| Amber: Suspicious activity | 1 to 5 failed logins in 10 minutes, or a failed critical system check |
| Red: THREAT DETECTED | More than 5 failed logins in 10 minutes (names the top source IP) |

## Testing the tool

### Attack test (wrong passwords)

In a second terminal:

```bash
ssh fakeuser@localhost
```

Enter a wrong password at least 6 times, reconnecting each time. Within about 5 seconds the banner turns red, the attacker IP table fills in, and a blip appears on the radar.

When attacking `localhost`, the IP shows as `127.0.0.1` (Local). To see a LAN address, attack the server's IP shown in the dashboard header:

```bash
ssh fakeuser@192.168.x.x
```

### Real login test (correct password)

```bash
ssh YOUR_USERNAME@localhost
sudo ls /etc
```

The dashboard shows a `Login` event, a `Sudo` event, and your user under Logged-in users. Type `exit` when done.

### Confirm with the script

```bash
./monitoring.sh
```

Expected: `ALERT: 6 failed login attempts detected!` (or higher).

## Automation (cron)

```bash
sudo crontab -e
```

Add this line, replacing `YOUR_USERNAME`:

```
*/5 * * * * /home/YOUR_USERNAME/monitoring/monitoring.sh
```

Verify with `sudo crontab -l`.

## Demo order

1. `hostname` shows `ubuntu`
2. `./monitoring.sh` shows the report
3. `sudo python3 dashboard.py`, then open the browser to the green banner
4. `ssh fakeuser@localhost` with wrong passwords turns the dashboard red with the attacker IP and radar blip
5. `ssh YOUR_USERNAME@localhost` with the correct password shows the Login event
6. `./monitoring.sh` again shows the ALERT
7. `sudo crontab -l` shows the automation, and `ls ~/monitoring/logs` shows the saved reports

## Troubleshooting

| Problem | Fix |
|---|---|
| Permission denied running the script | `chmod +x monitoring.sh` |
| Dashboard stays green after attacks | `sudo tail /var/log/auth.log` to confirm failures are logged |
| SSH connection refused | `sudo systemctl enable --now ssh` |
| Dashboard says it cannot read the log | Start it with `sudo` |
| No `Login` row after a real login | `sudo tail /var/log/auth.log \| grep Accepted` and check `grep PasswordAuthentication /etc/ssh/sshd_config` |
| Port 8080 already in use | `sudo python3 dashboard.py --port 9000` |

## How it works

- **Log source:** reads `/var/log/auth.log`. If it does not exist (newer Ubuntu), it falls back to `journalctl` for `sshd`, `sshd-session`, and `sudo`.
- **Detection:** matches `Failed password`, `Accepted`, and `sudo ... COMMAND=` lines with regular expressions.
- **IP classification:** uses Python's `ipaddress` module. Loopback is Local, private and link-local ranges are Private, everything else is Public.
- **Dashboard:** a small `http.server` that serves one HTML page and a JSON endpoint (`/api/data`) the page polls every 5 seconds.

## Security notes

- The dashboard binds to `127.0.0.1` by default. Only use `--host 0.0.0.0` on a trusted network, because the dashboard has no login of its own.
- Run the tool only on systems you own or are authorized to monitor. Only attack-test your own machine.

## Team

Add your team members' names, roll numbers, and subject details here.
