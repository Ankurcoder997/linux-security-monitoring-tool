#!/bin/bash
# Security Monitoring Tool - Ubuntu
LOGDIR=~/monitoring/logs
mkdir -p "$LOGDIR"
REPORT="$LOGDIR/report_$(date +%F_%H-%M).txt"
THRESHOLD=5

getlog() {
    if [ -f /var/log/auth.log ]; then
        sudo cat /var/log/auth.log
    else
        sudo journalctl -t sshd -t sshd-session -t sudo --no-pager
    fi
}

LOG=$(getlog)

{
echo "===== SECURITY REPORT: $(hostname) - $(date) ====="

echo -e "\n[1] Failed login attempts (last 10)"
echo "$LOG" | grep "Failed password" | tail -10

echo -e "\n[2] Top IPs with failed logins"
echo "$LOG" | grep "Failed password" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -5

echo -e "\n[3] Currently logged-in users"
who

echo -e "\n[4] Recent logins"
last -n 5

echo -e "\n[5] Open listening ports"
ss -tulnp

echo -e "\n[6] Recent sudo usage"
echo "$LOG" | grep "sudo:" | grep "COMMAND" | tail -5

echo -e "\n[7] World-writable files in /etc (risky)"
sudo find /etc -xdev -type f -perm -0002 2>/dev/null

echo -e "\n[8] Users with UID 0 (should only be root)"
awk -F: '$3==0 {print $1}' /etc/passwd

echo -e "\n[9] Firewall status"
sudo ufw status
} > "$REPORT"

COUNT=$(echo "$LOG" | grep -c "Failed password")
if [ "$COUNT" -gt "$THRESHOLD" ]; then
    echo "ALERT: $COUNT failed login attempts detected!" | tee -a "$REPORT"
else
    echo "OK: $COUNT failed login attempts. No alert." | tee -a "$REPORT"
fi

echo "Report saved: $REPORT"
