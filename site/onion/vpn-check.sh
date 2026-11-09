#!/usr/bin/env bash
# Run any time: shows tunnel state, the public IP, and whether anything can leak outside the VPN.
IF=wg0
echo "tunnel:"; wg show $IF 2>/dev/null | sed -n '1,12p' || echo "  wg0 is down"
echo "public IP: $(curl -fsS --max-time 15 https://check.torproject.org/api/ip 2>/dev/null | jq -r '.IP // "unreachable"')"
dif=$(ip -o link show | awk -F': ' '$2 !~ /^(lo|wg0)/ {print $2; exit}')
if [ -n "$dif" ] && curl -fsS --max-time 6 --interface "$dif" -o /dev/null https://check.torproject.org/ 2>/dev/null; then
  echo "LEAK: reachable through $dif outside the tunnel"; exit 1
else
  echo "leak test: nothing leaves outside the tunnel"
fi
