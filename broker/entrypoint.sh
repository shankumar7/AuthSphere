#!/bin/sh
set -e

# Fix permissions on /mosquitto/data volume if running as root initially or entrypoint
chmod -R 777 /mosquitto/data 2>/dev/null || true

# Start Mosquitto in background
mosquitto -c /mosquitto/config/mosquitto.conf &
MOSQUITTO_PID=$!

# Background watcher: reloads Mosquitto ONLY when crl.pem modification time changes
(
  LAST_MTIME=0
  while true; do
    sleep 5
    if [ -f /mosquitto/pki/crl.pem ]; then
      CURRENT_MTIME=$(stat -c %Y /mosquitto/pki/crl.pem 2>/dev/null || date +%s)
      if [ "$LAST_MTIME" -ne 0 ] && [ "$CURRENT_MTIME" -ne "$LAST_MTIME" ]; then
        if kill -0 $MOSQUITTO_PID 2>/dev/null; then
          echo "[broker-entrypoint] crl.pem updated, reloading Mosquitto config..."
          kill -HUP $MOSQUITTO_PID 2>/dev/null || true
        fi
      fi
      LAST_MTIME=$CURRENT_MTIME
    fi
  done
) &

# Wait for main process
wait $MOSQUITTO_PID
