#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
    echo ""
    echo "[*] Shutting down..."
    kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
    wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
}
trap cleanup INT TERM

echo "[*] Starting backend..."
cd "$ROOT/backend"
go run . &
BACKEND_PID=$!

echo "[*] Starting frontend..."
cd "$ROOT/frontend"
npm start &
FRONTEND_PID=$!

echo "[*] Backend PID: $BACKEND_PID  Frontend PID: $FRONTEND_PID"
echo "[*] Press Ctrl+C to stop both."

wait "$BACKEND_PID" "$FRONTEND_PID"
