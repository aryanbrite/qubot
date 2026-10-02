#!/usr/bin/env bash
cd "$(dirname "$0")"
export PQSECURE_HOME="$(mktemp -d)"   # throwaway keys, so the demo leaves nothing behind
python3 server.py & S=$!
sleep 2
python3 client.py
sleep 0.5
kill $S 2>/dev/null
rm -rf "$PQSECURE_HOME"
