#!/usr/bin/env bash
cd "$(dirname "$0")"
python3 server.py & S=$!
sleep 1
python3 client.py
sleep 0.5
kill $S 2>/dev/null
