#!/bin/bash
# Script to run the gateway and mock upstream server concurrently

echo "Starting Mock Upstream Server on port 8080..."
python -m uvicorn upstream.mock_server:app --host 127.0.0.1 --port 8080 &
UPSTREAM_PID=$!

echo "Starting Gateway on port 8000..."
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &
GATEWAY_PID=$!

function cleanup {
  echo "Shutting down servers..."
  kill $UPSTREAM_PID
  kill $GATEWAY_PID
  exit
}

trap cleanup SIGINT SIGTERM

echo "Servers are running. Press Ctrl+C to stop."
wait
