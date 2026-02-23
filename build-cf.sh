#!/bin/bash
set -e

echo "=== Running OpenNext Cloudflare build ==="
npx @opennextjs/cloudflare build

echo ""
echo "=== .open-next directory contents ==="
ls -la .open-next/ 2>/dev/null || echo "(not found)"

echo ""
# Check for worker file and rename to _worker.js if needed
if [ -f ".open-next/worker.js" ]; then
  echo "Found worker.js -> renaming to _worker.js"
  mv .open-next/worker.js .open-next/_worker.js
elif [ -f ".open-next/_worker.js" ]; then
  echo "_worker.js already present — good"
else
  echo "WARNING: No worker.js found in .open-next/"
  find .open-next -name "*.js" | head -10
fi

echo ""
echo "=== Final .open-next contents ==="
ls -la .open-next/
