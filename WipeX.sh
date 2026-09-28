#!/bin/bash
# WipeX launcher for Linux: run ./WipeX.sh (asks for your password once).
# Reading and erasing drives directly needs root rights; the browser still opens as you.
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  echo "First start: installing WipeX's Python packages into .venv (needs the internet once)..."
  echo "(Debian / Ubuntu need: sudo apt install python3-venv python3-dev build-essential)"
  python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt || { echo "Install failed"; read -r; exit 1; }
fi
if [ ! -f dist/index.html ]; then
  echo "Building the user interface once (needs Node.js and the internet once)..."
  npm install && npm run build || { echo "Build failed"; read -r; exit 1; }
fi
sudo -v || exit 1
sudo .venv/bin/python wipex.py --no-browser --port 8000 &
for _ in $(seq 1 60); do
  .venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=1)" 2>/dev/null && break
  sleep 0.5
done
xdg-open http://127.0.0.1:8000/ >/dev/null 2>&1 || echo "Open http://127.0.0.1:8000/ in your browser"
echo "WipeX is running. Close this window or press Ctrl+C to stop it."
wait
