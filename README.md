# Python Vulnerability Scanner (Flask + Nmap + Requests + ZAP)

A lightweight web dashboard to run common recon and vulnerability checks:

- Nmap scan (python-nmap or subprocess fallback)
- TCP port scan using sockets (common ports)
- Basic web scan (Requests + BeautifulSoup): security headers, sensitive files
- OWASP ZAP API integration (passive + optional active scan)

## Prerequisites

- Python 3.10+
- Windows: PowerShell, ensure Python is on PATH
- Optional: Nmap installed and on PATH for subprocess fallback
- Optional: OWASP ZAP (daemon mode) running for ZAP scans

## Setup

1. Create and activate a virtual environment (recommended)

```powershell
python -m venv .venv
. .venv\\Scripts\\Activate.ps1
```

2. Install dependencies

```powershell
pip install -r requirements.txt
```

3. (Optional) Install Nmap for better results
- Download from https://nmap.org/download.html and ensure `nmap` is in PATH

4. (Optional) Run OWASP ZAP in daemon mode
- Download: https://www.zaproxy.org/download/
- Start (example):

```powershell
& "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat" -daemon -host 127.0.0.1 -port 8090 -config api.key=YOUR_ZAP_API_KEY
```

Or set API key via environment and keep ZAP key-protected:

```powershell
$env:ZAP_API_KEY = "YOUR_ZAP_API_KEY"
$env:ZAP_ADDRESS = "127.0.0.1"
$env:ZAP_PORT = "8090"
```

## Run the app

```powershell
$env:FLASK_SECRET_KEY = "dev-secret-key"
python app.py
```

Open http://127.0.0.1:5000

## Environment (.env)

Create a `.env` file at the project root to persist config:

```
# Flask
FLASK_SECRET_KEY=dev-secret-key

# Optional integrations
URLSCAN_API_KEY=your_urlscan_key      # from https://urlscan.io/user/profile/
SHODAN_API_KEY=your_shodan_key        # from https://account.shodan.io/

# OWASP ZAP
ZAP_API_KEY=YOUR_ZAP_API_KEY
ZAP_ADDRESS=127.0.0.1
ZAP_PORT=8090

# Windows-only: set this if Nmap isn't in PATH
# Example: C:\\Program Files (x86)\\Nmap\\nmap.exe
NMAP_PATH=
```

The app auto-loads `.env` if present.

## Notes

- Use only against targets you own or have permission to test.
- Web scan is minimal and safe (headers + discovery of a few files).
- ZAP active scan can be intrusive; enable it only when you have authorization.
- If a dependency (e.g., Nmap or ZAP daemon) is not available, the app will mark that scan as **skipped** with a friendly message so other scans can still run.

## Windows Tips (Nmap)

- If you installed Nmap but the app still says not found:
  - Add Nmap folder to PATH, e.g. `C:\\Program Files (x86)\\Nmap`.
  - Or set `NMAP_PATH` in `.env` to the full path of `nmap.exe`.

Verify from PowerShell:

```powershell
where nmap
```

## Project Structure

- `app.py` — Flask app and routes
- `scanners/` — scan modules
  - `nmap_scanner.py` — Nmap integration
  - `port_scanner.py` — socket-based ports scan
  - `web_scanner.py` — Requests + BeautifulSoup checks
  - `zap_scanner.py` — OWASP ZAP API client
- `templates/` — Jinja2 templates (`index.html`, `results.html`, `base.html`)
- `static/` — CSS styles and favicon
