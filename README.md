# 🔐 Mini Vulnerability Scanner

> **⚠️ ETHICAL USE ONLY** — Only scan systems you own or have **explicit written permission** to test.  
> Unauthorized scanning may violate computer crime laws in your jurisdiction.

A beginner-to-intermediate production-ready vulnerability scanner built with **FastAPI + SQLite + vanilla HTML/CSS/JS**.

---

## 📁 Project Structure

```
mini-vuln-scanner/
├── backend/
│   ├── main.py                  # FastAPI app entry point
│   ├── requirements.txt
│   ├── .env.example
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── port_scanner.py      # Multithreaded TCP port scanner
│   │   ├── web_scanner.py       # HTTP header & HTTPS analysis
│   │   ├── orchestrator.py      # Combines all scan modules
│   │   └── utils.py             # Validation, DNS, risk scoring
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py            # FastAPI route handlers
│   └── models/
│       ├── __init__.py
│       └── database.py          # SQLite CRUD layer
├── frontend/
│   └── index.html               # Single-file UI (HTML + CSS + JS)
├── render.yaml                  # Render.com deployment config
├── vercel.json                  # Vercel frontend deployment
├── Procfile                     # Railway / Heroku
└── README.md
```

---

## 🚀 Local Setup (5 minutes)

### Prerequisites
- Python 3.11+
- pip

### 1. Clone / download the project
```bash
git clone https://github.com/yourname/mini-vuln-scanner.git
cd mini-vuln-scanner
```

### 2. Create virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 4. Configure environment
```bash
cp .env.example .env
# Edit .env if needed (defaults work for local dev)
```

### 5. Run the server
```bash
# From the backend/ directory
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Open the UI
Visit **http://localhost:8000** in your browser.  
The backend serves the frontend at the root path automatically.

---

## 🌐 API Reference

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scans` | Start a new scan |
| `GET`  | `/scans` | List scan history |
| `GET`  | `/scans/{id}` | Get scan result |
| `DELETE` | `/scans/{id}` | Delete a scan |
| `GET`  | `/scans/{id}/report` | Download JSON report |
| `GET`  | `/health` | Health check |

### Example: Start a scan
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "common_ports_only": true,
    "skip_web": false
  }'
```

Response:
```json
{ "scan_id": 1, "status": "running", "target": "example.com" }
```

### Example: Poll result
```bash
curl http://localhost:8000/api/v1/scans/1
```

---

## ☁️ Free Cloud Deployment

### Option A: Backend on Render.com + Frontend on Vercel

#### Backend (Render)
1. Push code to GitHub
2. Go to [render.com](https://render.com) → **New Web Service**
3. Connect your GitHub repo
4. Set:
   - **Root Directory**: `backend`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free
5. Add environment variables from `.env.example`
6. Deploy. Note your URL: `https://mini-vuln-scanner.onrender.com`

#### Frontend (Vercel)
1. Go to [vercel.com](https://vercel.com) → **New Project**
2. Import your repo
3. Set **Output Directory** to `frontend`
4. In `frontend/index.html`, change:
   ```js
   const API = 'https://mini-vuln-scanner.onrender.com';
   ```
5. Deploy

### Option B: Full stack on Railway.app
1. Push to GitHub
2. Go to [railway.app](https://railway.app) → **New Project from GitHub**
3. Railway auto-detects the `Procfile`
4. Add env vars from `.env.example`
5. Done – Railway provides a public URL

---

## 🔬 Scan Modules

### Port Scanner (`scanner/port_scanner.py`)
- Multithreaded TCP connect scan (default: 100 threads)
- Scans 24 common ports by default, or full 1–1024 range
- Identifies services (HTTP, SSH, FTP, etc.)
- Flags insecure ports (FTP/21, Telnet/23, Redis/6379, etc.)

### Web Scanner (`scanner/web_scanner.py`)
Checks:
- HTTPS availability
- HTTP → HTTPS redirect
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Server banner version disclosure
- Insecure cookie flags (missing Secure / HttpOnly)

### Risk Scoring
- Each vulnerability carries a severity weight: Critical=30, High=15, Medium=8, Low=3
- Risk score is capped at 100
- Levels: Safe / Low / Medium / High / Critical

---

## 🧪 Example Test

### Input
```json
{
  "target": "neverssl.com",
  "common_ports_only": true,
  "skip_web": false
}
```

### Expected Output (abbreviated)
```json
{
  "target": "neverssl.com",
  "risk_score": 31,
  "risk_level": "Medium",
  "port_count": 1,
  "open_ports": [
    { "port": 80, "service": "HTTP", "state": "open",
      "vulnerability": { "severity": "medium", "message": "Plain HTTP is exposed…" } }
  ],
  "vulnerabilities": [
    { "type": "NO_HTTPS", "severity": "high", "title": "HTTPS not available", ... },
    { "type": "MISSING_HSTS", "severity": "high", "title": "Missing header: Strict-Transport-Security", ... },
    { "type": "MISSING_CSP",  "severity": "high", "title": "Missing header: Content-Security-Policy", ... }
  ],
  "total_issues": 7
}
```

---

## 🛡️ Security & Rate Limiting

- **Input validation**: Only valid IPs and domains accepted; loopback blocked
- **Rate limiting**: Max 5 scan requests / minute per IP (via slowapi)
- **CORS**: Configurable allowed origins
- **No external services**: Everything runs locally; no data leaves your server

---

## 🔧 Extending the Scanner

Adding a new check is simple:

1. Create a function in `scanner/web_scanner.py` or a new module
2. Return a list of vulnerability dicts with keys: `type`, `severity`, `title`, `detail`, `recommendation`
3. Merge results in `scanner/orchestrator.py`

Severity values: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `fastapi` | Web framework |
| `uvicorn` | ASGI server |
| `requests` | HTTP client for web scanner |
| `slowapi` | Rate limiting |
| `pydantic` | Request validation |
| `python-dotenv` | Environment config |

SQLite is built into Python — no external database needed.

---

## 📄 License

MIT — use freely, responsibly.
