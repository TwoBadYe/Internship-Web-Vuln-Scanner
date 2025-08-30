# 🛡️ Web Vulnerability Scanner

[![GitHub stars](https://img.shields.io/github/stars/yourusername/your-repo.svg?style=social)](https://github.com/yourusername/your-repo)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Frontend](https://img.shields.io/badge/frontend-React%20%2B%20ChakraUI-61dafb.svg)]()

> Full-stack web vulnerability scanner — FastAPI backend + React frontend.  
> Detects common web vulnerabilities (SQLi, XSS, etc.), fingerprints web technologies and performs CVE lookups (Vulners). Built as an internship project.

---

## 💡 Project overview

This repository contains a lightweight, modular web vulnerability scanner intended for educational and authorized security testing. It includes:

- **Basic scans** (SQLi, XSS, open ports, directory traversal, security headers)
- **Advanced scans** (technology fingerprinting + CVE lookup using Vulners or a static DB)
- **Backend**: FastAPI (async), modular scanner plugin architecture  
- **Frontend**: React with Chakra UI (interactive dashboard to start scans & view results)

> ⚠️ **Use responsibly.** Only scan systems you own or have explicit permission to test.

---

## ✨ Highlights / Why this project

- Modular scan architecture — add/remove scanners as independent modules.
- Asynchronous scanning for performance (httpx + asyncio).
- Easy to use UI for non-CLI users.
- Extensible advanced pipeline: fingerprint → CVE lookup → aggregated report.

---

## 🚀 Demo / Quickstart

### Prerequisites
- Python 3.10+
- Node.js 16+ / npm or yarn

### Backend (FastAPI)
```bash
# from repo root
cd vuln-scanner-backend

# create & activate venv (Linux/macOS)
python -m venv venv
source venv/bin/activate

# or Windows Powershell
python -m venv venv
.env\Scripts\Activate.ps1

pip install -r requirements.txt

# create .env (see .env.example)
# VULNERS_API_KEY=your_key_here

uvicorn app.main:app --reload
# Open: http://127.0.0.1:8000/docs for Swagger UI
```

### Frontend (React + Chakra)
```bash
cd vuln-scanner-frontend
npm install
npm run dev              # or npm start (depending on setup)
# Open: http://localhost:5173 (or indicated port)
```

---

## 🧭 API Quick Reference

**Start basic scan**
```
POST /scan/scan/basic
Content-Type: application/json

{
  "target": "http://testphp.vulnweb.com",
  "options": ["XSS", "SQL Injection", "Open Ports"]
}
```
Response:
```json
{ "scan_id": "<uuid>", "status": "in_progress" }
```

**Check status**
```
GET /scan/scan/{scan_id}/status
```

**Get results**
```
GET /scan/scan/{scan_id}/results
```

**List available modular scans**
```
GET /scan/available
```

---

## 🧩 Architecture

```
Frontend (React + Chakra)
          ↓ REST
Backend (FastAPI)
 ├─ router.py (API)
 ├─ scan_core.py (scan orchestration)
 ├─ scans_basic/ (individual basic scanner modules)
 └─ scans_advanced/ (fingerprint + cve_lookup)
Store (in-memory dict for scan status/results) ← replaceable by DB
```

---
## 📸 Screenshots

### Dashboard View
![Dashboard Screenshot](docs/ProjectUI.JPG.png)

### Basic Vulnerability Report
![Vulnerability Report Screenshot](docs/ProjectTest1.png)

### Service Scan
![Service Scan Screenshot](docs/ProjectTest2.png)

---
## 🔧 Configuration & Environment

Create a `.env` file in the backend root (do **not** commit it). Example `.env.example`:

```
VULNERS_API_KEY=your_vulners_api_key_here
# OPTIONAL: other config
```

Add `.env` to `.gitignore`:
```
# .gitignore
.env
venv/
node_modules/
```

**Keep API keys secret.** Use GitHub Secrets for CI or environment variables on your deployment host.

---

## 🧪 Testing the CVE lookup (standalone)

You can test the CVE lookup without the full scanner using a test script:

```bash
# from vuln-scanner-backend
python -m app.scans_advanced.test_cve_lookup
```

(Or run the included `test_cve_lookup.py` - use `python -m` from the project root so Python finds the `app` package.)

---

## ✅ What to expect when scanning a test target

- For intentionally vulnerable targets like `http://testphp.vulnweb.com/`, basic scanners should report XSS and SQLi signals (reflected payloads and SQL errors).
- Fingerprinting should detect server/technology headers (Apache, PHP, nginx, etc.).
- CVE lookup will return HIGH/CRITICAL results if a product+version match exists in Vulners or the static DB.

---

## 📚 Static CVE DB fallback

If no Vulners key is provided, the scanner falls back to a local JSON (`app/data/cve_db.json`). Use this to ship deterministic tests.

---

## 🛠️ Development notes & tips

- If FastAPI docs (`/docs`) don’t load, ensure uvicorn is started in the backend folder and your Python path includes `app/` (start using `python -m app.main` or `uvicorn app.main:app` from project root).
- When running test scripts inside subpackages, prefer `python -m app.scans_advanced.test_*` so Python treats `app` as a package.
- Remove unused/experimental modules (e.g., `nvdlib`) to reduce complexity and dependency issues.

---

## 🔁 Roadmap / Future work

- Persist scans to SQLite/Postgres (instead of in-memory store).
- Add authenticated scanning & login flows.
- Rate limiting and user quotas for safe multi-tenant usage.
- Export scan reports (PDF/CSV) and scheduled recurring scans.
- Containerize (Docker) for deployment.

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE).

---

## 👤 Author / Contact

Jawher Khiari — Internship Project (2025)  
[text](https://www.linkedin.com/in/jawher-khiari-88a32b2ba/)
