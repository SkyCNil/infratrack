# InfraTrack

<p align="center">
  <img src="static/branding/company_logo.png" alt="InfraTrack Logo" width="96" />
</p>

<p align="center">
  <b>Enterprise IT Asset Management for modern infrastructure teams.</b><br/>
  Track assets. Control lifecycle. Stay audit-ready.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/React-Frontend-61DAFB?logo=react&logoColor=black">
  <img alt="SQL Server" src="https://img.shields.io/badge/SQL%20Server-Database-CC2927?logo=microsoftsqlserver&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-blue">
</p>

---

## Why InfraTrack?

InfraTrack is built for organizations that need:
- Centralized asset visibility
- Controlled assignment/return/repair workflows
- Strong audit trails with lifecycle events
- Business-ready reports in CSV
- Role-based access for Admin, IT User, and Viewer

---

## Key Features

### Asset Lifecycle Management
- Structured Asset ID generation (`ITAM-<TYPE>-<LOC>-<YEAR>-<SEQ>`)
- Asset creation (single + bulk upload via CSV/XLSX)
- Status transitions with mandatory remarks
- Lifecycle actions: `InStock`, `Assigned`, `UnderRepair`, `Lost`, `EndOfLife`, `Scrapped`

### Assignment & Accountability
- Assign assets to users with department/location context
- Return to inventory and repair workflows
- Timeline history per asset and per user
- Current and historical assignment visibility

### Security & Access Control
- JWT auth with refresh token flow
- Password policy enforcement
- Role-based permissions
- First-login password change flow

### Reporting
- Asset Register
- Current Assignments
- Assignment History
- Lifecycle Events
- Assets by Status
- Assets by Department
- Warranty Expiry reports

### Branding
- Product branding as **InfraTrack**
- Admin-uploadable company logo for each customer deployment

---

## Product Preview

> Add screenshots/gifs in this section for stronger GitHub presentation.

```text
assets/screenshots/dashboard.png
assets/screenshots/asset-detail.png
assets/screenshots/assignment.png
assets/screenshots/reports.png
```

---

## Architecture

```text
Frontend (React + CSS)
        |
        v
Backend API (FastAPI)
        |
        v
SQL Server (Assets, Users, Assignments, Audit)
```

---

## Quick Start

### 1) Clone
```bash
git clone https://github.com/<your-username>/infratrack.git
cd infratrack
```

### 2) Configure
```bash
cp .env.example .env
```
Update `.env` with your DB and secret values.

### 3) Setup DB
Run:
`db/setup_sqlserver.sql`

### 4) Install dependencies
```bash
pip install -r requirements.txt
```

### 5) Run
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open: `http://127.0.0.1:8000`

---

## Deployment Notes

- Use `ITAM_HOST=0.0.0.0` for LAN access.
- For domain-based access, deploy behind IIS/Nginx reverse proxy with HTTPS.
- See full setup guide: `docs/INSTALLATION.md`

---

## Documentation

- Installation: `docs/INSTALLATION.md`
- Admin Guide: `docs/ADMIN_GUIDE.md`
- User Guide: `docs/USER_GUIDE.md`
- Troubleshooting: `docs/TROUBLESHOOTING.md`
- Release Checklist: `docs/RELEASE_CHECKLIST.md`

---

## Roadmap

- PDF/Excel advanced report packs
- Multi-company partitioning
- Email/Teams notifications
- SSO integration
- API docs for third-party integrations

---

## Contributing

Contributions are welcome.

1. Fork the repo
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

## License

Licensed under the Apache 2.0 License.
See `LICENSE` for details.

---

## Built For IT Teams Who Need Control

If your organization manages hardware at scale, InfraTrack gives you the visibility, process discipline, and reporting confidence required for real operations.
