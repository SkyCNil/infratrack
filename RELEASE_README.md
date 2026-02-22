# InfraTrack Commercial Release Bundle

This package is prepared for customer delivery and on-prem installation.

## Folder Overview
- `main.py` - backend API and server.
- `static/` - frontend React/CSS and barcode files.
- `templates/` - HTML shell template.
- `requirements.txt` - Python dependencies.
- `.env.example` - environment template.
- `db/` - SQL Server setup scripts.
- `docs/` - installation/admin/user/troubleshooting guides.
- `start.bat`, `start.sh` - convenience startup scripts.

## Quick Start
1. Setup database with `db/setup_sqlserver.sql`.
2. Copy `.env.example` to `.env` and update values.
3. Install dependencies using `requirements.txt`.
4. Start app using `start.bat` (Windows) or `start.sh` (Linux).
5. Open `http://127.0.0.1:8000`.

## URL Change (Non-localhost)
- For LAN/IP access:
  - Set `ITAM_HOST=0.0.0.0`
  - Set `ITAM_PORT=<your-port>`
  - Access `http://<server-ip>:<port>`
- For custom domain:
  - Add DNS record to server IP
  - Put IIS/Nginx reverse proxy in front of app
  - Use HTTPS certificate
  - Set `ITAM_PUBLIC_URL=https://your-domain`

## Detailed Docs
- Installation: `docs/INSTALLATION.md`
- Admin operations: `docs/ADMIN_GUIDE.md`
- End-user operations: `docs/USER_GUIDE.md`
- Troubleshooting: `docs/TROUBLESHOOTING.md`
- Release checklist: `docs/RELEASE_CHECKLIST.md`

## Branding
- Product name is set as `InfraTrack`.
- Customer logo can be uploaded by Admin from `Users -> Branding`.
