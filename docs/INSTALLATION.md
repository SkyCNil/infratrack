# InfraTrack Installation Manual

## 1. Prerequisites
- Windows Server/Windows 10+ (or Linux) with network access to SQL Server.
- Python 3.11+ recommended.
- SQL Server (Express/Standard/Enterprise).
- ODBC Driver 17 or 18 for SQL Server.

## 2. Application Package
Expected package contents:
- `main.py`
- `static/`
- `templates/`
- `requirements.txt`
- `.env.example`
- `db/setup_sqlserver.sql`
- `start.bat` / `start.sh`

## 3. Database Setup
1. Open SSMS with admin rights.
2. Run `db/setup_sqlserver.sql`.
3. Confirm DB `itam_db` and user `apitam_user` exist.

## 4. Configure Environment
1. Copy `.env.example` to `.env`.
2. Set:
   - `ITAM_SECRET_KEY`
   - `ITAM_DB_URL`
   - `ITAM_HOST`
   - `ITAM_PORT`
   - `ITAM_PUBLIC_URL` (optional but recommended)

Example:
`mssql+pyodbc://apitam_user:StrongPassword123!@localhost\\SQLEXPRESS/itam_db?driver=ODBC+Driver+17+for+SQL+Server`

Example host/port:
- `ITAM_HOST=0.0.0.0` (accessible from network)
- `ITAM_PORT=8000`
- `ITAM_PUBLIC_URL=http://10.10.10.25:8000`

## 5. Install Dependencies
### Windows
1. Open terminal in project folder.
2. Run:
   - `python -m venv .venv`
   - `.venv\Scripts\activate`
   - `pip install -r requirements.txt`

### Linux
1. Run:
   - `python3 -m venv .venv`
   - `source .venv/bin/activate`
   - `pip install -r requirements.txt`

## 6. Start Application
- Windows: `start.bat`
- Linux: `bash start.sh`

App URL:
- `http://127.0.0.1:8000`

If you changed host/port:
- `http://<server-ip>:<port>`
- Example: `http://10.10.10.25:8000`

## 7. First-Time Access
1. Open app in browser.
2. Create first user from `/users/` (first user becomes `Admin`).
3. Login and complete password change if prompted.
4. Go to `Users` page and upload customer/company logo in `Branding` section.

## 8. Production Run (No Reload)
Use:
`uvicorn main:app --host 0.0.0.0 --port 8000`

Run behind reverse proxy (IIS/Nginx) for HTTPS.

## 8A. Using a Custom URL/Domain
### Option 1: Access by server IP
1. Set `ITAM_HOST=0.0.0.0`.
2. Keep `ITAM_PORT=8000` (or another open port).
3. Open firewall for that port.
4. Access using `http://<server-ip>:<port>`.

### Option 2: Access by domain name (recommended)
1. Create DNS record (e.g., `itam.yourcompany.com`) pointing to server IP.
2. Configure reverse proxy (IIS/Nginx) to forward to `127.0.0.1:8000`.
3. Bind SSL certificate on reverse proxy.
4. Set `ITAM_PUBLIC_URL=https://itam.yourcompany.com`.
5. Users access app via domain URL only.

## 9. Backup
- SQL backup: full DB backup of `itam_db`.
- App backup: project files + `.env`.
- Barcode images: `static/barcodes/`.

## 10. Upgrade
1. Stop app service.
2. Backup DB and app files.
3. Replace app files with new release.
4. Run app and validate login/report/asset workflows.
5. Validate branding logo is displayed on login and sidebar.

## 11. Troubleshooting
See `docs/TROUBLESHOOTING.md`.
