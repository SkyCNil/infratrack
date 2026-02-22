# Release Checklist

## Before Packaging
- [ ] Update version in release notes.
- [ ] Run app and verify login, asset creation, assignment, reports.
- [ ] Validate DB connectivity on clean environment.
- [ ] Validate CSV report downloads.
- [ ] Remove dev-only credentials.

## Package Contents
- [ ] Application code (`main.py`, `static/`, `templates/`)
- [ ] `requirements.txt`
- [ ] `.env.example`
- [ ] `db/setup_sqlserver.sql`
- [ ] `docs/` manuals
- [ ] startup scripts (`start.bat`, `start.sh`)

## Delivery
- [ ] Zip folder as `ITAM_vX.Y.Z.zip`
- [ ] Provide checksum (SHA256)
- [ ] Provide license/EULA documents
- [ ] Provide support contact and SLA details
