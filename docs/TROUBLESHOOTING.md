# Troubleshooting

## App does not start
- Check Python version: `python --version`
- Reinstall dependencies: `pip install -r requirements.txt`
- Verify `.env` values.

## Database connection error
- Validate SQL Server instance name in `ITAM_DB_URL`.
- Confirm ODBC Driver installed.
- Confirm SQL login/user/password.

## `No time zone found with key Asia/Kolkata`
- App has fallback to fixed IST offset.
- Optional fix: install tzdata `pip install tzdata`.

## 401 Unauthorized on first page load
- Usually caused by expired access/refresh tokens in browser.
- Logout and login again.
- Clear browser local storage if needed.

## Bulk upload failures
- Use sample CSV template.
- Keep dates as `YYYY-MM-DD`.
- Ensure serial numbers are unique.
- Check toast error lines for row-level issues.

## QR/Barcode not printing
- Ensure `static/barcodes/` is writable.
- Reopen asset detail and use reprint option.
