@echo off
setlocal

if "%ITAM_HOST%"=="" set ITAM_HOST=127.0.0.1
if "%ITAM_PORT%"=="" set ITAM_PORT=8000

if not exist ".venv" (
  echo Creating virtual environment...
  python -m venv .venv
)

call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt

echo Starting ITAM on http://%ITAM_HOST%:%ITAM_PORT%
uvicorn main:app --host %ITAM_HOST% --port %ITAM_PORT% --reload

endlocal
