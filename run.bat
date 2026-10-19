@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Creating LogScout-SH virtual environment...
  py -m venv .venv
  if errorlevel 1 goto error
)
call ".venv\Scripts\activate.bat"
python -m pip install -r requirements.txt
if errorlevel 1 goto error
python -m streamlit run app.py
if errorlevel 1 goto error
goto end
:error
echo.
echo LogScout-SH could not start. Check the error above.
pause
:end
endlocal
