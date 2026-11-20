@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
title Telmex ONT Extractor (Nokia & Huawei) - Auto-Installer & Launcher

:: Ir siempre a la carpeta donde se encuentra este script .bat
cd /d "%~dp0"

echo ========================================================================
echo  TELMEX ONT EXTRACTOR ^& GESTOR VOIP SIP / ASTERISK (NOKIA ^& HUAWEI)
echo  Auto-instalador de entorno Python, PATH y dependencias para Windows
echo ========================================================================
echo.

:: -----------------------------------------------------------------------
:: 1. Verificar si Python 3 ya esta instalado y en el PATH
:: -----------------------------------------------------------------------
set "PY_CMD="

where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PY_CMD=python"
    )
)

if not defined PY_CMD (
    where py >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            set "PY_CMD=py -3"
        )
    )
)

:: Buscar en rutas tipicas de instalacion de Windows si aun no esta en el PATH de esta consola
if not defined PY_CMD (
    for %%P in (
        "%LocalAppData%\Programs\Python\Python312\python.exe"
        "%LocalAppData%\Programs\Python\Python311\python.exe"
        "%LocalAppData%\Programs\Python\Python310\python.exe"
        "%ProgramFiles%\Python312\python.exe"
        "%ProgramFiles%\Python311\python.exe"
        "%ProgramFiles%\Python310\python.exe"
    ) do (
        if exist %%P (
            set "PY_CMD=%%P"
            for %%D in (%%P) do set "PATH=%%~dpD;%%~dpDScripts;%PATH%"
            goto :python_found
        )
    )
)

:check_install_python
if defined PY_CMD goto :python_found

echo [!] Python 3.8+ no se detecto en este equipo.
echo [*] Iniciando descarga e instalacion automatica de Python 3.12 (con PrependPath=1)...

:: Intentar primero con winget si esta disponible en Windows 10/11
where winget >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Instalando Python 3.12 mediante Windows Package Manager ^(winget^)...
    winget install -e --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements
)

:: Verificar si winget lo instalo en LocalAppData
if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
    set "PY_DIR=%LocalAppData%\Programs\Python\Python312"
    set "PATH=!PY_DIR!;!PY_DIR!\Scripts;%PATH%"
    set "PY_CMD=!PY_DIR!\python.exe"
    goto :python_found
)

:: Fallback: Descargar el instalador oficial desde python.org con PowerShell e instalar silenciosamente con PrependPath=1
echo [*] Descargando instalador oficial de Python 3.12.7 ^(64-bit^) desde python.org...
set "PY_INSTALLER=%TEMP%\python-3.12.7-amd64.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe' -OutFile '%PY_INSTALLER%'"

if not exist "%PY_INSTALLER%" (
    echo [X] Error: No se pudo descargar el instalador de Python. Verifica tu conexion a Internet.
    pause
    exit /b 1
)

echo [*] Ejecutando instalacion desatendida de Python ^(agregando Python al PATH^)...
"%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_pip=1

if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
    set "PY_DIR=%LocalAppData%\Programs\Python\Python312"
    set "PATH=!PY_DIR!;!PY_DIR!\Scripts;%PATH%"
    set "PY_CMD=!PY_DIR!\python.exe"
) else (
    where python >nul 2>&1
    if !ERRORLEVEL! EQU 0 set "PY_CMD=python"
)

if not defined PY_CMD (
    echo [X] Error: Python se instalo pero requiere reiniciar la ventana de comandos.
    echo     Cierra y vuelve a abrir este archivo setup_and_run.bat.
    pause
    exit /b 1
)

:python_found
echo [+] Python detectado correctamente: %PY_CMD%
%PY_CMD% --version

:: -----------------------------------------------------------------------
:: 2. Crear entorno virtual (.venv) e instalar requirements.txt
:: -----------------------------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creando entorno virtual aislado ^(.venv^)...
    %PY_CMD% -m venv .venv
)

set "VENV_PY=.venv\Scripts\python.exe"
if not exist "%VENV_PY%" (
    echo [!] No se pudo crear .venv, usando Python global...
    set "VENV_PY=%PY_CMD%"
)

echo [*] Verificando e instalando librerias de requirements.txt ^(cryptography^)...
%VENV_PY% -m pip install --upgrade pip --quiet
%VENV_PY% -m pip install -r requirements.txt --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [X] Error instalando requirements.txt. Verifica tu conexion a Internet.
    pause
    exit /b 1
)
echo [+] Entorno y librerias listas ^(descifrado Huawei $2 y Nokia RSA+AES 100%% en Python puro^).
echo.

:: Si se pasaron argumentos por linea de comandos, ejecutarlos directamente
if not "%~1"=="" (
    %VENV_PY% %*
    exit /b %ERRORLEVEL%
)

:: -----------------------------------------------------------------------
:: 3. Lanzar Menu Interactivo Unificado (telmex_launcher.py)
:: -----------------------------------------------------------------------
%VENV_PY% telmex_launcher.py
exit /b %ERRORLEVEL%
