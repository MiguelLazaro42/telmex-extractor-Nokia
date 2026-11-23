@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
title Telmex ONT Extractor (Nokia & Huawei) - Auto-Installer & Launcher

:: Ubicarse siempre en la carpeta donde esta este archivo .bat
cd /d "%~dp0"

echo ========================================================================
echo  TELMEX ONT EXTRACTOR ^& GESTOR VOIP SIP / ASTERISK (NOKIA ^& HUAWEI)
echo  Auto-instalador 1-Click para Windows (Repositorio + Python + Librerias)
echo ========================================================================
echo.

:: -----------------------------------------------------------------------
:: PASO 0: Si este .bat se ejecuto suelto (sin el repositorio al lado),
::         descargar y extraer automaticamente todo el proyecto desde GitHub
:: -----------------------------------------------------------------------
if not exist "telmex_launcher.py" (
    if exist "telmex-extractor-Nokia-main\telmex_launcher.py" (
        cd /d "telmex-extractor-Nokia-main"
    ) else (
        echo [*] No se encontraron los archivos del proyecto en esta carpeta.
        echo [*] Descargando automaticamente el repositorio desde GitHub...
        set "REPO_ZIP=%TEMP%\telmex-extractor-Nokia.zip"
        powershell -NoProfile -ExecutionPolicy Bypass -Command ^
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://github.com/MiguelLazaro42/telmex-extractor-Nokia/archive/refs/heads/main.zip' -OutFile '!REPO_ZIP!'; Expand-Archive -Path '!REPO_ZIP!' -DestinationPath '%cd%' -Force"
        if exist "telmex-extractor-Nokia-main\telmex_launcher.py" (
            echo [+] Proyecto descargado y descomprimido en: %cd%\telmex-extractor-Nokia-main
            cd /d "telmex-extractor-Nokia-main"
        ) else (
            echo [X] Error al descargar el repositorio desde GitHub. Verifica tu conexion a Internet.
            pause
            exit /b 1
        )
    )
)

:: -----------------------------------------------------------------------
:: PASO 1: Detectar Python 3.8+ real (ignorando el alias vacio de Windows Store)
:: -----------------------------------------------------------------------
set "PY_CMD="

for %%P in (
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%LocalAppData%\Programs\Python\Python310\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles%\Python310\python.exe"
) do (
    if exist %%P (
        set "PY_CMD=%%~P"
        for %%D in (%%P) do set "PATH=%%~dpD;%%~dpDScripts;!PATH!"
        goto :python_found
    )
)

where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PY_CMD=py -3"
        goto :python_found
    )
)

where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PY_CMD=python"
        goto :python_found
    )
)

:: -----------------------------------------------------------------------
:: PASO 2: Instalar Python 3.12 automaticamente si el PC no tiene Python
:: -----------------------------------------------------------------------
echo [!] Python 3.8+ no esta instalado en este PC.
echo [*] Descargando e instalando Python 3.12.7 ^(64-bit^) automaticamente...

where winget >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Intentando instalacion rapida via winget...
    winget install -e --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements >nul 2>&1
)

if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
    set "PY_DIR=%LocalAppData%\Programs\Python\Python312"
    set "PATH=!PY_DIR!;!PY_DIR!\Scripts;!PATH!"
    set "PY_CMD=!PY_DIR!\python.exe"
    goto :python_found
)

set "PY_INSTALLER=%TEMP%\python-3.12.7-amd64.exe"
echo [*] Descargando instalador oficial desde python.org...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe' -OutFile '%PY_INSTALLER%'"

if not exist "%PY_INSTALLER%" (
    echo [X] Error: No se pudo descargar el instalador de Python. Verifica tu conexion a Internet.
    pause
    exit /b 1
)

echo [*] Instalando Python 3.12 y configurando el PATH del usuario ^(espera ~30 segundos^)...
"%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_pip=1

if exist "%LocalAppData%\Programs\Python\Python312\python.exe" (
    set "PY_DIR=%LocalAppData%\Programs\Python\Python312"
    set "PATH=!PY_DIR!;!PY_DIR!\Scripts;!PATH!"
    set "PY_CMD=!PY_DIR!\python.exe"
) else (
    where py >nul 2>&1
    if !ERRORLEVEL! EQU 0 set "PY_CMD=py -3"
)

if not defined PY_CMD (
    echo [X] Python se instalo pero requiere volver a abrir esta ventana.
    echo     Haz doble clic nuevamente en este archivo .bat.
    pause
    exit /b 1
)

:python_found
echo [+] Usando Python: %PY_CMD%
"%PY_CMD%" --version 2>nul || %PY_CMD% --version

:: -----------------------------------------------------------------------
:: PASO 3: Crear entorno virtual (.venv) e instalar dependencias (cryptography)
:: -----------------------------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creando entorno virtual local ^(.venv^)...
    "%PY_CMD%" -m venv .venv 2>nul || %PY_CMD% -m venv .venv
)

set "VENV_PY=.venv\Scripts\python.exe"
if not exist "%VENV_PY%" (
    set "VENV_PY=%PY_CMD%"
)

echo [*] Instalando dependencias necesarias ^(cryptography^)...
"%VENV_PY%" -m pip install --upgrade pip --quiet --disable-pip-version-check
"%VENV_PY%" -m pip install -r requirements.txt --quiet --disable-pip-version-check
if %ERRORLEVEL% NEQ 0 (
    echo [X] Error al instalar las dependencias con pip. Verifica tu conexion a Internet.
    pause
    exit /b 1
)

echo [+] Todo listo. Iniciando menu interactivo...
echo.

:: Si se pasaron argumentos al .bat, ejecutarlos directamente
if not "%~1"=="" (
    "%VENV_PY%" %*
    pause
    exit /b %ERRORLEVEL%
)

:: -----------------------------------------------------------------------
:: PASO 4: Lanzar el menu interactivo unificado
:: -----------------------------------------------------------------------
"%VENV_PY%" telmex_launcher.py
echo.
pause
exit /b 0
