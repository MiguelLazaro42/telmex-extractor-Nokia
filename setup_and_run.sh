#!/usr/bin/env bash
# ==============================================================================
# 📡 Telmex ONT Extractor & Gestor VoIP SIP / Asterisk (Nokia & Huawei)
# Auto-instalador de Python 3, entorno virtual (.venv), requirements y lanzador
# Compatible con: Linux (Debian/Ubuntu/Fedora/Arch) y macOS
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================================"
echo " 📡 TELMEX ONT EXTRACTOR & GESTOR VOIP SIP / ASTERISK (NOKIA & HUAWEI)"
echo " Auto-instalador de Python, entorno virtual (.venv) y dependencias"
echo "========================================================================"
echo ""

# ------------------------------------------------------------------------------
# 1. Detectar o instalar Python 3.8+ y venv
# ------------------------------------------------------------------------------
ensure_python() {
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
            echo "[+] Python 3 detectado: $(python3 --version)"
            return 0
        fi
    fi

    echo "[!] Python 3.8+ no detectado. Instalando automáticamente..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v brew >/dev/null 2>&1; then
            echo "[*] Instalando Homebrew para macOS..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            if [[ -x "/opt/homebrew/bin/brew" ]]; then
                eval "$(/opt/homebrew/bin/brew shellenv)"
            elif [[ -x "/usr/local/bin/brew" ]]; then
                eval "$(/usr/local/bin/brew shellenv)"
            fi
        fi
        brew install python
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 python3-pip
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm python python-pip
    else
        echo "[X] No se pudo instalar Python 3 automáticamente en esta distribución."
        exit 1
    fi
}

ensure_python

# En Debian/Ubuntu asegurarse de que python3-venv esté disponible
if ! python3 -m venv --help >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "[*] Instalando paquete python3-venv..."
        sudo apt-get update && sudo apt-get install -y python3-venv python3-pip
    fi
fi

# ------------------------------------------------------------------------------
# 2. Crear entorno virtual (.venv) e instalar requirements.txt
# ------------------------------------------------------------------------------
if [[ ! -x ".venv/bin/python" ]]; then
    echo "[*] Creando entorno virtual aislado (.venv)..."
    python3 -m venv .venv
fi

VENV_PY="$SCRIPT_DIR/.venv/bin/python"
export PATH="$SCRIPT_DIR/.venv/bin:$PATH"

echo "[*] Instalando dependencias desde requirements.txt (cryptography)..."
"$VENV_PY" -m pip install --upgrade pip --quiet
"$VENV_PY" -m pip install -r requirements.txt --quiet
echo "[+] Entorno listo (descifrado Huawei \$2 y Nokia RSA+AES 100% en Python puro)."
echo ""

# Si el usuario pasó argumentos al script, ejecutarlos directamente con el Python del .venv
if [[ $# -gt 0 ]]; then
    exec "$VENV_PY" "$@"
fi

# ------------------------------------------------------------------------------
# 3. Lanzar Menú Interactivo Unificado (telmex_launcher.py)
# ------------------------------------------------------------------------------
exec "$VENV_PY" "$SCRIPT_DIR/telmex_launcher.py"
