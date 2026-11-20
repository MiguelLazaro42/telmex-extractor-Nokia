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
# 3. Menú Interactivo (Nokia & Huawei)
# ------------------------------------------------------------------------------
while true; do
    echo "========================================================================"
    echo " SELECCIONA UNA OPCIÓN:"
    echo "========================================================================"
    echo "  [1] Extraer credenciales de Módem HUAWEI (HG8145V5 / HG8145V5V3 / HG8245)"
    echo "  [2] Extraer telemetría y plantillas Asterisk de Módem NOKIA (G-1425G-H)"
    echo "  [3] Desactivar cliente SIP interno en Módem HUAWEI (--disable --apply)"
    echo "  [4] Reactivar cliente SIP interno en Módem HUAWEI (--enable --apply)"
    echo "  [5] Diagnosticar estado SIP y Checklist de Red en Módem NOKIA"
    echo "  [0] Salir"
    echo "========================================================================"
    read -rp "Ingresa el número de opción [0-5]: " OPT

    case "$OPT" in
        1)
            echo ""
            read -rp "IP del módem Huawei [Enter para auto-detectar]: " MODEM_IP
            read -rsp "Contraseña web del módem Huawei (etiqueta): " MODEM_PASS
            echo ""
            read -rp "Carpeta de salida [Enter para 'output']: " OUT_DIR
            OUT_DIR="${OUT_DIR:-output}"
            if [[ -z "$MODEM_IP" ]]; then
                "$VENV_PY" huawei_hg8145v5_extractor.py -u TELMEX -p "$MODEM_PASS" -o "$OUT_DIR"
            else
                "$VENV_PY" huawei_hg8145v5_extractor.py --ip "$MODEM_IP" -u TELMEX -p "$MODEM_PASS" -o "$OUT_DIR"
            fi
            echo ""
            ;;
        2)
            echo ""
            read -rp "IP del módem Nokia [Enter para 192.168.1.254]: " MODEM_IP
            MODEM_IP="${MODEM_IP:-192.168.1.254}"
            read -rsp "Contraseña web del módem Nokia (etiqueta): " MODEM_PASS
            echo ""
            read -rp "Carpeta de salida [Enter para 'output']: " OUT_DIR
            OUT_DIR="${OUT_DIR:-output}"
            "$VENV_PY" nokia_g1425gh_extractor.py --ip "$MODEM_IP" -u TELMEX -p "$MODEM_PASS" -o "$OUT_DIR"
            echo ""
            ;;
        3)
            echo ""
            read -rp "IP del módem Huawei [Enter para 192.168.1.254]: " MODEM_IP
            MODEM_IP="${MODEM_IP:-192.168.1.254}"
            read -rsp "Contraseña web del módem Huawei: " MODEM_PASS
            echo ""
            read -rp "Carpeta donde extrajiste el XML [Enter para 'output']: " OUT_DIR
            OUT_DIR="${OUT_DIR:-output}"
            "$VENV_PY" huawei_sip_manager.py --disable \
                --xml "$OUT_DIR/hw_ctree_decrypted.xml" \
                -o "$OUT_DIR/hw_ctree_sip_modified.xml" \
                --template "$OUT_DIR/hw_ctree_encrypted.xml" \
                --apply --ip "$MODEM_IP" -p "$MODEM_PASS"
            echo ""
            ;;
        4)
            echo ""
            read -rp "IP del módem Huawei [Enter para 192.168.1.254]: " MODEM_IP
            MODEM_IP="${MODEM_IP:-192.168.1.254}"
            read -rsp "Contraseña web del módem Huawei: " MODEM_PASS
            echo ""
            read -rp "Carpeta donde extrajiste el XML [Enter para 'output']: " OUT_DIR
            OUT_DIR="${OUT_DIR:-output}"
            "$VENV_PY" huawei_sip_manager.py --enable \
                --xml "$OUT_DIR/hw_ctree_decrypted.xml" \
                -o "$OUT_DIR/hw_ctree_sip_modified.xml" \
                --template "$OUT_DIR/hw_ctree_encrypted.xml" \
                --apply --ip "$MODEM_IP" -p "$MODEM_PASS"
            echo ""
            ;;
        5)
            echo ""
            read -rp "IP del módem Nokia [Enter para 192.168.1.254]: " MODEM_IP
            MODEM_IP="${MODEM_IP:-192.168.1.254}"
            read -rsp "Contraseña web del módem Nokia: " MODEM_PASS
            echo ""
            "$VENV_PY" nokia_sip_manager.py --check-network --ip "$MODEM_IP" -p "$MODEM_PASS"
            echo ""
            ;;
        0)
            exit 0
            ;;
        *)
            echo "[!] Opción no válida."
            ;;
    esac
done
