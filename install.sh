#!/usr/bin/env bash
# Quick installer for js-extractor + optional external recon tools
set -e

echo "[*] Installing js-extractor..."

if ! command -v python3 &>/dev/null; then
    echo "[!] python3 not found. Install Python 3.9+ first." >&2
    exit 1
fi

python3 -m pip install --upgrade pip
python3 -m pip install .

echo ""
read -p "[?] Install optional --dynamic support (Playwright headless Chromium)? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    python3 -m pip install ".[dynamic]"
    python3 -m playwright install chromium
fi

echo ""
echo "[+] Core package installed. Run with: js-extractor <url> [options]"

# ──────────────────────────────────────────────────────────────────────────
# Optional external tools
# ──────────────────────────────────────────────────────────────────────────
# These are NOT Python packages — they're separate Go/Node/Python CLI
# binaries that the corresponding flags shell out to. js-extractor detects
# them at runtime (shutil.which) and skips that analysis step with a
# warning if missing — it never installs them silently on its own, since
# that would mean quietly running `go install` / `npm install -g` /
# downloading a binary without your say-so. This section installs them for
# you, one at a time, only if you say yes.

echo ""
echo "──────────────────────────────────────────────────────"
echo " Optional external recon tools"
echo "──────────────────────────────────────────────────────"
read -p "[?] Install optional external tools now (katana, gau, httpx, wappalyzer, retire, semgrep)? [y/N] " install_tools

if [[ "$install_tools" =~ ^[Yy]$ ]]; then

    HAS_GO=$(command -v go &>/dev/null && echo 1 || echo 0)
    HAS_NPM=$(command -v npm &>/dev/null && echo 1 || echo 0)

    if [[ "$HAS_GO" == "0" ]]; then
        echo "[!] Go is not installed — katana, gau, and httpx require it."
        echo "    Install Go from https://go.dev/dl/ then re-run this script,"
        echo "    or install them manually afterwards."
    fi
    if [[ "$HAS_NPM" == "0" ]]; then
        echo "[!] npm is not installed — wappalyzer and retire.js require it."
        echo "    Install Node.js/npm then re-run this script, or install manually."
    fi

    install_go_tool() {
        local name="$1" pkg="$2"
        if command -v "$name" &>/dev/null; then
            echo "[=] $name already installed, skipping."
            return
        fi
        if [[ "$HAS_GO" == "1" ]]; then
            read -p "    Install $name via 'go install $pkg'? [y/N] " a
            [[ "$a" =~ ^[Yy]$ ]] && go install "$pkg"
        fi
    }

    install_npm_tool() {
        local name="$1" pkg="$2"
        if command -v "$name" &>/dev/null; then
            echo "[=] $name already installed, skipping."
            return
        fi
        if [[ "$HAS_NPM" == "1" ]]; then
            read -p "    Install $name via 'npm install -g $pkg'? [y/N] " a
            [[ "$a" =~ ^[Yy]$ ]] && npm install -g "$pkg"
        fi
    }

    echo ""
    echo "-- katana (deep crawl, --katana)"
    install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest

    echo ""
    echo "-- gau (historical URLs, --gau)"
    install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest

    echo ""
    echo "-- httpx (alive-probe, --httpx-probe)"
    install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest

    echo ""
    echo "-- wappalyzer (tech fingerprint, --wappalyzer)"
    install_npm_tool wappalyzer wappalyzer

    echo ""
    echo "-- retire.js (local CVE scan, --retire)"
    install_npm_tool retire retire

    echo ""
    echo "-- semgrep (static analysis, --semgrep)"
    if command -v semgrep &>/dev/null; then
        echo "[=] semgrep already installed, skipping."
    else
        read -p "    Install semgrep via pip? [y/N] " a
        if [[ "$a" =~ ^[Yy]$ ]]; then
            python3 -m pip install semgrep || python3 -m pip install --break-system-packages semgrep
        fi
    fi

    echo ""
    echo "-- LinkFinder (endpoint extraction, --linkfinder)"
    echo "   Not installed automatically — it isn't packaged for go/npm/pip install."
    echo "   Manual install:"
    echo "     git clone https://github.com/GerbenJavado/LinkFinder.git"
    echo "     cd LinkFinder && pip install -r requirements.txt"
    echo "     then pass --linkfinder-path /path/to/linkfinder.py"

    echo ""
    if [[ "$HAS_GO" == "1" ]]; then
        echo "[i] Make sure \$(go env GOPATH)/bin is on your PATH so the Go tools are found:"
        echo "      export PATH=\"\$PATH:\$(go env GOPATH)/bin\""
    fi
fi

echo ""
echo "[+] Done. Run with: js-extractor <url> [options]"
echo "[+] Re-run this script anytime to install more optional tools, or install them manually:"
echo "      katana      -> go install github.com/projectdiscovery/katana/cmd/katana@latest"
echo "      gau         -> go install github.com/lc/gau/v2/cmd/gau@latest"
echo "      httpx       -> go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
echo "      wappalyzer  -> npm install -g wappalyzer"
echo "      retire      -> npm install -g retire"
echo "      semgrep     -> pip install semgrep"
echo "      LinkFinder  -> https://github.com/GerbenJavado/LinkFinder"

