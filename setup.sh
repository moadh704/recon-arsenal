#!/bin/bash
# ============================================================
#  SETUP.SH — Install all bug bounty tools
#  Run once before using the toolkit
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

# ---------- Check root / sudo ----------
if [[ $EUID -ne 0 ]]; then
  warning "Not root — some installs may fail. Run with sudo if needed."
fi

# ---------- System packages ----------
info "Updating apt and installing base packages..."
apt-get update -qq
apt-get install -y -qq \
  curl wget git python3 python3-pip jq nmap \
  chromium-browser ruby unzip dnsutils whois \
  libcurl4-openssl-dev libssl-dev build-essential 2>/dev/null

# ---------- Go (required by most tools) ----------
if ! command -v go &>/dev/null; then
  info "Installing Go..."
  GO_VER="1.22.3"
  wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  tar -C /usr/local -xzf /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  export PATH=$PATH:/usr/local/go/bin
  info "Go installed: $(go version)"
else
  info "Go already installed: $(go version)"
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ---------- Go-based tools ----------
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/gau/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/tomnomnom/qsreplace@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/KathanP19/Gxss@latest"
  "github.com/sw33tLie/sns@latest"
  "github.com/trickest/dsieve@latest"
)

info "Installing Go tools..."
for tool in "${GO_TOOLS[@]}"; do
  name=$(basename "$tool" | cut -d'@' -f1)
  if command -v "$name" &>/dev/null; then
    warning "$name already installed, skipping."
  else
    info "Installing $name..."
    go install "$tool" 2>/dev/null && info "$name ✓" || error "$name failed"
  fi
done

# ---------- Python tools ----------
info "Installing Python tools..."
pip3 install -q \
  requests beautifulsoup4 lxml dnspython \
  python-whois colorama tqdm rich \
  trufflehog arjun jsbeautifier 2>/dev/null

# ---------- Nuclei templates ----------
info "Updating Nuclei templates..."
nuclei -update-templates 2>/dev/null

# ---------- GF patterns ----------
info "Installing GF patterns..."
mkdir -p ~/.gf
git clone -q https://github.com/1ndianl33t/Gf-Patterns ~/.gf/Gf-Patterns 2>/dev/null
cp ~/.gf/Gf-Patterns/*.json ~/.gf/ 2>/dev/null

# ---------- Wordlists ----------
info "Downloading wordlists..."
mkdir -p ~/wordlists
LISTS=(
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/fuzz-Bo0oM.txt"
)
for url in "${LISTS[@]}"; do
  fname=$(basename "$url")
  [[ -f ~/wordlists/$fname ]] || wget -q "$url" -O ~/wordlists/"$fname" && info "$fname ✓"
done

info "Setup complete! All tools installed."
echo ""
echo "Add to your PATH: export PATH=\$PATH:\$HOME/go/bin"
