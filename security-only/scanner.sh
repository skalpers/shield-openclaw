#!/bin/bash
# OpenClaw Security Scanner v0.1
# Non-intrusive security check for exposed OpenClaw instances
# Usage: curl -s https://raw.githubusercontent.com/skalpers/shield-openclaw/main/bundle/scanner.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 OpenClaw Security Scanner v0.1"
echo "=================================="
echo ""

# Check dependencies
check_deps() {
    local missing=()
    for cmd in curl nc; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}⚠ Warning: Missing dependencies: ${missing[*]}${NC}"
        echo "Some checks may be limited."
    fi
}

# Check if port is open
check_port() {
    local host=$1
    local port=$2
    if command -v nc &> /dev/null; then
        if nc -z -w 2 "$host" "$port" 2>/dev/null; then
            return 0
        fi
    fi
    # Fallback using curl
    if curl -s --max-time 3 "http://$host:$port" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Check OpenClaw version (if accessible)
check_version() {
    local host=$1
    local port=$2
    
    # Try to get version from /api/status or similar endpoint
    # This is a placeholder - actual endpoint may differ
    local response=$(curl -s --max-time 3 "http://$host:$port/" 2>/dev/null || true)
    
    # Check for version indicators in response
    if echo "$response" | grep -q "OpenClaw\|ClawdBot\|Moltbot"; then
        echo -e "${GREEN}✅ OpenClaw instance detected${NC}"
        
        # Try to extract version (simplistic approach)
        if echo "$response" | grep -q "2026\.1\.29\|2026\.1\.30"; then
            echo -e "${GREEN}✅ Version appears patched (≥2026.1.29)${NC}"
            return 0
        else
            echo -e "${RED}🚨 Version may be vulnerable (<2026.1.29)${NC}"
            echo -e "${YELLOW}⚠ CVE-2026-25253: WebSocket token hijacking possible${NC}"
            return 1
        fi
    fi
    
    return 2
}

# Check for authentication
check_auth() {
    local host=$1
    local port=$2
    
    # Try to access tools/invoke endpoint without auth
    local response=$(curl -s -w "%{http_code}" --max-time 3 "http://$host:$port/tools/invoke" -d '{"tool":"test"}' 2>/dev/null || echo "000")
    
    if [[ "$response" =~ ^(200|401|403) ]]; then
        if [[ "$response" == "401" ]] || [[ "$response" == "403" ]]; then
            echo -e "${GREEN}✅ Authentication appears enabled${NC}"
            return 0
        elif [[ "$response" == "200" ]]; then
            echo -e "${RED}🚨 CRITICAL: No authentication detected!${NC}"
            echo -e "${YELLOW}⚠ Anyone can execute commands on this instance${NC}"
            return 1
        fi
    fi
    
    echo -e "${YELLOW}⚠ Could not determine authentication status${NC}"
    return 2
}

# Check for CVE-2026-25475 (Path Traversal)
check_path_traversal() {
    local host=$1
    local port=$2
    
    # This is a simplified check - actual CVE requires specific MEDIA: URI exploitation
    echo -e "${YELLOW}⚠ Path traversal check requires deeper analysis${NC}"
    return 0
}

# Main scanning function
scan_instance() {
    local host=${1:-127.0.0.1}
    local port=${2:-18789}
    
    echo "Scanning: $host:$port"
    echo ""
    
    # Check port
    if check_port "$host" "$port"; then
        echo -e "${GREEN}✅ Port $port is open${NC}"
        
        # Check version
        check_version "$host" "$port"
        
        # Check authentication
        check_auth "$host" "$port"
        
        # Check path traversal
        check_path_traversal "$host" "$port"
        
    else
        echo -e "${GREEN}✅ Port $port appears closed (good)${NC}"
    fi
    
    echo ""
}

# Generate report
generate_report() {
    echo "📊 SECURITY REPORT"
    echo "================="
    echo "Scan timestamp: $(date)"
    echo "Target: ${TARGET:-Not specified}"
    echo ""
    echo "SUMMARY:"
    echo "• Port 18789 status: $(if check_port "${HOST:-127.0.0.1}" "${PORT:-18789}"; then echo "OPEN"; else echo "CLOSED"; fi)"
    echo "• Version check: $(check_version "${HOST:-127.0.0.1}" "${PORT:-18789}" >/dev/null 2>&1 && echo "PATCHED" || echo "POTENTIALLY VULNERABLE")"
    echo "• Authentication: $(check_auth "${HOST:-127.0.0.1}" "${PORT:-18789}" >/dev/null 2>&1 && echo "ENABLED" || echo "MISSING OR UNDETECTABLE")"
    echo ""
    echo "RECOMMENDATIONS:"
    echo "1. Update to OpenClaw 2026.1.29+ immediately"
    echo "2. Ensure authentication is enabled (auth: token or password)"
    echo "3. Bind to localhost (127.0.0.1) instead of 0.0.0.0"
    echo "4. Use firewall to block external access to port 18789"
    echo "5. Regularly audit skills for malicious code"
    echo ""
    echo "Need help securing your instance?"
    echo "Visit https://shield.openclaw.ai for professional security hardening."
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --report)
            REPORT=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--host HOST] [--port PORT] [--report]"
            exit 1
            ;;
    esac
done

check_deps

if [ -n "$HOST" ] || [ -n "$PORT" ]; then
    scan_instance "${HOST:-127.0.0.1}" "${PORT:-18789}"
    
    if [ "$REPORT" = true ]; then
        TARGET="${HOST:-127.0.0.1}:${PORT:-18789}"
        generate_report
    fi
else
    # Interactive mode
    echo "Enter OpenClaw instance to scan (default: 127.0.0.1:18789)"
    read -p "Host [127.0.0.1]: " input_host
    read -p "Port [18789]: " input_port
    
    scan_instance "${input_host:-127.0.0.1}" "${input_port:-18789}"
    
    echo "Generate detailed report? (y/n)"
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        TARGET="${input_host:-127.0.0.1}:${input_port:-18789}"
        generate_report
    fi
fi

echo ""
echo "🔒 For complete security hardening:"
echo "   https://shield.openclaw.ai"
echo ""