#!/bin/bash
# NetWatch - Live Network Port Monitor
# Aye & Hue's real-time network detective!
# Because Trish wants to see network magic happen LIVE!

# ANSI color codes for our beautiful output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default values - sensible defaults for Hue
PORT_RANGE="22-65535"
REFRESH_INTERVAL=2
WATCH_MODE=false
FILTER_LISTEN=false
FILTER_ESTABLISHED=false
OUTPUT_FILE=""

# Fun banner because we're not boring!
print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         🌐 NetWatch - Live Network Monitor 🔍           ║"
    echo "║         Aye & Hue's Network Detective Tool              ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Help function - for when Hue needs guidance
show_help() {
    print_banner
    echo -e "${GREEN}Usage:${NC} $0 [options]"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo "  -p, --ports RANGE      Port range to monitor (default: 22-65535)"
    echo "  -w, --watch           Watch mode - refresh every N seconds"
    echo "  -i, --interval SEC    Refresh interval for watch mode (default: 2)"
    echo "  -l, --listen-only     Show only listening ports"
    echo "  -e, --established     Show only established connections"
    echo "  -o, --output FILE     Save output to file"
    echo "  -q, --quick           Quick summary only"
    echo "  -h, --help           Show this help message"
    echo
    echo -e "${CYAN}Examples:${NC}"
    echo "  # Monitor all ports with live updates"
    echo "  $0 -w"
    echo
    echo "  # Check specific port range"
    echo "  $0 -p 8000-9000"
    echo
    echo "  # Watch only listening services"
    echo "  $0 -w -l"
    echo
    echo "  # Quick one-time check with output to file"
    echo "  $0 -q -o network_report.txt"
    echo
    echo -e "${PURPLE}Made with 💜 by Aye for Hue (and Trish says hi!)${NC}"
}

# Parse command line arguments - making it user-friendly for Hue
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--ports)
            PORT_RANGE="$2"
            shift 2
            ;;
        -w|--watch)
            WATCH_MODE=true
            shift
            ;;
        -i|--interval)
            REFRESH_INTERVAL="$2"
            shift 2
            ;;
        -l|--listen-only)
            FILTER_LISTEN=true
            shift
            ;;
        -e|--established)
            FILTER_ESTABLISHED=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Function to run the network scan
run_scan() {
    # Build lsof command
    LSOF_CMD="sudo lsof -i :${PORT_RANGE} -n -P"
    
    # Apply filters if requested
    if [ "$FILTER_LISTEN" = true ]; then
        LSOF_FILTER="grep LISTEN"
    elif [ "$FILTER_ESTABLISHED" = true ]; then
        LSOF_FILTER="grep ESTABLISHED"
    else
        LSOF_FILTER="cat"
    fi
    
    # Run the command and pipe to our analyzer
    if [ "$QUICK_MODE" = true ]; then
        # Quick mode - just summary stats
        echo -e "${CYAN}${BOLD}Quick Network Summary${NC}"
        echo "====================="
        
        RESULT=$($LSOF_CMD 2>/dev/null | $LSOF_FILTER)
        
        LISTEN_COUNT=$(echo "$RESULT" | grep -c "LISTEN" || echo 0)
        ESTABLISHED_COUNT=$(echo "$RESULT" | grep -c "ESTABLISHED" || echo 0)
        CLOSED_COUNT=$(echo "$RESULT" | grep -c "CLOSED" || echo 0)
        
        echo -e "🎧 Listening Services: ${GREEN}${LISTEN_COUNT}${NC}"
        echo -e "🔗 Established Connections: ${YELLOW}${ESTABLISHED_COUNT}${NC}"
        echo -e "🚫 Closed Connections: ${RED}${CLOSED_COUNT}${NC}"
        
        # Show top ports
        echo -e "\n${CYAN}Top Listening Ports:${NC}"
        echo "$RESULT" | grep LISTEN | awk '{print $9}' | grep -oE ':[0-9]+' | sort | uniq -c | sort -rn | head -5 | while read count port; do
            port_num=${port#:}
            echo -e "  • Port ${YELLOW}${port_num}${NC}: ${count} service(s)"
        done
    else
        # Full analysis mode
        $LSOF_CMD 2>/dev/null | $LSOF_FILTER | python3 network_analyzer.py
    fi
    
    # Save to file if requested
    if [ -n "$OUTPUT_FILE" ]; then
        $LSOF_CMD 2>/dev/null | $LSOF_FILTER > "$OUTPUT_FILE"
        echo -e "${GREEN}✅ Output saved to: $OUTPUT_FILE${NC}"
    fi
}

# Main execution logic
main() {
    # Check if we need sudo
    if ! sudo -n true 2>/dev/null; then
        echo -e "${YELLOW}⚠️  This tool requires sudo access to see all network connections${NC}"
        echo -e "${CYAN}Please enter your password:${NC}"
    fi
    
    if [ "$WATCH_MODE" = true ]; then
        # Watch mode - continuous monitoring
        print_banner
        echo -e "${GREEN}Starting watch mode (refresh every ${REFRESH_INTERVAL}s)${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop${NC}\n"
        
        while true; do
            clear
            print_banner
            echo -e "${BLUE}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
            echo "----------------------------------------"
            run_scan
            sleep "$REFRESH_INTERVAL"
        done
    else
        # Single run mode
        print_banner
        run_scan
    fi
}

# Trap Ctrl+C for clean exit
trap 'echo -e "\n${YELLOW}👋 NetWatch stopped. Stay secure, Hue!${NC}"; exit 0' INT

# Let's rock and roll!
main