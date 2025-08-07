#!/bin/bash
# SecurAye Management Script - The Control Center! 🎮
# Aye & Hue's service orchestrator with Trish's sparkle ✨
# Because managing services should be fun and colorful!

# ANSI color codes - Trish's palette of joy!
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
MAGENTA='\033[0;95m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
API_PORT=${SECURITY_ADVISOR_PORT:-8888}
PID_FILE="/tmp/securaye_advisor.pid"
LOG_FILE="/tmp/securaye_advisor.log"

# Load environment variables if .env exists
if [ -f "$PROJECT_ROOT/.env" ]; then
    export $(cat "$PROJECT_ROOT/.env" | grep -v '^#' | xargs)
fi

# Fun banner - because we're not boring!
print_banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     🚀 SecurAye Management Console 🚀                       ║"
    echo "║     Aye, Hue & Trish's Service Control Center               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Animated spinner for long operations
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies
install_deps() {
    echo -e "${CYAN}📦 Installing dependencies...${NC}"
    
    # Python dependencies
    if command_exists pip3; then
        echo -e "${YELLOW}Installing Python packages...${NC}"
        pip3 install fastapi uvicorn httpx python-dotenv pydantic requests
        echo -e "${GREEN}✅ Python dependencies installed!${NC}"
    else
        echo -e "${RED}❌ pip3 not found! Please install Python 3${NC}"
        exit 1
    fi
    
    # Check for OpenRouter API key
    if [ -z "$OPENROUTER_API_KEY" ] || [ "$OPENROUTER_API_KEY" = "your_openrouter_api_key_here" ]; then
        echo -e "${YELLOW}⚠️  Warning: OpenRouter API key not configured${NC}"
        echo -e "${CYAN}   Get your key at: https://openrouter.ai/keys${NC}"
        echo -e "${CYAN}   Then add it to .env file${NC}"
    fi
}

# Start the Security Advisor API
start_api() {
    echo -e "${CYAN}🚀 Starting Security Advisor API...${NC}"
    
    # Check if already running
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}⚠️  API is already running (PID: $PID)${NC}"
            echo -e "${CYAN}   Access it at: http://localhost:$API_PORT${NC}"
            return
        fi
    fi
    
    # Start the API in background
    cd "$PROJECT_ROOT"
    nohup python3 security_advisor.py > "$LOG_FILE" 2>&1 &
    PID=$!
    echo $PID > "$PID_FILE"
    
    # Wait for API to start
    echo -e "${YELLOW}Waiting for API to start...${NC}"
    sleep 2
    
    # Check if started successfully
    if curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Security Advisor API started successfully!${NC}"
        echo -e "${CYAN}   📍 API: http://localhost:$API_PORT${NC}"
        echo -e "${CYAN}   📚 Docs: http://localhost:$API_PORT/docs${NC}"
        echo -e "${CYAN}   📝 PID: $PID${NC}"
    else
        echo -e "${RED}❌ Failed to start API. Check logs: $LOG_FILE${NC}"
        rm -f "$PID_FILE"
        exit 1
    fi
}

# Stop the Security Advisor API
stop_api() {
    echo -e "${YELLOW}🛑 Stopping Security Advisor API...${NC}"
    
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            kill $PID
            rm -f "$PID_FILE"
            echo -e "${GREEN}✅ API stopped successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  API not running (stale PID file removed)${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${YELLOW}⚠️  API is not running${NC}"
    fi
}

# Restart the API
restart_api() {
    echo -e "${CYAN}🔄 Restarting Security Advisor API...${NC}"
    stop_api
    sleep 1
    start_api
}

# Check API status
status_api() {
    echo -e "${CYAN}📊 Checking API Status...${NC}"
    
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${GREEN}✅ API is running (PID: $PID)${NC}"
            
            # Check health endpoint
            if curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
                HEALTH=$(curl -s http://localhost:$API_PORT/health)
                echo -e "${GREEN}✅ API is healthy${NC}"
                echo -e "${CYAN}   Response: $HEALTH${NC}"
            else
                echo -e "${YELLOW}⚠️  API is running but not responding${NC}"
            fi
        else
            echo -e "${RED}❌ API is not running (stale PID file)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  API is not running${NC}"
    fi
}

# View API logs
view_logs() {
    echo -e "${CYAN}📜 Viewing API Logs...${NC}"
    
    if [ -f "$LOG_FILE" ]; then
        echo -e "${YELLOW}Last 50 lines of log:${NC}"
        tail -n 50 "$LOG_FILE"
    else
        echo -e "${YELLOW}No logs found${NC}"
    fi
}

# Run a quick network scan
quick_scan() {
    echo -e "${CYAN}🔍 Running Quick Network Scan...${NC}"
    cd "$PROJECT_ROOT"
    ./securaye.sh -q
}

# Run a full scan with AI
ai_scan() {
    echo -e "${CYAN}🤖 Running AI-Powered Security Scan...${NC}"
    
    # Check if API is running
    if ! curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
        echo -e "${YELLOW}Starting API first...${NC}"
        start_api
        sleep 2
    fi
    
    cd "$PROJECT_ROOT"
    ./securaye.sh -a
}

# Watch mode
watch_mode() {
    echo -e "${CYAN}👁️  Starting Watch Mode...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    cd "$PROJECT_ROOT"
    ./securaye.sh -w
}

# Setup environment
setup() {
    echo -e "${CYAN}🔧 Setting up SecurAye environment...${NC}"
    
    # Copy .env.example if .env doesn't exist
    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        if [ -f "$PROJECT_ROOT/.env.example" ]; then
            cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
            echo -e "${GREEN}✅ Created .env file from template${NC}"
            echo -e "${YELLOW}   Please edit .env and add your OpenRouter API key${NC}"
        fi
    fi
    
    # Make scripts executable
    chmod +x "$PROJECT_ROOT/securaye.sh"
    chmod +x "$PROJECT_ROOT/scripts/manage.sh"
    echo -e "${GREEN}✅ Scripts are executable${NC}"
    
    # Install dependencies
    install_deps
    
    echo -e "${GREEN}✅ Setup complete!${NC}"
    echo -e "${CYAN}   Run './scripts/manage.sh start' to start the AI advisor${NC}"
}

# Test the full integration
test_integration() {
    echo -e "${CYAN}🧪 Testing Full Integration...${NC}"
    
    # Start API if not running
    if ! curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
        start_api
        sleep 2
    fi
    
    # Run test with sample data
    echo -e "${YELLOW}Testing with sample network data...${NC}"
    cd "$PROJECT_ROOT"
    
    if [ -f "network_data.txt" ]; then
        python3 network_analyzer.py --ai < network_data.txt
        echo -e "${GREEN}✅ Test completed!${NC}"
    else
        echo -e "${YELLOW}⚠️  No sample data file found${NC}"
        echo -e "${CYAN}   Running live test instead...${NC}"
        ./securaye.sh -a -q
    fi
}

# Development mode - run API with auto-reload
dev_mode() {
    echo -e "${CYAN}💻 Starting Development Mode...${NC}"
    echo -e "${YELLOW}API will auto-reload on code changes${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    
    cd "$PROJECT_ROOT"
    python3 security_advisor.py
}

# Show help
show_help() {
    print_banner
    echo -e "${GREEN}Usage:${NC} $0 <command> [options]"
    echo
    echo -e "${YELLOW}Commands:${NC}"
    echo -e "  ${CYAN}start${NC}       - Start the Security Advisor API"
    echo -e "  ${CYAN}stop${NC}        - Stop the Security Advisor API"
    echo -e "  ${CYAN}restart${NC}     - Restart the Security Advisor API"
    echo -e "  ${CYAN}status${NC}      - Check API status"
    echo -e "  ${CYAN}logs${NC}        - View API logs"
    echo -e "  ${CYAN}setup${NC}       - Setup environment and install dependencies"
    echo -e "  ${CYAN}quick${NC}       - Run a quick network scan"
    echo -e "  ${CYAN}ai-scan${NC}     - Run AI-powered security scan"
    echo -e "  ${CYAN}watch${NC}       - Start watch mode (continuous monitoring)"
    echo -e "  ${CYAN}test${NC}        - Test the full integration"
    echo -e "  ${CYAN}dev${NC}         - Run in development mode (auto-reload)"
    echo -e "  ${CYAN}help${NC}        - Show this help message"
    echo
    echo -e "${PURPLE}Examples:${NC}"
    echo "  # First time setup"
    echo "  $0 setup"
    echo
    echo "  # Start the AI advisor and run a scan"
    echo "  $0 start"
    echo "  $0 ai-scan"
    echo
    echo "  # Monitor network continuously"
    echo "  $0 watch"
    echo
    echo -e "${MAGENTA}✨ Made with love by Aye, Hue & Trish! ✨${NC}"
}

# Main command handler
main() {
    case "$1" in
        start)
            print_banner
            start_api
            ;;
        stop)
            print_banner
            stop_api
            ;;
        restart)
            print_banner
            restart_api
            ;;
        status)
            print_banner
            status_api
            ;;
        logs)
            print_banner
            view_logs
            ;;
        setup)
            print_banner
            setup
            ;;
        quick)
            print_banner
            quick_scan
            ;;
        ai-scan)
            print_banner
            ai_scan
            ;;
        watch)
            print_banner
            watch_mode
            ;;
        test)
            print_banner
            test_integration
            ;;
        dev)
            print_banner
            dev_mode
            ;;
        help|"")
            show_help
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Let's rock and roll! 🎸
main "$@"