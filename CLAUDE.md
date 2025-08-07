# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetWatch is a comprehensive network security monitoring tool that analyzes open ports, active connections, and security vulnerabilities. Built by Aye for Hue with Trish's enthusiastic approval, it provides colorful, real-time network analysis with security recommendations.

## Architecture

### Core Components

1. **netwatch.sh** - Main entry point and orchestrator
   - Handles command-line arguments and user interface
   - Manages watch mode for continuous monitoring
   - Coordinates between lsof and the Python analyzer
   - Location: `/netwatch.sh`

2. **network_analyzer.py** - Analysis engine
   - Parses lsof output and categorizes services
   - Performs security risk assessment
   - Generates detailed reports with security scoring
   - Location: `/network_analyzer.py`

3. **network_data.txt** - Sample data file
   - Contains example lsof output for testing
   - Used for development and debugging
   - Location: `/network_data.txt`

### Data Flow
```
User → netwatch.sh → sudo lsof → network_analyzer.py → Formatted Report
         ↓                ↓                ↓
    Parse Args      Get Network      Analyze & Score
                        Data
```

## Build/Lint/Test Commands

### Running NetWatch
```bash
# Quick security scan
./netwatch.sh -q

# Full analysis
sudo lsof -i -n -P | python3 network_analyzer.py

# Watch mode (continuous monitoring)
./netwatch.sh -w

# Watch with custom interval (5 seconds)
./netwatch.sh -w -i 5

# Filter only listening services
./netwatch.sh -l

# Save output to file
./netwatch.sh -o report.txt
```

### Python Development
```bash
# Run the analyzer with sample data
python3 network_analyzer.py < network_data.txt

# Test with live data
sudo lsof -i -n -P | python3 network_analyzer.py

# Check Python syntax
python3 -m py_compile network_analyzer.py
```

### Shell Script Testing
```bash
# Check shell script syntax
bash -n netwatch.sh

# Make executable if needed
chmod +x netwatch.sh
```

## Code Style Guidelines

### Shell Script (netwatch.sh)
- Use ANSI color codes for visual feedback
- Include helpful error messages and usage examples
- Trap signals for clean exit
- Validate user input and provide sensible defaults

### Python (network_analyzer.py)
- Extensive inline comments explaining logic
- Color-coded output using ANSI codes
- Group related functionality in the NetworkAnalyzer class
- Handle edge cases gracefully with try/except blocks

### General Principles
- Prioritize security analysis and risk assessment
- Make output visually appealing with colors and emojis
- Provide actionable security recommendations
- Keep Trish's love for sparkle and organization in mind

## Key Security Features

### Risk Assessment Categories
- **CRITICAL**: Services with no authentication (Redis, MongoDB, Telnet)
- **HIGH**: Remote access services and databases
- **MEDIUM**: Standard system services on well-known ports
- **LOW**: High-port services with limited exposure

### Security Scoring Algorithm
- Start with 100 points
- Deduct 10 points per service exposed to all interfaces
- Deduct 5 points per suspicious port in use
- Deduct 2 points per root service on high ports
- Provide recommendations based on findings

### Service Categories
The analyzer groups services into categories for better organization:
- `system`: Core OS services (launchd, mDNSResponder, etc.)
- `development`: Development tools (Node.js, Docker, etc.)
- `file_sharing`: Network file systems (NFS, SMB, etc.)
- `communication`: SSH, mail, and messaging services
- `media`: Spotify and other media applications
- `browsers`: Web browsers with active connections
- `productivity`: Office and productivity tools

## Important Port Definitions

Well-known ports monitored by default:
- 22 (SSH), 80 (HTTP), 443 (HTTPS)
- 3389 (RDP), 5432 (PostgreSQL), 6379 (Redis)
- 3000/8000/8080 (Common dev servers)
- 111 (RPC), 2049 (NFS), 445 (SMB)

## Testing Approach

Since this is a system monitoring tool:
1. Test with the provided `network_data.txt` sample file
2. Verify output formatting and color codes work correctly
3. Test various command-line argument combinations
4. Ensure security scoring algorithm produces expected results
5. Validate that all service categories are properly detected

## Common Development Tasks

### Adding New Security Checks
1. Add detection logic in `NetworkAnalyzer._parse_network_info()` or `analyze_data()`
2. Update security scoring in the security analysis section
3. Add relevant recommendations to the recommendations list
4. Test with sample data to ensure proper detection

### Adding New Service Categories
1. Update `self.service_categories` dictionary in `NetworkAnalyzer.__init__()`
2. Add color mapping in `print_summary()` if needed
3. Test categorization with real lsof output

### Modifying Risk Assessment
1. Update port lists in `_assess_port_risk()` method
2. Adjust scoring algorithm in security analysis section
3. Update security recommendations accordingly

## Notes for Aye, Hue & Trish

- Keep the output colorful and engaging - Trish loves the sparkle!
- Add humor to comments and error messages
- Prioritize security without being preachy
- Make sure the tool runs fast - Hue needs quick results
- Consider voice feedback integration for important security alerts
- Remember: "A secure network is a happy network!" - Trish 💜