# 🌐 NetWatch - Network Security Monitor

> *"Because Trish in Accounting said our network security reports were boring!"* - Aye & Hue

A colorful, comprehensive network port analyzer and security scanner that makes network monitoring actually fun (and secure). Built with love by Aye for Hue, with Trish's seal of approval for maximum sparkle ✨

## 🚀 Features

### 🔥 Security Analysis
- **Critical Port Detection** - Identifies high-risk services (Redis, MongoDB, Telnet)
- **Risk Assessment** - Evaluates each service's security implications
- **Security Scoring** - Get a 0-100 score for your network's security posture
- **External Connection Tracking** - Monitor outbound connections to external IPs
- **Root Service Monitoring** - Track services running with elevated privileges

### 📊 Network Intelligence
- **Service Categorization** - Groups services by type (system, development, browsers, etc.)
- **Port Conflict Detection** - Identifies multiple services on the same port
- **Development Service Detection** - Spots dev servers that shouldn't be in production
- **Well-Known Port Mapping** - Instantly recognize standard services

### 🎨 Beautiful Output
- **Color-Coded Severity** - Red for critical, yellow for warnings, green for all-clear
- **Organized Reports** - Clean, structured output that's easy to read
- **Live Monitoring** - Watch mode for real-time network changes
- **Export Options** - Save reports for documentation or analysis

## 📦 Installation

### Prerequisites
- Python 3.6+
- `lsof` command (pre-installed on most Unix systems)
- `sudo` access for complete network visibility

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/netwatch.git
cd netwatch

# Make the shell script executable
chmod +x netwatch.sh

# You're ready to go!
```

## 🎯 Usage

### Quick Security Check
```bash
# One-time security scan
./netwatch.sh -q

# Full analysis with Python analyzer
sudo lsof -i -n -P | python3 network_analyzer.py
```

### Live Monitoring
```bash
# Watch all ports with 2-second refresh
./netwatch.sh -w

# Custom refresh interval (5 seconds)
./netwatch.sh -w -i 5
```

### Filtered Scans
```bash
# Only show listening services
./netwatch.sh -l

# Only show established connections
./netwatch.sh -e

# Specific port range
./netwatch.sh -p 8000-9000
```

### Export Reports
```bash
# Save output to file
./netwatch.sh -o network_report.txt

# Combine with other options
./netwatch.sh -w -l -o listening_services.log
```

## 🔍 Understanding the Output

### Security Score Breakdown
- **100-80**: GOOD 👍 - Your network is well-configured
- **79-60**: MODERATE ⚠️ - Some improvements recommended
- **59-0**: NEEDS ATTENTION 🚨 - Critical security issues detected

### Risk Levels
- **CRITICAL**: Services with known security vulnerabilities or no authentication
- **HIGH**: Remote access services and databases
- **MEDIUM**: Standard system services
- **LOW**: High-port services with limited exposure

## 🛡️ Security Best Practices

The tool provides specific recommendations based on your network configuration:

1. **Bind to localhost** - Services should listen on 127.0.0.1 when possible
2. **Add authentication** - Especially for databases like Redis and MongoDB
3. **Use SSH keys** - Disable password authentication for SSH
4. **Enable firewalls** - Use pf (macOS) or iptables (Linux) to restrict access
5. **Regular audits** - Run NetWatch periodically to catch new issues

## 📝 Example Output

```
🌐 Network Analysis Report - Aye & Hue's Network Detective 🔍
================================================================================

📊 Summary Statistics:
  • Total Listening Services: 42
  • Active Connections: 31
  • Closed Connections: 8
  • Unique Processes: 28

🔥 SECURITY ANALYSIS - THE HOT STUFF! 🔥

  🚨 CRITICAL - Services Exposed to ALL Networks:
    • Redis (port 6379, user: root) - CRITICAL
    • PostgreSQL (port 5432, user: wraith) - HIGH

  📊 Security Score:
    Score: 65/100 - MODERATE ⚠️

  🛡️ Security Recommendations:
    1. Bind services to localhost/127.0.0.1 when possible
    2. Add authentication to Redis (requirepass)
    3. Ensure database has strong authentication
```

## 🤝 Contributing

Found a bug? Have a feature request? Trish has a suggestion? We'd love to hear from you!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (with lots of comments, as Aye would!)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is open source and available under the MIT License.

## 🎉 Credits

- **Aye** - The AI who loves commenting everything
- **Hue** - The human who needed better network monitoring
- **Trish from Accounting** - Chief Sparkle Officer and security enthusiast

---

*"Remember, a secure network is a happy network!"* - Trish 💜

Made with 🎉 at 8b.is