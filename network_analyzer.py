#!/usr/bin/env python3
"""
Network Port Analyzer - Because Trish wants to know what's happening on the network!
This beauty will parse lsof output and make it sparkle with colors and organization.
Aye and Hue's collaborative network detective tool!
"""

import re
import sys
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import json
import os
import requests
from datetime import datetime

# ANSI color codes for our beautiful terminal output
class Colors:
    """Color codes to make Trish happy with pretty outputs"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class NetworkAnalyzer:
    """Main analyzer class - the detective of network connections"""
    
    def __init__(self):
        """Initialize our data structures for the analysis party"""
        self.listeners = []  # All listening services
        self.connections = []  # Active connections
        self.services_by_port = defaultdict(list)  # Group by port
        self.services_by_process = defaultdict(list)  # Group by process
        
        # Service categories for better organization
        self.service_categories = {
            'system': ['launchd', 'mDNSRespo', 'kdc', 'AirPlayXP', 'rpcbind'],
            'file_sharing': ['nfsd', 'netbiosd', 'rpc.statd', 'rpc.lockd', 'rpc.rquot'],
            'development': ['Code\\x20H', 'node', 'ollama', 'Ollama', 'com.docke', 'Docker'],
            'communication': ['Mail', 'ssh', 'rapportd', 'identitys'],
            'media': ['Spotify', 'Jump\\x20D'],
            'browsers': ['Brave\\x20', 'firefox'],
            'productivity': ['Windows', 'ControlCe'],
            'system_services': ['homed', 'replicato']
        }
    
    def parse_line(self, line: str) -> Dict:
        """Parse a single line of lsof output - detective work at its finest"""
        # Skip header line
        if line.startswith('COMMAND'):
            return None
            
        # Parse the delicious data
        parts = line.split()
        if len(parts) < 9:
            return None
            
        try:
            # The lsof format varies but typically:
            # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            # But sometimes USER field is longer, so we need to be smart
            
            # Find where TCP/UDP appears - that's our protocol field
            protocol_idx = -1
            for i, part in enumerate(parts):
                if part in ['TCP', 'UDP', 'ICMP', 'ICMPV6']:
                    protocol_idx = i
                    break
            
            if protocol_idx == -1:
                # Not a network connection we care about
                return None
            
            # Build the name field from protocol index onwards
            name_parts = parts[protocol_idx+1:]
            name = ' '.join(name_parts) if name_parts else ''
            
            data = {
                'command': parts[0],
                'pid': parts[1],
                'user': parts[2],  # Sometimes this is longer like _mdnsresponder
                'protocol': parts[protocol_idx],
                'name': name,
                'full_line': line  # Keep for debugging
            }
            
            # Parse the network info from the name field
            self._parse_network_info(data)
                
            return data
        except Exception as e:
            # Hue sometimes gives us weird data, let's be graceful
            return None
    
    def _parse_network_info(self, data: Dict):
        """Extract network details - the juicy bits Trish loves"""
        name = data['name']
        
        # Protocol is already set from parse_line
        # Check if listening or connected
        if '(LISTEN)' in name:
            data['state'] = 'LISTENING'
            # Extract port from patterns like *:80 or 127.0.0.1:8080
            port_match = re.search(r':(\d+)', name)
            if not port_match:
                # Try to get it from the address part
                addr_match = re.search(r'(\*|[\d\.]+|\[.*?\]):(\d+)', name)
                if addr_match:
                    data['port'] = int(addr_match.group(2))
            else:
                data['port'] = int(port_match.group(1))
        elif '(ESTABLISHED)' in name:
            data['state'] = 'ESTABLISHED'
        elif '(CLOSED)' in name:
            data['state'] = 'CLOSED'
        elif '(SYN_SENT)' in name:
            data['state'] = 'SYN_SENT'
        else:
            # For UDP or other states
            data['state'] = 'OTHER'
            # Try to extract port for UDP
            if data['protocol'] == 'UDP':
                port_match = re.search(r':(\d+)$', name)
                if port_match:
                    data['port'] = int(port_match.group(1))
    
    def categorize_service(self, command: str) -> str:
        """Figure out what category this service belongs to - organization is key!"""
        for category, services in self.service_categories.items():
            if any(service in command for service in services):
                return category
        return 'other'
    
    def analyze_data(self, lines: List[str]):
        """Main analysis function - where the magic happens"""
        for line in lines:
            if not line.strip():
                continue
                
            data = self.parse_line(line)
            if not data:
                continue
            
            # Categorize by state
            if data.get('state') == 'LISTENING':
                self.listeners.append(data)
                if 'port' in data:
                    self.services_by_port[data['port']].append(data)
            elif data.get('state') in ['ESTABLISHED', 'CLOSED', 'SYN_SENT']:
                self.connections.append(data)
            
            # Group by process
            self.services_by_process[data['command']].append(data)
    
    def print_summary(self):
        """Print a beautiful summary that would make Trish proud"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}🌐 Network Analysis Report - Aye & Hue's Network Detective 🔍{Colors.END}\n")
        print("=" * 80)
        
        # Summary statistics
        print(f"\n{Colors.CYAN}{Colors.BOLD}📊 Summary Statistics:{Colors.END}")
        print(f"  • Total Listening Services: {Colors.GREEN}{len(self.listeners)}{Colors.END}")
        print(f"  • Active Connections: {Colors.YELLOW}{len([c for c in self.connections if c.get('state') == 'ESTABLISHED'])}{Colors.END}")
        print(f"  • Closed Connections: {Colors.RED}{len([c for c in self.connections if c.get('state') == 'CLOSED'])}{Colors.END}")
        print(f"  • Unique Processes: {Colors.BLUE}{len(self.services_by_process)}{Colors.END}")
        
        # Listening ports by category
        print(f"\n{Colors.CYAN}{Colors.BOLD}🎧 Listening Services by Category:{Colors.END}")
        categorized = defaultdict(list)
        
        for listener in self.listeners:
            category = self.categorize_service(listener['command'])
            if 'port' in listener:
                categorized[category].append((listener['command'], listener['port'], listener['protocol']))
        
        for category, services in sorted(categorized.items()):
            # Pick a color for each category
            cat_color = {
                'system': Colors.BLUE,
                'development': Colors.GREEN,
                'file_sharing': Colors.YELLOW,
                'communication': Colors.CYAN,
                'media': Colors.RED,
                'browsers': Colors.HEADER,
                'productivity': Colors.BOLD,
                'other': ''
            }.get(category, '')
            
            print(f"\n  {cat_color}{category.upper().replace('_', ' ')}:{Colors.END}")
            
            # Group by unique command
            by_command = defaultdict(list)
            for cmd, port, proto in services:
                by_command[cmd].append((port, proto))
            
            for cmd, ports in sorted(by_command.items()):
                # Clean up command name
                clean_cmd = cmd.replace('\\x20', ' ')
                ports_str = ', '.join([f"{port}/{proto}" for port, proto in sorted(ports)])
                print(f"    • {clean_cmd}: {Colors.GREEN}{ports_str}{Colors.END}")
        
        # Well-known ports
        print(f"\n{Colors.CYAN}{Colors.BOLD}🔒 Well-Known Ports in Use:{Colors.END}")
        well_known = {
            22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 
            3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8000: 'HTTP Alt', 3000: 'Dev Server', 111: 'RPC',
            2049: 'NFS', 88: 'Kerberos', 53: 'DNS', 5353: 'mDNS',
            11434: 'Ollama', 7000: 'Control Center'
        }
        
        for port, name in sorted(well_known.items()):
            if port in self.services_by_port:
                services = self.services_by_port[port]
                cmds = set([s['command'].replace('\\x20', ' ') for s in services])
                print(f"    • Port {Colors.YELLOW}{port:5}{Colors.END} ({name:12}): {', '.join(cmds)}")
        
        # Active connections summary
        print(f"\n{Colors.CYAN}{Colors.BOLD}🔗 Active Connection Summary:{Colors.END}")
        active_by_cmd = defaultdict(int)
        for conn in self.connections:
            if conn.get('state') == 'ESTABLISHED':
                active_by_cmd[conn['command']] += 1
        
        if active_by_cmd:
            for cmd, count in sorted(active_by_cmd.items(), key=lambda x: x[1], reverse=True)[:10]:
                clean_cmd = cmd.replace('\\x20', ' ')
                print(f"    • {clean_cmd}: {Colors.GREEN}{count} connections{Colors.END}")
        else:
            print("    No active connections")
        
        # Security Analysis - The Hot Stuff Trish Requested!
        print(f"\n{Colors.RED}{Colors.BOLD}🔥 SECURITY ANALYSIS - THE HOT STUFF! 🔥{Colors.END}")
        
        security_issues = []  # Track security concerns
        
        # 1. CRITICAL: Services on all interfaces
        all_interface_listeners = []
        for listener in self.listeners:
            if '*:' in listener.get('name', '') or '0.0.0.0' in listener.get('name', ''):
                if 'port' in listener:
                    all_interface_listeners.append((listener['command'], listener['port'], listener['user']))
        
        if all_interface_listeners:
            print(f"\n  {Colors.RED}🚨 CRITICAL - Services Exposed to ALL Networks:{Colors.END}")
            for cmd, port, user in sorted(set(all_interface_listeners)):
                clean_cmd = cmd.replace('\\x20', ' ')
                severity = self._assess_port_risk(port)
                color = Colors.RED if severity == 'CRITICAL' else Colors.YELLOW
                print(f"    {color}• {clean_cmd} (port {port}, user: {user}) - {severity}{Colors.END}")
                security_issues.append(f"{clean_cmd}:{port}")
        
        # 2. Check for suspicious ports
        print(f"\n  {Colors.YELLOW}🔍 Port Risk Assessment:{Colors.END}")
        suspicious_ports = {
            23: ('Telnet', 'CRITICAL - Unencrypted!'),
            21: ('FTP', 'HIGH - Unencrypted transfers'),
            139: ('NetBIOS', 'MEDIUM - Windows networking'),
            445: ('SMB', 'MEDIUM - File sharing exposed'),
            3389: ('RDP', 'HIGH - Remote desktop access'),
            5900: ('VNC', 'HIGH - Remote desktop'),
            6379: ('Redis', 'CRITICAL if exposed - No auth by default!'),
            5432: ('PostgreSQL', 'HIGH - Database exposed'),
            3306: ('MySQL', 'HIGH - Database exposed'),
            27017: ('MongoDB', 'CRITICAL if exposed - Often no auth!'),
            9200: ('Elasticsearch', 'HIGH - Often unsecured'),
            111: ('RPC', 'MEDIUM - Service enumeration risk')
        }
        
        for port, (service, risk) in suspicious_ports.items():
            if port in self.services_by_port:
                services = self.services_by_port[port]
                for svc in services:
                    print(f"    {Colors.RED}⚠️  Port {port} ({service}): {risk}{Colors.END}")
                    print(f"       Running: {svc['command']} (user: {svc['user']})")
        
        # 3. Check for development services in production
        print(f"\n  {Colors.YELLOW}💻 Development Services Detection:{Colors.END}")
        dev_indicators = {
            'webpack': 'Webpack dev server',
            'node': 'Node.js app',
            'python': 'Python app',
            'ruby': 'Ruby app',
            'php': 'PHP server',
            'django': 'Django dev server',
            'flask': 'Flask dev server'
        }
        
        dev_ports = [3000, 3001, 4200, 5000, 5001, 8000, 8080, 8081, 9000]
        for port in dev_ports:
            if port in self.services_by_port:
                print(f"    {Colors.YELLOW}📦 Dev port {port} is active - ensure this isn't production!{Colors.END}")
        
        # 4. Check for multiple services on same port (port conflicts)
        print(f"\n  {Colors.CYAN}🔄 Port Conflict Analysis:{Colors.END}")
        for port, services in self.services_by_port.items():
            if len(services) > 1:
                print(f"    ⚡ Port {port} has multiple services: {', '.join([s['command'] for s in services])}")
        
        # 5. Analyze established connections for suspicious patterns
        print(f"\n  {Colors.YELLOW}🌐 Connection Analysis:{Colors.END}")
        external_connections = []
        for conn in self.connections:
            if conn.get('state') == 'ESTABLISHED':
                name = conn.get('name', '')
                # Check for external IPs (not localhost, not private)
                if '127.0.0.1' not in name and 'localhost' not in name:
                    if '->' in name:
                        parts = name.split('->')
                        if len(parts) == 2:
                            dest = parts[1].split(':')[0]
                            # Check if it's an external IP
                            if not self._is_private_ip(dest):
                                external_connections.append((conn['command'], dest))
        
        if external_connections:
            print(f"    {Colors.YELLOW}📡 External connections detected:{Colors.END}")
            for cmd, dest in set(external_connections):
                clean_cmd = cmd.replace('\\x20', ' ')
                print(f"       • {clean_cmd} → {dest}")
        
        # 6. Check for root services
        print(f"\n  {Colors.RED}👑 Root/System Services:{Colors.END}")
        root_services = [l for l in self.listeners if l.get('user') == 'root' and l.get('port', 0) > 1024]
        if root_services:
            print(f"    {Colors.YELLOW}⚠️  {len(root_services)} services running as root on high ports:{Colors.END}")
            for svc in root_services[:5]:  # Show first 5
                print(f"       • {svc['command']} on port {svc.get('port', 'unknown')}")
        
        # 7. Security Score
        print(f"\n  {Colors.CYAN}{Colors.BOLD}📊 Security Score:{Colors.END}")
        score = 100
        score -= len(all_interface_listeners) * 10  # -10 for each exposed service
        score -= len([p for p in suspicious_ports if p in self.services_by_port]) * 5
        score -= len(root_services) * 2
        score = max(0, score)  # Don't go below 0
        
        if score >= 80:
            color = Colors.GREEN
            rating = "GOOD 👍"
        elif score >= 60:
            color = Colors.YELLOW
            rating = "MODERATE ⚠️"
        else:
            color = Colors.RED
            rating = "NEEDS ATTENTION 🚨"
        
        print(f"    {color}{Colors.BOLD}Score: {score}/100 - {rating}{Colors.END}")
        
        # 8. Recommendations
        print(f"\n  {Colors.GREEN}{Colors.BOLD}🛡️  Security Recommendations:{Colors.END}")
        if all_interface_listeners:
            print(f"    1. Bind services to localhost/127.0.0.1 when possible")
        if 6379 in self.services_by_port:
            print(f"    2. Add authentication to Redis (requirepass)")
        if 5432 in self.services_by_port or 3306 in self.services_by_port:
            print(f"    3. Ensure database has strong authentication")
        if any(p in self.services_by_port for p in [3000, 8000, 8080]):
            print(f"    4. Verify development servers aren't exposed in production")
        if 22 in self.services_by_port:
            print(f"    5. Use SSH keys instead of passwords, disable root login")
        print(f"    6. Consider using a firewall (pf/iptables) to restrict access")
        print(f"    7. Regular security audits with 'securaye.sh -w'")
        
        print(f"\n{Colors.GREEN}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}Analysis complete! Stay secure, Hue! 🛡️{Colors.END}\n")
    
    def _assess_port_risk(self, port: int) -> str:
        """Assess the risk level of a port - Trish's risk calculator"""
        critical_ports = [23, 6379, 27017, 9200]  # Telnet, Redis, MongoDB, Elasticsearch
        high_ports = [21, 22, 3389, 5900, 5432, 3306]  # FTP, SSH, RDP, VNC, DBs
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_ports:
            return "HIGH"
        elif port < 1024:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private - network detective work"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', 'fe80:', 'fd'
        ]
        return any(ip.startswith(r) for r in private_ranges)
    
    def get_ai_recommendations(self, enable_ai: bool = False) -> Optional[Dict]:
        """Get AI-powered security recommendations if enabled - the smart stuff!"""
        if not enable_ai:
            return None
        
        # Check if the security advisor API is running
        api_url = os.getenv('SECURITY_ADVISOR_URL', 'http://localhost:8888')
        
        try:
            # Prepare data for AI analysis
            services_data = []
            for listener in self.listeners:
                if 'port' in listener:
                    # Determine interface from name field
                    interface = '*' if '*:' in listener.get('name', '') else '127.0.0.1'
                    services_data.append({
                        'command': listener['command'],
                        'port': listener['port'],
                        'protocol': listener.get('protocol', 'TCP'),
                        'user': listener['user'],
                        'state': listener.get('state', 'LISTENING'),
                        'interface': interface
                    })
            
            # Calculate current security score
            all_interface_listeners = [l for l in self.listeners 
                                      if '*:' in l.get('name', '') or '0.0.0.0' in l.get('name', '')]
            suspicious_ports = [p for p in [23, 6379, 27017, 9200] if p in self.services_by_port]
            root_services = [l for l in self.listeners if l.get('user') == 'root' and l.get('port', 0) > 1024]
            
            score = 100
            score -= len(all_interface_listeners) * 10
            score -= len(suspicious_ports) * 5
            score -= len(root_services) * 2
            score = max(0, score)
            
            # Prepare vulnerabilities list
            vulnerabilities = []
            if 6379 in self.services_by_port:
                vulnerabilities.append('Redis exposed without authentication')
            if 27017 in self.services_by_port:
                vulnerabilities.append('MongoDB potentially without authentication')
            if 23 in self.services_by_port:
                vulnerabilities.append('Telnet service (unencrypted)')
            
            # Get external connections
            external_conns = []
            for conn in self.connections:
                if conn.get('state') == 'ESTABLISHED':
                    name = conn.get('name', '')
                    if '127.0.0.1' not in name and 'localhost' not in name:
                        if '->' in name:
                            parts = name.split('->')
                            if len(parts) == 2:
                                dest = parts[1].split(':')[0]
                                if not self._is_private_ip(dest):
                                    external_conns.append({
                                        'command': conn['command'],
                                        'destination': dest
                                    })
            
            # Make API request
            payload = {
                'services': services_data,
                'security_score': score,
                'vulnerabilities': vulnerabilities,
                'external_connections': external_conns,
                'suspicious_ports': suspicious_ports
            }
            
            response = requests.post(
                f"{api_url}/analyze",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"{Colors.YELLOW}⚠️  AI advisor returned status {response.status_code}{Colors.END}")
                return None
                
        except requests.exceptions.ConnectionError:
            print(f"{Colors.YELLOW}💡 Tip: Start the Security Advisor API for AI-powered recommendations{Colors.END}")
            print(f"    Run: python3 security_advisor.py")
            return None
        except Exception as e:
            print(f"{Colors.RED}❌ AI analysis error: {e}{Colors.END}")
            return None
    
    def print_ai_recommendations(self, ai_response: Dict):
        """Print AI-generated security recommendations - making them sparkle!"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}🤖 AI SECURITY ADVISOR RECOMMENDATIONS 🤖{Colors.END}")
        print("=" * 80)
        
        # Overall assessment
        print(f"\n{Colors.BOLD}Overall Assessment:{Colors.END}")
        print(f"  {ai_response.get('overall_assessment', 'Analysis complete')}")
        
        # Risk level with color
        risk_level = ai_response.get('risk_level', 'UNKNOWN')
        risk_color = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.YELLOW,
            'MEDIUM': Colors.CYAN,
            'LOW': Colors.GREEN
        }.get(risk_level, Colors.END)
        
        print(f"\n{Colors.BOLD}Risk Level: {risk_color}{risk_level}{Colors.END}")
        
        # Executive summary
        print(f"\n{Colors.BOLD}Executive Summary:{Colors.END}")
        print(f"  {ai_response.get('executive_summary', 'Network requires attention')}")
        
        # Recommendations
        recommendations = ai_response.get('recommendations', [])
        if recommendations:
            print(f"\n{Colors.BOLD}Detailed Recommendations:{Colors.END}")
            for i, rec in enumerate(recommendations[:10], 1):
                severity_color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.YELLOW,
                    'MEDIUM': Colors.CYAN,
                    'LOW': Colors.GREEN
                }.get(rec.get('severity', 'MEDIUM'), Colors.END)
                
                print(f"\n  {i}. {severity_color}[{rec.get('severity', 'MEDIUM')}]{Colors.END} {rec.get('issue', 'Issue')}")
                print(f"     {Colors.GREEN}→ {rec.get('recommendation', 'No specific recommendation')}{Colors.END}")
                
                # Show commands if available
                commands = rec.get('commands', [])
                if commands:
                    print(f"     {Colors.BLUE}Commands to fix:{Colors.END}")
                    for cmd in commands:
                        print(f"       {Colors.CYAN}$ {cmd}{Colors.END}")
        
        # Action items
        action_items = ai_response.get('action_items', [])
        if action_items:
            print(f"\n{Colors.BOLD}Immediate Action Items:{Colors.END}")
            for item in action_items:
                print(f"  {Colors.YELLOW}→{Colors.END} {item}")
        
        # Learning notes from Aye
        learning = ai_response.get('learning_notes')
        if learning:
            print(f"\n{Colors.HEADER}{Colors.BOLD}📚 Aye's Learning Note:{Colors.END}")
            print(f"  {learning}")
        
        print(f"\n{Colors.GREEN}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}AI analysis complete! Stay secure with smart recommendations! 🛡️{Colors.END}\n")

def main():
    """Main function - where Aye and Hue's adventure begins"""
    # Check for AI mode flag
    enable_ai = '--ai' in sys.argv or '-a' in sys.argv or os.getenv('SECURAYE_AI', '').lower() == 'true'
    
    # Remove AI flags from argv if present
    sys.argv = [arg for arg in sys.argv if arg not in ['--ai', '-a']]
    
    # Read from stdin or file
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            lines = f.readlines()
    else:
        # Don't print if reading from pipe
        if sys.stdin.isatty():
            print("Reading from stdin... (paste your lsof output)")
        lines = sys.stdin.readlines()
    
    # Create analyzer and work the magic
    analyzer = NetworkAnalyzer()
    analyzer.analyze_data(lines)
    analyzer.print_summary()
    
    # Get AI recommendations if enabled
    if enable_ai:
        print(f"\n{Colors.CYAN}🤖 Consulting AI Security Advisor...{Colors.END}")
        ai_response = analyzer.get_ai_recommendations(enable_ai=True)
        if ai_response:
            analyzer.print_ai_recommendations(ai_response)
        else:
            print(f"{Colors.YELLOW}💡 AI advisor not available - showing standard analysis only{Colors.END}")

if __name__ == "__main__":
    main()