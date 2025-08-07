#!/usr/bin/env python3
"""
Security Advisor API - AI-Powered Network Security Recommendations
Aye's intelligent security assistant that connects to OpenRouter for expert analysis!
Trish says this is the coolest thing since color-coded spreadsheets! 🌈
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import httpx
import os
import json
from datetime import datetime
import asyncio
from collections import defaultdict
import hashlib

# FastAPI app initialization - let's make it sparkle!
app = FastAPI(
    title="NetWatch Security Advisor",
    description="AI-powered security recommendations for network analysis. Built with 💜 by Aye & Hue!",
    version="1.0.0"
)

# CORS middleware - because sharing is caring
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration - getting our settings sorted
class Config:
    """Configuration for our AI security advisor"""
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    # Default to a fast, cost-effective model - you can change this!
    DEFAULT_MODEL = os.getenv("AI_MODEL", "anthropic/claude-3-haiku")
    MAX_RETRIES = 3
    TIMEOUT = 30
    
    # Security thresholds
    CRITICAL_THRESHOLD = 30
    HIGH_THRESHOLD = 50
    MEDIUM_THRESHOLD = 70

config = Config()

# Pydantic models for our data structures
class ServiceInfo(BaseModel):
    """Information about a network service"""
    command: str = Field(..., description="Process command name")
    port: int = Field(..., description="Port number")
    protocol: str = Field(..., description="Protocol (TCP/UDP)")
    user: str = Field(..., description="User running the service")
    state: str = Field(..., description="Connection state")
    interface: Optional[str] = Field(None, description="Network interface")

class NetworkAnalysis(BaseModel):
    """Network analysis data to send for AI evaluation"""
    services: List[ServiceInfo] = Field(..., description="List of network services")
    security_score: int = Field(..., description="Current security score (0-100)")
    vulnerabilities: List[str] = Field(default=[], description="Known vulnerabilities")
    external_connections: List[Dict[str, str]] = Field(default=[], description="External connections")
    suspicious_ports: List[int] = Field(default=[], description="Suspicious ports detected")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class SecurityRecommendation(BaseModel):
    """AI-generated security recommendation"""
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")
    category: str = Field(..., description="Category of the issue")
    issue: str = Field(..., description="Description of the security issue")
    recommendation: str = Field(..., description="Specific recommendation to fix")
    commands: Optional[List[str]] = Field(None, description="Commands to execute")
    priority: int = Field(..., description="Priority (1-10, 10 being highest)")

class AIResponse(BaseModel):
    """Complete AI security analysis response"""
    overall_assessment: str = Field(..., description="Overall security assessment")
    risk_level: str = Field(..., description="Overall risk level")
    recommendations: List[SecurityRecommendation] = Field(..., description="List of recommendations")
    executive_summary: str = Field(..., description="Brief summary for non-technical users")
    action_items: List[str] = Field(..., description="Immediate action items")
    learning_notes: Optional[str] = Field(None, description="Educational notes from Aye")

# In-memory cache for recent analyses - because fast is better than slow!
analysis_cache = {}
CACHE_DURATION = 300  # 5 minutes

class SecurityAdvisor:
    """The brain of our security advisor - where the magic happens!"""
    
    def __init__(self):
        """Initialize our security advisor with all the bells and whistles"""
        self.client = httpx.AsyncClient(
            base_url=config.OPENROUTER_BASE_URL,
            headers={
                "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://github.com/yourusername/netwatch",
                "X-Title": "NetWatch Security Advisor"
            },
            timeout=config.TIMEOUT
        )
        
        # Knowledge base for common security patterns
        self.security_patterns = {
            "redis_exposed": {
                "pattern": lambda s: s.port == 6379 and s.interface in ["*", "0.0.0.0"],
                "severity": "CRITICAL",
                "message": "Redis exposed without authentication!"
            },
            "mongodb_exposed": {
                "pattern": lambda s: s.port == 27017 and s.interface in ["*", "0.0.0.0"],
                "severity": "CRITICAL", 
                "message": "MongoDB exposed without authentication!"
            },
            "ssh_root": {
                "pattern": lambda s: s.port == 22 and s.user == "root",
                "severity": "HIGH",
                "message": "SSH running as root - security risk!"
            },
            "dev_server_exposed": {
                "pattern": lambda s: s.port in [3000, 8000, 8080] and s.interface in ["*", "0.0.0.0"],
                "severity": "MEDIUM",
                "message": "Development server exposed to network"
            }
        }
    
    async def analyze_with_ai(self, data: NetworkAnalysis) -> AIResponse:
        """Send network data to AI for expert analysis - the smart stuff!"""
        
        # Check cache first - work smarter, not harder
        cache_key = self._generate_cache_key(data)
        if cache_key in analysis_cache:
            cached_time, cached_response = analysis_cache[cache_key]
            if (datetime.now() - cached_time).seconds < CACHE_DURATION:
                return cached_response
        
        # Build the prompt for our AI friend
        prompt = self._build_security_prompt(data)
        
        try:
            # Call OpenRouter API
            response = await self.client.post(
                "/chat/completions",
                json={
                    "model": config.DEFAULT_MODEL,
                    "messages": [
                        {
                            "role": "system",
                            "content": """You are a senior network security expert helping analyze network configurations. 
                            You're working with Aye (an AI assistant) and Hue (a human) to improve security.
                            Provide specific, actionable recommendations with actual commands when possible.
                            Be thorough but concise. Include a touch of humor to keep things engaging.
                            Format your response as valid JSON matching the required schema."""
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.3,  # More deterministic for security analysis
                    "max_tokens": 2000
                }
            )
            
            response.raise_for_status()
            result = response.json()
            
            # Parse AI response
            ai_text = result['choices'][0]['message']['content']
            
            # Try to extract JSON from the response
            try:
                # If the response is wrapped in markdown code blocks, extract it
                if "```json" in ai_text:
                    ai_text = ai_text.split("```json")[1].split("```")[0]
                elif "```" in ai_text:
                    ai_text = ai_text.split("```")[1].split("```")[0]
                
                ai_data = json.loads(ai_text)
                
                # Convert to our response model
                ai_response = AIResponse(
                    overall_assessment=ai_data.get("overall_assessment", "Security analysis complete"),
                    risk_level=ai_data.get("risk_level", "MEDIUM"),
                    recommendations=[
                        SecurityRecommendation(**rec) for rec in ai_data.get("recommendations", [])
                    ],
                    executive_summary=ai_data.get("executive_summary", "Network requires attention"),
                    action_items=ai_data.get("action_items", []),
                    learning_notes=ai_data.get("learning_notes", None)
                )
                
            except json.JSONDecodeError:
                # Fallback to pattern-based analysis if AI response isn't JSON
                ai_response = self._fallback_analysis(data)
            
            # Cache the response
            analysis_cache[cache_key] = (datetime.now(), ai_response)
            
            return ai_response
            
        except httpx.RequestError as e:
            # Network error - fall back to local analysis
            print(f"🚨 AI request failed: {e}")
            return self._fallback_analysis(data)
        
        except Exception as e:
            print(f"🔥 Unexpected error: {e}")
            return self._fallback_analysis(data)
    
    def _build_security_prompt(self, data: NetworkAnalysis) -> str:
        """Build a comprehensive prompt for AI analysis"""
        
        # Group services by risk
        critical_services = []
        high_risk_services = []
        
        for service in data.services:
            for pattern_name, pattern_info in self.security_patterns.items():
                if pattern_info["pattern"](service):
                    if pattern_info["severity"] == "CRITICAL":
                        critical_services.append(service)
                    elif pattern_info["severity"] == "HIGH":
                        high_risk_services.append(service)
        
        prompt = f"""Analyze this network security data and provide recommendations:

Network Overview:
- Total Services: {len(data.services)}
- Security Score: {data.security_score}/100
- Critical Services: {len(critical_services)}
- Suspicious Ports: {data.suspicious_ports}
- External Connections: {len(data.external_connections)}

Services Running:
{json.dumps([s.dict() for s in data.services[:20]], indent=2)}  # Limit to first 20 for token efficiency

Known Vulnerabilities:
{json.dumps(data.vulnerabilities, indent=2)}

Please provide a JSON response with:
1. overall_assessment: Brief assessment of the network security posture
2. risk_level: CRITICAL, HIGH, MEDIUM, or LOW
3. recommendations: Array of specific recommendations with severity, category, issue, recommendation, commands (if applicable), and priority
4. executive_summary: 2-3 sentence summary for management
5. action_items: List of immediate actions to take
6. learning_notes: Educational note about security best practices

Focus on practical, implementable solutions. Include specific commands for macOS/Linux where applicable.
"""
        
        return prompt
    
    def _generate_cache_key(self, data: NetworkAnalysis) -> str:
        """Generate a cache key from the analysis data"""
        # Create a hash of the service data for caching
        service_str = json.dumps([s.dict() for s in data.services], sort_keys=True)
        return hashlib.md5(service_str.encode()).hexdigest()
    
    def _fallback_analysis(self, data: NetworkAnalysis) -> AIResponse:
        """Fallback analysis when AI is unavailable - still pretty smart!"""
        
        recommendations = []
        
        # Check against our security patterns
        for service in data.services:
            for pattern_name, pattern_info in self.security_patterns.items():
                if pattern_info["pattern"](service):
                    recommendations.append(SecurityRecommendation(
                        severity=pattern_info["severity"],
                        category="Network Exposure",
                        issue=f"{pattern_info['message']} on port {service.port}",
                        recommendation=self._get_fallback_recommendation(service),
                        commands=self._get_fix_commands(service),
                        priority=9 if pattern_info["severity"] == "CRITICAL" else 7
                    ))
        
        # Determine overall risk level
        if any(r.severity == "CRITICAL" for r in recommendations):
            risk_level = "CRITICAL"
        elif any(r.severity == "HIGH" for r in recommendations):
            risk_level = "HIGH"
        elif data.security_score < 60:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return AIResponse(
            overall_assessment="Automated security analysis completed. Several issues require attention.",
            risk_level=risk_level,
            recommendations=recommendations[:10],  # Limit to top 10
            executive_summary="Network security scan revealed configuration issues that need immediate attention.",
            action_items=[
                "Review and close unnecessary open ports",
                "Bind services to localhost where possible",
                "Enable authentication on all databases",
                "Implement firewall rules"
            ],
            learning_notes="Remember: The principle of least privilege applies to network services too! 🛡️"
        )
    
    def _get_fallback_recommendation(self, service: ServiceInfo) -> str:
        """Get specific recommendation for a service"""
        if service.port == 6379:
            return "Configure Redis with authentication and bind to localhost"
        elif service.port == 27017:
            return "Enable MongoDB authentication and restrict network access"
        elif service.port == 22:
            return "Use SSH keys, disable root login, and consider changing default port"
        elif service.port in [3000, 8000, 8080]:
            return "Ensure development servers are not exposed in production"
        else:
            return f"Review security configuration for {service.command} on port {service.port}"
    
    def _get_fix_commands(self, service: ServiceInfo) -> List[str]:
        """Get fix commands for common issues"""
        commands = []
        
        if service.port == 6379:
            commands = [
                "# Edit Redis config",
                "sudo nano /etc/redis/redis.conf",
                "# Add: bind 127.0.0.1",
                "# Add: requirepass your_strong_password_here",
                "sudo systemctl restart redis"
            ]
        elif service.port == 27017:
            commands = [
                "# Enable MongoDB auth",
                "mongo",
                "use admin",
                "db.createUser({user:'admin',pwd:'strong_password',roles:['root']})",
                "# Edit /etc/mongod.conf",
                "# Add: security.authorization: enabled"
            ]
        elif service.port == 22 and service.user == "root":
            commands = [
                "# Disable root SSH",
                "sudo nano /etc/ssh/sshd_config",
                "# Set: PermitRootLogin no",
                "sudo systemctl restart sshd"
            ]
        
        return commands

# Initialize our security advisor
advisor = SecurityAdvisor()

# API Endpoints - where the magic meets the network!

@app.get("/")
async def root():
    """Welcome endpoint - Trish insisted on a friendly greeting!"""
    return {
        "message": "🌐 NetWatch Security Advisor is running!",
        "status": "operational",
        "tip": "Send your network data to /analyze for AI-powered recommendations",
        "created_by": "Aye & Hue with Trish's sparkle ✨"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint - keeping things running smooth"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "api_configured": bool(config.OPENROUTER_API_KEY),
        "cache_size": len(analysis_cache)
    }

@app.post("/analyze", response_model=AIResponse)
async def analyze_network(data: NetworkAnalysis, background_tasks: BackgroundTasks):
    """
    Analyze network configuration and provide AI-powered security recommendations
    
    This endpoint accepts network service data and returns comprehensive security
    recommendations powered by AI analysis.
    """
    
    if not config.OPENROUTER_API_KEY:
        # Use fallback analysis if no API key
        return advisor._fallback_analysis(data)
    
    # Get AI analysis
    result = await advisor.analyze_with_ai(data)
    
    # Log analysis for learning (optional)
    background_tasks.add_task(log_analysis, data, result)
    
    return result

@app.post("/quick-check")
async def quick_security_check(services: List[ServiceInfo]):
    """
    Quick security check for a list of services
    Returns immediate risk assessment without full AI analysis
    """
    
    critical_count = 0
    high_count = 0
    issues = []
    
    for service in services:
        # Check against patterns
        for pattern_name, pattern_info in advisor.security_patterns.items():
            if pattern_info["pattern"](service):
                issues.append({
                    "service": service.command,
                    "port": service.port,
                    "severity": pattern_info["severity"],
                    "message": pattern_info["message"]
                })
                
                if pattern_info["severity"] == "CRITICAL":
                    critical_count += 1
                elif pattern_info["severity"] == "HIGH":
                    high_count += 1
    
    # Calculate quick score
    score = 100 - (critical_count * 15) - (high_count * 10)
    score = max(0, score)
    
    return {
        "score": score,
        "critical_issues": critical_count,
        "high_issues": high_count,
        "issues": issues[:10],  # Top 10 issues
        "recommendation": "Run full analysis for detailed recommendations" if issues else "Looking good! 🎉"
    }

@app.get("/recommendations/{port}")
async def get_port_recommendations(port: int):
    """
    Get specific recommendations for a port
    Useful for targeted security improvements
    """
    
    port_recommendations = {
        22: {
            "service": "SSH",
            "risks": ["Brute force attacks", "Root access if misconfigured"],
            "recommendations": [
                "Use SSH keys instead of passwords",
                "Disable root login",
                "Change default port",
                "Use fail2ban for brute force protection"
            ],
            "commands": [
                "ssh-keygen -t ed25519 -C 'your_email@example.com'",
                "sudo nano /etc/ssh/sshd_config",
                "# Set: PermitRootLogin no",
                "# Set: PasswordAuthentication no",
                "sudo apt install fail2ban"
            ]
        },
        6379: {
            "service": "Redis",
            "risks": ["No authentication by default", "Data exposure", "Remote code execution"],
            "recommendations": [
                "Enable password authentication",
                "Bind to localhost only",
                "Use ACLs for fine-grained access",
                "Enable TLS for connections"
            ],
            "commands": [
                "redis-cli CONFIG SET requirepass 'strong_password_here'",
                "redis-cli CONFIG SET bind '127.0.0.1'",
                "redis-cli CONFIG REWRITE"
            ]
        },
        27017: {
            "service": "MongoDB",
            "risks": ["No authentication by default", "Database exposure", "Data theft"],
            "recommendations": [
                "Enable authentication",
                "Create admin user",
                "Bind to localhost",
                "Enable TLS"
            ],
            "commands": [
                "mongosh",
                "use admin",
                "db.createUser({user: 'admin', pwd: 'password', roles: ['root']})",
                "# Edit /etc/mongod.conf",
                "# security.authorization: enabled"
            ]
        }
    }
    
    if port in port_recommendations:
        return port_recommendations[port]
    else:
        return {
            "service": "Unknown",
            "risks": ["Potential security exposure"],
            "recommendations": [
                "Verify if this port should be open",
                "Check service documentation for security best practices",
                "Consider firewall rules to restrict access",
                "Monitor for unusual activity"
            ],
            "commands": [
                f"sudo lsof -i :{port}  # Check what's using this port",
                f"sudo ufw deny {port}  # Block port with UFW firewall"
            ]
        }

async def log_analysis(data: NetworkAnalysis, result: AIResponse):
    """Log analysis results for future learning - Aye loves to learn!"""
    # You could log to a file, database, or monitoring system here
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "security_score": data.security_score,
        "risk_level": result.risk_level,
        "critical_issues": len([r for r in result.recommendations if r.severity == "CRITICAL"]),
        "services_analyzed": len(data.services)
    }
    
    # For now, just print it - but you could do more!
    print(f"📊 Analysis logged: {json.dumps(log_entry, indent=2)}")

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting NetWatch Security Advisor API...")
    print("📍 API will be available at: http://localhost:8888")
    print("📚 Documentation at: http://localhost:8888/docs")
    print("💡 Tip: Set OPENROUTER_API_KEY environment variable for AI analysis")
    print("\n✨ Trish says: 'Let's make network security sparkle!' ✨\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8888, reload=True)