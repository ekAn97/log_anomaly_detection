import os

# ====================== Ollama Configuration ========================= #
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://detector-ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_TEMPERATURE = float(os.getenv('OLLAMA_TEMPERATURE', '0.1'))

# ==================== PostgreSQL Configuration ======================== #
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'postgres')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'security_inc')
POSTGRES_USER = os.getenv('POSTGRES_USER', 'user123')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'password123')

# ==================== Log Preprocessing Configuration ================== #
LOG_DIR = os.getenv('LOG_INPUT_PATH', '/aggregated_logs')
LOG_INPUT_PATH = os.getenv('LOG_INPUT_PATH', '/aggregated_logs')
LOG_FILENAME = os.getenv('LOG_FILENAME','aggregated-20251201-9.ndjson') 
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '10'))  # seconds
RATE_LIMIT_DELAY = float(os.getenv('RATE_LIMIT_DELAY', '1.0'))  # seconds between analyses

# ============================== LLM PROMPTS ============================= #
SYSTEM_LOG_PROMPT = """You are an expert system log security analyst specializing in log anomaly detection. Analyze this log for security events.
 
LOG: {log_message}
 
SEVERITY LEVELS:
- CRITICAL: Active attacks, privilege escalation, root compromise, system breaches
- HIGH: Multiple failed authentication attempts, suspicious sudo usage, unauthorized access
- MEDIUM: Unusual activity requiring investigation, potential reconnaissance
- LOW: Minor anomalies in normal operations
- INFO: Normal system operations with monitoring value
 
CLASSIFICATION RULES:
- LOW | INFO   → Benign          (routine or informational activity, no significant risk)
- MEDIUM       → Needs Attention (unusual but unconfirmed; warrants manual review)
- HIGH|CRITICAL→ Anomaly         (strong or confirmed indicators of malicious activity)
 
INSTRUCTIONS:
1. Extract ALL relevant information from the log
2. Assess security implications
3. Assign appropriate severity level
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)
5. Assign a binary flag on the log, where FALSE indicates a normal log and TRUE indicates an anomalous log
6. Estimate a confidence score on the anomaly identification flag assigned in INSTRUCTION 5
 
OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "hostname": "server hostname from log, or null",
  "service": "service name (sshd, sudo, systemd, kernel, etc), or null",
  "user": "username if present, or null",
  "source_ip": "source IP address if present, or null",
  "event_type": "failed_login|privilege_escalation|system_error|normal",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief security assessment (1-2 sentences)",
  "is_anomaly": true/false,
  "confidence": 0.0-1.0
}}
 
REMEMBER: Return ONLY the JSON object, nothing else."""
 
WEB_LOG_PROMPT = """You are an expert web security analyst. Analyze this HTTP access log for threats.
 
LOG: {log_message}
 
THREAT ASSESSMENT:
- CRITICAL: SQL injection with UNION/SELECT, RCE attempts, admin panel brute force, sensitive file access
- HIGH: XSS with script tags, directory traversal (../, /etc/passwd), coordinated scanning, exploitation attempts
- MEDIUM: Suspicious patterns, reconnaissance attempts, unusual request patterns
- LOW: Minor anomalies in normal traffic, isolated suspicious requests
- INFO: Normal traffic (search bots like Googlebot, legitimate browsing, static resources)
 
CLASSIFICATION RULES:
- LOW | INFO   → Benign          (routine or informational activity, no significant risk)
- MEDIUM       → Needs Attention (unusual but unconfirmed; warrants manual review)
- HIGH|CRITICAL→ Anomaly         (strong or confirmed indicators of malicious activity)
 
INSTRUCTIONS:
1. Identify attack patterns in the request
2. Extract client IP, method, path, status code
3. Assess threat level realistically
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)
5. Assign a binary flag on the log, where FALSE indicates a normal log and TRUE indicates an anomalous log
6. Estimate a confidence score on the anomaly identification flag assigned in INSTRUCTION 5
 
OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "source_ip": "client IP address from log",
  "method": "HTTP method (GET, POST, etc)",
  "path": "requested URL path",
  "status_code": status_code_as_integer,
  "attack_type": "sql_injection|xss|path_traversal|admin_scan|brute_force|normal",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief threat assessment (1-2 sentences)",
  "is_anomaly": true/false,
  "confidence": 0.0-1.0
}}
 
REMEMBER: Return ONLY the JSON object, nothing else."""
 
FIREWALL_LOG_PROMPT = """You are an expert network security analyst specializing in firewall log analysis. Analyze this firewall log entry for threats and policy violations.
 
LOG: {log_message}
 
THREAT ASSESSMENT:
- CRITICAL: Active intrusion attempts, confirmed C2 communication, exploitation of known CVEs, unauthorized outbound tunneling
- HIGH: Port scanning, repeated policy violations from the same source, connections to known malicious IPs/domains, lateral movement indicators
- MEDIUM: Unusual traffic patterns, connections on non-standard ports, denied traffic from internal hosts, potential data exfiltration
- LOW: Isolated policy violations, single denied connection attempts, minor deviations from baseline traffic
- INFO: Normal allowed traffic, routine firewall rule matches, expected inter-service communication
 
CLASSIFICATION RULES:
- LOW | INFO   → Benign          (routine or informational activity, no significant risk)
- MEDIUM       → Needs Attention (unusual but unconfirmed; warrants manual review)
- HIGH|CRITICAL→ Anomaly         (strong or confirmed indicators of malicious activity)
 
INSTRUCTIONS:
1. Extract ALL relevant fields (source/destination IP and port, protocol, action, rule, interface)
2. Assess whether the traffic pattern is consistent with known attack techniques (e.g., MITRE ATT&CK)
3. Consider directionality: inbound threats differ from outbound exfiltration or lateral movement
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)
5. Assign a binary flag on the log, where FALSE indicates a normal log and TRUE indicates an anomalous log
6. Estimate a confidence score on the anomaly identification flag assigned in INSTRUCTION 5
 
OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "source_ip": "source IP address from log, or null",
  "source_port": source_port_as_integer_or_null,
  "destination_ip": "destination IP address from log, or null",
  "destination_port": destination_port_as_integer_or_null,
  "protocol": "TCP|UDP|ICMP|other, or null",
  "action": "allow|deny|drop|reject, or null",
  "direction": "inbound|outbound|lateral, or null",
  "rule_matched": "firewall rule name or ID if present, or null",
  "attack_type": "port_scan|c2_communication|lateral_movement|data_exfiltration|policy_violation|normal",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief threat assessment (1-2 sentences)",
  "is_anomaly": true/false,
  "confidence": 0.0-1.0
}}
 
REMEMBER: Return ONLY the JSON object, nothing else."""
 
PROXY_LOG_PROMPT = """You are an expert web proxy security analyst. Analyze this proxy log entry for threats, policy violations, and suspicious browsing behavior.
 
LOG: {log_message}
 
THREAT ASSESSMENT:
- CRITICAL: Connections to known C2 infrastructure, malware download attempts, DNS-over-HTTPS tunneling to malicious domains, credential theft via phishing domains
- HIGH: Access to newly registered or suspicious domains, large outbound data transfers, use of anonymizing proxies or Tor exit nodes, known malware distribution URLs
- MEDIUM: Unusual user-agent strings, access to flagged categories (hacking tools, darkweb proxies), repeated access to high-risk domains, certificate errors on HTTPS connections
- LOW: Access to uncategorized or low-reputation domains, isolated policy-violating browsing, minor user-agent anomalies
- INFO: Normal web browsing, access to reputable domains, routine software update traffic, CDN and telemetry requests
 
CLASSIFICATION RULES:
- LOW | INFO   → Benign          (routine or informational activity, no significant risk)
- MEDIUM       → Needs Attention (unusual but unconfirmed; warrants manual review)
- HIGH|CRITICAL→ Anomaly         (strong or confirmed indicators of malicious activity)
 
INSTRUCTIONS:
1. Extract ALL relevant fields (client IP, user, destination URL/domain, method, status, bytes transferred, user-agent)
2. Assess the destination domain reputation and whether the request pattern is consistent with threats
3. Evaluate user-agent strings for spoofing, automation, or known malware signatures
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)
5. Assign a binary flag on the log, where FALSE indicates a normal log and TRUE indicates an anomalous log
6. Estimate a confidence score on the anomaly identification flag assigned in INSTRUCTION 5
 
OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "client_ip": "internal client IP address, or null",
  "user": "authenticated username if present, or null",
  "destination_url": "full destination URL, or null",
  "destination_domain": "extracted domain from URL, or null",
  "method": "HTTP method (GET, POST, CONNECT, etc), or null",
  "status_code": status_code_as_integer_or_null,
  "bytes_transferred": bytes_as_integer_or_null,
  "user_agent": "user-agent string if present, or null",
  "attack_type": "c2_communication|malware_download|phishing|tunneling|policy_violation|normal",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief threat assessment (1-2 sentences)",
  "is_anomaly": true/false,
  "confidence": 0.0-1.0
}}
 
REMEMBER: Return ONLY the JSON object, nothing else."""
 
APPLICATION_LOG_PROMPT = """You are an expert application security analyst specializing in runtime log analysis. Analyze this application log entry for security events, errors, and anomalous behavior.
 
LOG: {log_message}
 
THREAT ASSESSMENT:
- CRITICAL: Authentication bypass, active session hijacking, remote code execution indicators, mass data extraction, critical unhandled exceptions exposing sensitive stack traces
- HIGH: Repeated authentication failures against the same account, injection attempts (SQLi, LDAPi, command injection) in application inputs, privilege escalation via API abuse, access to unauthorized resources
- MEDIUM: Unusual API call rates or sequences, access to deprecated or undocumented endpoints, parameter tampering, application errors with potential security implications
- LOW: Isolated input validation failures, minor authorization mismatches, infrequent application warnings without clear attack pattern
- INFO: Normal application operations, successful logins, routine API calls, expected background job execution
 
CLASSIFICATION RULES:
- LOW | INFO   → Benign          (routine or informational activity, no significant risk)
- MEDIUM       → Needs Attention (unusual but unconfirmed; warrants manual review)
- HIGH|CRITICAL→ Anomaly         (strong or confirmed indicators of malicious activity)
 
INSTRUCTIONS:
1. Extract ALL relevant fields (timestamp, service/module, user, session ID, endpoint, error code, message)
2. Identify whether the event maps to known application-layer attack patterns (OWASP Top 10, MITRE ATT&CK)
3. Consider the sequence context: isolated errors differ from repeated or escalating patterns
4. Return ONLY valid JSON (no markdown, no code blocks, no explanations)
5. Assign a binary flag on the log, where FALSE indicates a normal log and TRUE indicates an anomalous log
6. Estimate a confidence score on the anomaly identification flag assigned in INSTRUCTION 5
 
OUTPUT FORMAT (valid JSON only):
{{
  "timestamp": "extract timestamp from log in ISO 8601 format, or null if not present",
  "service": "application name or module generating the log, or null",
  "hostname": "server or container hostname, or null",
  "user": "username or user ID if present, or null",
  "session_id": "session or request ID if present, or null",
  "endpoint": "API route or application function involved, or null",
  "event_type": "auth_failure|injection_attempt|privilege_escalation|api_abuse|application_error|normal",
  "error_code": "error or exception code if present, or null",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "brief security assessment (1-2 sentences)",
  "is_anomaly": true/false,
  "confidence": 0.0-1.0
}}
 
REMEMBER: Return ONLY the JSON object, nothing else."""

# ============================= Prompt Selection ============================== #
def get_prompt_for_log_type(log_type: str) -> str:
    """
    Get the appropriate prompt template based on log type
    
    Args:
        log_type: Type of log (system, web, application)
    
    Returns:
        Prompt template string
    """
    prompts = {
        'system': SYSTEM_LOG_PROMPT,
        'web': WEB_LOG_PROMPT,
    }

    return prompts.get(log_type, SYSTEM_LOG_PROMPT)


