"""
protocols.py - Protocol Detection
===================================

This module detects application-layer protocols based on port numbers.

OWNER: Member 4 (Packet Capture Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from config import PROTOCOL_PORTS

2. detect_protocol(src_port, dst_port, raw_protocol) function:
   - Takes source port, destination port, and raw protocol type
   - Checks both ports against known port mappings
   - Returns the detected protocol name as a string
   
   Logic:
   - First check destination port (more commonly used)
   - Then check source port (for response packets)
   - If no match, return the raw protocol ('TCP', 'UDP')
   - If no raw protocol, return 'UNKNOWN'

3. Port mapping (use PROTOCOL_PORTS from config or define here):
   - 80 → HTTP
   - 443 → HTTPS
   - 22 → SSH
   - 21 → FTP
   - 53 → DNS
   - 25, 465, 587 → SMTP
   - 110, 995 → POP3
   - 143, 993 → IMAP
   - 3306 → MySQL
   - 5432 → PostgreSQL
   - 3389 → RDP
   - 23 → TELNET
   - 67, 68 → DHCP
   - 123 → NTP

4. Helper functions:

   get_protocol_by_port(port) -> str:
   - Look up port in PROTOCOL_PORTS dictionary
   - Return protocol name or None
   
   is_http_traffic(src_port, dst_port) -> bool:
   - Check if traffic is HTTP/HTTPS
   - Useful for filtering or categorization
   
   get_protocol_category(protocol_name) -> str:
   - Categorize protocols: 'web', 'email', 'file_transfer', 'remote', 'other'
   - Useful for grouping in analytics

EXAMPLE FUNCTION SIGNATURES:
----------------------------
def detect_protocol(src_port: int, dst_port: int, raw_protocol: str = 'TCP') -> str:
    '''
    Detect application-layer protocol from port numbers.
    
    Args:
        src_port: Source port number (can be None)
        dst_port: Destination port number (can be None)
        raw_protocol: Transport protocol ('TCP', 'UDP', 'ICMP')
    
    Returns:
        Protocol name string (e.g., 'HTTP', 'HTTPS', 'DNS', 'TCP')
    '''
    # Check destination port first
    if dst_port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[dst_port]
    
    # Check source port
    if src_port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[src_port]
    
    # Fall back to raw protocol
    return raw_protocol or 'UNKNOWN'

def get_protocol_by_port(port: int) -> str:
    pass

def is_http_traffic(src_port: int, dst_port: int) -> bool:
    pass

def get_protocol_category(protocol_name: str) -> str:
    pass
"""
