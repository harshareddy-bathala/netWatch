"""
protocols.py - Protocol Detection
===================================

This module detects application-layer protocols based on port numbers.

OWNER: Member 4 (Packet Capture Developer)
"""

# Try to import from config, fallback to local definition if not available
try:
    from config import PROTOCOL_PORTS
except ImportError:
    # Fallback protocol port mapping
    PROTOCOL_PORTS = {
        # Web
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
        
        # Email
        25: 'SMTP',
        465: 'SMTPS',
        587: 'SMTP',
        110: 'POP3',
        995: 'POP3S',
        143: 'IMAP',
        993: 'IMAPS',
        
        # File Transfer
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        
        # Database
        3306: 'MySQL',
        5432: 'PostgreSQL',
        1433: 'MSSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        
        # Remote Access
        3389: 'RDP',
        5900: 'VNC',
        
        # DNS & Network
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        123: 'NTP',
        161: 'SNMP',
        162: 'SNMP-TRAP',
        
        # Other Common
        445: 'SMB',
        139: 'NetBIOS',
        389: 'LDAP',
        636: 'LDAPS',
    }


def detect_protocol(src_port: int, dst_port: int, raw_protocol: str = 'TCP') -> str:
    """
    Detect application-layer protocol from port numbers.
    
    Args:
        src_port: Source port number (can be None)
        dst_port: Destination port number (can be None)
        raw_protocol: Transport protocol ('TCP', 'UDP', 'ICMP')
    
    Returns:
        Protocol name string (e.g., 'HTTP', 'HTTPS', 'DNS', 'TCP')
    """
    # Check destination port first (more commonly used for services)
    if dst_port and dst_port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[dst_port]
    
    # Check source port (for response packets)
    if src_port and src_port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[src_port]
    
    # Fall back to raw protocol
    return raw_protocol if raw_protocol else 'UNKNOWN'


def get_protocol_by_port(port: int) -> str:
    """
    Look up protocol by port number.
    
    Args:
        port: Port number
    
    Returns:
        Protocol name or None if not found
    """
    if port is None:
        return None
    return PROTOCOL_PORTS.get(port)


def is_http_traffic(src_port: int, dst_port: int) -> bool:
    """
    Check if traffic is HTTP or HTTPS.
    
    Args:
        src_port: Source port number
        dst_port: Destination port number
    
    Returns:
        True if HTTP/HTTPS traffic, False otherwise
    """
    http_ports = {80, 443, 8080, 8443}
    return (src_port in http_ports) or (dst_port in http_ports)


def get_protocol_category(protocol_name: str) -> str:
    """
    Get category for a protocol.
    
    Args:
        protocol_name: Name of the protocol (e.g., 'HTTP', 'SSH')
    
    Returns:
        Category string: 'web', 'email', 'file_transfer', 'remote', 
                        'database', 'dns', 'network', 'other'
    """
    categories = {
        'web': ['HTTP', 'HTTPS', 'HTTP-ALT', 'HTTPS-ALT'],
        'email': ['SMTP', 'SMTPS', 'POP3', 'POP3S', 'IMAP', 'IMAPS'],
        'file_transfer': ['FTP', 'FTP-DATA', 'SSH'],
        'remote': ['SSH', 'TELNET', 'RDP', 'VNC'],
        'dns': ['DNS'],
        'database': ['MySQL', 'PostgreSQL', 'MSSQL', 'MongoDB', 'Redis'],
        'network': ['DHCP', 'NTP', 'SNMP', 'SNMP-TRAP', 'LDAP', 'LDAPS'],
    }
    
    for category, protocols in categories.items():
        if protocol_name in protocols:
            return category
    
    return 'other'