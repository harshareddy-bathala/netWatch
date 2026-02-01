"""
parser.py - Packet Parsing Logic
==================================

This module parses raw Scapy packet objects and extracts relevant information.

OWNER: Member 4 (Packet Capture Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from scapy.all import IP, TCP, UDP, ICMP, Ether
   - from datetime import datetime
   - from packet_capture.protocols import detect_protocol

2. parse_packet(packet) function:
   - Takes a raw Scapy packet object
   - Returns a dictionary with extracted fields or None if not parseable
   
   Returned dictionary structure:
   {
       'timestamp': datetime object,
       'source_ip': str,
       'dest_ip': str,
       'source_port': int or None,
       'dest_port': int or None,
       'protocol': str (from detect_protocol),
       'bytes': int (packet length),
       'raw_protocol': str ('TCP', 'UDP', 'ICMP', etc.)
   }

3. Helper functions:

   extract_ip_info(packet)
   - Check if packet has IP layer
   - Extract source and destination IP addresses
   - Returns (src_ip, dst_ip) tuple or (None, None)
   
   extract_port_info(packet)
   - Check if packet has TCP or UDP layer
   - Extract source and destination ports
   - Returns (src_port, dst_port) tuple or (None, None)
   
   get_packet_size(packet)
   - Get the size of the packet in bytes
   - Use len(packet) or packet.len
   - Returns int

4. The parser should:
   - Handle packets without IP layer (return None)
   - Handle packets without transport layer (TCP/UDP)
   - Not crash on malformed packets
   - Log parsing errors for debugging

EXAMPLE FUNCTION SIGNATURES:
----------------------------
def parse_packet(packet) -> dict:
    '''
    Parse a raw Scapy packet and return structured data.
    
    Args:
        packet: Raw Scapy packet object
    
    Returns:
        dict with packet info or None if not parseable
    '''
    if not packet.haslayer(IP):
        return None
    
    ip_layer = packet[IP]
    return {
        'timestamp': datetime.now(),
        'source_ip': ip_layer.src,
        'dest_ip': ip_layer.dst,
        'bytes': len(packet),
        # ... more fields
    }

def extract_ip_info(packet) -> tuple:
    pass

def extract_port_info(packet) -> tuple:
    pass

def get_packet_size(packet) -> int:
    pass
"""
