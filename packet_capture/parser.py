"""
test_parser.py - Unit tests for packet parsing
================================================

Run this file to test your parser.py implementation.

Usage:
    python test_parser.py
"""

import sys
import os

# Add parent directory to path if running standalone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import IP, TCP, UDP, ICMP, Ether
from datetime import datetime

try:
    from parser import (
        parse_packet,
        extract_ip_info,
        extract_port_info,
        get_packet_size
    )
except ImportError:
    from packet_capture.parser import (
        parse_packet,
        extract_ip_info,
        extract_port_info,
        get_packet_size
    )


def test_extract_ip_info():
    """Test IP address extraction"""
    print("Testing extract_ip_info()...")
    
    # Create test packet with IP
    pkt_with_ip = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")
    src, dst = extract_ip_info(pkt_with_ip)
    
    if src == "192.168.1.1" and dst == "192.168.1.2":
        print(f"  ✓ IP extraction: {src} -> {dst}")
        success = True
    else:
        print(f"  ✗ IP extraction failed: got {src} -> {dst}")
        success = False
    
    # Test packet without IP
    pkt_without_ip = Ether()
    src, dst = extract_ip_info(pkt_without_ip)
    
    if src is None and dst is None:
        print(f"  ✓ Non-IP packet handled correctly")
    else:
        print(f"  ✗ Non-IP packet should return (None, None)")
        success = False
    
    print(f"\n{'✓ PASSED' if success else '✗ FAILED'}\n")
    return success


def test_extract_port_info():
    """Test port extraction"""
    print("Testing extract_port_info()...")
    
    passed = 0
    failed = 0
    
    # Test TCP packet
    tcp_pkt = Ether()/IP()/TCP(sport=12345, dport=80)
    src, dst = extract_port_info(tcp_pkt)
    if src == 12345 and dst == 80:
        print(f"  ✓ TCP ports: {src} -> {dst}")
        passed += 1
    else:
        print(f"  ✗ TCP ports failed: got {src} -> {dst}")
        failed += 1
    
    # Test UDP packet
    udp_pkt = Ether()/IP()/UDP(sport=54321, dport=53)
    src, dst = extract_port_info(udp_pkt)
    if src == 54321 and dst == 53:
        print(f"  ✓ UDP ports: {src} -> {dst}")
        passed += 1
    else:
        print(f"  ✗ UDP ports failed: got {src} -> {dst}")
        failed += 1
    
    # Test ICMP packet (no ports)
    icmp_pkt = Ether()/IP()/ICMP()
    src, dst = extract_port_info(icmp_pkt)
    if src is None and dst is None:
        print(f"  ✓ ICMP (no ports) handled correctly")
        passed += 1
    else:
        print(f"  ✗ ICMP should return (None, None)")
        failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed\n")
    return failed == 0


def test_get_packet_size():
    """Test packet size calculation"""
    print("Testing get_packet_size()...")
    
    # Create packet and check size
    pkt = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80)
    size = get_packet_size(pkt)
    
    if size > 0:
        print(f"  ✓ Packet size: {size} bytes")
        success = True
    else:
        print(f"  ✗ Invalid packet size: {size}")
        success = False
    
    print(f"\n{'✓ PASSED' if success else '✗ FAILED'}\n")
    return success


def test_parse_packet():
    """Test complete packet parsing"""
    print("Testing parse_packet()...")
    
    passed = 0
    failed = 0
    
    # Test 1: TCP packet (HTTP)
    tcp_pkt = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=54321, dport=80)
    result = parse_packet(tcp_pkt)
    
    if result:
        checks = [
            ('source_ip', '192.168.1.100'),
            ('dest_ip', '93.184.216.34'),
            ('source_port', 54321),
            ('dest_port', 80),
            ('protocol', 'HTTP'),
            ('raw_protocol', 'TCP'),
        ]
        
        tcp_pass = True
        for key, expected in checks:
            if result.get(key) == expected:
                print(f"  ✓ TCP packet {key}: {result[key]}")
            else:
                print(f"  ✗ TCP packet {key}: {result.get(key)} (expected {expected})")
                tcp_pass = False
        
        if tcp_pass:
            passed += 1
        else:
            failed += 1
    else:
        print(f"  ✗ TCP packet parsing returned None")
        failed += 1
    
    print()
    
    # Test 2: UDP packet (DNS)
    udp_pkt = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)
    result = parse_packet(udp_pkt)
    
    if result and result.get('protocol') == 'DNS' and result.get('raw_protocol') == 'UDP':
        print(f"  ✓ UDP packet: protocol={result['protocol']}, raw={result['raw_protocol']}")
        passed += 1
    else:
        print(f"  ✗ UDP packet parsing failed")
        failed += 1
    
    # Test 3: ICMP packet
    icmp_pkt = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/ICMP()
    result = parse_packet(icmp_pkt)
    
    if result and result.get('raw_protocol') == 'ICMP':
        print(f"  ✓ ICMP packet: raw_protocol={result['raw_protocol']}")
        passed += 1
    else:
        print(f"  ✗ ICMP packet parsing failed")
        failed += 1
    
    # Test 4: Non-IP packet (should return None)
    non_ip_pkt = Ether()
    result = parse_packet(non_ip_pkt)
    
    if result is None:
        print(f"  ✓ Non-IP packet correctly returns None")
        passed += 1
    else:
        print(f"  ✗ Non-IP packet should return None")
        failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed\n")
    return failed == 0


def main():
    """Run all tests"""
    print("=" * 60)
    print("PACKET PARSER MODULE TESTS")
    print("=" * 60)
    print()
    
    all_passed = True
    
    all_passed &= test_extract_ip_info()
    all_passed &= test_extract_port_info()
    all_passed &= test_get_packet_size()
    all_passed &= test_parse_packet()
    
    print("=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED!")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())