"""
monitor.py - Network Packet Capture Engine
============================================

This module implements the core packet capture functionality using Scapy.

OWNER: Member 4 (Packet Capture Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from scapy.all import sniff, IP, TCP, UDP, Ether
   - from queue import Queue
   - import threading
   - from config import NETWORK_INTERFACE, PACKET_BATCH_SIZE
   - from packet_capture.parser import parse_packet
   - from database.db_handler import save_packet

2. NetworkMonitor class:
   
   __init__(self, interface=None, packet_queue=None)
   - Set the network interface (use config default if None)
   - Create a Queue for buffering captured packets
   - Initialize running flag to False
   
   start(self)
   - Set running flag to True
   - Start the packet capture in a background thread
   - Start the packet processor in another background thread
   - Log that monitoring has started
   
   stop(self)
   - Set running flag to False
   - Wait for threads to finish
   - Log that monitoring has stopped
   
   _capture_packets(self)
   - The main capture loop
   - Uses scapy.sniff() with a callback function
   - The callback puts each packet in the queue
   - Runs until running flag is False
   
   _packet_callback(self, packet)
   - Called by Scapy for each captured packet
   - Parse the packet using parser.parse_packet()
   - Put the parsed data in the queue
   
   _process_packets(self)
   - The processor loop running in a background thread
   - Reads packets from the queue
   - Calls save_packet() from database module
   - Handles queue empty gracefully

3. Error handling:
   - Catch PermissionError and log helpful message about admin rights
   - Catch interface not found errors
   - Handle keyboard interrupt for graceful shutdown

EXAMPLE FUNCTION SIGNATURES:
----------------------------
class NetworkMonitor:
    def __init__(self, interface: str = None):
        self.interface = interface or NETWORK_INTERFACE
        self.packet_queue = Queue()
        self.running = False
        self.capture_thread = None
        self.processor_thread = None
    
    def start(self):
        '''Start packet capture and processing threads'''
        pass
    
    def stop(self):
        '''Stop packet capture gracefully'''
        pass
    
    def _capture_packets(self):
        '''Main capture loop using Scapy sniff'''
        pass
    
    def _packet_callback(self, packet):
        '''Callback for each captured packet'''
        pass
    
    def _process_packets(self):
        '''Process packets from queue and save to database'''
        pass
"""

import time
from scapy.all import sniff, IP, TCP, UDP, Ether
from queue import Queue, Empty
import threading
from config import NETWORK_INTERFACE, PACKET_BATCH_SIZE
from packet_capture.parser import parse_packet
from database.db_handler import save_packet

class NetworkMonitor:
    def __init__(self, interface: str = None, packet_queue: Queue = None):
        self.interface = interface or NETWORK_INTERFACE
        self.packet_queue = packet_queue or Queue()
        self.running = False
        self.capture_thread = None
        self.processor_thread = None

    def _packet_callback(self, packet):
        '''Callback for each captured packet - queues packet for processing'''
        if not self.running:
            return
        try:
            parsed = parse_packet(packet)
        except Exception as e:
            print(f"Error parsing packet: {e}")
            parsed = None
        # Queue raw and parsed packet for real-time processing
        self.packet_queue.put((packet, parsed))

    def _capture_packets(self):
        '''Main capture loop using Scapy sniff - runs continuously until stopped'''
        print(f"Starting packet capture on interface: {self.interface}")
        try:
            while self.running:
                # Capture packets with 1-second timeout for responsiveness
                sniff(
                    iface=self.interface,
                    prn=self._packet_callback,
                    store=False,
                    timeout=1
                )
        except PermissionError:
            print("Permission denied: Please run as administrator/root.")
            self.running = False
        except OSError as e:
            print(f"Error with interface {self.interface}: {e}")
            self.running = False
        except Exception as e:
            print(f"Unexpected error during packet capture: {e}")
            self.running = False
        
    def _process_packets(self):
        '''Process packets from queue and save to database in real-time'''
        while self.running or not self.packet_queue.empty():
            try:
                packet, parsed = self.packet_queue.get(timeout=1)
            except Empty:
                continue
            
            try:
                # Save parsed packet data to database
                if parsed:
                    save_packet(parsed)
                elif packet is not None and packet.haslayer(IP):
                    # Fallback: create minimal packet record if parsing failed
                    save_packet({"src": packet[IP].src, "dst": packet[IP].dst})
            except Exception as e:
                print(f"Error saving packet to database: {e}")
            finally:
                # Mark task as done for proper queue processing
                self.packet_queue.task_done()

    def start(self):
        '''Start packet capture and processing threads for real-time monitoring'''
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_packets, name="cap-thread", daemon=True)
        self.processor_thread = threading.Thread(target=self._process_packets, name="proc-thread", daemon=True)
        self.capture_thread.start()
        self.processor_thread.start()
        print("Packet capture started.")

    def stop(self, join_timeout: float = 2.0):
        '''Stop packet capture gracefully and wait for threads to finish'''
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=join_timeout)
        if self.processor_thread:
            self.processor_thread.join(timeout=join_timeout)
        print("Packet capture stopped.")

if __name__ == "__main__":
    monitor = NetworkMonitor()
    try:
        monitor.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping packet capture...")
        monitor.stop()