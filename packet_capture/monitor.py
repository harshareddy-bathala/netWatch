from scapy.all import sniff, IP, TCP, UDP, Ether
from queue import Queue, Empty
import threading
import logging
from config import NETWORK_INTERFACE, PACKET_BATCH_SIZE
from packet_capture.parser import parse_packet
from database.db_handler import save_packet


class NetworkMonitor:
    def __init__(self, interface: str = None):
        self.interface = interface or NETWORK_INTERFACE
        self.packet_queue = Queue()
        self.running = False
        self.capture_thread = None
        self.processor_thread = None
        self.stop_event = threading.Event()
        self.logger = logging.getLogger(__name__)

    def start(self):
        '''Start packet capture and processing threads'''
        if self.running:
            self.logger.warning("Monitor is already running")
            return
        
        self.running = True
        self.stop_event.clear()
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.processor_thread = threading.Thread(target=self._process_packets)
        self.capture_thread.daemon = True
        self.processor_thread.daemon = True
        self.capture_thread.start()
        self.processor_thread.start()
        self.logger.info(f"Started monitoring on interface: {self.interface}")

    def stop(self):
        '''Stop packet capture gracefully'''
        if not self.running:
            return
        
        self.running = False
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        if self.processor_thread:
            self.processor_thread.join(timeout=2.0)
        self.logger.info("Monitoring stopped")

    def _capture_packets(self):
        '''Main capture loop using Scapy sniff'''
        def stop_filter(packet):
            return self.stop_event.is_set()

        def packet_callback(packet):
            self._packet_callback(packet)

        try:
            sniff(iface=self.interface, prn=packet_callback, stop_filter=stop_filter, store=0)
        except PermissionError:
            self.logger.error("Permission denied. Run as administrator/root to capture packets.")
        except Exception as e:
            if "no such device" in str(e).lower() or "interface" in str(e).lower():
                self.logger.error(f"Interface '{self.interface}' not found. Check if it exists.")
            else:
                self.logger.error(f"Capture error: {e}")
        finally:
            self.running = False

    def _packet_callback(self, packet):
        '''Callback for each captured packet'''
        try:
            parsed_data = parse_packet(packet)
            self.packet_queue.put(parsed_data)
        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")

    def _process_packets(self):
        '''Process packets from queue and save to database'''
        while self.running or not self.packet_queue.empty():
            try:
                batch = []
                # Collect batch up to PACKET_BATCH_SIZE
                for _ in range(PACKET_BATCH_SIZE):
                    parsed_data = self.packet_queue.get(timeout=1.0)
                    batch.append(parsed_data)
                    self.packet_queue.task_done()
                
                # Save batch to database
                save_packet(batch)  # Assuming save_packet handles list/batch
                self.logger.debug(f"Processed batch of {len(batch)} packets")
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
        self.logger.debug("Packet processor finished")
