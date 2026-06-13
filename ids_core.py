"""
ids_core.py
-----------
Network Intrusion Detection System - Core Detection Engine

Captures live traffic with Scapy and applies signature/threshold based
heuristics to flag suspicious activity:
    - Port scan detection      (many distinct ports from one source IP)
    - SYN flood detection       (high rate of TCP SYN packets)
    - ICMP flood detection      (ping flood)

Each detection is persisted as an alert via DBHandler so it can be
surfaced on the live dashboard (Flask + dashboard.html).

Author : Rithika U
Project: IDS - Intrusion Detection System
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

from db_handler import DBHandler


class IDSEngine:
    """Core packet-capture and threat-detection engine."""

    # ---- detection tuning (override via constructor if required) -------
    PORT_SCAN_THRESHOLD = 5      # distinct dest ports from one src IP
    PORT_SCAN_WINDOW = 5         # ...within this many seconds

    SYN_FLOOD_THRESHOLD = 15     # SYN packets from one src IP
    SYN_FLOOD_WINDOW = 5         # ...within this many seconds

    ICMP_FLOOD_THRESHOLD = 5     # ICMP echo packets from one src IP
    ICMP_FLOOD_WINDOW = 5        # ...within this many seconds

    def __init__(self, interface=None, db_path="alerts.db"):
        """
        :param interface: network interface to sniff on (None = default)
        :param db_path:   path to the SQLite alert database
        """
        self.interface = interface
        self.db = DBHandler(db_path)

        self.running = False
        self._sniff_thread = None
        self._lock = threading.Lock()

        # rolling time-windows keyed by source IP
        self._port_scan_tracker = defaultdict(deque)
        self._syn_tracker = defaultdict(deque)
        self._icmp_tracker = defaultdict(deque)

        self._stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "alerts_generated": 0,
            "start_time": None,
            "last_error": None,
        }

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self):
        """Start the sniffer in a background thread. Returns False if
        already running."""
        if self.running:
            return False

        self.running = True
        with self._lock:
            self._stats["start_time"] = datetime.now().isoformat()
            self._stats["last_error"] = None

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._sniff_thread.start()
        return True

    def stop(self):
        """Signal the sniffer loop to stop. The underlying scapy sniff()
        call exits on the next captured packet (stop_filter)."""
        self.running = False
        return True

    def _sniff_loop(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _pkt: not self.running,
            )
        except PermissionError:
            self._fatal_error(
                "Permission denied. Run with sudo / admin privileges "
                "to capture packets."
            )
        except Exception as exc:  # noqa: BLE001 - surface any sniff error
            self._fatal_error(f"Sniffer error: {exc}")
        finally:
            self.running = False

    def _fatal_error(self, message):
        with self._lock:
            self._stats["last_error"] = message
        self.db.insert_alert(
            "ENGINE_ERROR", "local", "local", message, "critical"
        )

    # ------------------------------------------------------------------
    # packet processing
    # ------------------------------------------------------------------
    def _process_packet(self, packet):
        if not self.running:
            return

        with self._lock:
            self._stats["total_packets"] += 1

        if IP not in packet:
            with self._lock:
                self._stats["other_packets"] += 1
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            with self._lock:
                self._stats["tcp_packets"] += 1
            self._check_port_scan(packet, src_ip, dst_ip)
            self._check_syn_flood(packet, src_ip, dst_ip)

        elif UDP in packet:
            with self._lock:
                self._stats["udp_packets"] += 1

        elif ICMP in packet:
            with self._lock:
                self._stats["icmp_packets"] += 1
            self._check_icmp_flood(packet, src_ip, dst_ip)

        else:
            with self._lock:
                self._stats["other_packets"] += 1

    # ------------------------------------------------------------------
    # detection rules
    # ------------------------------------------------------------------
    def _check_port_scan(self, packet, src_ip, dst_ip):
        now = time.time()
        dport = packet[TCP].dport

        tracker = self._port_scan_tracker[src_ip]
        tracker.append((now, dport))
        self._trim(tracker, now, self.PORT_SCAN_WINDOW)

        distinct_ports = {port for _, port in tracker}
        if len(distinct_ports) >= self.PORT_SCAN_THRESHOLD:
            self._raise_alert(
                "PORT_SCAN", src_ip, dst_ip,
                f"{len(distinct_ports)} distinct destination ports probed "
                f"from {src_ip} within {self.PORT_SCAN_WINDOW}s",
                "high",
            )
            tracker.clear()

    def _check_syn_flood(self, packet, src_ip, dst_ip):
        tcp_layer = packet[TCP]
        if tcp_layer.flags != "S":  # only pure SYN packets
            return

        now = time.time()
        tracker = self._syn_tracker[src_ip]
        tracker.append(now)
        self._trim(tracker, now, self.SYN_FLOOD_WINDOW)

        if len(tracker) >= self.SYN_FLOOD_THRESHOLD:
            self._raise_alert(
                "SYN_FLOOD", src_ip, dst_ip,
                f"{len(tracker)} SYN packets from {src_ip} within "
                f"{self.SYN_FLOOD_WINDOW}s - possible SYN flood / DoS",
                "critical",
            )
            tracker.clear()

    def _check_icmp_flood(self, packet, src_ip, dst_ip):
        now = time.time()
        tracker = self._icmp_tracker[src_ip]
        tracker.append(now)
        self._trim(tracker, now, self.ICMP_FLOOD_WINDOW)

        if len(tracker) >= self.ICMP_FLOOD_THRESHOLD:
            self._raise_alert(
                "ICMP_FLOOD", src_ip, dst_ip,
                f"{len(tracker)} ICMP echo packets from {src_ip} within "
                f"{self.ICMP_FLOOD_WINDOW}s - possible ping flood",
                "medium",
            )
            tracker.clear()

    @staticmethod
    def _trim(tracker, now, window):
        """Drop entries older than `window` seconds from a deque whose
        items are either timestamps or (timestamp, value) tuples."""
        while tracker:
            ts = tracker[0][0] if isinstance(tracker[0], tuple) else tracker[0]
            if now - ts > window:
                tracker.popleft()
            else:
                break

    # ------------------------------------------------------------------
    # alerting / stats
    # ------------------------------------------------------------------
    def _raise_alert(self, alert_type, src_ip, dst_ip, description, severity):
        with self._lock:
            self._stats["alerts_generated"] += 1
        self.db.insert_alert(alert_type, src_ip, dst_ip, description, severity)

    def get_stats(self):
        with self._lock:
            return dict(self._stats)
