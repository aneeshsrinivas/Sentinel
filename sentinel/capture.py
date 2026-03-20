"""
SENTINEL Live Capture Module

Wraps scapy AsyncSniffer to produce 5-second flow batches.
Requires: Linux, root/CAP_NET_RAW, scapy installed.

Reference: Section 5.4 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

import threading
import time
from collections import defaultdict
from typing import List, Dict


SYN_FLAG = 0x02
ACK_FLAG = 0x10
FIN_FLAG = 0x01
RST_FLAG = 0x04
PUSH_FLAG = 0x08


class LiveCapture:
    """
    Live packet capture producing 5-second flow batches.

    Requires scapy and root/CAP_NET_RAW capability.
    Falls back gracefully if scapy unavailable.
    """

    def __init__(self, interface: str = "eth0", ports: List[int] = None):
        if ports is None:
            ports = [80, 443]
        self._interface = interface
        self._ports = ports
        self._flow_table = {}
        self._batch = []
        self._lock = threading.Lock()
        self._batch_start_time = None
        self._sniffer = None
        self._check_dependencies()

    def _check_dependencies(self):
        try:
            import scapy.all  # noqa: F401
        except ImportError:
            raise ImportError(
                "Live capture requires scapy: pip install scapy\n"
                "Also requires root or CAP_NET_RAW capability."
            )

    def _process_packet(self, pkt):
        """Called by scapy for each captured packet. Updates flow table."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            return

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto_num = ip.proto

        sport = 0
        dport = 0
        tcp_flags = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            tcp_flags = int(tcp.flags)

        pkt_time = float(pkt.time)
        pkt_len = len(pkt)
        proto_str = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "OTHER")

        key = (src_ip, sport, dst_ip, dport, proto_num)

        with self._lock:
            if key not in self._flow_table:
                self._flow_table[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sport": sport,
                    "dport": dport,
                    "proto": proto_str,
                    "start_time": pkt_time,
                    "last_time": pkt_time,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "packets": 0,
                    "handshake_complete": False,
                    "request_count": 0,
                    "protocol_violation": False,
                    "user_agent": "live",
                    "country_code": "UNKNOWN",
                    "response_status": 0,
                    "_syn_seen": False,
                    "_synack_seen": False,
                    "_batch_time": pkt_time,
                }

            rec = self._flow_table[key]
            rec["bytes_sent"] += pkt_len
            rec["packets"] += 1
            rec["last_time"] = max(rec["last_time"], pkt_time)

            # TCP handshake state machine
            if proto_num == 6 and pkt.haslayer(TCP):
                f = tcp_flags
                is_syn = bool(f & SYN_FLAG) and not bool(f & ACK_FLAG)
                is_synack = bool(f & SYN_FLAG) and bool(f & ACK_FLAG)
                is_ack = bool(f & ACK_FLAG) and not bool(f & SYN_FLAG)
                is_fin = bool(f & FIN_FLAG)
                is_rst = bool(f & RST_FLAG)

                if is_syn:
                    rec["_syn_seen"] = True
                if is_synack:
                    rec["_synack_seen"] = True
                if is_ack and rec["_syn_seen"] and rec["_synack_seen"]:
                    rec["handshake_complete"] = True

                # Protocol violations: SYN+FIN, SYN+RST
                if (f & SYN_FLAG) and (f & FIN_FLAG):
                    rec["protocol_violation"] = True
                if (f & SYN_FLAG) and (f & RST_FLAG):
                    rec["protocol_violation"] = True
                if is_fin and not rec["handshake_complete"]:
                    rec["protocol_violation"] = True

            if self._batch_start_time is None:
                self._batch_start_time = pkt_time

            # Move completed/inactive flows to batch after 5 seconds
            if pkt_time - self._batch_start_time >= 5.0:
                self._flush_batch(pkt_time)

    def _flush_batch(self, current_time: float):
        """Move active flows to batch and clean up old flows."""
        new_batch = []
        to_delete = []
        for key, rec in self._flow_table.items():
            if current_time - rec["last_time"] > 1.0 or current_time - rec["_batch_time"] >= 5.0:
                new_batch.append(self._clean_record(rec))
                rec["_batch_time"] = current_time
            if current_time - rec["last_time"] > 60.0:
                to_delete.append(key)

        self._batch.extend(new_batch)
        for k in to_delete:
            del self._flow_table[k]
        self._batch_start_time = current_time

    def _clean_record(self, rec: dict) -> dict:
        """Convert internal record to clean 16-key flow dict."""
        req_count = max(1, rec.get("packets", 1) // 3)
        return {
            "src_ip": rec.get("src_ip", "0.0.0.0"),
            "dst_ip": rec.get("dst_ip", "0.0.0.0"),
            "sport": rec.get("sport", 0),
            "dport": rec.get("dport", 80),
            "proto": rec.get("proto", "TCP"),
            "start_time": rec.get("start_time", 0.0),
            "last_time": rec.get("last_time", 0.0),
            "bytes_sent": rec.get("bytes_sent", 0),
            "bytes_recv": rec.get("bytes_recv", 0),
            "packets": rec.get("packets", 1),
            "handshake_complete": rec.get("handshake_complete", True),
            "request_count": req_count,
            "protocol_violation": rec.get("protocol_violation", False),
            "user_agent": rec.get("user_agent", "live"),
            "country_code": rec.get("country_code", "UNKNOWN"),
            "response_status": rec.get("response_status", 0),
        }

    def get_batch(self) -> List[Dict]:
        """Return and clear current 5-second batch of flow dicts."""
        with self._lock:
            batch = list(self._batch)
            self._batch.clear()
            # Also flush any active flows
            if self._flow_table:
                for key, rec in list(self._flow_table.items()):
                    batch.append(self._clean_record(rec))
            return batch

    def start(self):
        """Start async packet capture."""
        from scapy.all import AsyncSniffer
        port_filter = " or ".join(f"port {p}" for p in self._ports)
        bpf = f"tcp and ({port_filter})" if port_filter else "tcp"
        self._sniffer = AsyncSniffer(
            iface=self._interface,
            filter=bpf,
            prn=self._process_packet,
            store=False,
        )
        self._sniffer.start()
        time.sleep(0.5)  # Give sniffer time to start

    def stop(self):
        """Stop packet capture."""
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
