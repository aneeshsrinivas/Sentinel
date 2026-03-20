"""
SENTINEL Data Ingestion Module

Converts external traffic data (CIC-DDoS2019 CSV, PCAP, JSON) into the
16-key flow dict format that FeatureExtractor understands.

Reference: Section 5.1 in "SENTINEL: A Behavioral DDoS Detection Framework"
"""

import json
import sys
import os
from collections import defaultdict
from typing import Dict, List, Iterator, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.config import OBSERVATION_INTERVAL


REQUIRED_FLOW_KEYS = [
    "src_ip", "dst_ip", "sport", "dport", "proto",
    "start_time", "last_time", "bytes_sent", "bytes_recv",
    "packets", "handshake_complete", "request_count",
    "protocol_violation", "user_agent", "country_code", "response_status",
]

FLOW_DEFAULTS = {
    "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0",
    "sport": 0, "dport": 80, "proto": "TCP",
    "start_time": 0.0, "last_time": 0.0,
    "bytes_sent": 0, "bytes_recv": 0, "packets": 1,
    "handshake_complete": True, "request_count": 1,
    "protocol_violation": False, "user_agent": "unknown",
    "country_code": "UNKNOWN", "response_status": 200,
}

CIC_COLUMN_MAP = {
    "Source IP": "src_ip",
    "Destination IP": "dst_ip",
    "Source Port": "sport",
    "Destination Port": "dport",
    "Protocol": "proto",
    "Timestamp": "start_time",
    "Flow Duration": "flow_duration_us",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "bytes_sent",
    "Total Length of Bwd Packets": "bytes_recv",
    "Flow Packets/s": "packet_rate",
    "Flow Bytes/s": "byte_rate",
    "Label": "label",
}


def ip_to_country(ip: str) -> str:
    """Simple IP-to-country mapping based on first octet ranges."""
    try:
        first = int(str(ip).split(".")[0])
        if first in range(1, 10): return "US"
        if first in range(10, 50): return "CN"
        if first in range(50, 100): return "EU"
        if first in range(100, 150): return "RU"
        if first in range(150, 200): return "IN"
        return "OTHER"
    except Exception:
        return "OTHER"


def _proto_to_str(p) -> str:
    """Map numeric protocol to string."""
    try:
        pn = int(p)
        if pn == 6: return "TCP"
        if pn == 17: return "UDP"
    except (ValueError, TypeError):
        pass
    return "OTHER"


def _parse_cic_timestamp(ts) -> float:
    """Parse CIC-DDoS2019 timestamp to float."""
    from datetime import datetime
    s = str(ts).strip()
    # Try format: dd/mm/yyyy HH:MM:SS
    for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.timestamp()
        except ValueError:
            continue
    # Fallback: try unix float
    try:
        return float(s)
    except ValueError:
        return 0.0


def validate_and_fill(flow: dict) -> dict:
    """Ensure all 16 required keys exist, fill missing with defaults."""
    return {k: flow.get(k, FLOW_DEFAULTS[k]) for k in REQUIRED_FLOW_KEYS}


def _group_into_windows(flows: list, interval: float = None) -> List[List[dict]]:
    """Group a flat list of flows into interval-sized windows by start_time."""
    if interval is None:
        interval = float(OBSERVATION_INTERVAL)
    if not flows:
        return []
    windows = defaultdict(list)
    for f in flows:
        ts = float(f.get("start_time", 0))
        window_id = int(ts // interval)
        windows[window_id].append(f)
    result = []
    for wid in sorted(windows.keys()):
        if windows[wid]:
            result.append(windows[wid])
    return result


def load_cic_ddos2019(csv_path: str, chunk_size: int = 1000) -> Iterator[list]:
    """
    Load CIC-DDoS2019 CSV file and yield 5-second flow windows.

    Args:
        csv_path: Path to CIC-DDoS2019 CSV file.
        chunk_size: Number of rows to read per chunk.

    Yields:
        Each window as a list of flow dicts with 16 required keys.
    """
    import pandas as pd

    dt = float(OBSERVATION_INTERVAL)
    row_count = 0
    window_buffer = defaultdict(list)
    window_counter = 0
    min_window_id = None

    for chunk in pd.read_csv(csv_path, chunksize=chunk_size, low_memory=False):
        # Rename columns using CIC column map
        existing = {c: CIC_COLUMN_MAP[c] for c in CIC_COLUMN_MAP if c in chunk.columns}
        df = chunk.rename(columns=existing)

        for _, row in df.iterrows():
            row_count += 1
            if row_count % 10000 == 0:
                print(f"  [ingest] Processed {row_count} rows...", flush=True)

            # Parse timestamp
            raw_ts = row.get("start_time", row.get("Timestamp", 0))
            start_time = _parse_cic_timestamp(raw_ts)

            # Parse protocol
            raw_proto = row.get("proto", row.get("Protocol", 6))
            proto = _proto_to_str(raw_proto)

            # Numeric fields with safe conversion
            flow_dur = _safe_float(row.get("flow_duration_us", 0))
            fwd_pkts = _safe_int(row.get("fwd_packets", row.get("Total Fwd Packets", 1)))
            bwd_pkts = _safe_int(row.get("bwd_packets", row.get("Total Backward Packets", 0)))
            bytes_sent = _safe_int(row.get("bytes_sent", row.get("Total Length of Fwd Packets", 0)))
            bytes_recv = _safe_int(row.get("bytes_recv", row.get("Total Length of Bwd Packets", 0)))
            pkt_rate = _safe_float(row.get("packet_rate", row.get("Flow Packets/s", 0)))

            src_ip = str(row.get("src_ip", row.get("Source IP", "0.0.0.0")))
            dst_ip = str(row.get("dst_ip", row.get("Destination IP", "0.0.0.0")))
            sport = _safe_int(row.get("sport", row.get("Source Port", 0)))
            dport = _safe_int(row.get("dport", row.get("Destination Port", 80)))

            label = str(row.get("label", row.get("Label", "BENIGN"))).strip().upper()

            # Derive fields
            last_time = start_time + max(flow_dur / 1e6, 0.0)
            packets = max(fwd_pkts + bwd_pkts, 1)
            handshake_complete = (proto == "TCP" and pkt_rate > 0 and bytes_recv > 0)
            request_count = max(1, int(fwd_pkts / 3))
            country_code = ip_to_country(src_ip)
            response_status = 200 if label == "BENIGN" else 0

            flow = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "sport": int(sport),
                "dport": int(dport),
                "proto": proto,
                "start_time": float(start_time),
                "last_time": float(last_time),
                "bytes_sent": int(max(bytes_sent, 0)),
                "bytes_recv": int(max(bytes_recv, 0)),
                "packets": int(max(packets, 1)),
                "handshake_complete": bool(handshake_complete),
                "request_count": int(max(request_count, 1)),
                "protocol_violation": False,
                "user_agent": "unknown",
                "country_code": country_code,
                "response_status": int(response_status),
            }

            # Assign to window by start_time
            if min_window_id is None:
                min_window_id = int(start_time // dt)
            window_id = int(start_time // dt)
            window_buffer[window_id].append(flow)

            # Yield completed windows (that have closed)
            while window_counter < window_id:
                if window_buffer.get(window_counter):
                    yield window_buffer.pop(window_counter)
                else:
                    window_buffer.pop(window_counter, None)
                window_counter += 1

    # Flush remaining windows
    for wid in sorted(window_buffer.keys()):
        if window_buffer[wid]:
            yield window_buffer[wid]


def _safe_float(v) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0


def _safe_int(v) -> int:
    try:
        return int(float(v))
    except (ValueError, TypeError):
        return 0


def load_pcap(pcap_path: str) -> Iterator[list]:
    """
    Load a PCAP file and yield 5-second flow windows.

    Uses scapy for packet parsing. Requires scapy to be installed.
    """
    try:
        from scapy.all import PcapReader, IP, TCP
    except ImportError:
        raise ImportError("Install scapy: pip install scapy")

    dt = float(OBSERVATION_INTERVAL)
    flow_table = {}
    last_flush_time = None
    current_batch_start = None

    for pkt in PcapReader(pcap_path):
        if not pkt.haslayer(IP):
            continue
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        sport = 0
        dport = 0
        flags = 0

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            sport = tcp_layer.sport
            dport = tcp_layer.dport
            flags = tcp_layer.flags

        pkt_time = float(pkt.time)
        pkt_len = len(pkt)

        # 5-tuple key (with direction normalization not done - keep as-is)
        key = (src_ip, sport, dst_ip, dport, proto)

        if key not in flow_table:
            flow_table[key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "sport": sport,
                "dport": dport,
                "proto": _proto_to_str(proto),
                "start_time": pkt_time,
                "last_time": pkt_time,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets": 0,
                "handshake_complete": False,
                "request_count": 0,
                "protocol_violation": False,
                "user_agent": "pcap",
                "country_code": "UNKNOWN",
                "response_status": 0,
                "_syn_seen": False,
                "_synack_seen": False,
                "_flags_seen": set(),
            }

        rec = flow_table[key]
        rec["bytes_sent"] += pkt_len
        rec["packets"] += 1
        rec["last_time"] = max(rec["last_time"], pkt_time)

        # TCP flag parsing for handshake detection
        if pkt.haslayer(TCP):
            f = int(flags)
            rec["_flags_seen"].add(f)
            # SYN=0x02, SYN-ACK=0x12, ACK=0x10, FIN=0x01, RST=0x04
            if f & 0x02 and not (f & 0x10):
                rec["_syn_seen"] = True
            if f & 0x02 and f & 0x10:
                rec["_synack_seen"] = True
            if f & 0x10 and rec["_syn_seen"] and rec["_synack_seen"]:
                rec["handshake_complete"] = True
            if f & 0x10 and not (f & 0x02) and not rec["handshake_complete"]:
                # Plain ACK without prior SYN — might still be valid
                pass
            # Protocol violations: SYN+FIN, SYN+RST
            if (f & 0x02) and (f & 0x01):
                rec["protocol_violation"] = True
            if (f & 0x02) and (f & 0x04):
                rec["protocol_violation"] = True

        if last_flush_time is None:
            last_flush_time = pkt_time
            current_batch_start = pkt_time

        # Flush expired flows and yield 5-second windows
        if pkt_time - current_batch_start >= dt:
            window = _extract_window(flow_table, current_batch_start, pkt_time)
            if window:
                yield window
            # Remove very old flows
            _expire_flows(flow_table, pkt_time - 60.0)
            current_batch_start = pkt_time

    # Flush remaining
    if flow_table:
        final_window = []
        for key, rec in list(flow_table.items()):
            final_window.append(_clean_flow_record(rec))
        if final_window:
            yield final_window


def _extract_window(flow_table: dict, start: float, end: float) -> list:
    """Extract flows that were active during [start, end) and yield as clean dicts."""
    window = []
    for key, rec in flow_table.items():
        if rec["start_time"] < end and rec["last_time"] >= start:
            window.append(_clean_flow_record(rec))
    return window


def _clean_flow_record(rec: dict) -> dict:
    """Convert internal flow record to clean 16-key dict."""
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
        "user_agent": rec.get("user_agent", "pcap"),
        "country_code": rec.get("country_code", "UNKNOWN"),
        "response_status": rec.get("response_status", 0),
    }


def _expire_flows(flow_table: dict, cutoff: float):
    """Remove flows with last_time before cutoff."""
    to_delete = [k for k, v in flow_table.items() if v["last_time"] < cutoff]
    for k in to_delete:
        del flow_table[k]


def load_json_flows(json_path: str) -> Iterator[list]:
    """
    Load a JSON file containing a list of flow dicts and yield 5-second windows.
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    if isinstance(data, list):
        flows = [validate_and_fill(flow) for flow in data]
    elif isinstance(data, dict) and "flows" in data:
        flows = [validate_and_fill(flow) for flow in data["flows"]]
    else:
        raise ValueError("JSON must contain a list of flow dicts or a dict with 'flows' key")

    dt = float(OBSERVATION_INTERVAL)
    windows = defaultdict(list)
    for f in flows:
        ts = float(f.get("start_time", 0))
        window_id = int(ts // dt)
        windows[window_id].append(f)

    for wid in sorted(windows.keys()):
        if windows[wid]:
            yield windows[wid]
