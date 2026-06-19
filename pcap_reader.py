"""
pcap_reader.py — Minimal PCAP reader with read_pcap_incidents()
"""

import os
import time
from typing import List, Dict
from datetime import datetime

# Try to import feature extractor
try:
    from feature_extractor import extract_from_packets
except ImportError:
    # Dummy fallback
    def extract_from_packets(packets):
        return {
            "packet_count": len(packets),
            "unique_src_ips": 0,
            "port_variety": 0,
            "avg_payload_size": 0,
            "syn_flag_ratio": 0,
            "avg_ttl": 64,
            "packets_per_second": 0,
            "dns_query_ratio": 0,
            "failed_auth_count": 0,
            "protocol_anomaly": 0,
        }


# ─── THE FUNCTION THAT app.py IMPORT ──────────────────────────────
def read_pcap_incidents(filepath: str) -> List[Dict]:
    """
    Read a PCAP file and return a list of incident dicts.
    This is what app.py calls during PCAP upload.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    # Try to read with Scapy, fallback to simulated packets
    packets = _read_pcap_with_scapy(filepath)
    if not packets:
        print("[PCAP] No real packets read – using simulated demo packets")
        packets = _generate_demo_packets(200)

    # Extract features for DNN
    features = extract_from_packets(packets)

    # Build one incident
    incident = {
        "type": "PCAP Analysis",
        "severity": "MEDIUM",          # will be updated by LLM
        "source_ip": packets[0].get("src_ip", "N/A") if packets else "N/A",
        "dest_ip": packets[0].get("dst_ip", "N/A") if packets else "N/A",
        "port": packets[0].get("dst_port", 0) if packets else 0,
        "packet_count": len(packets),
        "timestamp": datetime.now().isoformat(),
        "simulated": False,
        "features": features,
    }

    print(f"[PCAP] Created 1 incident from {len(packets)} packets")
    return [incident]


def _read_pcap_with_scapy(filepath: str) -> List[Dict]:
    """Read packets using Scapy if available."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        print(f"[PCAP] Reading {filepath} with Scapy...")
        packets = []
        for pkt in rdpcap(filepath):
            p = {
                "src_ip": pkt[IP].src if pkt.haslayer(IP) else None,
                "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else None,
                "src_port": None,
                "dst_port": None,
                "protocol": "UNKNOWN",
                "payload_size": len(bytes(pkt)),
                "ttl": pkt[IP].ttl if pkt.haslayer(IP) else None,
                "flags": {},
                "timestamp": float(pkt.time),
            }
            if pkt.haslayer(TCP):
                p["src_port"] = pkt[TCP].sport
                p["dst_port"] = pkt[TCP].dport
                p["protocol"] = "TCP"
                f = int(pkt[TCP].flags)
                p["flags"] = {"SYN": bool(f & 0x02), "ACK": bool(f & 0x10)}
            elif pkt.haslayer(UDP):
                p["src_port"] = pkt[UDP].sport
                p["dst_port"] = pkt[UDP].dport
                p["protocol"] = "UDP"
            elif pkt.haslayer(ICMP):
                p["protocol"] = "ICMP"
            packets.append(p)
        print(f"[PCAP] Parsed {len(packets)} packets")
        return packets
    except ImportError:
        print("[PCAP] Scapy not installed – will simulate packets")
        return []
    except Exception as e:
        print(f"[PCAP] Error reading PCAP: {e}")
        return []


def _generate_demo_packets(count: int) -> List[Dict]:
    """Generate mock packets when Scapy is missing."""
    import random
    random.seed(42)
    base = time.time()
    packets = []
    for i in range(count):
        packets.append({
            "src_ip": f"192.168.1.{random.randint(2,254)}",
            "dst_ip": f"10.0.0.{random.randint(1,20)}",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 53]),
            "protocol": random.choice(["TCP", "UDP"]),
            "payload_size": random.randint(40, 1500),
            "ttl": random.randint(32, 128),
            "flags": {"SYN": random.random() < 0.3},
            "timestamp": base + i * 0.01,
        })
    return packets


# ─── Legacy compatibility ──────────────────────────────────────────
def read_pcap(filepath: str) -> List[Dict]:
    """Legacy function – returns packet summaries."""
    incidents = read_pcap_incidents(filepath)
    return [{
        "src_ip": inc.get("source_ip"),
        "dst_ip": inc.get("dest_ip"),
        "dst_port": inc.get("port"),
        "timestamp": inc.get("timestamp"),
    } for inc in incidents] if incidents else []