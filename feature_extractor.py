"""
feature_extractor.py — Feature Engineering
Layer 2: Packet Capture Layer — converts raw packets into DNN-ready numbers

Think of this like converting a book into a list of key statistics:
instead of reading every word, we extract: word count, paragraph count,
unique words, etc. Similarly, we extract key metrics from network packets.
"""

import numpy as np
from typing import List, Dict


def extract_from_packets(packets: List[Dict]) -> Dict:
    """
    Extract DNN-ready features from a list of raw packet dicts.
    Used when processing real PCAP data from pcap_reader.py.

    Args:
        packets: list of dicts from pcap_reader.read_pcap()

    Returns:
        Feature dict matching dnn_model.FEATURE_NAMES
    """
    if not packets:
        print("[FE] ⚠️  Empty packet list — returning zero features")
        return _zero_features()

    n = len(packets)

    # ── 1. Packet count ───────────────────────────────────────────────────
    packet_count = n

    # ── 2. Unique source IPs ─────────────────────────────────────────────
    src_ips = {p.get("src_ip") for p in packets if p.get("src_ip")}
    unique_src_ips = len(src_ips)

    # ── 3. Port variety (unique destination ports) ────────────────────────
    dst_ports = {p.get("dst_port") for p in packets if p.get("dst_port")}
    port_variety = len(dst_ports)

    # ── 4. Average payload size ───────────────────────────────────────────
    payloads = [p.get("payload_size", 0) for p in packets]
    avg_payload_size = float(np.mean(payloads))

    # ── 5. SYN flag ratio ─────────────────────────────────────────────────
    #  High SYN ratio → possible SYN flood / port scan
    syn_count = sum(1 for p in packets if p.get("flags", {}).get("SYN", False))
    syn_flag_ratio = round(syn_count / n, 4)

    # ── 6. Average TTL ────────────────────────────────────────────────────
    #  Very low TTL (< 20) → possible IP spoofing or traffic from distant botnets
    ttls = [p.get("ttl", 64) for p in packets if p.get("ttl") is not None]
    avg_ttl = float(np.mean(ttls)) if ttls else 64.0

    # ── 7. Packets per second ─────────────────────────────────────────────
    times = sorted(p.get("timestamp", 0) for p in packets if p.get("timestamp"))
    if len(times) >= 2:
        duration = max(times[-1] - times[0], 0.001)
        packets_per_second = round(n / duration, 2)
    else:
        packets_per_second = float(n)

    # ── 8. DNS query ratio ────────────────────────────────────────────────
    #  High DNS ratio → possible DNS tunneling (data hidden in DNS requests)
    dns_count = sum(1 for p in packets if p.get("dst_port") == 53)
    dns_query_ratio = round(dns_count / n, 4)

    # ── 9. Failed auth count ──────────────────────────────────────────────
    #  SSH (22), FTP (21), RDP (3389), LDAP (389) with tiny payloads
    auth_ports = {22, 21, 3389, 389, 636}
    failed_auth_count = sum(
        1 for p in packets
        if p.get("dst_port") in auth_ports and p.get("payload_size", 200) < 80
    )

    # ── 10. Protocol anomaly score ────────────────────────────────────────
    protocol_anomaly = _compute_protocol_anomaly(packets)

    features = {
        "packet_count":      packet_count,
        "unique_src_ips":    unique_src_ips,
        "port_variety":      port_variety,
        "avg_payload_size":  round(avg_payload_size, 2),
        "syn_flag_ratio":    syn_flag_ratio,
        "avg_ttl":           round(avg_ttl, 2),
        "packets_per_second":packets_per_second,
        "dns_query_ratio":   dns_query_ratio,
        "failed_auth_count": failed_auth_count,
        "protocol_anomaly":  round(protocol_anomaly, 4),
    }

    print(f"[FE] ✅ Extracted features: {packet_count} packets, "
          f"{unique_src_ips} src IPs, {port_variety} ports, "
          f"SYN ratio={syn_flag_ratio:.2f}, Anomaly={protocol_anomaly:.2f}")

    return features


def extract_from_simulated(incident: Dict) -> Dict:
    """
    Map a simulated incident to approximate DNN features.
    Used when running in --simulate mode (no real PCAP).

    The mapping is based on the incident severity — higher severity
    produces features that resemble real attack traffic.

    Args:
        incident: dict from detector.detect_simulated_incident()

    Returns:
        Feature dict matching dnn_model.FEATURE_NAMES
    """
    severity = incident.get("severity", "MEDIUM")
    packet_count = incident.get("packet_count", 1000)

    # Severity → typical feature profile
    profiles = {
        "CRITICAL": {
            "unique_src_ips": 500, "port_variety": 200,
            "avg_payload_size": 64,  "syn_flag_ratio": 0.85,
            "avg_ttl": 14,           "dns_query_ratio": 0.70,
            "failed_auth_count": 500, "protocol_anomaly": 0.90,
        },
        "HIGH": {
            "unique_src_ips": 100, "port_variety": 50,
            "avg_payload_size": 128, "syn_flag_ratio": 0.60,
            "avg_ttl": 28,           "dns_query_ratio": 0.40,
            "failed_auth_count": 100, "protocol_anomaly": 0.60,
        },
        "MEDIUM": {
            "unique_src_ips": 20,  "port_variety": 15,
            "avg_payload_size": 256, "syn_flag_ratio": 0.30,
            "avg_ttl": 48,           "dns_query_ratio": 0.20,
            "failed_auth_count": 10,  "protocol_anomaly": 0.30,
        },
        "LOW": {
            "unique_src_ips": 2,   "port_variety": 2,
            "avg_payload_size": 400, "syn_flag_ratio": 0.05,
            "avg_ttl": 64,           "dns_query_ratio": 0.05,
            "failed_auth_count": 0,   "protocol_anomaly": 0.05,
        },
    }

    profile = profiles.get(severity, profiles["MEDIUM"]).copy()

    # Add slight noise for realism
    rng = np.random.default_rng()
    for key in ("unique_src_ips", "failed_auth_count", "port_variety"):
        profile[key] = max(0, int(profile[key] * rng.uniform(0.7, 1.3)))

    profile["packet_count"] = packet_count
    profile["packets_per_second"] = round(
        packet_count / max(rng.uniform(1, 60), 1), 2
    )

    return profile


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _compute_protocol_anomaly(packets: List[Dict]) -> float:
    """
    Estimate a protocol anomaly score 0.0–1.0 from packet behavior.
    A score near 1.0 means the traffic looks suspicious/unusual.
    """
    if not packets:
        return 0.0

    sample = packets[:2000]   # cap at 2000 for speed
    score_sum = 0.0

    for p in sample:
        ttl = p.get("ttl") or 64
        payload = p.get("payload_size", 0)
        dst_port = p.get("dst_port") or 0

        # Very low TTL → suspicious
        if ttl < 20:
            score_sum += 0.5

        # Tiny TTL (< 10) → likely spoofed
        if ttl < 10:
            score_sum += 0.5

        # Oversized payload on normally small-payload services
        if dst_port in {53, 22} and payload > 4000:
            score_sum += 0.3

        # HTTPS payload that is unrealistically tiny (likely SYN flood)
        if dst_port in {443, 8443} and payload < 20:
            score_sum += 0.2

    # Normalize against sample size
    raw_score = score_sum / max(len(sample), 1)
    return min(1.0, raw_score)


def _zero_features() -> Dict:
    """Return all-zero features for empty input"""
    return {
        "packet_count":       0,
        "unique_src_ips":     0,
        "port_variety":       0,
        "avg_payload_size":   0.0,
        "syn_flag_ratio":     0.0,
        "avg_ttl":            64.0,
        "packets_per_second": 0.0,
        "dns_query_ratio":    0.0,
        "failed_auth_count":  0,
        "protocol_anomaly":   0.0,
    }