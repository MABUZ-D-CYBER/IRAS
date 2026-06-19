"""
dnn_model.py — Deep Neural Network Threat Classifier
Layer 3: DNN AI Analysis Layer — inspired by Darktrace Self-Learning AI

Architecture:
  Input (10 features) → Dense(128, relu) → Dense(64, relu) → Dense(32, relu)
                      → Output(3 classes: Normal / Suspicious / Malicious)

The model trains on synthetic data at startup.
In production, replace with real labeled network traffic data.
"""

import warnings
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")   # suppress sklearn convergence notices

# ── Feature names (must match feature_extractor.py output) ──────────────────
FEATURE_NAMES = [
    "packet_count",        # Total packets in the window
    "unique_src_ips",      # Number of distinct source IP addresses
    "port_variety",        # Number of distinct destination ports
    "avg_payload_size",    # Average payload size in bytes
    "syn_flag_ratio",      # Fraction of packets with SYN flag set
    "avg_ttl",             # Average IP Time-To-Live value
    "packets_per_second",  # Traffic rate (volume over time)
    "dns_query_ratio",     # Fraction of packets targeting port 53
    "failed_auth_count",   # Packets on auth ports with tiny payload
    "protocol_anomaly",    # Composite protocol-level anomaly score
]

# ── Output classes ───────────────────────────────────────────────────────────
LABELS = ["Normal", "Suspicious", "Malicious"]


# ═══════════════════════════════════════════════════════════════════════════════
#  SYNTHETIC TRAINING DATA
# ═══════════════════════════════════════════════════════════════════════════════

def _make_training_data():
    """
    Generate labeled synthetic traffic samples.

    Each sample is a feature vector + class label:
      0 = Normal    (legitimate traffic)
      1 = Suspicious (possibly malicious, needs monitoring)
      2 = Malicious  (confirmed attack pattern)

    In a real deployment, replace this with a real dataset such as
    CICIDS 2017/2018, NSL-KDD, or your own network captures.
    """
    rng = np.random.default_rng(seed=42)
    X, y = [], []

    # ── Normal traffic (class 0) — 500 samples ───────────────────────────
    #  Low packet counts, few source IPs, standard TTL, near-zero SYN ratio
    for _ in range(500):
        X.append([
            rng.integers(10, 400),          # packet_count
            rng.integers(1, 8),             # unique_src_ips
            rng.integers(1, 4),             # port_variety
            rng.integers(300, 1500),        # avg_payload_size
            rng.uniform(0.0, 0.08),         # syn_flag_ratio
            rng.integers(60, 128),          # avg_ttl
            rng.uniform(0.5, 40.0),         # packets_per_second
            rng.uniform(0.0, 0.15),         # dns_query_ratio
            0,                              # failed_auth_count
            rng.uniform(0.0, 0.08),         # protocol_anomaly
        ])
        y.append(0)

    # ── Suspicious traffic (class 1) — 300 samples ───────────────────────
    #  Elevated counts, multiple source IPs, unusual ports, moderate SYN
    for _ in range(300):
        X.append([
            rng.integers(400, 6000),        # packet_count
            rng.integers(8, 120),           # unique_src_ips
            rng.integers(5, 60),            # port_variety
            rng.integers(60, 600),          # avg_payload_size
            rng.uniform(0.08, 0.55),        # syn_flag_ratio
            rng.integers(25, 60),           # avg_ttl
            rng.uniform(40.0, 600.0),       # packets_per_second
            rng.uniform(0.15, 0.55),        # dns_query_ratio
            rng.integers(5, 60),            # failed_auth_count
            rng.uniform(0.1, 0.55),         # protocol_anomaly
        ])
        y.append(1)

    # ── Malicious traffic (class 2) — 200 samples ────────────────────────
    #  Very high packet counts, many source IPs, high SYN ratio, very low TTL
    for _ in range(200):
        X.append([
            rng.integers(6000, 200000),     # packet_count
            rng.integers(100, 20000),       # unique_src_ips
            rng.integers(60, 65535),        # port_variety
            rng.integers(40, 200),          # avg_payload_size
            rng.uniform(0.55, 1.0),         # syn_flag_ratio
            rng.integers(1, 25),            # avg_ttl
            rng.uniform(600.0, 20000.0),    # packets_per_second
            rng.uniform(0.55, 1.0),         # dns_query_ratio
            rng.integers(60, 2000),         # failed_auth_count
            rng.uniform(0.55, 1.0),         # protocol_anomaly
        ])
        y.append(2)

    return np.array(X, dtype=float), np.array(y, dtype=int)


# ═══════════════════════════════════════════════════════════════════════════════
#  MODEL BUILD & TRAIN
# ═══════════════════════════════════════════════════════════════════════════════

def _build_model() -> Pipeline:
    """
    Build and train the DNN pipeline.

    Pipeline = StandardScaler (normalise features) + MLPClassifier (neural net)

    Hidden layers: 128 → 64 → 32 neurons  (ReLU activation)
    Solver: Adam (fast, suitable for small-medium datasets)
    """
    print("[DNN] 🧠 Building neural network: 10 inputs → 128→64→32 → 3 outputs")
    X, y = _make_training_data()

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("net", MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            solver="adam",
            max_iter=500,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.15,
            n_iter_no_change=20,
        ))
    ])

    model.fit(X, y)
    acc = model.score(X, y)
    print(f"[DNN] ✅ Model trained — training accuracy: {acc:.1%}")
    print("[DNN]    Classes: 0=Normal  1=Suspicious  2=Malicious")
    return model


# ── Train once at import time ────────────────────────────────────────────────
_MODEL: Pipeline = _build_model()


# ═══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def predict(features: dict) -> dict:
    """
    Classify a feature vector and return a threat assessment.

    Args:
        features: dict with keys matching FEATURE_NAMES
                  (missing keys safely default to 0)

    Returns:
        {
          "label":          "Normal" | "Suspicious" | "Malicious",
          "threat_score":   float  0.0 (safe) → 1.0 (critical),
          "probabilities":  {"Normal": …, "Suspicious": …, "Malicious": …},
          "classification": int  0 | 1 | 2
        }
    """
    vec = np.array([[
        float(features.get("packet_count",       0)),
        float(features.get("unique_src_ips",      1)),
        float(features.get("port_variety",        1)),
        float(features.get("avg_payload_size",  500)),
        float(features.get("syn_flag_ratio",    0.0)),
        float(features.get("avg_ttl",          64.0)),
        float(features.get("packets_per_second",10.0)),
        float(features.get("dns_query_ratio",   0.0)),
        float(features.get("failed_auth_count",   0)),
        float(features.get("protocol_anomaly",  0.0)),
    ]])

    cls  = int(_MODEL.predict(vec)[0])
    prob = _MODEL.predict_proba(vec)[0]

    # Weighted score: Normal→0.0, Suspicious→0.5, Malicious→1.0
    score = float(0.0 * prob[0] + 0.5 * prob[1] + 1.0 * prob[2])

    return {
        "label":          LABELS[cls],
        "threat_score":   round(score, 3),
        "probabilities":  {
            "Normal":     round(float(prob[0]), 3),
            "Suspicious": round(float(prob[1]), 3),
            "Malicious":  round(float(prob[2]), 3),
        },
        "classification": cls,
    }


def predict_from_incident(incident: dict) -> dict:
    """
    Shortcut: directly classify a simulated incident dict.

    Internally calls feature_extractor.extract_from_simulated → predict().

    Args:
        incident: dict from detector.detect_simulated_incident()

    Returns:
        Same structure as predict()
    """
    from feature_extractor import extract_from_simulated
    features = extract_from_simulated(incident)
    return predict(features)