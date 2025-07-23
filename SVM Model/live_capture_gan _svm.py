from scapy.all import sniff, rdpcap
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import pandas as pd
import joblib
import os
import time
from datetime import datetime
from tensorflow.keras.models import load_model  # type: ignore
import numpy as np
import matplotlib.pyplot as plt  # type: ignore
import seaborn as sns  # type: ignore
from collections import defaultdict

# Constants and thresholds
FLOOD_THRESHOLD = 100
WINDOW_SECONDS = 5
FLOOD_THRESHOLDS = {
    6: 100,   # TCP
    17: 100,  # UDP
    1: 50,    # ICMP
    0: 2000   # Ethernet or ARP
}

# Global variables
packet_rate_tracker = defaultdict(list)
dst_proto_tracker = defaultdict(list)
log_data = []

# Load One-Class SVM model and scaler
def load_model_ocsvm():
    if os.path.exists("model/model1.pkl") and os.path.exists("model/scaler1.pkl"):
        print("📦 Loading One-Class SVM model and scaler...")
        model = joblib.load("model/model1.pkl")
        scaler = joblib.load("model/scaler1.pkl")
        return model, scaler
    else:
        print("🚨 One-Class SVM model or scaler not found.")
        exit()

model_ocsvm, scaler_ocsvm = load_model_ocsvm()

# Load GAN discriminator
def load_gan_discriminator():
    path = "model/gan_discriminator.h5"
    if os.path.exists(path):
        print("📦 Loading GAN discriminator (Keras)...")
        return load_model(path)
    else:
        print("🚨 GAN discriminator model not found.")
        exit()

gan_discriminator = load_gan_discriminator()

# Extract features from packet
def extract_features(packet):
    try:
        length = len(packet)
        proto = packet.proto if hasattr(packet, 'proto') else 0
        src = packet[0].src if hasattr(packet[0], 'src') else 'N/A'
        dst = packet[0].dst if hasattr(packet[0], 'dst') else 'N/A'
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return [length, proto, src, dst, timestamp]
    except:
        return None

# Signature-based check for benign packets
def is_benign_signature(proto, length):
    if proto == 6 and 40 <= length <= 74:
        return True
    elif proto == 17 and 60 <= length <= 100:
        return True
    elif proto == 1 and 64 <= length < 85:
        return True
    elif proto == 0 and 60 <= length <= 1500:
        return True
    elif proto == 2 and 8 <= length <= 64:
        return True
    return False

# Flood detection logic
def detect_flooding_by_dst(dst, proto):
    now = time.time()
    key = (dst, proto)
    dst_proto_tracker[key].append(now)
    dst_proto_tracker[key] = [t for t in dst_proto_tracker[key] if now - t <= WINDOW_SECONDS]
    threshold = FLOOD_THRESHOLDS.get(proto, FLOOD_THRESHOLD)
    return len(dst_proto_tracker[key]) > threshold

# Attack type and mitigation strategy
def identify_attack_type_and_mitigation(packet_info):
    proto = packet_info['protocol']
    length = packet_info['length']
    if proto == 1 and length > 1000:
        return "ICMP Flood", "Block ICMP or limit rate"
    elif proto == 2 and length > 1000:
        return "IGMP Flood", "Enable IGMP snooping, rate-limit IGMP traffic"
    elif proto == 6 and length < 100:
        return "TCP SYN Flood", "Enable SYN cookies or limit connections"
    elif proto == 17 and length > 1200:
        return "UDP Flood", "Limit UDP traffic or block unused ports"
    elif proto == 0 and length > 1500:
        return "Jumbo ethernet packets", "Check device level config"
    elif proto == 2 and length > 48:
        return "IGMP Anomaly", "Inspect for malformed multicast packets"
    elif proto == 6:
        return "TCP Anomaly", "Inspect TCP flows"
    elif proto == 17:
        return "UDP Anomaly", "Monitor UDP sources"
    elif proto == 1:
        return "ICMP Anomaly", "Check ICMP traffic volume"
    elif proto == 2:
        return "IGMP Anomaly", "Check multicast group subscriptions"
    else:
        return "Unknown Protocol", "Inspect protocol or block if unneeded"

# Main packet processing function
def process_packet(packet):
    features = extract_features(packet)
    if not features:
        return

    length, proto, src, dst, timestamp = features
    df = pd.DataFrame([[length, proto]], columns=["length", "proto"])

    classification = 'Benign'
    gan_score = None
    attack_type, mitigation = "None", "N/A"

    if detect_flooding_by_dst(dst, proto):
        classification = 'Malicious'
        attack_type, mitigation = identify_attack_type_and_mitigation({"protocol": proto, "length": length})
    elif is_benign_signature(proto, length):
        classification = 'Benign'
    else:
        scaled_df = scaler_ocsvm.transform(df)
        iso_pred = model_ocsvm.predict(scaled_df)[0]
        if iso_pred == -1:
            x = np.array([[length, proto, 0]], dtype=np.float32)
            x_norm = (x - x.mean(axis=1, keepdims=True)) / (x.std(axis=1, keepdims=True) + 1e-6)
            gan_output = gan_discriminator.predict(x_norm, verbose=0)[0][0]
            gan_score = round(float(gan_output), 4)
            if gan_output < 0.49:
                classification = 'Malicious'
                attack_type, mitigation = identify_attack_type_and_mitigation({"protocol": proto, "length": length})

    emoji = "🛡️" if classification == "Benign" else "☠️"
    print(f"{emoji} [{classification}] {features}")
    if classification == "Malicious":
        print(f"   🚨 Attack Type: {attack_type}")
        print(f"   🛠️ Mitigation: {mitigation}")

    log_data.append({
        "length": length,
        "protocol": proto,
        "src": src,
        "dst": dst,
        "timestamp": timestamp,
        "classification": classification,
        "gan_score": gan_score,
        "attack_type": attack_type,
        "mitigation": mitigation
    })

# Compute safety score
def compute_safety_score(df):
    if df.empty:
        return 0.0
    malicious_ratio = (df["classification"] == "Malicious").mean()
    uncommon_proto_ratio = (df["protocol"] > 132).mean()
    impact = malicious_ratio * 10
    exposure = uncommon_proto_ratio * 10
    risk_score = impact + (0.5 * exposure)
    return round(max(0, 100 - risk_score * 10), 2)

# --- Start capture ---
print("🔍 Select capture method:")
print("1️⃣  Live Capture")
print("2️⃣  Read from PCAP file")
choice = input("Enter choice (1 or 2): ").strip()

if choice == "1":
    try:
        duration = int(input("⏳ Enter capture duration (seconds): "))
        iface = "Wi-Fi"
        print(f"📡 Capturing for {duration}s on '{iface}'...\n")
        sniff(prn=process_packet, store=False, timeout=duration, iface=iface)
    except ValueError:
        print("❌ Invalid input.")
        exit()
elif choice == "2":
    path = input("📁 Enter .pcap file path: ").strip()
    if not os.path.exists(path):
        print("❌ File not found.")
        exit()
    packets = rdpcap(path)
    for packet in packets:
        process_packet(packet)
else:
    print("❌ Invalid choice.")
    exit()

# --- Save logs and show summary ---
df = pd.DataFrame(log_data)
if not df.empty:
    os.makedirs("logs", exist_ok=True)
    fname = f"logs/capture_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(fname, index=False)
    print(f"\n📁 Log saved to {fname}")

    print("\n📊 Summary:")
    print(f"Total Packets: {len(df)}")
    print(f"🛡️ Benign: {(df['classification'] == 'Benign').sum()}")
    print(f"☠️ Malicious: {(df['classification'] == 'Malicious').sum()}")

    print(f"\n🧠 Safety Score: {compute_safety_score(df)}%")

    if 'attack_type' in df.columns:
        print("\n📌 Attack Types:")
        for attack, count in df[df['classification'] == 'Malicious']['attack_type'].value_counts().items():
            print(f"🔸 {attack}: {count} packet(s)")

    # Visualization
    plt.figure(figsize=(10, 6))
    sns.histplot(df['length'], bins=30, kde=True, color='skyblue')
    plt.title('Packet Length Distribution')
    plt.xlabel('Length')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 6))
    sns.countplot(x='protocol', data=df, palette='viridis')
    plt.title('Protocol Distribution')
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(6, 6))
    sns.countplot(x='classification', data=df, palette={'Malicious': 'red', 'Benign': 'green'})
    plt.title('Traffic Classification')
    plt.tight_layout()
    plt.show()

else:
    print("❌ No packets processed.")

input("\n✅ Press Enter to exit.")
