from scapy.all import sniff, rdpcap
from sklearn.ensemble import IsolationForest
import pandas as pd
import joblib
import os
from datetime import datetime
from tensorflow.keras.models import load_model  # type: ignore
import numpy as np
import matplotlib.pyplot as plt  # type: ignore
import seaborn as sns  # type: ignore
from collections import defaultdict
import time

# Global dictionaries to track packet rates
packet_rate_tracker = defaultdict(list)  
FLOOD_THRESHOLD = 100  # packets per src/proto within WINDOW_SECONDS
WINDOW_SECONDS = 5


sns.set(style="darkgrid")

# Load Isolation Forest model
def load_model_if():
    path = "model/model.pkl"
    if os.path.exists(path):
        print("\n Loading Isolation Forest model...")
        return joblib.load(path)
    else:
        print(" Isolation Forest model not found.")
        exit()

# Load GAN Discriminator
def load_gan_discriminator():
    path = "model/gan_discriminator.h5"
    if os.path.exists(path):
        print(" Loading GAN discriminator...")
        return load_model(path)
    else:
        print(" GAN discriminator model not found.")
        exit()

# Identify attack type and mitigation
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

model_if = load_model_if()
gan_discriminator = load_gan_discriminator()
log_data = []

# Feature extraction
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

# Signature-based benign check
def is_benign_signature(proto, length):
   
    if proto == 6 and 40 <= length <= 74:  # TCP
        return True
    elif proto == 17 and 60 <= length <= 100:  # UDP
        return True
    elif proto == 1 and 64 <=length < 85:  # ICMP
        return True
    elif proto == 0 and 60 <= length <=1500: #Ethernet
        return True
    elif proto == 2 and 8<= length <=64: #IGMP
        return True
    
    return False

# For flood detection by destination and protocol
dst_proto_tracker = defaultdict(list)  # key: (dst, proto) => timestamps

FLOOD_THRESHOLDS = {
    6: 100,   # TCP
    17: 100,  # UDP
    1: 50,    # ICMP
    0: 2000   # Ethernet
}

def detect_flooding_by_dst(dst, proto):
    now = time.time()
    key = (dst, proto)
    dst_proto_tracker[key].append(now)

    dst_proto_tracker[key] = [t for t in dst_proto_tracker[key] if now - t <= WINDOW_SECONDS]
    threshold = FLOOD_THRESHOLDS.get(proto, FLOOD_THRESHOLD)
    return len(dst_proto_tracker[key]) > threshold



def process_packet(packet):
    features = extract_features(packet)
    if features:
        length, proto, src, dst, timestamp = features
        df = pd.DataFrame([[length, proto]], columns=["length", "proto"])

        classification = 'Benign'
        gan_score = None
        attack_type, mitigation = "None", "N/A"

        is_flood = detect_flooding_by_dst(dst, proto)
        is_benign = is_benign_signature(proto, length)

        if is_flood:
            classification = 'Malicious'
            attack_type, mitigation = identify_attack_type_and_mitigation({
                "protocol": proto,
                "length": length
            })
        elif is_benign:
            classification = 'Benign'
        else:
            # Proceed with anomaly detection
            iso_pred = model_if.predict(df)[0]
            if iso_pred == -1:
                x = np.array([[length, proto, 0]], dtype=np.float32)
                x_norm = (x - x.mean(axis=1, keepdims=True)) / (x.std(axis=1, keepdims=True) + 1e-6)
                gan_output = gan_discriminator.predict(x_norm, verbose=0)[0][0]
                gan_score = round(float(gan_output), 4)

                if gan_output < 0.49:
                    classification = 'Malicious'
                    attack_type, mitigation = identify_attack_type_and_mitigation({
                        "protocol": proto,
                        "length": length
                    })

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

# Safety Score Calculation
def compute_safety_score(df):
    total = len(df)
    if total == 0:
        return 0.0

   
    malicious_ratio = (df["classification"] == "Malicious").mean()
    uncommon_proto_ratio = (df["protocol"] > 132).mean()  

    
    impact = malicious_ratio * 10
    exposure = uncommon_proto_ratio * 10

    
    risk_score = impact + (0.5 * exposure)
    safety_score = max(0, 100 - risk_score * 10)

    return round(safety_score, 2)


# Select capture method
print(" Select capture method:")
print("1️⃣  Live Capture")
print("2️⃣  Read from PCAP file")

choice = input("Enter choice (1 or 2): ").strip()

if choice == "1":
    try:
        capture_duration = int(input(" Enter capture duration (in seconds): "))
    except ValueError:
        print(" Invalid input. Please enter a number.")
        exit()

    iface = "Wi-Fi"  # Default interface
    print(f"\n Capturing packets for {capture_duration} seconds on interface '{iface}'...\n")
    sniff(prn=process_packet, store=False, timeout=capture_duration, iface=iface)

elif choice == "2":
    pcap_path = input(" Enter path to your .pcap file: ").strip()
    if not os.path.exists(pcap_path):
        print(" PCAP file not found.")
        exit()

    print(f"\n Reading packets from {pcap_path}...\n")
    packets = rdpcap(pcap_path)
    for packet in packets:
        process_packet(packet)
else:
    print(" Invalid choice. Exiting.")
    exit()

# Save logs and show summary
df = pd.DataFrame(log_data)
if not df.empty:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"logs/capture_log_{timestamp}.csv"
    os.makedirs("logs", exist_ok=True)
    df.to_csv(filename, index=False)
    print(f"\n Log saved to {filename}")

    print("\n Summary:")
    print(f"Total Packets: {len(df)}")
    print(f"🛡️ Benign: {(df['classification'] == 'Benign').sum()}")
    print(f"☠️ Malicious: {(df['classification'] == 'Malicious').sum()}")

    safety_score = compute_safety_score(df)
    print(f"\ Safety Score: {safety_score}%")
    if safety_score > 85:
        print(" Network looks safe.")
    elif safety_score > 60:
        print(" Moderate anomalies detected.")
    else:
        print(" High risk! Investigate immediately.")

    if 'attack_type' in df.columns:
        print("\n Attack Types Summary:")
        attack_counts = df[df['classification'] == 'Malicious']['attack_type'].value_counts()
        for attack, count in attack_counts.items():
            print(f"🔸 {attack}: {count} packet(s)")

    # Graphs
    # 1.Packet Length Distribution
    plt.figure(figsize=(10, 6))
    sns.histplot(df['length'], bins=30, kde=True, color='skyblue')
    plt.title('Packet Length Distribution')
    plt.xlabel('Length')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()
    
    # 2. Protocol Distribution
    plt.figure(figsize=(8, 6))
    sns.countplot(x='protocol', data=df, palette='viridis')
    plt.title('Protocol Distribution')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.show()

    # 3. Classfication histogram
    custom_palette = {"Malicious": "darkred", "Benign": "lightgreen"}
    plt.figure(figsize=(6, 6))
    sns.countplot(x='classification', data=df, palette=custom_palette)
    plt.title('Traffic Classification')
    plt.xlabel('Type')
    plt.ylabel('Number of Packets')
    plt.tight_layout()
    plt.show()

    # 4. Mitigation Commands
    detected_threats = {
        "TCP SYN Flood": "netsh advfirewall firewall add rule name=\"Block SYN Flood\" dir=in action=block protocol=TCP",
        "UDP Flood": "netsh advfirewall firewall add rule name=\"Block UDP Flood\" dir=in action=block protocol=UDP",
        "ICMP Flood": "netsh advfirewall firewall add rule name=\"Block ICMP Flood\" dir=in action=block protocol=ICMPV4",
        "TCP Anomaly": "netstat -an | findstr :80 && netsh int tcp show global",
        "UDP Anomaly": "netstat -an | findstr :53 && netsh trace start scenario=netconnection",
        "ICMP Anomaly": "netsh firewall set icmpsetting 8 disable"
    }

   
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor('#f4f4f4')
    ax.axis('off')

    text = "🛡️ **Windows Firewall Command Recommendations** 🛡️\n\n"
    for threat, command in detected_threats.items():
        text += f"🔸 {threat}:\n    `{command}`\n\n"

    plt.text(0.01, 0.9, text, va='top', ha='left', wrap=True, fontsize=12, fontfamily='monospace')
    plt.title("🚨 Detected Threats & Suggested Windows Commands 🚨", fontsize=16, weight='bold', pad=20)
    plt.tight_layout()
    plt.show()
else:
    print(" No packets captured.")

input("\n Capture complete. Press Enter to exit.")
