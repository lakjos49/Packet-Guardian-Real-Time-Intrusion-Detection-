# Packet-Guardian: Real-Time Network Intrusion Detection System 🛡️

## 📄 Summary

Packet-Guardian is a robust and versatile Hybrid Intrusion Detection System (IDS) designed to monitor network traffic in real-time, identifying and classifying malicious activities from benign patterns. By combining the power of machine learning, signature-based checks, and rate-based flood detection, this system aims to enhance network security, reduce false positives, and provide actionable insights to network administrators.

The IDS can operate by capturing live packets from network interfaces or by analyzing existing PCAP files, making it adaptable to various deployment scenarios. Its core objective is to detect a wide array of network attacks, ensure high accuracy through a multi-layered approach, and offer comprehensive logging and intuitive visualizations for effective threat management.

---

## ✨ Key Features

* **Signature-Based Benign Traffic Filtering:**
    * Initial rapid classification of well-known, safe traffic patterns (TCP, UDP, ICMP, IGMP, Ethernet) based on predefined characteristics and length ranges.
    * Reduces the load on advanced detection mechanisms.

* **Advanced Flooding Attack Detection:**
    * Rate-based mechanism to identify various flooding attacks (TCP SYN, UDP, ICMP floods).
    * Monitors packet rates per source/destination and protocol within a sliding time window.
    * Provides early warnings for high-volume denial-of-service attempts.

* **Hybrid Anomaly Detection (Isolation Forest & GAN):**
    * **Isolation Forest:** Non-benign packets are first analyzed by an Isolation Forest model, which excels at identifying outliers and anomalies in high-dimensional data.
    * **GAN Discriminator:** Suspicious packets flagged by Isolation Forest are further scrutinized by a Generative Adversarial Network (GAN) discriminator. This model leverages learned patterns of benign traffic to distinguish between subtle anomalies and true malicious intent, minimizing false positives.

* **Intelligent Attack Identification & Mitigation:**
    * Automatically identifies the specific type of detected attack (e.g., ICMP flood, TCP SYN flood).
    * Generates actionable recommendations for mitigation, such as blocking specific protocols or advising on rate-limiting configurations.
    * Includes suggested **Windows Firewall commands** to aid in immediate threat response.

* **Comprehensive Safety Score Calculation:**
    * Calculates a dynamic "safety score" for the network environment.
    * Factors in the proportion of malicious traffic, prevalence of uncommon protocols, and other network behavior indicators.
    * A higher score signifies a more secure network state.

* **Detailed Logging & Intuitive Visualization:**
    * All captured and analyzed packets are meticulously logged in a CSV file for post-incident analysis.
    * Displays real-time summary statistics, including total packet counts, detected attack types, and the current safety score.
    * Generates insightful visualizations:
        * Packet length distribution
        * Protocol distribution
        * Traffic classification distribution (Benign, Malicious, Anomalous)

---

## 🛠️ Technologies Used

* **Python:** The primary programming language.
* **Scapy:** For powerful packet capture, crafting, and manipulation.
* **Scikit-learn:** For implementing the Isolation Forest algorithm.
* **TensorFlow/PyTorch (Choose one based on your actual implementation):** For building and training the GAN discriminator.
* **Pandas:** For data handling and manipulation of logs.
* **Matplotlib/Seaborn:** For generating data visualizations.

