# Packet-Guardian-Real-Time-Intrusion-Detection-
Summary
This project implements a Hybrid Intrusion Detection System (IDS) using multiple machine learning models to classify network traffic as benign or malicious in real-time. The system utilizes Scapy for packet capture and feature extraction, along with Isolation Forest and a GAN discriminator for anomaly detection. It also includes a signature-based check for known benign traffic patterns and an integrated flooding attack detection mechanism based on packet source, protocol, and rate.
The IDS system is designed to be versatile, allowing both live packet capture from network interfaces and reading from PCAP files. The goal is to detect network attacks, mitigate false positives, and provide detailed logs and visualizations for network administrators.
Key Components
1.
Signature-Based Benign Traffic Check: The system first performs a basic signature-based analysis to classify well-known traffic patterns as benign. This includes checks for TCP, UDP, ICMP, IGMP, and Ethernet traffic based on predefined length ranges.
2.
Flooding Detection: A rate-based flooding detection mechanism is implemented to track traffic by source/destination and protocol. The system detects various flooding attacks, such as TCP SYN floods, UDP floods, and ICMP floods, using packet rates within a sliding time window.
3.
Anomaly Detection with Isolation Forest and GAN: After signature-based checks, packets that do not match benign patterns are passed to an Isolation Forest model to detect anomalies. A GAN discriminator is used to further evaluate suspicious packets and classify them as benign or malicious based on learned patterns of benign traffic.
4.
Attack Identification and Mitigation: When an attack is detected, the system identifies the type of attack (e.g., ICMP flood, TCP SYN flood) and recommends mitigation actions, such as blocking specific protocols or enabling rate-limiting features.
5.
Safety Score Calculation: The system computes a safety score based on the proportion of malicious traffic, uncommon protocols, and other network behaviors. A higher safety score indicates a safer network environment.
6.
Log Generation and Visualization: Captured packets are logged in a CSV file, and summary statistics, including packet counts, attack types, and safety scores, are displayed. The system generates visualizations for packet length distribution, protocol distribution, and classification distribution.
7.
Windows Firewall Mitigation Commands: Suggested Windows firewall commands are generated for the detected threats to assist in mitigating the attacks.


