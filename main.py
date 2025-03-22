from scapy.all import sniff, wrpcap
from datetime import datetime
import time
import threading

# List to store captured packets
captured_packets = []
packet_count = 0
data_transferred = 0  # Bytes transferred
start_time = time.time()

# Function to analyze live traffic
def analyze_traffic():
    global packet_count, data_transferred, start_time

    while True:
        time.sleep(5)  # Update every 5 seconds

        elapsed_time = time.time() - start_time
        pps = packet_count / elapsed_time  # Packets per second
        bps = (data_transferred / elapsed_time) * 8  # Bits per second

        print(f"\n📊 Live Traffic Stats (Last {int(elapsed_time)}s)")
        print(f"   - Packets Captured: {packet_count}")
        print(f"   - Data Transferred: {data_transferred / 1024:.2f} KB")
        print(f"   - Packets per Second (PPS): {pps:.2f}")
        print(f"   - Data Rate: {bps / 1024:.2f} Kbps\n")

        # Reset for next interval
        packet_count = 0
        data_transferred = 0
        start_time = time.time()

# Function to detect anomalies (e.g., traffic spikes)
def detect_anomalies(packet):
    global packet_count, data_transferred

    packet_count += 1
    data_transferred += len(packet)

    # Basic anomaly detection: Unusual traffic bursts
    if packet_count > 100:  # Adjust threshold as needed
        print("⚠️ High traffic detected! Possible DDoS attack?")

# Function to handle captured packets
def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Extract packet details
    src_ip = packet[0][1].src if packet.haslayer('IP') else "Unknown"
    dst_ip = packet[0][1].dst if packet.haslayer('IP') else "Unknown"
    protocol = packet[0][1].proto if packet.haslayer('IP') else "N/A"

    # Print packet summary
    print(f"[{timestamp}] {src_ip} -> {dst_ip} | Protocol: {protocol}")

    # Store and analyze packets
    captured_packets.append(packet)
    detect_anomalies(packet)

# Function to start sniffing
def start_sniffing(filter_expr=""):
    print("\n🔍 Starting Enhanced Packet Sniffer... Press Ctrl+C to stop.\n")

    # Start traffic analysis in a separate thread
    analysis_thread = threading.Thread(target=analyze_traffic, daemon=True)
    analysis_thread.start()

    try:
        sniff(filter=filter_expr, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n⚡ Sniffing stopped. Saving packets...\n")
        save_packets()

# Function to save packets to a file
def save_packets():
    if captured_packets:
        filename = f"captured_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(filename, captured_packets)
        print(f"✅ Packets saved to {filename}")

# User-defined filters
filter_option = input("Enter filter (e.g., 'tcp', 'udp', 'port 80', or leave blank for all): ").strip()
start_sniffing(filter_option)

