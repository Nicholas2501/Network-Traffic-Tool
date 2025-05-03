from scapy.all import sniff, wrpcap, rdpcap
from scapy.layers.inet import IP
from datetime import datetime
import time
import threading
import csv
import os
import sys
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# List to store captured packets and datagrams
captured_packets = []
datagram_log = []

# Shared variables
packet_count = 0
data_transferred = 0  # Bytes
start_time = time.time()

# Lock for thread safety
lock = threading.Lock()

# Thresholds for anomaly detection
PPS_THRESHOLD = 20     # Packets per second
BPS_THRESHOLD = 100000 # Bits per second (bps)

# Define a relative directory for saving files
SAVE_DIRECTORY = "./output"
os.makedirs(SAVE_DIRECTORY, exist_ok=True)
print(f"Saving files to directory: {os.path.abspath(SAVE_DIRECTORY)}")

# Protocol count dictionary
protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

# Data for live graph
pps_data = []
time_data = []

# Shared variable to control sniffing
stop_sniffing_flag = False

# Function to analyze live traffic
def analyze_traffic():
    global packet_count, data_transferred, start_time

    while True and not stop_sniffing_flag:
        time.sleep(5)
        
        with lock:
            elapsed_time = time.time() - start_time
            pps = packet_count / elapsed_time if elapsed_time > 0 else 0
            bps = (data_transferred / elapsed_time) * 8 if elapsed_time > 0 else 0

            print(f"\n📊 Live Traffic Stats (Last {int(elapsed_time)}s)")
            print(f"   - Packets Captured: {packet_count}")
            print(f"   - Data Transferred: {data_transferred / 1024:.2f} KB")
            print(f"   - Packets per Second (PPS): {pps:.2f}")
            print(f"   - Data Rate: {bps / 1024:.2f} Kbps\n")

            if pps > PPS_THRESHOLD or bps > BPS_THRESHOLD:
                print("⚠️ Anomaly detected: Traffic spike! Possible DDoS?")

            packet_count = 0
            data_transferred = 0
            start_time = time.time()

# Anomaly detection
def detect_anomalies(packet):
    global packet_count, data_transferred
    with lock:
        packet_count += 1
        data_transferred += len(packet)

# Callback for each packet
def packet_callback(packet):
    global protocol_count
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    ip_layer = packet.getlayer(IP)
    if ip_layer:
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        if protocol == 6:
            protocol_count["TCP"] += 1
        elif protocol == 17:
            protocol_count["UDP"] += 1
        elif protocol == 1:
            protocol_count["ICMP"] += 1
        else:
            protocol_count["Other"] += 1
    else:
        src_ip = dst_ip = "Unknown"
        protocol = "N/A"

    packet_length = len(packet)

    datagram = {
        "timestamp": timestamp,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "length": packet_length
    }

    # Print the datagram in a concise format
    print(f"{datagram['source_ip']} -> {datagram['destination_ip']} | Protocol: {datagram['protocol']} | Length: {datagram['length']} bytes")

    captured_packets.append(packet)
    datagram_log.append(datagram)
    detect_anomalies(packet)

# Input thread for stop command
def interactive_input():
    global stop_sniffing_flag
    while True:
        try:
            command = input("Type 'stop' to inspect packets, or Ctrl+C to quit: ").strip().lower()
            if command == "stop":
                stop_sniffing_flag = True
                print("\n⚡ Stopping sniffing...")
                break
            elif command.isdigit():
                print("Sniffer is active. Type 'stop' to inspect packets.")
            else:
                print("Invalid input. Type a number (ignored) or 'stop'.")
        except KeyboardInterrupt:
            print("\n🛑 Program interrupted. Exiting gracefully.")
            os._exit(0)

# Start sniffing
def start_sniffing(filter_expr=""):
    global stop_sniffing_flag

    ip_filter = input("Enter IP to filter (or leave blank for all): ").strip()
    port_filter = input("Enter port to filter (or leave blank for all): ").strip()

    if ip_filter:
        filter_expr += f" and host {ip_filter}"
    if port_filter:
        filter_expr += f" and port {port_filter}"

    print(f"\n🔍 Starting Packet Sniffer with filter: {filter_expr}...\n")

    threading.Thread(target=interactive_input).start()
    threading.Thread(target=analyze_traffic, daemon=True).start()
    threading.Thread(target=start_graph, daemon=True).start()

    try:
        sniff(filter=filter_expr, prn=packet_callback, store=False, stop_filter=lambda x: stop_sniffing_flag)
    except KeyboardInterrupt:
        print("\n⚡ Sniffing stopped by keyboard interrupt.")
    finally:
        print("\n⚡ Sniffing stopped. Saving data...\n")
        save_packets()
        save_log()
        inspect_packets()

# Save packets
def save_packets():
    if captured_packets:
        filename = os.path.join(SAVE_DIRECTORY, f"captured_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        wrpcap(filename, captured_packets)
        print(f"✅ Packets saved to {filename}")
    else:
        print("No packets captured to save.")

# load packets from a file
def load_packets(filename):
    global captured_packets
    captured_packets = rdpcap(filename)
    if captured_packets:
        print(f"Finished loading packets from {filename}")
        inspect_packets()
    else:
        print(f"Could not load file {filename}.")


# Save datagram logs
def save_log():
    if datagram_log:
        filename = os.path.join(SAVE_DIRECTORY, f"traffic_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=datagram_log[0].keys())
            writer.writeheader()
            writer.writerows(datagram_log)
        print(f"📝 Datagram log saved to {filename}")
    else:
        print("No datagrams to log.")

# Packet inspection interface
def inspect_packets():
    if not captured_packets:
        print("No packets captured to inspect.")
        return

    print("\n📦 Captured Packets:")
    for i, packet in enumerate(captured_packets):
        print(f"{i}: {packet.summary()}")

    while True:
        try:
            choice = input("\nEnter packet number to inspect, or 'q' to quit: ").strip().lower()
            if choice == 'q':
                print("🔍 Exiting inspection mode. Program will now terminate.")
                os._exit(0)  # Exit the program completely
            elif choice.isdigit():
                index = int(choice)
                if 0 <= index < len(captured_packets):
                    print("\nPacket Details:")
                    captured_packets[index].show()
                else:
                    print("❌ Invalid packet number.")
            else:
                print("❌ Invalid input. Enter a number or 'q'.")
        except KeyboardInterrupt:
            print("\n🛑 Interrupted. Returning to main program.")
            os._exit(0)  # Exit the program completely

# Live graph
def update_graph(i):
    pps_data.append(packet_count)
    time_data.append(len(pps_data))
    plt.cla() 
    plt.plot(time_data, pps_data, label="Packets per Second")
    plt.legend(loc="upper left")
    plt.tight_layout()

def start_graph():
    ani = FuncAnimation(plt.gcf(), update_graph, interval=1000)
    plt.show()

# Entry point
if __name__ == "__main__":
    try:
        if(len(sys.argv)==2):
            # load packets and go into inspect mode
            load_packets(sys.argv[1])
        else:
            # prompt and go into live mode
            filter_option = input("Enter filter (e.g., 'tcp', 'udp', 'port 80', or leave blank for all): ").strip()
            start_sniffing(filter_option)
    except KeyboardInterrupt:
        print("\n🛑 Final interrupt received. Exiting now.")
    finally:
        print("✅ Program ended.")
