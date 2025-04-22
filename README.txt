Packet Sniffer with Anomaly Detection, Logging, and Graphing
============================================================

This Python program captures network packets using Scapy, analyzes traffic, logs packet information, detects anomalies, and provides live graph visualization. It supports interactive inspection of captured packets and saves output files in a local `output` directory.

---

📦 Requirements:
- Python 3.x
- scapy
- matplotlib

Install dependencies via pip:
```bash
pip install scapy matplotlib
```

---

🚀 How to Run:
```bash
python main.py
```

You will be prompted to:
- Enter a packet filter (e.g., 'tcp', 'port 80', or leave blank for all).
- Optionally enter an IP or port filter.

Example:
```bash
Enter filter (e.g., 'tcp', 'udp', 'port 80', or leave blank for all): tcp
Enter IP to filter (or leave blank for all): 192.168.1.1
Enter port to filter (or leave blank for all): 80
```

Type `stop` to stop sniffing and enter packet inspection mode.

---

🧠 Function Descriptions:

1. `analyze_traffic()`
   - Periodically analyzes traffic every 5 seconds.
   - Calculates and prints packets per second (PPS) and bits per second (BPS).
   - Detects anomalies when PPS or BPS exceeds thresholds.

2. `detect_anomalies(packet)`
   - Updates counters for number of packets and total data size.

3. `packet_callback(packet)`
   - Runs every time a packet is captured.
   - Extracts and logs packet info (timestamp, source, destination, length).
   - Adds packet to capture list and datagram log.
   - Calls `detect_anomalies()`.

4. `interactive_input()`
   - Listens for `stop` command to end packet capture.
   - Allows clean termination or continues sniffing.

5. `start_sniffing(filter_expr="")`
   - Starts packet sniffing based on user input filters.
   - Launches threads for input, traffic analysis, and graph visualization.
   - Stops when `stop_sniffing_flag` is True.

6. `save_packets()`
   - Saves all captured packets to a `.pcap` file in the `output` folder.

7. `save_log()`
   - Saves datagram log (metadata of packets) as a `.csv` file.

8. `inspect_packets()`
   - After sniffing stops, allows user to inspect packets one by one.
   - View a packet's details using `.show()` method.

9. `update_graph(i)`
   - Updates the live matplotlib graph with packet count over time.

10. `start_graph()`
    - Launches a live graph showing packets per second.

---

📁 Output Files
- `.pcap` file of captured packets.
- `.csv` file logging packet metadata.

Example Output File Names:
- `captured_packets_20250422_150530.pcap`
- `traffic_log_20250422_150530.csv`

---

🧪 Sample Use Case:
- Start the program and monitor HTTP traffic on port 80:
```bash
Enter filter (e.g., 'tcp', 'udp', 'port 80', or leave blank for all): tcp
Enter IP to filter (or leave blank for all): 
Enter port to filter (or leave blank for all): 80
```

- Type `stop` to inspect and view packets.

---

❓ Need Help?
If a packet doesn't show in detail, try using the `.summary()` method or `.show()` in inspection mode.

---

✅ End of README