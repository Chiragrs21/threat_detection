from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import psutil
import time
import threading
import scapy.all as scapy
import logging
from threading import Lock
import re  # For HTTP attack patterns

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
socketio = SocketIO(app, cors_allowed_origins="http://localhost:3000")

# Thread-safe data stores
packet_buffer = []
request_rates = []
port_status = {}
packet_lock = Lock()
rate_lock = Lock()
port_lock = Lock()

# HTTP attack patterns
HTTP_ATTACK_PATTERNS = {
    "sql_injection": re.compile(r"(select|union|drop|insert|update|delete|--|;|\b1=1\b)", re.I),
    "xss": re.compile(r"(<script>|javascript:|on\w+=)", re.I),
    "path_traversal": re.compile(r"(\.\./|\/\.\.)")
}


def capture_packets():
    def packet_callback(packet):
        if packet.haslayer(scapy.IP):
            packet_info = {
                "timestamp": time.time(),
                "src_ip": packet[scapy.IP].src,
                "dst_ip": packet[scapy.IP].dst,
                "protocol": packet[scapy.IP].proto
            }
            if packet.haslayer(scapy.TCP):
                packet_info["src_port"] = packet[scapy.TCP].sport
                packet_info["dst_port"] = packet[scapy.TCP].dport
                packet_info["flags"] = str(packet[scapy.TCP].flags)

                # HTTP Attack Detection for port 5001
                if packet_info["dst_port"] == 5001 and packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load.decode(
                        errors="ignore").lower()
                    for attack_type, pattern in HTTP_ATTACK_PATTERNS.items():
                        if pattern.search(payload):
                            attack_info = {
                                "timestamp": packet_info["timestamp"],
                                "src_ip": packet_info["src_ip"],
                                "attack_type": attack_type,
                                "payload": payload[:100]
                            }
                            logger.warning(
                                f"Detected {attack_type} on port 5001: {attack_info}")
                            socketio.emit('http_attack', attack_info)

            # Spoofing Detection
            src_ip = packet[scapy.IP].src
            if is_spoofed_ip(src_ip):
                spoof_info = {
                    "timestamp": packet_info["timestamp"],
                    "src_ip": src_ip,
                    "dst_ip": packet_info["dst_ip"],
                    "reason": "Suspected spoofed IP"
                }
                logger.warning(f"Detected spoofing: {spoof_info}")
                socketio.emit('spoofing_alert', spoof_info)

            with packet_lock:
                packet_buffer.append(packet_info)
                if len(packet_buffer) > 1000:
                    packet_buffer.pop(0)
            socketio.emit('new_packet', packet_info)

    try:
        logger.info(
            "Starting packet capture for port 5001 (requires root privileges)")
        scapy.sniff(prn=packet_callback, store=False,
                    filter="tcp port 5001")  # Monitor port 5001
    except PermissionError:
        logger.error(
            "Packet capture requires root/admin privileges. Run with sudo.")
    except Exception as e:
        logger.error(f"Packet capture failed: {str(e)}")


def is_spoofed_ip(ip):
    """Detect potentially spoofed IPs."""
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
        ("127.0.0.0", "127.255.255.255")  # Loopback
    ]
    try:
        ip_int = int.from_bytes(scapy.inet_aton(ip), "big")
        for start, end in private_ranges:
            start_int = int.from_bytes(scapy.inet_aton(start), "big")
            end_int = int.from_bytes(scapy.inet_aton(end), "big")
            if start_int <= ip_int <= end_int and ip != "127.0.0.1":  # Allow local loopback
                return True
        if ip == "255.255.255.255" or ip.startswith("224."):
            return True
    except Exception:
        return False
    return False


def monitor_request_rate():
    while True:
        try:
            current_time = time.time()
            with packet_lock:
                recent_packets = [
                    p for p in packet_buffer if current_time - p["timestamp"] < 1 and p["dst_port"] == 5001]
            rate_data = {"timestamp": current_time,
                         "count": len(recent_packets)}

            with rate_lock:
                request_rates.append(rate_data)
                if len(request_rates) > 300:
                    request_rates.pop(0)

                if len(request_rates) >= 30:
                    recent_counts = [r["count"] for r in request_rates[-30:]]
                    avg_rate = sum(recent_counts) / 30
                    std_dev = (
                        sum((x - avg_rate) ** 2 for x in recent_counts) / 30) ** 0.5
                    if len(recent_packets) > avg_rate + 2 * std_dev and avg_rate > 5:
                        socketio.emit('anomaly_alert', {
                            "timestamp": current_time,
                            "current_rate": len(recent_packets),
                            "avg_rate": avg_rate,
                            "increase_factor": len(recent_packets) / avg_rate if avg_rate > 0 else 0
                        })

            socketio.emit('request_rate', rate_data)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Request rate monitoring failed: {str(e)}")
            time.sleep(1)


def scan_ports():
    while True:
        try:
            connections = psutil.net_connections()
            current_ports = {}
            for conn in connections:
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    current_ports[port] = {
                        "status": "OPEN",
                        "program": psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    }

            with port_lock:
                for port, info in current_ports.items():
                    if port not in port_status:
                        socketio.emit('port_change', {
                            "port": port, "status": "OPEN", "program": info["program"]})
                for port in list(port_status.keys()):
                    if port not in current_ports:
                        socketio.emit('port_change', {
                            "port": port, "status": "CLOSED", "program": port_status[port]["program"]})
                port_status.clear()
                port_status.update(current_ports)
                socketio.emit('port_status', port_status)
            time.sleep(5)
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            time.sleep(5)


@app.route('/api/packets/recent')
def get_recent_packets():
    with packet_lock:
        return jsonify(packet_buffer[-100:] if packet_buffer else [])


@app.route('/api/stats/request_rate')
def get_request_rates():
    with rate_lock:
        return jsonify(request_rates)


@app.route('/api/ports')
def get_ports():
    with port_lock:
        return jsonify(port_status)


if __name__ == "__main__":
    threading.Thread(target=capture_packets, daemon=True).start()
    threading.Thread(target=monitor_request_rate, daemon=True).start()
    threading.Thread(target=scan_ports, daemon=True).start()
    logger.info("Starting Flask-SocketIO server on 0.0.0.0:5000 with eventlet")
    socketio.run(app, debug=True, host='0.0.0.0',
                 port=5000, use_reloader=False)
