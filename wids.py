import time
import argparse
import json
import os
import sys
import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List

# Optional dependencies with graceful fallback
try:
    from scapy.all import sniff, rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas, Dot11ProbeReq
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

# ANSI Color Codes for CLI
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class Alert:
    type: str
    severity: str
    timestamp: float
    details: Dict[str, Any]
    source: str = "local" # "local" (Scapy) or "remote" (ESP8266)

class AlertSink:
    def __init__(self, log_file: str = "wids_alerts.log"):
        self.log_file = log_file
        # Initialize log file with a header
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                f.write(f"# Widely WIDS Alert Log - Started {datetime.datetime.now()}\n")

    def emit(self, alert: Alert) -> None:
        payload = asdict(alert)
        payload["dt"] = datetime.datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Color styling based on severity
        color = Colors.ENDC
        if alert.severity.lower() == "high":
            color = Colors.FAIL + Colors.BOLD
        elif alert.severity.lower() == "medium":
            color = Colors.WARNING
        elif alert.severity.lower() == "low":
            color = Colors.GREEN
            
        # Console Output
        tag = f"[{alert.source.upper()}]"
        print(f"{Colors.BLUE}[{payload['dt']}]{Colors.ENDC} {color}{tag} {alert.type.upper()}{Colors.ENDC}: {alert.details.get('msg', alert.details)}")
        
        # File Logging
        with open(self.log_file, "a") as f:
            f.write(json.dumps(payload) + "\n")

# --- Detectors ---

class DeauthDetector:
    def __init__(self, window_seconds: int = 5, count_threshold: int = 30, per_target_threshold: int = 10) -> None:
        self.window_seconds = window_seconds
        self.count_threshold = count_threshold
        self.per_target_threshold = per_target_threshold
        self.global_counts: List[float] = []
        self.by_attacker: Dict[str, List[float]] = {}
        self.by_attacker_target: Dict[str, Dict[str, List[float]]] = {}

    def process(self, pkt) -> Optional[Alert]:
        if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas)):
            return None
            
        now = time.time()
        src = pkt[Dot11].addr2 or "UNKNOWN"
        dst = pkt[Dot11].addr3 or "UNKNOWN"
        
        self._append_and_prune(self.global_counts, now)
        self.by_attacker.setdefault(src, [])
        self._append_and_prune(self.by_attacker[src], now)
        
        self.by_attacker_target.setdefault(src, {})
        self.by_attacker_target[src].setdefault(dst, [])
        self._append_and_prune(self.by_attacker_target[src][dst], now)
        
        g = len(self.global_counts)
        a = len(self.by_attacker[src])
        t = len(self.by_attacker_target[src][dst])
        
        if g >= self.count_threshold or a >= self.count_threshold or t >= self.per_target_threshold:
            return Alert(
                type="deauth_attack",
                severity="high" if g >= self.count_threshold else "medium",
                timestamp=now,
                details={
                    "msg": f"Deauth flood detected from {src} targeting {dst}",
                    "attacker": src,
                    "target": dst,
                    "rate": t,
                    "global_rate": g
                }
            )
        return None

    def _append_and_prune(self, arr: List[float], now: float) -> None:
        arr.append(now)
        cutoff = now - self.window_seconds
        while arr and arr[0] < cutoff:
            arr.pop(0)

class EvilTwinDetector:
    def __init__(self, allowed_bssid_per_ssid: int = 2) -> None:
        self.allowed_bssid_per_ssid = allowed_bssid_per_ssid
        self.ssids: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def process(self, pkt) -> Optional[Alert]:
        if not pkt.haslayer(Dot11Beacon):
            return None
            
        now = time.time()
        ssid = None
        el = pkt[Dot11Elt]
        while isinstance(el, Dot11Elt):
            if el.ID == 0:
                ssid = el.info.decode(errors='ignore')
                break
            el = el.payload.getlayer(Dot11Elt)
            
        if not ssid or ssid.strip() == "":
            return None
            
        bssid = pkt[Dot11].addr3 or "UNKNOWN"
        self.ssids.setdefault(ssid, {})
        self.ssids[ssid][bssid] = {"last_seen": now}
        
        if len(self.ssids[ssid]) > self.allowed_bssid_per_ssid:
            return Alert(
                type="evil_twin_detected",
                severity="medium",
                timestamp=now,
                details={
                    "msg": f"Suspicious BSSID count ({len(self.ssids[ssid])}) for SSID: {ssid}",
                    "ssid": ssid,
                    "bssids": list(self.ssids[ssid].keys())
                }
            )
        return None

class ProbeRequestDetector:
    def __init__(self):
        self.seen_devices = {}

    def process(self, pkt) -> Optional[Alert]:
        if not pkt.haslayer(Dot11ProbeReq):
            return None
            
        now = time.time()
        src = pkt[Dot11].addr2 or "UNKNOWN"
        
        # Only alert once every 5 minutes per device to avoid spam
        if src not in self.seen_devices or (now - self.seen_devices[src] > 300):
            self.seen_devices[src] = now
            return Alert(
                type="recon_probe",
                severity="low",
                timestamp=now,
                details={
                    "msg": f"Device reconnaissance probe from: {src}",
                    "mac": src
                }
            )
        return None

class WIDS:
    def __init__(self, detectors: List[Any], sink: AlertSink) -> None:
        self.detectors = detectors
        self.sink = sink

    def handle_packet(self, pkt) -> None:
        for d in self.detectors:
            alert = d.process(pkt)
            if alert:
                alert.source = "local"
                self.sink.emit(alert)

    def handle_serial_data(self, data: str) -> None:
        try:
            raw = json.loads(data)
            alert = Alert(
                type=raw.get("type", "unknown_remote"),
                severity=raw.get("severity", "medium"),
                timestamp=time.time(),
                details={"msg": raw.get("msg", "No message provided"), **raw},
                source="esp8266"
            )
            self.sink.emit(alert)
        except json.JSONDecodeError:
            pass # Ignore malformed serial strings

# --- Runners ---

def run_serial_monitor(port: str, baud: int, wids: WIDS):
    if not SERIAL_AVAILABLE:
        print(f"{Colors.FAIL}Error: 'pyserial' not installed. Install with: pip install pyserial{Colors.ENDC}")
        return

    print(f"{Colors.CYAN}Listening to ESP8266 on {port} at {baud} baud...{Colors.ENDC}")
    try:
        ser = serial.Serial(port, baud, timeout=1)
        while True:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if line.startswith('{') and line.endswith('}'):
                    wids.handle_serial_data(line)
    except KeyboardInterrupt:
        print("\nStopping Serial monitoring...")
    except Exception as e:
        print(f"{Colors.FAIL}Serial Error: {e}{Colors.ENDC}")

def run_live_sniff(interface: str, wids: WIDS):
    if not SCAPY_AVAILABLE:
        print(f"{Colors.FAIL}Error: 'scapy' not installed or insufficient permissions.{Colors.ENDC}")
        return

    print(f"{Colors.CYAN}Starting live 802.11 monitor on {interface}...{Colors.ENDC}")
    try:
        sniff(iface=interface, prn=wids.handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping live sniff...")

def main() -> None:
    # Set console title if on Windows
    if sys.platform == "win32":
        os.system("title Widely WIDS Manager v2.0")

    parser = argparse.ArgumentParser(description="Widely WIDS Manager - Central Security Console")
    parser.add_argument("--interface", type=str, help="WiFi interface for live sniffing (monitor mode required)")
    parser.add_argument("--serial", type=str, help="Serial port for ESP8266 (e.g. COM3 or /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate for Serial (default: 115200)")
    parser.add_argument("--pcap", type=str, help="Read from a PCAP file")
    args = parser.parse_args()

    sink = AlertSink()
    detectors = [
        DeauthDetector(),
        EvilTwinDetector(),
        ProbeRequestDetector()
    ]
    wids = WIDS(detectors, sink)

    print(f"{Colors.HEADER}{Colors.BOLD}--- Widely WIDS Manager v2.0 ---{Colors.ENDC}")
    print(f"{Colors.BOLD}Status: Online and Monitoring{Colors.ENDC}\n")

    if args.pcap:
        if SCAPY_AVAILABLE:
            print(f"Processing PCAP: {args.pcap}")
            pkts = rdpcap(args.pcap)
            for p in pkts:
                wids.handle_packet(p)
        else:
            print("Scapy unavailable for PCAP.")
    
    if args.serial:
        # Start Serial monitoring in a thread or separate if needed, 
        # but for simplicity we'll just run it if provided.
        run_serial_monitor(args.serial, args.baud, wids)
    elif args.interface:
        run_live_sniff(args.interface, wids)
    elif not args.pcap:
        parser.print_help()

if __name__ == "__main__":
    main()