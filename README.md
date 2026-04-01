# Widely WIDS v2.0
**The Wireless Intrusion Detection System Suite**

Widely WIDS is a multi-platform security tool designed to detect wireless attacks and reconnaissance in real-time. It consists of an ESP8266-based passive sniffer firmware and a central Python management console.

## 🚀 Features
- **Spectral Awareness**: ESP8266 sweeps all 13 WiFi channels (2.4GHz) to ensure no attack goes unnoticed.
- **Attack Detection**: Real-time identification of **Deauthentication floods**, **Disassociation attacks**, and **Evil Twin** APs.
- **Reconnaissance Tracking**: Monitors device **Probe Requests** to identify nearby scanning devices.
- **Visual Feedback**: Built-in physical LED alerts on the ESP8266.
- **Centralized Logging**: Python manager saves all events to `wids_alerts.log` with detailed metadata.
- **Colorized UI**: High-visibility console output using ANSI color coding.

## 📁 Repository Structure
- `Widely_WIDS.ino`: Arduino firmware for ESP8266 or ESP32 (passive sniffer).
- `wids.py`: Python management console for local packet sniffing or Serial monitoring.
- `requirements.txt`: Python dependency list.

## 🛠️ Installation & Setup

### 1. ESP8266 Firmware
1. Open `Widely_WIDS.ino` in the **Arduino IDE**.
2. Install the **ESP8266 Board Package**.
3. Select your board (e.g., NodeMCU 1.0) and upload.

### 2. Python Manager
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the manager in Serial mode (connect ESP8266 via USB):
   ```bash
   python wids.py --serial COM3  
   ```
3. Or run in Live Monitor mode (requires a WiFi card in monitor mode):
   ```bash
   sudo python wids.py --interface wlan0
   ```

## ⚠️ Requirements
- **Hardware**: ESP8266 (NodeMCU/Wemos D1 Mini) or a PC WiFi card supporting Monitor Mode.
- **Software**: Python 3.8+, Scapy, PySerial.

## ⚖️ License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

**Disclaimer**: This project is for educational and authorized security auditing purposes only. Use responsibly.
