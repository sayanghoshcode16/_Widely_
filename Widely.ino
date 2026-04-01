#include <Arduino.h>

#ifdef __cplusplus
extern "C" {
#endif
  #include "user_interface.h"
#ifdef __cplusplus
}
#endif

// ================= CONFIGURATION =================
#define DEAUTH_WINDOW_MS 5000     // Window to count deauth frames
#define DEAUTH_THRESHOLD 30      // Deauth frames in window to trigger alert
#define MAX_SSIDS 20             // Max unique SSIDs to track
#define MAX_BSSID_PER_SSID 3     // Max BSSIDs allowed per SSID
#define HOP_INTERVAL_MS 250      // Time spent on each channel
#define LED_PIN 2                // GPIO2 (Internal LED)
#define MAX_ALERTS_QUEUE 5       // Pending alerts to handle in loop

// ================= DATA STRUCTURES =================
struct DeauthEvent {
  unsigned long ts;
};

struct SSIDEntry {
  char ssid[33];
  uint8_t bssid_count;
  uint8_t bssids[6 * MAX_BSSID_PER_SSID];
};

struct QueuedAlert {
  char type[16];
  char severity[8];
  char msg[64];
  uint8_t channel;
};

// ================= GLOBAL STATE =================
DeauthEvent deauthEvents[150];
int deauthIndex = 0;

SSIDEntry ssidTable[MAX_SSIDS];
int ssidCount = 0;

QueuedAlert alertQueue[MAX_ALERTS_QUEUE];
int alertQueueIndex = 0;

uint8_t currentChannel = 1;
unsigned long lastHopTime = 0;
unsigned long ledOffTime = 0;

// ================= HELPERS =================

void pruneDeauth(unsigned long now) {
  int j = 0;
  for (int i = 0; i < deauthIndex; i++) {
    if (now - deauthEvents[i].ts <= DEAUTH_WINDOW_MS) {
      deauthEvents[j++] = deauthEvents[i];
    }
  }
  deauthIndex = j;
}

// Non-blocking alert queuing
void queueAlert(const char* type, const char* severity, const char* msg) {
  if (alertQueueIndex < MAX_ALERTS_QUEUE) {
    QueuedAlert &a = alertQueue[alertQueueIndex++];
    strncpy(a.type, type, sizeof(a.type)-1);
    strncpy(a.severity, severity, sizeof(a.severity)-1);
    strncpy(a.msg, msg, sizeof(a.msg)-1);
    a.channel = currentChannel;
  }
}

void processAlerts() {
  for (int i = 0; i < alertQueueIndex; i++) {
    QueuedAlert &a = alertQueue[i];
    Serial.printf("{\"type\":\"%s\",\"severity\":\"%s\",\"channel\":%d,\"msg\":\"%s\"}\n", 
                  a.type, a.severity, a.channel, a.msg);
    
    if (strcmp(a.severity, "high") == 0) {
      digitalWrite(LED_PIN, LOW); // ON
      ledOffTime = millis() + 100;
    }
  }
  alertQueueIndex = 0;
}

void handleLED() {
  if (ledOffTime != 0 && millis() > ledOffTime) {
    digitalWrite(LED_PIN, HIGH); // OFF
    ledOffTime = 0;
  }
}

void hopChannel() {
  unsigned long now = millis();
  if (now - lastHopTime >= HOP_INTERVAL_MS) {
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    wifi_set_channel(currentChannel);
    lastHopTime = now;
  }
}

// ================= PACKET SNIFFER =================
void sniffer(uint8_t *buf, uint16_t len) {
  if (len < 12) return;

  uint8_t frameType = buf[0];
  unsigned long now = millis();

  // ----- Deauth (0xC0) / Disassociation (0xA0) -----
  if (frameType == 0xC0 || frameType == 0xA0) {
    if (deauthIndex < 150) {
      deauthEvents[deauthIndex++].ts = now;
    }
    pruneDeauth(now);

    if (deauthIndex >= DEAUTH_THRESHOLD) {
      queueAlert("deauth_attack", "high", "Deauthentication flood detected");
      deauthIndex = 0; 
    }
  }

  // ----- Beacon (0x80) -----
  if (frameType == 0x80 && len > 38) {
    uint8_t *bssid = buf + 10;
    uint8_t *ssidElt = buf + 36;

    if (ssidElt[0] == 0 && ssidElt[1] <= 32) {
      char tempSsid[33];
      int ssidLen = ssidElt[1];
      memcpy(tempSsid, ssidElt + 2, ssidLen);
      tempSsid[ssidLen] = '\0';

      int idx = -1;
      for (int i = 0; i < ssidCount; i++) {
        if (strcmp(ssidTable[i].ssid, tempSsid) == 0) {
          idx = i;
          break;
        }
      }

      if (idx == -1 && ssidCount < MAX_SSIDS) {
        strncpy(ssidTable[ssidCount].ssid, tempSsid, 32);
        ssidTable[ssidCount].bssid_count = 0;
        idx = ssidCount++;
      }

      if (idx >= 0) {
        SSIDEntry &e = ssidTable[idx];
        bool known = false;
        for (int i = 0; i < e.bssid_count; i++) {
          if (memcmp(e.bssids + i * 6, bssid, 6) == 0) {
            known = true;
            break;
          }
        }

        if (!known && e.bssid_count < MAX_BSSID_PER_SSID) {
          memcpy(e.bssids + e.bssid_count * 6, bssid, 6);
          e.bssid_count++;
          if (e.bssid_count >= MAX_BSSID_PER_SSID) {
            char alertMsg[64];
            snprintf(alertMsg, sizeof(alertMsg), "Evil Twin detected: %s", tempSsid);
            queueAlert("evil_twin", "medium", alertMsg);
          }
        }
      }
    }
  }
}

// ================= SETUP & LOOP =================
void setup() {
  Serial.begin(115200);
  delay(500);

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH); // Off

  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_promiscuous_enable(1);

  Serial.println("{\"status\":\"Widely WIDS v2.1 Stable\",\"mode\":\"Promiscuous\"}");
}

void loop() {
  hopChannel();
  processAlerts();
  handleLED();
  yield(); 
}
