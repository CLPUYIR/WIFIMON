#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <time.h>
#include <WebServer.h>
#include <Preferences.h>
#include <DNSServer.h>

// --- Portal and Storage Variables ---
WebServer server(80);
DNSServer dnsServer;
Preferences preferences;
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);

const char* CONFIG_HTML = 
"<!DOCTYPE html>"
"<html>"
"<head>"
"<meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>Sniffer Config</title>"
"<style>"
"body { font-family: -apple-system, sans-serif; background: #0f0f12; color: #e4e4e7; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }"
".card { background: #18181b; border: 1px solid #27272a; padding: 30px; border-radius: 12px; width: 100%; max-width: 320px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }"
"h2 { margin-top: 0; color: #06b6d4; text-align: center; font-size: 1.5rem; }"
"p { color: #a1a1aa; font-size: 0.9rem; text-align: center; margin-bottom: 20px; }"
"label { display: block; margin-bottom: 6px; font-size: 0.85rem; color: #a1a1aa; }"
"input, select { width: 100%; padding: 10px; background: #09090b; border: 1px solid #27272a; border-radius: 6px; color: white; margin-bottom: 15px; box-sizing: border-box; font-size: 0.95rem; }"
"input:focus, select:focus { border-color: #06b6d4; outline: none; }"
"button { width: 100%; padding: 12px; background: linear-gradient(135deg, #06b6d4, #0891b2); border: none; border-radius: 6px; color: white; font-weight: bold; cursor: pointer; font-size: 0.95rem; transition: opacity 0.2s; }"
"button:hover { opacity: 0.9; }"
"</style>"
"</head>"
"<body>"
"<div class='card'>"
"<h2>Sniffer Setup</h2>"
"<p>Configure the Wi-Fi credentials and Timezone for your plug-and-play sniffer clock.</p>"
"<form action='/save' method='POST'>"
"<label for='ssid'>Wi-Fi Name (SSID)</label>"
"<input type='text' id='ssid' name='ssid' placeholder='SSID Name' required>"
"<label for='pass'>Password</label>"
"<input type='password' id='pass' name='pass' placeholder='Password'>"
"<label for='tz'>Timezone Offset (Hours from UTC)</label>"
"<select id='tz' name='tz'>"
"<option value='-12'>UTC-12:00</option>"
"<option value='-11'>UTC-11:00</option>"
"<option value='-10'>UTC-10:00</option>"
"<option value='-9.5'>UTC-09:30</option>"
"<option value='-9'>UTC-09:00</option>"
"<option value='-8'>UTC-08:00 (PST)</option>"
"<option value='-7'>UTC-07:00 (MST)</option>"
"<option value='-6'>UTC-06:00 (CST)</option>"
"<option value='-5'>UTC-05:00 (EST)</option>"
"<option value='-4'>UTC-04:00 (AST)</option>"
"<option value='-3.5'>UTC-03:30</option>"
"<option value='-3'>UTC-03:00</option>"
"<option value='-2'>UTC-02:00</option>"
"<option value='-1'>UTC-01:00</option>"
"<option value='0'>UTC+00:00 (GMT/UTC)</option>"
"<option value='1'>UTC+01:00 (CET)</option>"
"<option value='2'>UTC+02:00 (EET)</option>"
"<option value='3'>UTC+03:00 (MSK)</option>"
"<option value='3.5'>UTC+03:30 (Iran)</option>"
"<option value='4'>UTC+04:00 (GST)</option>"
"<option value='4.5'>UTC+04:30 (Kabul)</option>"
"<option value='5'>UTC+05:00 (PKT)</option>"
"<option value='5.5' selected>UTC+05:30 (IST - India)</option>"
"<option value='5.75'>UTC+05:45 (Nepal)</option>"
"<option value='6'>UTC+06:00 (BST)</option>"
"<option value='6.5'>UTC+06:30 (Myanmar)</option>"
"<option value='7'>UTC+07:00 (WIB)</option>"
"<option value='8'>UTC+08:00 (SGT/CST)</option>"
"<option value='8.75'>UTC+08:45 (ACWST)</option>"
"<option value='9'>UTC+09:00 (JST)</option>"
"<option value='9.5'>UTC+09:30 (ACST)</option>"
"<option value='10'>UTC+10:00 (AEST)</option>"
"<option value='10.5'>UTC+10:30 (LHST)</option>"
"<option value='11'>UTC+11:00</option>"
"<option value='12'>UTC+12:00 (NZST)</option>"
"<option value='12.75'>UTC+12:45 (CHAST)</option>"
"<option value='13'>UTC+13:00</option>"
"<option value='14'>UTC+14:00</option>"
"</select>"
"<button type='submit'>Save and Connect</button>"
"</form>"
"</div>"
"</body>"
"</html>";

// --- TFT Pin Definitions ---
#define TFT_SCK   18
#define TFT_MISO  19
#define TFT_MOSI  23
#define TFT_RST   4
#define TFT_DC    2
#define TFT_CS    15

// Initialize the ST7735 screen (Using Software SPI to match physical wiring/board variant)
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCK, TFT_RST);

// Create a double-buffer canvas to eliminate screen flicker
GFXcanvas16 canvas(160, 128);

// --- HARDWARE BGR COLOR FIX ---
#define FIX_BLACK   0x0000
#define FIX_WHITE   0xFFFF
#define FIX_GREEN   0x07E0
#define FIX_RED     0x001F  // Sends Blue to trigger Red on physical BGR panel
#define FIX_YELLOW  0x07FF  // Sends Cyan to trigger Yellow on physical BGR panel
#define FIX_CYAN    0xFFE0  // Sends Yellow to trigger Cyan on physical BGR panel
#define FIX_GRAY    0x4A69

#define MAX_CLIENTS 30
#define MAX_APS     30

// Client Device structure (for Probe Requests & Data Traffic)
struct ClientDevice {
  uint8_t mac[6];
  int rssi;
  char probedSSID[33];
  unsigned long lastSeen;
  bool active;
};

// Access Point structure (for Beacon Frames)
struct AccessPoint {
  uint8_t bssid[6];
  char ssid[33];
  int rssi;
  int channel;
  char encryption[8];
  unsigned long lastSeen;
  bool active;
};

ClientDevice trackedClients[MAX_CLIENTS];
AccessPoint trackedAPs[MAX_APS];

int currentChannel = 1;
unsigned long lastChannelChange = 0;

enum DisplayMode { CLIENTS_MODE, APS_MODE, COMBINED_MODE, RADAR_MODE };
DisplayMode currentMode = RADAR_MODE;
unsigned long lastModeToggle = 0;

// --- Real-time Clock Variables ---
int rtcHour = 0;
int rtcMin = 0;
int rtcSec = 0;
unsigned long lastTimeUpdateMillis = 0;
bool clockSynced = false;

// --- Button Control Variables ---
#define BUTTON_PIN 0 // BOOT button on ESP32 is GPIO 0
bool autoToggleMode = true;
unsigned long buttonPressStart = 0;
bool buttonWasPressed = false;

bool liveSerialMonitor = true; // Active live stream for PuTTY
bool hudSerialMode = false;     // Live clean HUD non-spam mode
bool jsonSerialMode = false;    // Compact JSON Lines stream mode

int rssiToPercentage(int rssi) {
    if (rssi <= -100) return 0;
    if (rssi >= -30) return 100;
    return (int)((rssi + 100) * 1.42857f);
}

void renderSignalBar(int sigPct, char* outBuf, size_t bufSize) {
    int bars = sigPct / 10;
    if (bars > 10) bars = 10;
    if (bars < 0) bars = 0;
    
    int idx = 0;
    outBuf[idx++] = '[';
    for (int b = 0; b < 10; b++) {
        if (b < bars) {
            outBuf[idx++] = '=';
        } else {
            outBuf[idx++] = '-';
        }
    }
    outBuf[idx++] = ']';
    outBuf[idx] = '\0';
}

void logJsonClient(uint8_t* mac, int rssi, const char* ssid, bool isNew) {
    if (!jsonSerialMode) return;
    int h = 0, m = 0, s = 0;
    getCurrentTime(h, m, s);
    const char* vendor = getVendor(mac);
    float dist = pow(10.0f, (-40.0f - (float)rssi) / 27.0f);

    Serial.printf("{\"type\":\"client\",\"status\":\"%s\",\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"vendor\":\"%s\",\"rssi\":%d,\"dist\":%.1f,\"ch\":%d,\"probed\":\"%s\",\"time\":\"%02d:%02d:%02d\"}\r\n",
                  isNew ? "new" : "update",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                  vendor, rssi, dist, currentChannel,
                  ssid ? ssid : "", h, m, s);
}

void logJsonAP(uint8_t* bssid, const char* ssid, int rssi, int channel, const char* enc, bool isNew) {
    if (!jsonSerialMode) return;
    int h = 0, m = 0, s = 0;
    getCurrentTime(h, m, s);
    float dist = pow(10.0f, (-40.0f - (float)rssi) / 27.0f);

    Serial.printf("{\"type\":\"ap\",\"status\":\"%s\",\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ssid\":\"%s\",\"enc\":\"%s\",\"rssi\":%d,\"dist\":%.1f,\"ch\":%d,\"time\":\"%02d:%02d:%02d\"}\r\n",
                  isNew ? "new" : "update",
                  bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                  ssid, enc, rssi, dist, channel, h, m, s);
}

void exportJsonDatabase() {
    int h = 0, m = 0, s = 0;
    getCurrentTime(h, m, s);

    Serial.print("\r\n{\"timestamp\":\"");
    Serial.printf("%02d:%02d:%02d", h, m, s);
    Serial.print("\",\"channel\":");
    Serial.print(currentChannel);
    Serial.print(",\"clients\":[");

    bool first = true;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (trackedClients[i].active) {
            if (!first) Serial.print(",");
            first = false;
            float dist = pow(10.0f, (-40.0f - (float)trackedClients[i].rssi) / 27.0f);
            const char* vendor = getVendor(trackedClients[i].mac);
            Serial.printf("{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"vendor\":\"%s\",\"rssi\":%d,\"dist\":%.1f,\"probed\":\"%s\"}",
                          trackedClients[i].mac[0], trackedClients[i].mac[1], trackedClients[i].mac[2],
                          trackedClients[i].mac[3], trackedClients[i].mac[4], trackedClients[i].mac[5],
                          vendor, trackedClients[i].rssi, dist, trackedClients[i].probedSSID);
        }
    }

    Serial.print("],\"aps\":[");
    first = true;
    for (int i = 0; i < MAX_APS; i++) {
        if (trackedAPs[i].active) {
            if (!first) Serial.print(",");
            first = false;
            float dist = pow(10.0f, (-40.0f - (float)trackedAPs[i].rssi) / 27.0f);
            Serial.printf("{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ssid\":\"%s\",\"enc\":\"%s\",\"rssi\":%d,\"dist\":%.1f,\"ch\":%d}",
                          trackedAPs[i].bssid[0], trackedAPs[i].bssid[1], trackedAPs[i].bssid[2],
                          trackedAPs[i].bssid[3], trackedAPs[i].bssid[4], trackedAPs[i].bssid[5],
                          trackedAPs[i].ssid, trackedAPs[i].encryption, trackedAPs[i].rssi, dist, trackedAPs[i].channel);
        }
    }
    Serial.println("]}\r\n");
}

void logLiveClient(uint8_t* mac, int rssi, const char* ssid, bool isNew) {
    if (!liveSerialMonitor || hudSerialMode || jsonSerialMode) return;
    int h = 0, m = 0, s = 0;
    getCurrentTime(h, m, s);
    const char* vendor = getVendor(mac);
    float dist = pow(10.0f, (-40.0f - (float)rssi) / 27.0f);
    int sigPct = rssiToPercentage(rssi);

    const char* color = (rssi > -60) ? "\033[32m" : ((rssi > -80) ? "\033[33m" : "\033[31m");

    Serial.printf("\033[36m[%02d:%02d:%02d]\033[0m %s %sMAC: %02X:%02X:%02X:%02X:%02X:%02X\033[0m | Vendor: %-12s | RSSI: %3ddBm (%3d%%) | Dist: %4.1fm | CH: %2d",
                  h, m, s, isNew ? "\033[1;32m[DISCOVERED]\033[0m" : "\033[33m[UPDATED]\033[0m   ",
                  color, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                  vendor, rssi, sigPct, dist, currentChannel);

    if (ssid && strlen(ssid) > 0) {
        Serial.printf(" | Probed SSID: \033[1;37m%s\033[0m\r\n", ssid);
    } else {
        Serial.printf("\r\n");
    }
}

void logLiveAP(uint8_t* bssid, const char* ssid, int rssi, int channel, const char* enc, bool isNew) {
    if (!liveSerialMonitor || hudSerialMode || jsonSerialMode) return;
    int h = 0, m = 0, s = 0;
    getCurrentTime(h, m, s);
    float dist = pow(10.0f, (-40.0f - (float)rssi) / 27.0f);
    int sigPct = rssiToPercentage(rssi);

    const char* encColor = (strcmp(enc, "OPEN") == 0 || strcmp(enc, "WEP") == 0) ? "\033[1;31m" : "\033[32m";

    Serial.printf("\033[36m[%02d:%02d:%02d]\033[0m %s BSSID: %02X:%02X:%02X:%02X:%02X:%02X | SSID: \033[1;37m%-16.16s\033[0m | CH: %2d | Enc: %s%-4s\033[0m | RSSI: %3ddBm (%3d%%) | Dist: %4.1fm\r\n",
                  h, m, s, isNew ? "\033[1;35m[AP NEW]\033[0m" : "\033[35m[AP UPD]\033[0m",
                  bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                  ssid, channel, encColor, enc, rssi, sigPct, dist);
}

// Updates or inserts a client device in the tracker list
void update_client(uint8_t* mac, int rssi, const char* ssid, unsigned long now) {
  int foundIdx = -1;
  int emptyIdx = -1;
  int oldestIdx = 0;
  unsigned long oldestTime = 0xFFFFFFFF;

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (trackedClients[i].active) {
      if (memcmp(trackedClients[i].mac, mac, 6) == 0) {
        foundIdx = i;
        break;
      }
      if (trackedClients[i].lastSeen < oldestTime) {
        oldestTime = trackedClients[i].lastSeen;
        oldestIdx = i;
      }
    } else if (emptyIdx == -1) {
      emptyIdx = i;
    }
  }

  int insertIdx = (foundIdx >= 0) ? foundIdx : ((emptyIdx >= 0) ? emptyIdx : oldestIdx);
  bool isNew = (foundIdx < 0);

  memcpy(trackedClients[insertIdx].mac, mac, 6);
  trackedClients[insertIdx].rssi = rssi;
  
  // Only overwrite SSID if a valid SSID name is provided
  if (ssid && strlen(ssid) > 0) {
    strncpy(trackedClients[insertIdx].probedSSID, ssid, 32);
    trackedClients[insertIdx].probedSSID[32] = '\0';
  } else if (foundIdx < 0) {
    // If it's a new client found via data sniffing (no SSID), initialize as empty
    trackedClients[insertIdx].probedSSID[0] = '\0';
  }

  trackedClients[insertIdx].lastSeen = now;
  trackedClients[insertIdx].active = true;

  logLiveClient(mac, rssi, trackedClients[insertIdx].probedSSID, isNew);
  logJsonClient(mac, rssi, trackedClients[insertIdx].probedSSID, isNew);
}

// Updates or inserts an Access Point in the tracker list
void update_ap(uint8_t* bssid, const char* ssid, int rssi, int channel, const char* enc, unsigned long now) {
  int foundIdx = -1;
  int emptyIdx = -1;
  int oldestIdx = 0;
  unsigned long oldestTime = 0xFFFFFFFF;

  for (int i = 0; i < MAX_APS; i++) {
    if (trackedAPs[i].active) {
      if (memcmp(trackedAPs[i].bssid, bssid, 6) == 0) {
        foundIdx = i;
        break;
      }
      if (trackedAPs[i].lastSeen < oldestTime) {
        oldestTime = trackedAPs[i].lastSeen;
        oldestIdx = i;
      }
    } else if (emptyIdx == -1) {
      emptyIdx = i;
    }
  }

  int insertIdx = (foundIdx >= 0) ? foundIdx : ((emptyIdx >= 0) ? emptyIdx : oldestIdx);
  bool isNew = (foundIdx < 0);

  memcpy(trackedAPs[insertIdx].bssid, bssid, 6);
  strncpy(trackedAPs[insertIdx].ssid, ssid, 32);
  trackedAPs[insertIdx].ssid[32] = '\0';
  trackedAPs[insertIdx].rssi = rssi;
  trackedAPs[insertIdx].channel = (channel != -1) ? channel : currentChannel;
  strncpy(trackedAPs[insertIdx].encryption, enc, 7);
  trackedAPs[insertIdx].encryption[7] = '\0';
  trackedAPs[insertIdx].lastSeen = now;
  trackedAPs[insertIdx].active = true;

  logLiveAP(bssid, ssid, rssi, trackedAPs[insertIdx].channel, enc, isNew);
  logJsonAP(bssid, ssid, rssi, trackedAPs[insertIdx].channel, enc, isNew);
}

// Sniffer callback parses 802.11 management frames and active data frames
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return; // Ignore truncated packets

  uint8_t *payload = pkt->payload;
  uint8_t frameControl = payload[0];
  uint8_t typeVal = (frameControl & 0x0C) >> 2;
  uint8_t subtype = (frameControl & 0xF0) >> 4;
  int rssi = pkt->rx_ctrl.rssi;
  unsigned long now = millis();

  // --- CASE A: MANAGEMENT FRAMES (type = 0x00) ---
  if (typeVal == 0x00) {
    uint8_t *sa = payload + 10; // Source MAC starts at byte 10
    if ((sa[0] == 0xFF && sa[1] == 0xFF) || (sa[0] == 0x00 && sa[1] == 0x00)) return;

    if (subtype == 0x04) { // Probe Request (Client searching for SSIDs)
      char ssid[33] = {0};
      int offset = 24; // Tagged parameters start at offset 24

      while (offset + 2 <= len) {
        uint8_t tag_num = payload[offset];
        uint8_t tag_len = payload[offset + 1];
        if (offset + 2 + tag_len > len) break;

        if (tag_num == 0) { // Tag 0 is SSID
          int copy_len = (tag_len > 32) ? 32 : tag_len;
          memcpy(ssid, payload + offset + 2, copy_len);
          ssid[copy_len] = '\0';
          break;
        }
        offset += 2 + tag_len;
      }
      if (strlen(ssid) == 0) return;
      update_client(sa, rssi, ssid, now);
    } 
    else if (subtype == 0x08) { // Beacon Frame (AP broadcasting SSID & capabilities)
      char ssid[33] = {0};
      int offset = 36; // Tagged parameters start at offset 36

      while (offset + 2 <= len) {
        uint8_t tag_num = payload[offset];
        uint8_t tag_len = payload[offset + 1];
        if (offset + 2 + tag_len > len) break;

        if (tag_num == 0) { // Tag 0 is SSID
          int copy_len = (tag_len > 32) ? 32 : tag_len;
          memcpy(ssid, payload + offset + 2, copy_len);
          ssid[copy_len] = '\0';
          break;
        }
        offset += 2 + tag_len;
      }
      if (strlen(ssid) == 0) return;

      // Get channel from Tag 3 (DS Parameter Set)
      int channel = -1;
      offset = 36;
      while (offset + 2 <= len) {
        uint8_t tag_num = payload[offset];
        uint8_t tag_len = payload[offset + 1];
        if (offset + 2 + tag_len > len) break;

        if (tag_num == 3 && tag_len == 1) {
          channel = payload[offset + 2];
          break;
        }
        offset += 2 + tag_len;
      }

      // Parse security capabilities
      char enc[8] = "WEP";
      uint16_t capability = (payload[35] << 8) | payload[34];
      bool privacy = (capability & (1 << 4)) != 0;

      if (!privacy) {
        strcpy(enc, "OPEN");
      } else {
        bool hasWpa2 = false;
        bool hasWpa = false;
        offset = 36;
        while (offset + 2 <= len) {
          uint8_t tag_num = payload[offset];
          uint8_t tag_len = payload[offset + 1];
          if (offset + 2 + tag_len > len) break;

          if (tag_num == 48) { // Tag 48 represents RSN (WPA2/WPA3)
            hasWpa2 = true;
          } else if (tag_num == 221) { // Tag 221 represents Vendor Specific (often WPA)
            if (tag_len >= 4 && payload[offset+2] == 0x00 && payload[offset+3] == 0x50 && payload[offset+4] == 0xF2 && payload[offset+5] == 0x01) {
              hasWpa = true;
            }
          }
          offset += 2 + tag_len;
        }
        if (hasWpa2) strcpy(enc, "WPA2");
        else if (hasWpa) strcpy(enc, "WPA");
      }
      update_ap(sa, ssid, rssi, channel, enc, now);
    }
  }
  // --- CASE B: DATA FRAMES (type = 0x02) ---
  // If active data communication is happening, extract client MAC address immediately
  else if (typeVal == 0x02) {
    uint8_t flags = payload[1];
    uint8_t toDS = flags & 0x01;
    uint8_t fromDS = (flags & 0x02) >> 1;
    uint8_t *clientMac = NULL;

    if (toDS && !fromDS) {
      // Packet is Client -> AP (Source Address is client)
      clientMac = payload + 10;
    } else if (!toDS && fromDS) {
      // Packet is AP -> Client (Destination Address is client)
      clientMac = payload + 4;
    } else if (!toDS && !fromDS) {
      // Client-to-Client / Direct Ad-hoc
      clientMac = payload + 10;
    }

    if (clientMac) {
      // Ignore broadcast/multicast (LSB of first octet is 1)
      if (clientMac[0] & 0x01) return;
      // Filter out invalid null MACs
      if (clientMac[0] == 0x00 && clientMac[1] == 0x00 && clientMac[2] == 0x00) return;

      update_client(clientMac, rssi, "", now);
    }
  }
}

// --- Captive Portal & NTP Helper Functions ---
void handleRoot() {
  server.send(200, "text/html", CONFIG_HTML);
}

void handleSave() {
  String ssid = server.arg("ssid");
  String pass = server.arg("pass");
  float tz = server.arg("tz").toFloat();
  
  preferences.begin("wifi-config", false);
  preferences.putString("ssid", ssid);
  preferences.putString("pass", pass);
  preferences.putFloat("tzOffset", tz);
  preferences.end();
  
  String html = "<html><body style='background:#0f0f12;color:white;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;'>";
  html += "<div style='text-align:center;background:#18181b;padding:30px;border-radius:12px;border:1px solid #27272a;max-width:300px;'>";
  html += "<h2 style='color:#22c55e;margin-top:0;'>Saved!</h2>";
  html += "<p style='color:#a1a1aa;'>Connecting to: <b>" + ssid + "</b></p>";
  html += "<p style='color:#a1a1aa;'>Timezone Offset: <b>UTC " + String(tz >= 0 ? "+" : "") + String(tz) + "</b></p>";
  html += "<p style='font-size:0.85rem;color:#71717a;'>Device is restarting...</p>";
  html += "</div></body></html>";
  
  server.send(200, "text/html", html);
  delay(2000);
  ESP.restart();
}

void handleNotFound() {
  server.sendHeader("Location", String("http://192.168.4.1/"), true);
  server.send(302, "text/plain", "");
}

bool connectToWiFi(String ssid, String pass) {
  canvas.fillScreen(FIX_BLACK);
  canvas.setCursor(0, 5);
  canvas.setTextColor(FIX_CYAN);
  canvas.print("WiFi Connecting");
  canvas.drawLine(0, 16, 160, 16, FIX_WHITE);
  
  canvas.setTextColor(FIX_WHITE);
  canvas.setCursor(0, 24);
  canvas.print("SSID: "); canvas.println(ssid);
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    canvas.print(".");
    tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    canvas.println();
    canvas.setTextColor(FIX_GREEN);
    canvas.println("WiFi Connected!");
    tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
    return true;
  }
  
  canvas.println();
  canvas.setTextColor(FIX_RED);
  canvas.println("WiFi Timeout!");
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
  delay(1500);
  return false;
}

bool syncNTP(float tzOffset) {
  long gmtOffset_sec = long(tzOffset * 3600.0);
  configTime(gmtOffset_sec, 0, "pool.ntp.org");
  
  struct tm timeinfo;
  int attempts = 0;
  while (!getLocalTime(&timeinfo) && attempts < 10) {
    delay(500);
    attempts++;
  }
  
  if (getLocalTime(&timeinfo)) {
    rtcHour = timeinfo.tm_hour;
    rtcMin = timeinfo.tm_min;
    rtcSec = timeinfo.tm_sec;
    lastTimeUpdateMillis = millis();
    clockSynced = true;
    return true;
  }
  return false;
}

void runConfigPortal() {
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP("Sniffer-Config");
  
  dnsServer.start(DNS_PORT, "*", apIP);
  
  server.on("/", handleRoot);
  server.on("/save", HTTP_POST, handleSave);
  server.onNotFound(handleNotFound);
  server.begin();
  
  canvas.fillScreen(FIX_BLACK);
  canvas.setCursor(0, 5);
  canvas.setTextColor(FIX_YELLOW);
  canvas.print("WiFi Portal Active");
  canvas.drawLine(0, 16, 160, 16, FIX_WHITE);
  
  canvas.setTextColor(FIX_WHITE);
  canvas.setCursor(0, 24);
  canvas.println("SSID: Sniffer-Config");
  canvas.println("Open: 192.168.4.1");
  canvas.println("on your phone/PC.");
  canvas.println();
  canvas.setTextColor(FIX_CYAN);
  canvas.println("Press BOOT button");
  canvas.println("to bypass setup.");
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
  
  Serial.println("[PORTAL] AP started: Sniffer-Config");
  Serial.println("[PORTAL] Browse to 192.168.4.1");
  
  while (true) {
    dnsServer.processNextRequest();
    server.handleClient();
    
    // Check if BOOT button is pressed to bypass
    if (digitalRead(BUTTON_PIN) == LOW) {
      Serial.println("[PORTAL] Bypassed by button press.");
      break;
    }
    delay(10);
  }
  
  // Cleanup AP
  dnsServer.stop();
  server.stop();
  WiFi.softAPdisconnect(true);
}

void setup() {
  Serial.begin(115200);
  Serial.println("[SYSTEM] setup() started");
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  // Initialize screen using Software SPI
  Serial.println("[SYSTEM] Initializing Screen (Software SPI)...");
  tft.initR(INITR_BLACKTAB); 
  Serial.println("[SYSTEM] Screen initialized!");
  tft.setRotation(1);
  tft.fillScreen(FIX_BLACK);
  
  // Load credentials from Preferences
  preferences.begin("wifi-config", false); // Read-write mode
  String ssid = preferences.getString("ssid", "");
  String pass = preferences.getString("pass", "");
  float tzOffset = preferences.getFloat("tzOffset", 5.5);
  if (ssid.length() == 0) {
    ssid = "YOUR_SSID";
    pass = "YOUR_PASSWORD";
    preferences.putString("ssid", ssid);
    preferences.putString("pass", pass);
    preferences.putFloat("tzOffset", tzOffset);
  }
  preferences.end();
  
  bool connected = false;
  if (ssid.length() > 0) {
    connected = connectToWiFi(ssid, pass);
    if (connected) {
      if (syncNTP(tzOffset)) {
        canvas.setTextColor(FIX_GREEN);
        canvas.println("Time synced!");
      } else {
        canvas.setTextColor(FIX_RED);
        canvas.println("NTP sync failed!");
      }
      tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
      delay(1500);
    }
  }
  
  if (!connected) {
    // Start Web configuration portal if connection failed or no credentials
    runConfigPortal();
  }
  
  tft.fillScreen(FIX_BLACK);
  tft.setTextColor(FIX_GREEN);
  tft.setCursor(0, 5);
  tft.println("Auditor Sniffer Live...");
  tft.drawLine(0, 16, 160, 16, FIX_WHITE);
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
  delay(1000);

  // STA & Disconnect for Sniffer Mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  currentMode = RADAR_MODE;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  Serial.println("[SYSTEM] setup() finished, entering loop()");
}

// OUI Lookup to find Device Manufacturer from the first 3 bytes of the MAC address
const char* getVendor(uint8_t* mac) {
  uint32_t oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
  switch (oui) {
    // Apple
    case 0x5C013B: case 0xD8A01D: case 0xBCDDC2: case 0x002608: 
    case 0x88E9FE: case 0x94E979: case 0x244B03: case 0xD4F278: 
    case 0x404E36: case 0xF01898: case 0xF0B3EC: case 0xA45E60: 
    case 0xF4CB52: case 0x2CD066: case 0x3408BC: case 0xD0D2B0: 
    case 0xB418D1: case 0xAC7F3E:
      return "Apple";
      
    // Samsung
    case 0xF8E079: case 0xE4E0C5: case 0xCC6C59: case 0x7404F1:
    case 0x04D6AA: case 0x0CFE45: case 0xD4A33D:
      return "Samsung";

    // Espressif
    case 0x30AEA4: case 0xFCF5C4: case 0x18FE34: case 0x240AC4:
    case 0x2C3AE8: case 0x308398: case 0x4C11AE: case 0x500291:
    case 0x545A16: case 0x58CF79: case 0x600194: case 0x64B708:
    case 0x68C63A: case 0x70B3D5: case 0x7C9EBD: case 0x807D3A:
    case 0x840D8E: case 0x84F3EB: case 0x9097D5: case 0x90E202:
    case 0x98CDAC: case 0xA020A6: case 0xA47B2C: case 0xAC67B2:
    case 0xC049EF: case 0xC44F33: case 0xC82786: case 0xD8F15B:
    case 0xE05A1B: case 0xE831CD: case 0xE868E7: case 0xE89F6D:
    case 0xECFABC: case 0xF412FA: case 0xF4CFA2: case 0x1097BD:
    case 0xACC048: case 0x40AE30: case 0x3C6AD2: case 0xEC2BEB:
      return "Espressif";

    // Intel
    case 0x0013E8: case 0x001E67: case 0x0024D7: case 0xA438CC:
    case 0x281878: case 0x3C6A9D: case 0x4851B5: case 0x705A0F:
      return "Intel";

    // Google
    case 0xA0999B: case 0x001A11: case 0xE4A7A0: case 0x3C5AB6:
      return "Google";

    // OnePlus/Oppo
    case 0xC0EEFB: case 0x980DE4: case 0x7C04D0:
      return "Oppo/OnePlus";

    // Xiaomi
    case 0x9009DF: case 0x640980: case 0x50EC50: case 0x286C07:
      return "Xiaomi";

    // Huawei
    case 0x001E10: case 0x00E0FC: case 0x24DF6A: case 0x283152:
      return "Huawei";

    // TP-Link
    case 0x50C7BF: case 0xEC086B: case 0xF4F26D:
      return "TP-Link";

    // Netgear
    case 0x000F66: case 0x00146C: case 0x001F33: case 0x0026F2:
      return "Netgear";

    default:
      // If Locally Administered bit is set, it's a randomized MAC address
      if (mac[0] & 0x02) {
        return "Randomized";
      }
      return "Unknown";
  }
}

// --- Button Control Function ---
void handleButton() {
  int buttonState = digitalRead(BUTTON_PIN);
  unsigned long now = millis();
  
  if (buttonState == LOW) { // Button is pressed (Active LOW)
    if (!buttonWasPressed) {
      buttonPressStart = now;
      buttonWasPressed = true;
    }
  } else { // Button is released
    if (buttonWasPressed) {
      unsigned long pressDuration = now - buttonPressStart;
      buttonWasPressed = false;
      
      if (pressDuration > 1500) {
        // --- LONG PRESS: Clear all tracked devices and reset auto-toggle ---
        for (int i = 0; i < MAX_CLIENTS; i++) {
          trackedClients[i].active = false;
        }
        for (int i = 0; i < MAX_APS; i++) {
          trackedAPs[i].active = false;
        }
        autoToggleMode = true; // Restore auto-toggle
        
        // Show reset screen
        canvas.fillScreen(FIX_BLACK);
        canvas.setCursor(15, 55);
        canvas.setTextColor(FIX_RED);
        canvas.print("--- RADAR RESET ---");
        canvas.setCursor(10, 75);
        canvas.setTextColor(FIX_WHITE);
        canvas.print("All tracked devices");
        canvas.setCursor(40, 87);
        canvas.print("cleared!");
        tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
        delay(1500);
        
        lastModeToggle = millis();
      } else if (pressDuration > 50) {
        // --- SHORT PRESS: Manual toggle, freeze auto-toggling ---
        autoToggleMode = false;
        
        if (currentMode == CLIENTS_MODE) {
          currentMode = APS_MODE;
        } else if (currentMode == APS_MODE) {
          currentMode = COMBINED_MODE;
        } else if (currentMode == COMBINED_MODE) {
          currentMode = RADAR_MODE;
        } else {
          currentMode = CLIENTS_MODE;
        }
        lastModeToggle = now;
      }
    }
  }
}

void processSerialCommand(String cmd) {
  cmd.trim();
  if (cmd.startsWith("TIME:")) {
    int h = cmd.substring(5, 7).toInt();
    int m = cmd.substring(8, 10).toInt();
    int s = cmd.substring(11, 13).toInt();
    if (h >= 0 && h < 24 && m >= 0 && m < 60 && s >= 0 && s < 60) {
      rtcHour = h;
      rtcMin = m;
      rtcSec = s;
      lastTimeUpdateMillis = millis();
      clockSynced = true;
      Serial.println("\r\n\033[32m[CLOCK] Time successfully synced!\033[0m");
    }
  } else if (cmd.equalsIgnoreCase("m 1") || cmd.equalsIgnoreCase("m radar")) {
    autoToggleMode = false;
    currentMode = RADAR_MODE;
    Serial.println("\r\n\033[32m[UI] Switched to RADAR view\033[0m");
  } else if (cmd.equalsIgnoreCase("m 2") || cmd.equalsIgnoreCase("m clients") || cmd.equalsIgnoreCase("m probes")) {
    autoToggleMode = false;
    currentMode = CLIENTS_MODE;
    Serial.println("\r\n\033[32m[UI] Switched to PROBES / CLIENTS view\033[0m");
  } else if (cmd.equalsIgnoreCase("m 3") || cmd.equalsIgnoreCase("m aps")) {
    autoToggleMode = false;
    currentMode = APS_MODE;
    Serial.println("\r\n\033[32m[UI] Switched to ACCESS POINTS view\033[0m");
  } else if (cmd.equalsIgnoreCase("m 4") || cmd.equalsIgnoreCase("m combined")) {
    autoToggleMode = false;
    currentMode = COMBINED_MODE;
    Serial.println("\r\n\033[32m[UI] Switched to COMBINED view\033[0m");
  } else if (cmd.equalsIgnoreCase("m") || cmd.equalsIgnoreCase("mode")) {
    autoToggleMode = false;
    if (currentMode == CLIENTS_MODE) currentMode = APS_MODE;
    else if (currentMode == APS_MODE) currentMode = COMBINED_MODE;
    else if (currentMode == COMBINED_MODE) currentMode = RADAR_MODE;
    else currentMode = CLIENTS_MODE;
    Serial.printf("\r\n\033[32m[UI] Mode cycled to view #%d\033[0m\r\n", (int)currentMode + 1);
  } else if (cmd.equalsIgnoreCase("l")) {
    liveSerialMonitor = !liveSerialMonitor;
    if (liveSerialMonitor) {
      hudSerialMode = false;
      jsonSerialMode = false;
    }
    Serial.printf("\r\n\033[35m[SYSTEM] Live serial log stream: %s\033[0m\r\n", liveSerialMonitor ? "ENABLED" : "DISABLED");
  } else if (cmd.equalsIgnoreCase("hud")) {
    hudSerialMode = !hudSerialMode;
    if (hudSerialMode) {
      liveSerialMonitor = false;
      jsonSerialMode = false;
    }
    Serial.printf("\r\n\033[32m[SYSTEM] Terminal HUD mode: %s\033[0m\r\n", hudSerialMode ? "ENABLED" : "DISABLED");
  } else if (cmd.equalsIgnoreCase("j") || cmd.equalsIgnoreCase("json")) {
    jsonSerialMode = !jsonSerialMode;
    if (jsonSerialMode) {
      liveSerialMonitor = false;
      hudSerialMode = false;
    }
    Serial.printf("\r\n\033[33m[SYSTEM] JSON Lines stream mode: %s\033[0m\r\n", jsonSerialMode ? "ENABLED" : "DISABLED");
  } else if (cmd.equalsIgnoreCase("db") || cmd.equalsIgnoreCase("export")) {
    exportJsonDatabase();
  } else if (cmd.equalsIgnoreCase("auto")) {
    autoToggleMode = !autoToggleMode;
    Serial.printf("\r\n\033[32m[UI] Auto-toggle: %s\033[0m\r\n", autoToggleMode ? "ENABLED" : "DISABLED");
  } else if (cmd.equalsIgnoreCase("h") || cmd.equalsIgnoreCase("?")) {
    Serial.println("\r\n\033[35m--- ESP32 WIFIMON Serial View & Control Commands ---\033[0m");
    Serial.println("  m 1 / m radar    : Switch TFT to RADAR view");
    Serial.println("  m 2 / m clients  : Switch TFT to PROBES view");
    Serial.println("  m 3 / m aps      : Switch TFT to ACCESS POINTS view");
    Serial.println("  m 4 / m combined : Switch TFT to COMBINED view");
    Serial.println("  m or mode        : Cycle to next TFT view");
    Serial.println("  hud              : Toggle Live Terminal HUD Dashboard");
    Serial.println("  j or json        : Toggle compact JSON Lines stream");
    Serial.println("  db or export     : Dump full active database as JSON");
    Serial.println("  l                : Toggle live text packet stream");
    Serial.println("  auto             : Toggle auto-view switching on/off");
    Serial.println("  TIME:HH:MM:SS    : Sync device time");
    Serial.println("----------------------------------------------------\r\n");
  }
}

void handleSerial() {
  static String inputBuffer = "";
  while (Serial.available() > 0) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      inputBuffer.trim();
      if (inputBuffer.length() > 0) {
        processSerialCommand(inputBuffer);
        inputBuffer = "";
      }
    } else {
      inputBuffer += c;
      if (inputBuffer.length() > 64) {
        inputBuffer = "";
      }
    }
  }
}

void getCurrentTime(int &h, int &m, int &s) {
  if (!clockSynced) {
    h = 0;
    m = 0;
    s = 0;
    return;
  }
  unsigned long elapsed = millis() - lastTimeUpdateMillis;
  unsigned long totalSeconds = rtcHour * 3600 + rtcMin * 60 + rtcSec + (elapsed / 1000);
  h = (totalSeconds / 3600) % 24;
  m = (totalSeconds / 60) % 60;
  s = totalSeconds % 60;
}

void drawHeader(uint16_t textColor, const char* title) {
  canvas.setCursor(0, 5);
  canvas.setTextColor(textColor);
  canvas.printf("CH:%d | %s", currentChannel, title);
  
  canvas.setCursor(112, 5);
  canvas.setTextColor(FIX_WHITE);
  if (clockSynced) {
    int h, m, s;
    getCurrentTime(h, m, s);
    int h12 = h % 12;
    if (h12 == 0) h12 = 12;
    const char* ampm = (h >= 12) ? "PM" : "AM";
    canvas.printf("%02d:%02d %s", h12, m, ampm);
  } else {
    canvas.print("--:-- --");
  }
  canvas.drawLine(0, 16, 160, 16, FIX_WHITE);
}

// Draws tracked clients and the SSIDs they are actively probing for
void drawClients() {
  canvas.fillScreen(FIX_BLACK);
  drawHeader(FIX_CYAN, "Probes");

  int cursorY = 22;
  int count = 0;
  
  // Copy and sort active client indices by RSSI
  int activeIndices[MAX_CLIENTS];
  int activeCount = 0;
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (trackedClients[i].active) activeIndices[activeCount++] = i;
  }

  for (int i = 0; i < activeCount - 1; i++) {
    for (int j = 0; j < activeCount - i - 1; j++) {
      if (trackedClients[activeIndices[j]].rssi < trackedClients[activeIndices[j+1]].rssi) {
        int temp = activeIndices[j];
        activeIndices[j] = activeIndices[j+1];
        activeIndices[j+1] = temp;
      }
    }
  }

  // Draw top 6 strongest clients
  for (int i = 0; i < activeCount && count < 6; i++) {
    ClientDevice& d = trackedClients[activeIndices[i]];
    
    // Set MAC line color based on RSSI strength
    if (d.rssi > -60) canvas.setTextColor(FIX_GREEN);
    else if (d.rssi > -80) canvas.setTextColor(FIX_YELLOW);
    else canvas.setTextColor(FIX_GRAY);

    canvas.setCursor(0, cursorY);
    canvas.printf("%02X:%02X:%02X:%02X:%02X:%02X", d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
    canvas.setCursor(115, cursorY);
    canvas.printf("%ddBm", d.rssi);

    // Draw the SSID the device is actively probing for, or device vendor
    canvas.setCursor(10, cursorY + 8);
    canvas.setTextColor(FIX_WHITE);
    if (strlen(d.probedSSID) > 0) {
      canvas.printf("> %-18s", d.probedSSID);
    } else {
      const char* vendor = getVendor(d.mac);
      canvas.printf("* %-18s", vendor);
    }

    cursorY += 17;
    count++;
  }

  // Push double-buffer frame to screen (Zero-Flicker)
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

// Draws detected Access Points, showing SSID, Encryption, Channel & Signal Strength
void drawAPs() {
  canvas.fillScreen(FIX_BLACK);
  drawHeader(FIX_YELLOW, "APs");

  int cursorY = 22;
  int count = 0;

  // Copy and sort active AP indices by RSSI
  int activeIndices[MAX_APS];
  int activeCount = 0;
  for (int i = 0; i < MAX_APS; i++) {
    if (trackedAPs[i].active) activeIndices[activeCount++] = i;
  }

  for (int i = 0; i < activeCount - 1; i++) {
    for (int j = 0; j < activeCount - i - 1; j++) {
      if (trackedAPs[activeIndices[j]].rssi < trackedAPs[activeIndices[j+1]].rssi) {
        int temp = activeIndices[j];
        activeIndices[j] = activeIndices[j+1];
        activeIndices[j+1] = temp;
      }
    }
  }

  // Draw top 6 strongest Access Points
  for (int i = 0; i < activeCount && count < 6; i++) {
    AccessPoint& d = trackedAPs[activeIndices[i]];

    // Highlight insecure (OPEN/WEP) networks in red
    if (strcmp(d.encryption, "OPEN") == 0 || strcmp(d.encryption, "WEP") == 0) {
      canvas.setTextColor(FIX_RED);
    } else {
      canvas.setTextColor(FIX_GREEN);
    }

    char ssidTrunc[13];
    strncpy(ssidTrunc, d.ssid, 12);
    ssidTrunc[12] = '\0';

    canvas.setCursor(0, cursorY);
    canvas.printf("%-12s [%s]", ssidTrunc, d.encryption);

    canvas.setCursor(10, cursorY + 8);
    canvas.setTextColor(FIX_GRAY);
    canvas.printf("CH%d | %ddBm", d.channel, d.rssi);

    cursorY += 17;
    count++;
  }

  // Push double-buffer frame to screen (Zero-Flicker)
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

// Draw the Combined Radar Screen showing all discovered MACs sorted by RSSI
void drawCombined() {
  canvas.fillScreen(FIX_BLACK);
  drawHeader(FIX_WHITE, "Combined");

  int cursorY = 22;
  int count = 0;

  // Build unified list of devices
  struct UnifiedDevice {
    uint8_t mac[6];
    int rssi;
    char name[33];
    bool isAP;
  };

  static UnifiedDevice devices[MAX_CLIENTS + MAX_APS];
  int totalDevices = 0;

  // Add active APs
  for (int i = 0; i < MAX_APS; i++) {
    if (trackedAPs[i].active) {
      UnifiedDevice& ud = devices[totalDevices++];
      memcpy(ud.mac, trackedAPs[i].bssid, 6);
      ud.rssi = trackedAPs[i].rssi;
      snprintf(ud.name, sizeof(ud.name), "AP:%s", trackedAPs[i].ssid);
      ud.isAP = true;
    }
  }

  // Add active Clients
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (trackedClients[i].active) {
      UnifiedDevice& ud = devices[totalDevices++];
      memcpy(ud.mac, trackedClients[i].mac, 6);
      ud.rssi = trackedClients[i].rssi;
      ud.isAP = false;
      
      if (strlen(trackedClients[i].probedSSID) > 0) {
        snprintf(ud.name, sizeof(ud.name), "CL:%s", trackedClients[i].probedSSID);
      } else {
        const char* vendor = getVendor(trackedClients[i].mac);
        snprintf(ud.name, sizeof(ud.name), "CL:%s", vendor);
      }
    }
  }

  // Sort unified list indices by RSSI (bubble sort)
  int indices[MAX_CLIENTS + MAX_APS];
  for (int i = 0; i < totalDevices; i++) indices[i] = i;

  for (int i = 0; i < totalDevices - 1; i++) {
    for (int j = 0; j < totalDevices - i - 1; j++) {
      if (devices[indices[j]].rssi < devices[indices[j+1]].rssi) {
        int temp = indices[j];
        indices[j] = indices[j+1];
        indices[j+1] = temp;
      }
    }
  }

  // Draw top 6 strongest devices in range
  for (int i = 0; i < totalDevices && count < 6; i++) {
    UnifiedDevice& d = devices[indices[i]];

    if (d.isAP) {
      canvas.setTextColor(FIX_YELLOW); // Yellow for Access Points
    } else {
      canvas.setTextColor(FIX_CYAN); // Cyan for Client Devices
    }

    canvas.setCursor(0, cursorY);
    canvas.printf("%02X:%02X:%02X:%02X:%02X:%02X", d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
    
    canvas.setCursor(115, cursorY);
    canvas.printf("%ddBm", d.rssi);

    // Draw device classification name below it
    canvas.setCursor(10, cursorY + 8);
    canvas.setTextColor(FIX_WHITE);
    
    char nameTrunc[22];
    strncpy(nameTrunc, d.name, 21);
    nameTrunc[21] = '\0';
    canvas.print(nameTrunc);

    cursorY += 17;
    count++;
  }

  // Push double-buffer frame to screen
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

// Draw visual Radar screen with rotating sweep line & RSSI distance blips
void drawRadar() {
  canvas.fillScreen(FIX_BLACK);
  drawHeader(FIX_GREEN, "RADAR");

  static float radarSweepAngle = 0.0f;
  radarSweepAngle += 15.0f;
  if (radarSweepAngle >= 360.0f) radarSweepAngle -= 360.0f;

  const int radarCenterX = 40;
  const int radarCenterY = 72;
  const int radarRadius = 38;

  // Draw Concentric Rings (Distance / RSSI circles)
  canvas.drawCircle(radarCenterX, radarCenterY, radarRadius, FIX_GREEN);
  canvas.drawCircle(radarCenterX, radarCenterY, radarRadius * 2 / 3, FIX_GRAY);
  canvas.drawCircle(radarCenterX, radarCenterY, radarRadius / 3, FIX_GRAY);

  // Draw Radar Crosshairs
  canvas.drawFastHLine(radarCenterX - radarRadius, radarCenterY, radarRadius * 2, FIX_GRAY);
  canvas.drawFastVLine(radarCenterX, radarCenterY - radarRadius, radarRadius * 2, FIX_GRAY);

  // Draw Rotating Sweep Line
  float rad = radarSweepAngle * 0.0174532925f; // DEG_TO_RAD
  int sweepX = radarCenterX + (int)(cos(rad) * radarRadius);
  int sweepY = radarCenterY + (int)(sin(rad) * radarRadius);
  canvas.drawLine(radarCenterX, radarCenterY, sweepX, sweepY, FIX_GREEN);

  // Vertical Divider line between Radar (Left) and Data Panel (Right)
  canvas.drawFastVLine(82, 16, 112, FIX_WHITE);

  // Build unified list of active devices (APs + Clients) sorted by RSSI
  struct RadarItem {
    uint8_t mac[6];
    int rssi;
    float dist;
    char label[12];
    uint16_t color;
    bool isAP;
  };
  static RadarItem items[MAX_CLIENTS + MAX_APS];
  int totalCount = 0;

  // 1. Add active Access Points
  for (int i = 0; i < MAX_APS; i++) {
    if (trackedAPs[i].active && totalCount < (MAX_CLIENTS + MAX_APS)) {
      RadarItem& item = items[totalCount++];
      memcpy(item.mac, trackedAPs[i].bssid, 6);
      item.rssi = trackedAPs[i].rssi;
      item.dist = pow(10.0f, (-40.0f - (float)item.rssi) / 27.0f);
      item.isAP = true;
      if (strlen(trackedAPs[i].ssid) > 0) {
        snprintf(item.label, sizeof(item.label), "%.6s", trackedAPs[i].ssid);
      } else {
        snprintf(item.label, sizeof(item.label), "%02X%02X", item.mac[4], item.mac[5]);
      }
      item.color = FIX_YELLOW; // Yellow for Access Points
    }
  }

  // 2. Add active Clients
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (trackedClients[i].active && totalCount < (MAX_CLIENTS + MAX_APS)) {
      RadarItem& item = items[totalCount++];
      memcpy(item.mac, trackedClients[i].mac, 6);
      item.rssi = trackedClients[i].rssi;
      item.dist = pow(10.0f, (-40.0f - (float)item.rssi) / 27.0f);
      item.isAP = false;
      if (strlen(trackedClients[i].probedSSID) > 0) {
        snprintf(item.label, sizeof(item.label), "%.6s", trackedClients[i].probedSSID);
      } else {
        const char* vendor = getVendor(item.mac);
        snprintf(item.label, sizeof(item.label), "%.6s", vendor);
      }
      item.color = (item.rssi > -60) ? FIX_GREEN : ((item.rssi > -80) ? FIX_CYAN : FIX_RED);
    }
  }

  // Sort unified list by RSSI
  for (int i = 0; i < totalCount - 1; i++) {
    for (int j = 0; j < totalCount - i - 1; j++) {
      if (items[j].rssi < items[j + 1].rssi) {
        RadarItem temp = items[j];
        items[j] = items[j + 1];
        items[j + 1] = temp;
      }
    }
  }

  // Draw Blips on Radar (Circles for APs, Solid Dots for Clients)
  for (int i = 0; i < totalCount; i++) {
    int normR = map(constrain(items[i].rssi, -95, -30), -95, -30, radarRadius, 4);
    uint32_t angleHash = (items[i].mac[3] ^ items[i].mac[4] ^ items[i].mac[5]) * 360 / 256;
    float bRad = angleHash * 0.0174532925f;
    int bx = radarCenterX + (int)(cos(bRad) * normR);
    int by = radarCenterY + (int)(sin(bRad) * normR);

    if (items[i].isAP) {
      canvas.drawCircle(bx, by, 3, items[i].color); // Open circle for APs
    } else {
      canvas.fillCircle(bx, by, 2, items[i].color); // Solid dot for Clients
    }
  }

  // Right Side Data Panel: Header & top 4 devices
  canvas.setCursor(86, 20);
  canvas.setTextColor(FIX_CYAN);
  canvas.print("CLR DIST MAC");
  canvas.drawFastHLine(86, 30, 74, FIX_GRAY);

  int yPos = 34;
  for (int i = 0; i < totalCount && i < 4; i++) {
    // Blip color indicator (Circle outline for AP, Solid rect for Client)
    if (items[i].isAP) {
      canvas.drawCircle(88, yPos + 4, 3, items[i].color);
    } else {
      canvas.fillRect(86, yPos + 2, 5, 5, items[i].color);
    }

    // Distance in meters
    canvas.setCursor(94, yPos);
    canvas.setTextColor(FIX_WHITE);
    if (items[i].dist < 10.0f) {
      canvas.printf("%3.1fm", items[i].dist);
    } else {
      canvas.printf("%2.0fm ", items[i].dist);
    }

    // MAC suffix label
    canvas.setCursor(132, yPos);
    canvas.setTextColor(items[i].isAP ? FIX_YELLOW : FIX_GREEN);
    canvas.print(items[i].label);

    yPos += 22;
  }

  // Push double-buffer frame to screen
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

// Render non-spamming Live Terminal HUD Dashboard
void drawConsoleHUD() {
    if (!hudSerialMode) return;
    
    // ANSI clear screen & move cursor to home (top left)
    Serial.print("\033[2J\033[H");

    int h = 0, m = 0, s = 0;
    getCurrentTime(h, m, s);
    uint32_t uptimeSec = millis() / 1000;
    uint32_t upH = uptimeSec / 3600;
    uint32_t upM = (uptimeSec / 60) % 60;
    uint32_t upS = uptimeSec % 60;

    // Header
    Serial.println("\033[1;36m========================================================================================\033[0m");
    Serial.printf("\033[1;37m [ESP32 WIFIMON HUD] Time: %02d:%02d:%02d | Uptime: %02lu:%02lu:%02lu | Heap: %u KB | CH: %d\033[0m\r\n",
                  h, m, s, upH, upM, upS, ESP.getFreeHeap() / 1024, currentChannel);
    Serial.println("\033[1;36m========================================================================================\033[0m");
    Serial.println("\033[1;33m TOP CLOSEST DEVICES (Proximity Sorted):\033[0m");
    Serial.println(" --------------------------------------------------------------------------------------");
    Serial.printf(" \033[1;37m%-11s %-4s %-18s %-14s %-8s %-6s %-12s %s\033[0m\r\n",
                  "PROXIMITY", "TYPE", "MAC/BSSID", "VENDOR/NAME", "RSSI", "DIST", "SIGNAL BAR", "TARGET SSID / SECURITY");
    Serial.println(" --------------------------------------------------------------------------------------");

    // Unified Device List
    struct HUDDevice {
        uint8_t mac[6];
        int rssi;
        float dist;
        char name[18];
        char detail[33];
        bool isAP;
    };
    static HUDDevice items[MAX_CLIENTS + MAX_APS];
    int totalCount = 0;
    int openAPCount = 0;

    // 1. APs
    for (int i = 0; i < MAX_APS; i++) {
        if (trackedAPs[i].active && totalCount < (MAX_CLIENTS + MAX_APS)) {
            HUDDevice& d = items[totalCount++];
            memcpy(d.mac, trackedAPs[i].bssid, 6);
            d.rssi = trackedAPs[i].rssi;
            d.dist = pow(10.0f, (-40.0f - (float)d.rssi) / 27.0f);
            d.isAP = true;
            strncpy(d.name, trackedAPs[i].ssid, 17);
            d.name[17] = '\0';
            snprintf(d.detail, sizeof(d.detail), "[%s]", trackedAPs[i].encryption);

            if (strcmp(trackedAPs[i].encryption, "OPEN") == 0 || strcmp(trackedAPs[i].encryption, "WEP") == 0) {
                openAPCount++;
            }
        }
    }

    // 2. Clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (trackedClients[i].active && totalCount < (MAX_CLIENTS + MAX_APS)) {
            HUDDevice& d = items[totalCount++];
            memcpy(d.mac, trackedClients[i].mac, 6);
            d.rssi = trackedClients[i].rssi;
            d.dist = pow(10.0f, (-40.0f - (float)d.rssi) / 27.0f);
            d.isAP = false;
            const char* vendor = getVendor(d.mac);
            strncpy(d.name, vendor, 17);
            d.name[17] = '\0';

            if (strlen(trackedClients[i].probedSSID) > 0) {
                snprintf(d.detail, sizeof(d.detail), "> %s", trackedClients[i].probedSSID);
            } else {
                d.detail[0] = '\0';
            }
        }
    }

    // Sort by RSSI
    for (int i = 0; i < totalCount - 1; i++) {
        for (int j = 0; j < totalCount - i - 1; j++) {
            if (items[j].rssi < items[j + 1].rssi) {
                HUDDevice temp = items[j];
                items[j] = items[j + 1];
                items[j + 1] = temp;
            }
        }
    }

    // Render top 8
    for (int i = 0; i < totalCount && i < 8; i++) {
        HUDDevice& d = items[i];
        int sigPct = rssiToPercentage(d.rssi);

        const char* proxTag = "\033[31m[FAR]      \033[0m";
        if (d.dist < 3.0f) {
            proxTag = "\033[1;32m[IMMEDIATE]\033[0m";
        } else if (d.dist < 10.0f) {
            proxTag = "\033[1;33m[NEARBY]   \033[0m";
        }

        char sigBar[16];
        renderSignalBar(sigPct, sigBar, sizeof(sigBar));

        const char* typeColor = d.isAP ? "\033[1;35mAP\033[0m" : "\033[1;36mCL\033[0m";
        const char* rssiColor = (d.rssi > -60) ? "\033[32m" : ((d.rssi > -80) ? "\033[33m" : "\033[31m");

        Serial.printf(" %s %s %02X:%02X:%02X:%02X:%02X:%02X %-14s %s%3ddBm\033[0m %4.1fm \033[32m%-12s\033[0m %s\r\n",
                      proxTag, typeColor,
                      d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5],
                      d.name, rssiColor, d.rssi, d.dist, sigBar, d.detail);
    }

    if (totalCount == 0) {
        Serial.println("  \033[33mScanning... No active devices detected on current channel.\033[0m");
    }

    // Footer Stats
    Serial.println("\033[1;36m========================================================================================\033[0m");
    Serial.printf(" \033[1;37mActive Clients: %d | Active APs: %d | Vulnerable/Open APs: %s%d\033[1;37m | HUD Auto-Refresh: 1s\033[0m\r\n",
                  MAX_CLIENTS, MAX_APS, (openAPCount > 0) ? "\033[1;31m" : "\033[32m", openAPCount);
    Serial.println("\033[1;36m========================================================================================\033[0m");
    Serial.println(" \033[90mCommands: 'hud' (toggle HUD), 'l' (raw stream), 'm 1-4' (TFT views), 'h' (help)\033[0m\r\n");
}

void loop() {
  handleButton();
  handleSerial();
  unsigned long now = millis();

  // 1. Channel Hopping (every 300ms)
  if (now - lastChannelChange > 300) {
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelChange = now;
  }

  // 2. Age out active records if not seen in 30 seconds
  for (int i = 0; i < MAX_CLIENTS; i++) {
     if (trackedClients[i].active && (now - trackedClients[i].lastSeen > 30000)) {
         trackedClients[i].active = false;
     }
  }
  for (int i = 0; i < MAX_APS; i++) {
     if (trackedAPs[i].active && (now - trackedAPs[i].lastSeen > 30000)) {
         trackedAPs[i].active = false;
     }
  }

  // 3. Auto-Toggle display mode every 5 seconds (if enabled)
  if (autoToggleMode && (now - lastModeToggle > 5000)) {
    if (currentMode == CLIENTS_MODE) {
      currentMode = APS_MODE;
    } else if (currentMode == APS_MODE) {
      currentMode = COMBINED_MODE;
    } else if (currentMode == COMBINED_MODE) {
      currentMode = RADAR_MODE;
    } else {
      currentMode = CLIENTS_MODE;
    }
    lastModeToggle = now;
  }

  // 4. Update the screen (every 250ms for smooth animations)
  static unsigned long lastUIDraw = 0;
  if (now - lastUIDraw > 250) {
    if (currentMode == CLIENTS_MODE) {
      drawClients();
    } else if (currentMode == APS_MODE) {
      drawAPs();
    } else if (currentMode == COMBINED_MODE) {
      drawCombined();
    } else {
      drawRadar();
    }
    lastUIDraw = now;
  }

  // 5. Refresh Terminal Console HUD (every 1 second)
  static unsigned long lastHUDDraw = 0;
  if (now - lastHUDDraw >= 1000) {
    drawConsoleHUD();
    lastHUDDraw = now;
  }
}