#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <WiFi.h>
#include <esp_wifi.h>

// --- TFT Pin Definitions ---
#define TFT_SCK   18
#define TFT_MOSI  23
#define TFT_RST   4
#define TFT_DC    2
#define TFT_CS    15

// Initialize the ST7735 screen
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

enum DisplayMode { CLIENTS_MODE, APS_MODE, COMBINED_MODE };
DisplayMode currentMode = CLIENTS_MODE;
unsigned long lastModeToggle = 0;

// OUI Lookup to find Device Manufacturer from the first 3 bytes of the MAC address
const char* getVendor(uint8_t* mac) {
  uint32_t oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
  switch (oui) {
    case 0x5C013B: case 0xD8A01D: case 0xBCDDC2: case 0x002608: 
    case 0x88E9FE: case 0x94E979: case 0x244B03: case 0xD4F278: 
    case 0x404E36: case 0xF01898: case 0xF0B3EC: case 0xA45E60: 
    case 0xF4CB52: case 0x2CD066: case 0x3408BC: case 0xD0D2B0: 
    case 0xB418D1: case 0xAC7F3E:
      return "Apple";
    case 0xF8E079: case 0xE4E0C5: case 0xCC6C59: case 0x7404F1:
    case 0x04D6AA: case 0x0CFE45: case 0xD4A33D:
      return "Samsung";
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
    case 0x0013E8: case 0x001E67: case 0x0024D7: case 0xA438CC:
    case 0x281878: case 0x3C6A9D: case 0x4851B5: case 0x705A0F:
      return "Intel";
    case 0xA0999B: case 0x001A11: case 0xE4A7A0: case 0x3C5AB6:
      return "Google";
    case 0xC0EEFB: case 0x980DE4: case 0x7C04D0:
      return "Oppo/OnePlus";
    case 0x9009DF: case 0x640980: case 0x50EC50: case 0x286C07:
      return "Xiaomi";
    case 0x001E10: case 0x00E0FC: case 0x24DF6A: case 0x283152:
      return "Huawei";
    case 0x50C7BF: case 0xEC086B: case 0xF4F26D:
      return "TP-Link";
    case 0x000F66: case 0x00146C: case 0x001F33: case 0x0026F2:
      return "Netgear";
    default:
      if (mac[0] & 0x02) return "Randomized";
      return "Unknown";
  }
}

// Updates or inserts a client device in the tracker list (with Serial debugging)
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
  
  bool ssidAdded = false;
  if (ssid && strlen(ssid) > 0) {
    // Only update if it's a new SSID or changed
    if (strcmp(trackedClients[insertIdx].probedSSID, ssid) != 0) {
      strncpy(trackedClients[insertIdx].probedSSID, ssid, 32);
      trackedClients[insertIdx].probedSSID[32] = '\0';
      ssidAdded = true;
    }
  } else if (isNew) {
    trackedClients[insertIdx].probedSSID[0] = '\0';
  }

  trackedClients[insertIdx].lastSeen = now;
  trackedClients[insertIdx].active = true;

  // --- SERIAL DEBUGGING OUTPUT ---
  if (isNew || ssidAdded) {
    Serial.printf("[CLIENT] %s MAC: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d dBm",
                  isNew ? "DISCOVERED" : "UPDATED   ",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rssi);
    if (strlen(trackedClients[insertIdx].probedSSID) > 0) {
      Serial.printf(" | Probed SSID: %s\n", trackedClients[insertIdx].probedSSID);
    } else {
      Serial.printf(" | Vendor: %s\n", getVendor(mac));
    }
  }
}

// Updates or inserts an Access Point in the tracker list (with Serial debugging)
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

  // --- SERIAL DEBUGGING OUTPUT ---
  if (isNew) {
    Serial.printf("[AP] DISCOVERED BSSID: %02X:%02X:%02X:%02X:%02X:%02X | SSID: %-15s | CH: %d | Enc: %s | RSSI: %d dBm\n",
                  bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                  ssid, trackedAPs[insertIdx].channel, enc, rssi);
  }
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

    if (subtype == 0x04) { // Probe Request
      char ssid[33] = {0};
      int offset = 24;

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
    else if (subtype == 0x08) { // Beacon Frame
      char ssid[33] = {0};
      int offset = 36;

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

      // Get channel from Tag 3
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

      // Parse capabilities
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

          if (tag_num == 48) {
            hasWpa2 = true;
          } else if (tag_num == 221) {
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
  else if (typeVal == 0x02) {
    uint8_t flags = payload[1];
    uint8_t toDS = flags & 0x01;
    uint8_t fromDS = (flags & 0x02) >> 1;
    uint8_t *clientMac = NULL;

    if (toDS && !fromDS) {
      clientMac = payload + 10;
    } else if (!toDS && fromDS) {
      clientMac = payload + 4;
    } else if (!toDS && !fromDS) {
      clientMac = payload + 10;
    }

    if (clientMac) {
      if (clientMac[0] & 0x01) return;
      if (clientMac[0] == 0x00 && clientMac[1] == 0x00 && clientMac[2] == 0x00) return;
      update_client(clientMac, rssi, "", now);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n==========================================");
  Serial.println("[SYSTEM] ESP32 Wi-Fi Cybersecurity Sniffer");
  Serial.println("[SYSTEM] Diagnostic Serial Debug Mode: ACTIVE");
  Serial.println("==========================================\n");

  // Initialize screen
  tft.initR(INITR_BLACKTAB); 
  tft.setRotation(1);
  tft.fillScreen(FIX_BLACK);
  
  tft.setTextColor(FIX_GREEN);
  tft.setCursor(0, 5);
  tft.println("Auditor Sniffer Live...");
  delay(1000);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

// Draws tracked clients and the SSIDs they are actively probing for
void drawClients() {
  canvas.fillScreen(FIX_BLACK);
  
  canvas.setCursor(0, 5);
  canvas.setTextColor(FIX_CYAN);
  canvas.print("CH:"); canvas.print(currentChannel);
  canvas.print(" | Client Probes");
  canvas.drawLine(0, 16, 160, 16, FIX_WHITE);

  int cursorY = 22;
  int count = 0;
  
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

  for (int i = 0; i < activeCount && count < 6; i++) {
    ClientDevice& d = trackedClients[activeIndices[i]];
    
    if (d.rssi > -60) canvas.setTextColor(FIX_GREEN);
    else if (d.rssi > -80) canvas.setTextColor(FIX_YELLOW);
    else canvas.setTextColor(FIX_GRAY);

    canvas.setCursor(0, cursorY);
    canvas.printf("%02X:%02X:%02X:%02X:%02X:%02X", d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
    canvas.setCursor(115, cursorY);
    canvas.printf("%ddBm", d.rssi);

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

  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

// Draws detected Access Points, showing SSID, Encryption, Channel & Signal Strength
void drawAPs() {
  canvas.fillScreen(FIX_BLACK);
  
  canvas.setCursor(0, 5);
  canvas.setTextColor(FIX_YELLOW);
  canvas.print("CH:"); canvas.print(currentChannel);
  canvas.print(" | Access Points");
  canvas.drawLine(0, 16, 160, 16, FIX_WHITE);

  int cursorY = 22;
  int count = 0;

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

  for (int i = 0; i < activeCount && count < 6; i++) {
    AccessPoint& d = trackedAPs[activeIndices[i]];

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

  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

// Draw the Combined Radar Screen showing all discovered MACs sorted by RSSI
void drawCombined() {
  canvas.fillScreen(FIX_BLACK);
  
  canvas.setCursor(0, 5);
  canvas.setTextColor(FIX_WHITE);
  canvas.print("CH:"); canvas.print(currentChannel);
  canvas.print(" | Combined Radar");
  canvas.drawLine(0, 16, 160, 16, FIX_WHITE);

  int cursorY = 22;
  int count = 0;

  struct UnifiedDevice {
    uint8_t mac[6];
    int rssi;
    char name[33];
    bool isAP;
  };

  static UnifiedDevice devices[MAX_CLIENTS + MAX_APS];
  int totalDevices = 0;

  for (int i = 0; i < MAX_APS; i++) {
    if (trackedAPs[i].active) {
      UnifiedDevice& ud = devices[totalDevices++];
      memcpy(ud.mac, trackedAPs[i].bssid, 6);
      ud.rssi = trackedAPs[i].rssi;
      snprintf(ud.name, sizeof(ud.name), "AP:%s", trackedAPs[i].ssid);
      ud.isAP = true;
    }
  }

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

  for (int i = 0; i < totalDevices && count < 6; i++) {
    UnifiedDevice& d = devices[indices[i]];

    if (d.isAP) {
      canvas.setTextColor(FIX_YELLOW);
    } else {
      canvas.setTextColor(FIX_CYAN);
    }

    canvas.setCursor(0, cursorY);
    canvas.printf("%02X:%02X:%02X:%02X:%02X:%02X", d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
    canvas.setCursor(115, cursorY);
    canvas.printf("%ddBm", d.rssi);

    canvas.setCursor(10, cursorY + 8);
    canvas.setTextColor(FIX_WHITE);
    
    char nameTrunc[22];
    strncpy(nameTrunc, d.name, 21);
    nameTrunc[21] = '\0';
    canvas.print(nameTrunc);

    cursorY += 17;
    count++;
  }

  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

void loop() {
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

  // 3. Auto-Toggle display mode every 5 seconds (alternates between Clients, APs, and Combined)
  if (now - lastModeToggle > 5000) {
    if (currentMode == CLIENTS_MODE) {
      currentMode = APS_MODE;
    } else if (currentMode == APS_MODE) {
      currentMode = COMBINED_MODE;
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
    } else {
      drawCombined();
    }
    lastUIDraw = now;
  }
}
