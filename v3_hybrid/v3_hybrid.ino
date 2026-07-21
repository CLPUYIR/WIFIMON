#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <time.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// Color Definitions (5-6-5 RGB)
#define FIX_BLACK   0x0000
#define FIX_BLUE    0x001F
#define FIX_RED     0xF800
#define FIX_GREEN   0x07E0
#define FIX_CYAN    0x07FF
#define FIX_MAGENTA 0xF81F
#define FIX_YELLOW  0xFFE0
#define FIX_WHITE   0xFFFF
#define FIX_GRAY    0x7BEF
#define FIX_DARKGRAY 0x31E6

// Pin Definitions
#define TFT_SCK   18
#define TFT_MISO  19
#define TFT_MOSI  23
#define TFT_RST   4
#define TFT_DC    2
#define TFT_CS    15
#define BUTTON_PIN 0

// Hardware Display & Offscreen Double-Buffer Canvas
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCK, TFT_RST);
GFXcanvas16 canvas(160, 128);

// Storage & Time
Preferences preferences;
int rtcHour = 8, rtcMin = 41, rtcSec = 0;
unsigned long lastTimeUpdateMillis = 0;
bool clockSynced = false;

// Hybrid Radar Modes (20-Second Auto Cycle)
enum HybridRadarMode { RADAR_WIFI, RADAR_BLE };
HybridRadarMode currentRadarMode = RADAR_WIFI;
unsigned long lastRadarModeToggle = 0;

// Device Capacities
#define MAX_CLIENTS 30
#define MAX_APS     30
#define MAX_BLE_DEVICES 30

// --- Data Structures ---
struct ClientDevice {
  uint8_t mac[6];
  int rssi;
  char probedSSID[33];
  unsigned long lastSeen;
  bool active;
};

struct APDevice {
  uint8_t bssid[6];
  char ssid[33];
  int rssi;
  uint8_t channel;
  char encryption[8];
  unsigned long lastSeen;
  bool active;
};

struct BLEDeviceRecord {
  uint8_t mac[6];
  int rssi;
  float dist;
  char name[17];
  char vendor[10];
  char devType[8]; // "AUDIO", "WATCH", "TAG", "PHONE", "COMP", "ESP32", "BEACON"
  uint16_t companyId;
  unsigned long lastSeen;
  bool active;
};

ClientDevice trackedClients[MAX_CLIENTS];
APDevice trackedAPs[MAX_APS];
BLEDeviceRecord trackedBLE[MAX_BLE_DEVICES];

BLEScan* pBLEScan = nullptr;

uint8_t currentChannel = 1;
unsigned long lastChannelChange = 0;

// Targeting & HUD
uint8_t target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
bool targetLockActive = false;
float radarSweepAngle = 0.0f;
bool crtFilterEnabled = false;
int marqueeX = 160;
char marqueeText[128] = "WIFIMON V3 Hybrid 2.4GHz Airspace Monitor";

// OUI Lookup to find Device Manufacturer from the first 3 bytes of the MAC address
const char* getVendor(uint8_t* mac) {
  uint32_t oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
  switch (oui) {
    case 0x5C013B: case 0xD8A01D: case 0xBCDDC2: case 0x002608: 
    case 0x88E9FE: case 0x94E979: case 0x244B03: case 0xD4F278: return "APL";
    case 0xEC1F72: case 0x9852B1: case 0x0021D2: case 0xCC3A61: return "SAM";
    case 0x240AC4: case 0x30AEA4: case 0x2462AB: case 0xA4CF12: return "ESP";
    case 0x9499C7: case 0x9801A7: case 0xE82A44: case 0xF4F5D8: return "GGL";
    case 0x0013E8: case 0x001C10: case 0x0024D7: case 0x3C970E: return "INT";
    case 0x7427EA: case 0xC825E1: case 0xDC094C: case 0xFC7C02: return "OPP";
    case 0x640980: case 0x9C99A0: case 0xACF7F3: case 0xC8D719: return "XIA";
    case 0x000AF5: case 0x0014D1: case 0x001D0F: case 0x14CF92: return "TPL";
    default: return "RND";
  }
}

// Security Assessment & Airspace Threat Grade Calculator
int calculateThreatScore(char &gradeOut) {
  int openAPs = 0;
  int totalAPs = 0;
  int probeRequests = 0;

  for (int i = 0; i < MAX_APS; i++) {
    if (trackedAPs[i].active) {
      totalAPs++;
      if (strcmp(trackedAPs[i].encryption, "OPEN") == 0 || strcmp(trackedAPs[i].encryption, "WEP") == 0) {
        openAPs++;
      }
    }
  }

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (trackedClients[i].active && strlen(trackedClients[i].probedSSID) > 0) {
      probeRequests++;
    }
  }

  int score = 100;
  score -= (openAPs * 25);
  score -= (probeRequests * 4);
  if (score < 0) score = 0;

  if (score >= 90) gradeOut = 'A';
  else if (score >= 75) gradeOut = 'B';
  else if (score >= 60) gradeOut = 'C';
  else if (score >= 40) gradeOut = 'D';
  else gradeOut = 'F';

  return score;
}

// Track and update Wi-Fi clients
void update_client(uint8_t* mac, int rssi, const char* ssid, unsigned long now) {
  int foundIdx = -1;
  int emptyIdx = -1;
  unsigned long oldestTime = ULONG_MAX;
  int oldestIdx = 0;

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

  memcpy(trackedClients[insertIdx].mac, mac, 6);
  trackedClients[insertIdx].rssi = rssi;
  if (ssid && strlen(ssid) > 0) {
    strncpy(trackedClients[insertIdx].probedSSID, ssid, 32);
    trackedClients[insertIdx].probedSSID[32] = '\0';
    snprintf(marqueeText, sizeof(marqueeText), "[!] %02X:%02X:%02X -> SSID: %s", mac[3], mac[4], mac[5], ssid);
    marqueeX = 160;
  }
  trackedClients[insertIdx].lastSeen = now;
  trackedClients[insertIdx].active = true;
}

// Track and update Access Points
void update_ap(uint8_t* bssid, const char* ssid, int rssi, uint8_t channel, const char* enc, unsigned long now) {
  int foundIdx = -1;
  int emptyIdx = -1;
  unsigned long oldestTime = ULONG_MAX;
  int oldestIdx = 0;

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

  memcpy(trackedAPs[insertIdx].bssid, bssid, 6);
  strncpy(trackedAPs[insertIdx].ssid, ssid, 32);
  trackedAPs[insertIdx].ssid[32] = '\0';
  trackedAPs[insertIdx].rssi = rssi;
  trackedAPs[insertIdx].channel = channel;
  strncpy(trackedAPs[insertIdx].encryption, enc, 7);
  trackedAPs[insertIdx].encryption[7] = '\0';
  trackedAPs[insertIdx].lastSeen = now;
  trackedAPs[insertIdx].active = true;
}

// Track and update Bluetooth BLE devices with vendor classification
void update_ble(uint8_t* mac, int rssi, const char* name, const char* vendor, uint16_t companyId, unsigned long now) {
  int foundIdx = -1;
  int emptyIdx = -1;
  unsigned long oldestTime = ULONG_MAX;
  int oldestIdx = 0;

  for (int i = 0; i < MAX_BLE_DEVICES; i++) {
    if (trackedBLE[i].active) {
      if (memcmp(trackedBLE[i].mac, mac, 6) == 0) {
        foundIdx = i;
        break;
      }
      if (trackedBLE[i].lastSeen < oldestTime) {
        oldestTime = trackedBLE[i].lastSeen;
        oldestIdx = i;
      }
    } else if (emptyIdx == -1) {
      emptyIdx = i;
    }
  }

  int insertIdx = (foundIdx >= 0) ? foundIdx : ((emptyIdx >= 0) ? emptyIdx : oldestIdx);

  memcpy(trackedBLE[insertIdx].mac, mac, 6);
  trackedBLE[insertIdx].rssi = rssi;
  trackedBLE[insertIdx].dist = pow(10.0f, (-40.0f - (float)rssi) / 27.0f);
  trackedBLE[insertIdx].companyId = companyId;

  if (name && strlen(name) > 0) {
    strncpy(trackedBLE[insertIdx].name, name, 16);
    trackedBLE[insertIdx].name[16] = '\0';
  } else {
    snprintf(trackedBLE[insertIdx].name, sizeof(trackedBLE[insertIdx].name), "BT-%02X%02X%02X", mac[3], mac[4], mac[5]);
  }

  strncpy(trackedBLE[insertIdx].vendor, vendor, 9);
  trackedBLE[insertIdx].vendor[9] = '\0';

  // Device type classification
  const char* typeStr = "BLE";
  if (companyId == 0x004C) {
    if (strstr(name, "AirPods") || strstr(name, "Beats")) typeStr = "AUDIO";
    else if (strstr(name, "Watch")) typeStr = "WATCH";
    else typeStr = "APPLE";
  } else if (companyId == 0x0075) {
    if (strstr(name, "Buds")) typeStr = "AUDIO";
    else if (strstr(name, "Watch") || strstr(name, "Galaxy")) typeStr = "WATCH";
    else typeStr = "SAMSG";
  } else if (companyId == 0x00E0) {
    typeStr = "GGL";
  } else if (companyId == 0x0041) {
    typeStr = "TAG";
  } else if (companyId == 0x02E5) {
    typeStr = "ESP32";
  } else {
    if (strstr(name, "Audio") || strstr(name, "Buds") || strstr(name, "Head") || strstr(name, "Sound") || strstr(name, "JBL") || strstr(name, "Sony")) typeStr = "AUDIO";
    else if (strstr(name, "Watch") || strstr(name, "Band") || strstr(name, "Fit")) typeStr = "WATCH";
    else if (strstr(name, "Tag") || strstr(name, "Beacon")) typeStr = "BEACON";
  }
  strncpy(trackedBLE[insertIdx].devType, typeStr, 7);
  trackedBLE[insertIdx].devType[7] = '\0';

  trackedBLE[insertIdx].lastSeen = now;
  trackedBLE[insertIdx].active = true;
}

// Sniffer callback parses 802.11 management frames and active data frames
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
  int len = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t *payload = pkt->payload;
  uint8_t frameControl = payload[0];
  uint8_t typeVal = (frameControl & 0x0C) >> 2;
  uint8_t subtype = (frameControl & 0xF0) >> 4;
  int rssi = pkt->rx_ctrl.rssi;
  unsigned long now = millis();

  // MANAGEMENT FRAMES (type = 0x00)
  if (typeVal == 0x00) {
    uint8_t *sa = payload + 10;
    if ((sa[0] == 0xFF && sa[1] == 0xFF) || (sa[0] == 0x00 && sa[1] == 0x00)) return;

    if (subtype == 0x04) { // Probe Request
      char ssid[33] = {0};
      int offset = 24;
      while (offset + 2 <= len) {
        uint8_t tag_num = payload[offset];
        uint8_t tag_len = payload[offset + 1];
        if (offset + 2 + tag_len > len) break;

        if (tag_num == 0) {
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

        if (tag_num == 0) {
          int copy_len = (tag_len > 32) ? 32 : tag_len;
          memcpy(ssid, payload + offset + 2, copy_len);
          ssid[copy_len] = '\0';
          break;
        }
        offset += 2 + tag_len;
      }

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

          if (tag_num == 48) hasWpa2 = true;
          else if (tag_num == 221 && tag_len >= 4 && payload[offset+2] == 0x00 && payload[offset+3] == 0x50 && payload[offset+4] == 0xF2 && payload[offset+5] == 0x01) {
            hasWpa = true;
          }
          offset += 2 + tag_len;
        }
        if (hasWpa2) strcpy(enc, "WPA2");
        else if (hasWpa) strcpy(enc, "WPA");
      }
      update_ap(sa, ssid, rssi, currentChannel, enc, now);
    }
  }
  // DATA FRAMES (type = 0x02)
  else if (typeVal == 0x02) {
    uint8_t flags = payload[1];
    uint8_t toDS = flags & 0x01;
    uint8_t fromDS = (flags & 0x02) >> 1;
    uint8_t *clientMac = NULL;

    if (toDS && !fromDS) clientMac = payload + 10;
    else if (!toDS && fromDS) clientMac = payload + 4;
    else if (!toDS && !fromDS) clientMac = payload + 10;

    if (clientMac) {
      if (clientMac[0] & 0x01) return;
      if (clientMac[0] == 0x00 && clientMac[1] == 0x00 && clientMac[2] == 0x00) return;
      update_client(clientMac, rssi, "", now);
    }
  }
}

// BLE Scan Callbacks
class MyBLEAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
      uint8_t* nativeAddr = advertisedDevice.getAddress().getNative();
      uint8_t mac[6] = {0};
      if (nativeAddr) {
        memcpy(mac, nativeAddr, 6);
      } else {
        return;
      }
      int rssi = advertisedDevice.getRSSI();
      unsigned long now = millis();

      const char* name = nullptr;
      String devName = "";
      if (advertisedDevice.haveName()) {
        devName = advertisedDevice.getName().c_str();
        name = devName.c_str();
      }

      const char* vendor = "BLE Device";
      uint16_t companyId = 0xFFFF;
      if (advertisedDevice.haveManufacturerData()) {
        String mData = advertisedDevice.getManufacturerData();
        if (mData.length() >= 2) {
          companyId = ((uint8_t)mData[1] << 8) | (uint8_t)mData[0];
          if (companyId == 0x004C) vendor = "Apple";
          else if (companyId == 0x0075) vendor = "Samsung";
          else if (companyId == 0x00E0) vendor = "Google";
          else if (companyId == 0x0006) vendor = "Microsoft";
          else if (companyId == 0x0041) vendor = "Tile";
          else if (companyId == 0x02E5) vendor = "Espressif";
        }
      }

      update_ble(mac, rssi, name, vendor, companyId, now);
    }
};

void getCurrentTime(int &h, int &m, int &s) {
  if (!clockSynced) { h = 0; m = 0; s = 0; return; }
  unsigned long elapsed = millis() - lastTimeUpdateMillis;
  unsigned long totalSeconds = rtcHour * 3600 + rtcMin * 60 + rtcSec + (elapsed / 1000);
  h = (totalSeconds / 3600) % 24;
  m = (totalSeconds / 60) % 60;
  s = totalSeconds % 60;
}

// Fast, Smooth 2.4GHz Channel Hopping Tape (Header top-right X: 100 to 159, Y: 1 to 14)
void drawChannelTape() {
  const int tapeX = 100;
  const int tapeY = 1;
  const int tapeW = 59;
  const int tapeH = 13;

  canvas.fillRect(tapeX, tapeY, tapeW, tapeH, FIX_BLACK);
  canvas.drawRect(tapeX, tapeY, tapeW, tapeH, (currentRadarMode == RADAR_WIFI) ? FIX_CYAN : FIX_MAGENTA);

  float targetPos = (float)(currentChannel - 1) * 10.0f;
  static float scrollPos = 0.0f;
  scrollPos += (targetPos - scrollPos) * 0.45f;

  int centerX = tapeX + (tapeW / 2);

  for (int ch = 1; ch <= 13; ch++) {
    float chX = centerX + (float)(ch - 1) * 10.0f - scrollPos;
    int intX = (int)chX;

    if (intX >= tapeX + 2 && intX <= tapeX + tapeW - 6) {
      if (ch == currentChannel) {
        canvas.fillRect(intX - 4, tapeY + 1, 9, tapeH - 2, (currentRadarMode == RADAR_WIFI) ? FIX_CYAN : FIX_MAGENTA);
        canvas.setCursor(intX - 3, tapeY + 3);
        canvas.setTextColor(FIX_BLACK);
        canvas.printf("%d", ch);
      } else {
        canvas.drawFastVLine(intX, tapeY + 2, 2, FIX_WHITE);
        canvas.setCursor(intX - 2, tapeY + 5);
        canvas.setTextColor(FIX_WHITE);
        canvas.setTextWrap(false);
        canvas.printf("%d", ch);
      }
    }
  }

  canvas.drawFastVLine(centerX, tapeY + tapeH - 3, 2, FIX_YELLOW);
}

void drawHeader(uint16_t textColor, const char* title) {
  char grade = 'A';
  int threatScore = calculateThreatScore(grade);
  uint16_t gradeColor = (grade == 'A') ? FIX_GREEN : ((grade == 'B' || grade == 'C') ? FIX_YELLOW : FIX_RED);

  canvas.setCursor(0, 3);
  canvas.setTextColor(gradeColor);
  canvas.printf("[%c]", grade);

  canvas.setCursor(19, 3);
  canvas.setTextColor(textColor);
  canvas.print(title);

  canvas.setCursor(64, 3);
  canvas.setTextColor(FIX_WHITE);
  if (clockSynced) {
    int h, m, s;
    getCurrentTime(h, m, s);
    int h12 = h % 12;
    if (h12 == 0) h12 = 12;
    const char* ampm = (h >= 12) ? "P" : "A";
    canvas.printf("%02d:%02d%s", h12, m, ampm);
  } else {
    canvas.print("--:--");
  }

  drawChannelTape();
  canvas.drawLine(0, 15, 160, 15, FIX_WHITE);
}

// Bottom 10px High-Contrast Scrolling Ticker (Y: 116 to 127)
void drawMarqueeTicker() {
  canvas.fillRect(0, 116, 160, 12, FIX_BLACK);
  canvas.drawFastHLine(0, 115, 160, FIX_WHITE);

  canvas.setCursor(marqueeX, 118);
  canvas.setTextColor((currentRadarMode == RADAR_WIFI) ? FIX_CYAN : FIX_MAGENTA);
  canvas.setTextWrap(false);
  canvas.print(marqueeText);

  marqueeX -= 8;
  if (marqueeX < -400) marqueeX = 160;
}

// CRT Scanlines Effect
void applyScanlines() {
  if (!crtFilterEnabled) return;
  uint16_t* buf = canvas.getBuffer();
  for (int y = 0; y < 128; y += 3) {
    int rowOffset = y * 160;
    for (int x = 0; x < 160; x++) {
      uint16_t color = buf[rowOffset + x];
      uint8_t r = (color >> 11) & 0x1F;
      uint8_t g = (color >> 5) & 0x3F;
      uint8_t b = color & 0x1F;
      r = (r * 3) / 4;
      g = (g * 3) / 4;
      b = (b * 3) / 4;
      buf[rowOffset + x] = (r << 11) | (g << 5) | b;
    }
  }
}

// --- Visual 2D Radar Scope ---
void drawRadar() {
  canvas.fillScreen(FIX_BLACK);

  int radarCenterX = 51;
  int radarCenterY = 65;
  int radarRadius = 46;

  // Radar Concentric Signal Strength Rings (5m, 15m, 30m, 45m)
  canvas.drawCircle(radarCenterX, radarCenterY, 11, FIX_DARKGRAY);
  canvas.drawCircle(radarCenterX, radarCenterY, 23, FIX_GRAY);
  canvas.drawCircle(radarCenterX, radarCenterY, 34, FIX_DARKGRAY);
  canvas.drawCircle(radarCenterX, radarCenterY, radarRadius, FIX_WHITE);

  // Radar Crosshairs
  canvas.drawFastHLine(radarCenterX - radarRadius, radarCenterY, radarRadius * 2, FIX_GRAY);
  canvas.drawFastVLine(radarCenterX, radarCenterY - radarRadius, radarRadius * 2, FIX_GRAY);

  // Rotating Sweep Line
  radarSweepAngle += 6.0f;
  if (radarSweepAngle >= 360.0f) radarSweepAngle -= 360.0f;
  float rad = radarSweepAngle * 0.0174532925f;
  int sweepX = radarCenterX + (int)(cos(rad) * radarRadius);
  int sweepY = radarCenterY + (int)(sin(rad) * radarRadius);
  canvas.drawLine(radarCenterX, radarCenterY, sweepX, sweepY, (currentRadarMode == RADAR_WIFI) ? FIX_GREEN : FIX_MAGENTA);

  // Vertical Divider line between Radar (Left) and Data Panel (Right)
  canvas.drawFastVLine(101, 16, 99, FIX_WHITE);

  // Build unified list of active devices
  struct RadarItem {
    uint8_t mac[6];
    int rssi;
    float dist;
    char label[12];
    char subLabel[10];
    uint16_t color;
    bool isAP;
    bool isBT;
  };
  static RadarItem items[60];
  int totalCount = 0;

  if (currentRadarMode == RADAR_WIFI) {
    // 1. Access Points
    for (int i = 0; i < MAX_APS; i++) {
      if (trackedAPs[i].active && totalCount < 60) {
        RadarItem& item = items[totalCount++];
        memcpy(item.mac, trackedAPs[i].bssid, 6);
        item.rssi = trackedAPs[i].rssi;
        item.dist = pow(10.0f, (-40.0f - (float)item.rssi) / 27.0f);
        item.isAP = true;
        item.isBT = false;
        if (strlen(trackedAPs[i].ssid) > 0) snprintf(item.label, sizeof(item.label), "%.8s", trackedAPs[i].ssid);
        else snprintf(item.label, sizeof(item.label), "%02X%02X%02X", item.mac[3], item.mac[4], item.mac[5]);
        strcpy(item.subLabel, "AP");
        item.color = FIX_YELLOW;
      }
    }

    // 2. Wi-Fi Clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (trackedClients[i].active && totalCount < 60) {
        RadarItem& item = items[totalCount++];
        memcpy(item.mac, trackedClients[i].mac, 6);
        item.rssi = trackedClients[i].rssi;
        item.dist = pow(10.0f, (-40.0f - (float)item.rssi) / 27.0f);
        item.isAP = false;
        item.isBT = false;
        if (strlen(trackedClients[i].probedSSID) > 0) snprintf(item.label, sizeof(item.label), "%.8s", trackedClients[i].probedSSID);
        else snprintf(item.label, sizeof(item.label), "%.8s", getVendor(item.mac));
        strcpy(item.subLabel, "CL");
        item.color = (item.rssi > -60) ? FIX_GREEN : ((item.rssi > -80) ? FIX_CYAN : FIX_RED);
      }
    }
  } else {
    // 3. Bluetooth BLE Devices
    for (int i = 0; i < MAX_BLE_DEVICES; i++) {
      if (trackedBLE[i].active && totalCount < 60) {
        RadarItem& item = items[totalCount++];
        memcpy(item.mac, trackedBLE[i].mac, 6);
        item.rssi = trackedBLE[i].rssi;
        item.dist = trackedBLE[i].dist;
        item.isAP = false;
        item.isBT = true;
        snprintf(item.label, sizeof(item.label), "%.8s", trackedBLE[i].name);
        snprintf(item.subLabel, sizeof(item.subLabel), "%.6s", trackedBLE[i].devType);
        item.color = (item.rssi > -60) ? FIX_MAGENTA : FIX_BLUE;
      }
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

  // Header Telemetry Readout
  float farthestDist = (totalCount > 0) ? items[totalCount - 1].dist : 0.0f;
  char headerBuf[20];
  if (currentRadarMode == RADAR_WIFI) {
    snprintf(headerBuf, sizeof(headerBuf), "WF:%dD %.0fm", totalCount, farthestDist);
    drawHeader(FIX_GREEN, headerBuf);
  } else {
    snprintf(headerBuf, sizeof(headerBuf), "BT:%dD %.0fm", totalCount, farthestDist);
    drawHeader(FIX_MAGENTA, headerBuf);
  }

  // Draw Blips on Radar Scope
  for (int i = 0; i < totalCount; i++) {
    int normR = map(constrain(items[i].rssi, -95, -30), -95, -30, radarRadius, 4);
    uint32_t angleHash = (items[i].mac[3] ^ items[i].mac[4] ^ items[i].mac[5]) * 360 / 256;
    float bRad = angleHash * 0.0174532925f;
    int bx = radarCenterX + (int)(cos(bRad) * normR);
    int by = radarCenterY + (int)(sin(bRad) * normR);

    int trailR = constrain(normR + 3, 4, radarRadius);
    int tx = radarCenterX + (int)(cos(bRad + 0.1f) * trailR);
    int ty = radarCenterY + (int)(sin(bRad + 0.1f) * trailR);
    canvas.drawLine(bx, by, tx, ty, FIX_GRAY);

    if (items[i].isBT) {
      canvas.fillRect(bx - 2, by - 2, 4, 4, items[i].color);
    } else if (items[i].isAP) {
      canvas.drawCircle(bx, by, 3, items[i].color);
    } else {
      if (items[i].mac[0] & 0x02) {
        canvas.drawTriangle(bx, by - 3, bx - 3, by + 3, bx + 3, by + 3, items[i].color);
      } else {
        canvas.fillCircle(bx, by, 2, items[i].color);
      }
    }

    if (targetLockActive && memcmp(items[i].mac, target_mac, 6) == 0) {
      for (int t = 0; t <= 10; t += 2) {
        int lx1 = radarCenterX + (bx - radarCenterX) * t / 10;
        int ly1 = radarCenterY + (by - radarCenterY) * t / 10;
        int lx2 = radarCenterX + (bx - radarCenterX) * (t + 1) / 10;
        int ly2 = radarCenterY + (by - radarCenterY) * (t + 1) / 10;
        canvas.drawLine(lx1, ly1, lx2, ly2, FIX_RED);
      }
      float chAngle = (millis() % 2000) * 0.00314159f;
      int cx1 = bx + (int)(cos(chAngle) * 6);
      int cy1 = by + (int)(sin(chAngle) * 6);
      int cx2 = bx - (int)(cos(chAngle) * 6);
      int cy2 = by - (int)(sin(chAngle) * 6);
      canvas.drawLine(cx1, cy1, cx2, cy2, FIX_RED);
      canvas.drawCircle(bx, by, 7, FIX_RED);
    }
  }

  // Right Side Data Panel (Pixel-Perfect Aligned Columns for 4 Top Devices)
  canvas.setCursor(104, 18);
  canvas.setTextColor((currentRadarMode == RADAR_WIFI) ? FIX_CYAN : FIX_MAGENTA);
  canvas.print(currentRadarMode == RADAR_WIFI ? "WF-TGT" : "BT-TGT");
  canvas.setCursor(140, 18);
  canvas.setTextColor(FIX_WHITE);
  canvas.print("M");
  canvas.drawFastHLine(103, 26, 56, FIX_WHITE);

  int yPos = 28;
  for (int i = 0; i < totalCount && i < 4; i++) {
    // Line 1: Type Badge & Distance
    canvas.setCursor(104, yPos);
    canvas.setTextColor(items[i].color);
    canvas.printf("[%.5s]", items[i].subLabel);

    canvas.setCursor(136, yPos);
    canvas.setTextColor(FIX_WHITE);
    if (items[i].dist < 10.0f) canvas.printf("%3.1f", items[i].dist);
    else canvas.printf("%2.0f", items[i].dist);

    // Line 2: Device Name / MAC Hash
    canvas.setCursor(104, yPos + 9);
    canvas.setTextColor(items[i].color);
    canvas.printf("%.8s", items[i].label);

    yPos += 22;
  }

  drawMarqueeTicker();
  applyScanlines();
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
}

void handleButton() {
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50);
    if (digitalRead(BUTTON_PIN) == LOW) {
      targetLockActive = false;
      for (int i = 0; i < MAX_CLIENTS; i++) trackedClients[i].active = false;
      for (int i = 0; i < MAX_APS; i++) trackedAPs[i].active = false;
      for (int i = 0; i < MAX_BLE_DEVICES; i++) trackedBLE[i].active = false;
      
      canvas.fillScreen(FIX_BLACK);
      canvas.setCursor(20, 50);
      canvas.setTextColor(FIX_RED);
      canvas.println("RADAR RESET OK!");
      tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
      delay(800);
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.println("[SYSTEM] WIFIMON V3 Hybrid Radar Booting...");
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  tft.initR(INITR_BLACKTAB); 
  tft.setRotation(1);
  tft.fillScreen(FIX_BLACK);
  
  canvas.fillScreen(FIX_BLACK);
  canvas.setCursor(10, 30);
  canvas.setTextColor(FIX_CYAN);
  canvas.println("WIFIMON V3 HYBRID");
  canvas.setCursor(10, 50);
  canvas.setTextColor(FIX_GREEN);
  canvas.println("Wi-Fi + BLE Sniffer");
  canvas.drawFastHLine(0, 70, 160, FIX_WHITE);
  tft.drawRGBBitmap(0, 0, canvas.getBuffer(), 160, 128);
  delay(1200);

  // Initialize Wi-Fi Sniffer Mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

  // Initialize BLE Scanner
  BLEDevice::init("WIFIMON-V3");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyBLEAdvertisedDeviceCallbacks(), false);
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  Serial.println("[SYSTEM] WIFIMON V3 Ready! 20s Wi-Fi / BLE Hybrid Cycle Active.");
}

void loop() {
  handleButton();
  unsigned long now = millis();

  // 20-Second Auto-Toggle between Wi-Fi Radar and Bluetooth BLE Radar
  if (now - lastRadarModeToggle > 20000) {
    currentRadarMode = (currentRadarMode == RADAR_WIFI) ? RADAR_BLE : RADAR_WIFI;
    lastRadarModeToggle = now;

    if (currentRadarMode == RADAR_BLE) {
      esp_wifi_set_promiscuous(false); // Pause Wi-Fi sniffer while scanning Bluetooth
      if (pBLEScan) {
        pBLEScan->start(2, false); // Perform 2-second BLE scan
        pBLEScan->clearResults();
      }
    } else {
      esp_wifi_set_promiscuous(true); // Resume Wi-Fi sniffer for Wi-Fi Radar mode
    }
  }

  // Periodic BLE scan during BLE mode (every 3 seconds)
  static unsigned long lastBLEScanTrigger = 0;
  if (currentRadarMode == RADAR_BLE && (now - lastBLEScanTrigger > 3000)) {
    if (pBLEScan) {
      pBLEScan->start(2, false);
      pBLEScan->clearResults();
    }
    lastBLEScanTrigger = now;
  }

  // Channel Hopping (every 300ms during Wi-Fi mode)
  if (currentRadarMode == RADAR_WIFI && (now - lastChannelChange > 300)) {
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelChange = now;
  }

  // Age out active records if not seen in 30 seconds
  for (int i = 0; i < MAX_CLIENTS; i++) {
     if (trackedClients[i].active && (now - trackedClients[i].lastSeen > 30000)) trackedClients[i].active = false;
  }
  for (int i = 0; i < MAX_APS; i++) {
     if (trackedAPs[i].active && (now - trackedAPs[i].lastSeen > 30000)) trackedAPs[i].active = false;
  }
  for (int i = 0; i < MAX_BLE_DEVICES; i++) {
     if (trackedBLE[i].active && (now - trackedBLE[i].lastSeen > 30000)) trackedBLE[i].active = false;
  }

  // Update Visual Radar Scope (every 250ms)
  static unsigned long lastUIDraw = 0;
  if (now - lastUIDraw > 250) {
    drawRadar();
    lastUIDraw = now;
  }
}