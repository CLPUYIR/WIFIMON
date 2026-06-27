# WIFIMON: ESP32 Wi-Fi Cybersecurity Sniffer & TFT Radar

[![Platform: ESP32](https://img.shields.io/badge/Platform-ESP32-blue.svg?style=flat-square)](https://www.espressif.com/)
[![Language: C++](https://img.shields.io/badge/Language-C%2B%2B-orange.svg?style=flat-square)](https://en.cppreference.com/)
[![Framework: Arduino](https://img.shields.io/badge/Framework-Arduino-00979D.svg?style=flat-square)](https://www.arduino.cc/)
[![Awesome: Yes](https://img.shields.io/badge/Awesome-Yes-brightgreen.svg?style=flat-square)](#)

An active Wi-Fi packet analyzer and passive device tracker designed for the ESP32. It operates in **promiscuous mode** to capture raw 802.11 management and data frames, analyzing nearby devices in real time and visualizing them on an ST7735 1.8" TFT display.

---

## 🚀 Key Features

*   **Promiscuous Mode Packet Capture:** Hooks directly into ESP32's low-level Wi-Fi stack to sniff 802.11 management frames (Probe Requests, Beacons) and data packets.
*   **Double-Buffered Display System:** Uses Adafruit GFX's `GFXcanvas16` double-buffering. All graphics render off-screen first and are pushed to the display in a single operation, eliminating backlight flicker.
*   **Automatic Channel Hopping:** Dynamically cycles through Wi-Fi channels 1 to 13 every 300ms to monitor the entire 2.4GHz band.
*   **Intelligent Database & Node Aging:** Maintains a localized database of up to 30 clients and 30 Access Points. Cleanses inactive records after 30 seconds to prevent tracking stale data.
*   **OUI Vendor Lookup:** Decodes MAC address prefixes (OUI) in real-time to identify device manufacturers (e.g., Apple, Google, Samsung, Espressif, Xiaomi, Oppo).
*   **Dynamic UI Modes:** Alternates the screen view every 5 seconds across three modes:
    1.  **Clients Mode (Cyan):** Displays client MAC addresses, signal strength (RSSI in dBm), and the target SSIDs they are actively searching for.
    2.  **Access Points Mode (Yellow):** Displays nearby AP names, encryption types (WPA2, WPA, WEP, OPEN), channel number, and RSSI.
    3.  **Combined Radar (White/Mixed):** A consolidated list of all active nearby clients and APs sorted by proximity (RSSI).

---

## 🛠️ Hardware Requirements & Pinout

### Components
1.  **ESP32 Development Board** (NodeMCU-32S, ESP32-WROOM-32, etc.)
2.  **ST7735 1.8" SPI TFT Display** (128x160 pixels)
3.  Connecting Jumper Wires

### Wiring Configuration
Ensure the screen is connected to the ESP32 SPI pins specified below:

| ST7735 Pin | ESP32 GPIO | Description |
| :--- | :--- | :--- |
| **VCC** | `3V3` or `5V` | System Power |
| **GND** | `GND` | Ground |
| **CS** | `GPIO 15` | SPI Chip Select |
| **RST** | `GPIO 4` | Screen Hardware Reset |
| **A0 / DC** | `GPIO 2` | Data/Command Toggle |
| **SDA / MOSI**| `GPIO 23` | SPI MOSI Data Line |
| **SCK / SCLK**| `GPIO 18` | SPI Clock Line |
| **LED** | `3V3` (via 220Ω resistor) | Backlight Power |

---

## 💻 Installation and Setup

### 1. Prerequisites
Install the latest version of the [Arduino IDE](https://www.arduino.cc/en/software).

### 2. Install Board Manager
Open Arduino IDE, go to **File > Preferences**, and paste this URL into the **Additional Boards Manager URLs**:
```text
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```
Then go to **Tools > Board > Boards Manager**, search for `esp32` by Espressif Systems, and install it.

### 3. Install Library Dependencies
Go to **Sketch > Include Library > Manage Libraries...** and search for and install:
*   **Adafruit GFX Library**
*   **Adafruit ST7735 and ST7789 Library**

### 4. Uploading the Sketch
1. Connect the ESP32 board to your computer via USB.
2. Select your board from **Tools > Board > ESP32 Arduino** (e.g., *ESP32 Dev Module*).
3. Select the correct COM port under **Tools > Port**.
4. Open the `radar_debug.ino` file, then click the **Upload** button (arrow icon).

---

## 📊 Live Monitoring

### TFT Display Interface
*   **Signal Proximity Indicator:** Lists are dynamically sorted in real-time by RSSI (signal strength).
*   **Color coding:**
    *   `Green:` Strong signal (> -60 dBm)
    *   `Yellow:` Moderate signal (-60 to -80 dBm)
    *   `Gray:` Weak/Fading signal (< -80 dBm)
    *   `Red (APs Mode):` Unencrypted/Vulnerable networks (`OPEN`/`WEP`).

### Serial Monitor Debugging
Set your Serial Monitor baud rate to **115200** to view detailed log outputs of discovered wireless clients and access points.

```text
==========================================
[SYSTEM] ESP32 Wi-Fi Cybersecurity Sniffer
[SYSTEM] Diagnostic Serial Debug Mode: ACTIVE
==========================================

[CLIENT] DISCOVERED MAC: D8:A0:1D:XX:XX:XX | RSSI: -42 dBm | Vendor: Apple
[AP] DISCOVERED BSSID: E0:5A:1B:XX:XX:XX | SSID: Home_Network    | CH: 6 | Enc: WPA2 | RSSI: -54 dBm
[CLIENT] UPDATED    MAC: 30:AE:A4:XX:XX:XX | RSSI: -67 dBm | Probed SSID: Starbucks_WiFi
```

---

## ⚙️ How it Works under the Hood

*   **Promiscuous Mode Activation:** 
    ```cpp
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    ```
    This disables packet filtering in the Wi-Fi hardware controller, forcing it to forward all 802.11 packets on the channel to our callback function instead of discarding them.
*   **Frame Parsing:** The sniffer checks the frame headers to filter out non-management frames. For management frames:
    *   **Beacons (subtype `0x08`)** are parsed to extract SSID, Encryption support (WPA/WPA2/WEP), and operating channels.
    *   **Probe Requests (subtype `0x04`)** are parsed to determine which SSIDs mobile clients are actively looking for.
*   **Data Frame Tracking:** For standard data frames (e.g., from active web traffic), MAC addresses are extracted to track active but silent client devices.
