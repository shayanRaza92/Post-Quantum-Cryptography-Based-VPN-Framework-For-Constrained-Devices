# Capstone-I: Deliverable 1 — TCP Transport Setup

**Goal:** Establish a reliable client-server socket connection over Wi-Fi between the ESP32 client and the laptop gateway on TCP Port 9000.

---

## Folder Structure

```text
step1_tcp_transport/
├── laptop_server/
│   └── server.py          # Python TCP Server on Laptop
├── esp32_client/
│   └── esp32_client.ino   # Arduino Sketch on ESP32
└── README.md
```

---

## How to Run and Test

### 1. Start the Laptop Server
Open a terminal and run:
```bash
python3 /home/shayan/Downloads/VPN1/FYP/step1_tcp_transport/laptop_server/server.py
```
It will print:
```text
Server started on 192.168.1.38:9000
Waiting for ESP32 to connect...
```

---

### 2. Upload to ESP32
1. Open [`esp32_client.ino`](file:///home/shayan/Downloads/VPN1/FYP/step1_tcp_transport/esp32_client/esp32_client.ino) in the **Arduino IDE**.
2. Put your Wi-Fi name, password, and laptop IP at the top:
   ```cpp
   const char* WIFI_SSID     = "YOUR_WIFI_NAME";
   const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
   const char* LAPTOP_IP     = "192.168.1.38"; // Put your laptop IP here
   ```
3. Connect your ESP32 with USB, select your board and port, and click **Upload**.
4. Open the **Serial Monitor** at **115200 baud**.

Command for Arduino IDE: cd ~/Downloads
./arduino-ide_*.AppImage --no-sandbox

---

### 3. Expected Output

* **ESP32 Serial Monitor:**
  ```text
  Connecting to Wi-Fi...
  Wi-Fi connected!
  ESP32 IP: 192.168.1.50
  Connecting to laptop on port 9000...
  Connected to laptop!

  [Send]: PING #1
  [Reply]: ACK: PING #1
  [Send]: PING #2
  [Reply]: ACK: PING #2
  ```

* **Laptop Terminal:**
  ```text
  Server started on 192.168.1.38:9000
  Waiting for ESP32 to connect...

  ESP32 connected from 192.168.1.50
  [From ESP32]: PING #1
  [From ESP32]: PING #2
  ```
