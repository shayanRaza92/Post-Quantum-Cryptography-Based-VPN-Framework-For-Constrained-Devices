# Deliverable 1: TCP Transport Setup

Reliable client-server TCP socket connection established over local Wi-Fi between the ESP32 client and the laptop gateway on TCP port 9000.

## Directory Structure

```text
delivarable1_tcp_transport/
├── laptop_server/
│   └── server.py          # Python TCP server on laptop
├── esp32_client/
│   └── esp32_client.ino   # Arduino sketch on ESP32
└── README.md
```

## Running the Components

### Step 1: Start the Laptop Server
Open a terminal in the server directory and run:
```bash
python3 laptop_server/server.py
```
The server will bind to the local network IP and listen on port 9000:
```text
Server started on 192.168.1.38:9000
Waiting for ESP32 to connect...
```

### Step 2: Flash the ESP32 Client
1. Open `esp32_client/esp32_client.ino` in the Arduino IDE.
2. Verify network configuration parameters at the top of the sketch:
   ```cpp
   const char* WIFI_SSID     = "YOUR_WIFI_NAME";
   const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
   const char* LAPTOP_IP     = "192.168.1.38"; // Set to current laptop IP
   ```
3. Connect the ESP32 via USB and select the appropriate serial port.
4. Upload the sketch and open the Serial Monitor at 115200 baud.

## Expected Output

### ESP32 Serial Monitor
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

### Laptop Server Terminal
```text
Server started on 192.168.1.38:9000
Waiting for ESP32 to connect...

ESP32 connected from 192.168.1.50
[From ESP32]: PING #1
[From ESP32]: PING #2
```
