# Step 2: Mutual Authentication (HMAC-SHA256)

This step builds on the TCP socket connection from Step 1 by adding **Mutual Authentication** before any regular messages can be exchanged.

---

## How It Works

1. Both the ESP32 and Laptop share a secret key (`PSK = "vpn_secret_key_123"`).
2. The laptop sends a 16-byte random challenge.
3. The ESP32 signs it using HMAC-SHA256 and sends back its proof + its own 16-byte random challenge.
4. The laptop verifies the ESP32's proof, signs the ESP32's challenge, and sends back its proof.
5. The ESP32 verifies the laptop's proof.
6. If both proofs are valid, the connection is approved and data exchange begins. If either fails, the connection is immediately terminated.

---

## File Structure

```text
step2_mutual_auth/
├── laptop_server/
│   └── server.py           # Python server with HMAC challenge-response
├── esp32_client/
│   └── esp32_client.ino    # ESP32 sketch using built-in MbedTLS for HMAC
└── README.md
```

---

## Libraries Used & Purpose

### On ESP32 (`esp32_client.ino`):
* **`WiFi.h`**: Built into the ESP32 Arduino core. Handles connecting to your Wi-Fi network and provides `WiFiClient` to open TCP socket connections.
* **`mbedtls/md.h`**: Pre-installed cryptographic engine inside ESP32. We use it to compute the **HMAC-SHA256** authentication tag with hardware acceleration. (No external installation required).
* **Hardware RNG (`esp_fill_random`)**: Built into the ESP32 silicon. Generates 16 unpredictable, cryptographically secure random bytes for the authentication challenge.

### On Laptop Server (`server.py`):
* **`socket`**: Standard Python library used to create the TCP server, bind to port 9000, and receive/send network packets.
* **`hmac` & `hashlib`**: Standard Python libraries used to compute and safely verify (`hmac.compare_digest`) the HMAC-SHA256 authentication signatures.
* **`os`**: Standard Python library used to generate 16 cryptographically secure random bytes (`os.urandom`) for the laptop's challenge.
*(No `pip install` required — everything uses Python's standard library).*

---

## How to Run

### 1. Start the Laptop Server
In your terminal, run:
```bash
python3 /home/shayan/Downloads/VPN1/FYP/step2_mutual_auth/laptop_server/server.py
```

### 2. Upload to ESP32
1. Open [`esp32_client.ino`](file:///home/shayan/Downloads/VPN1/FYP/step2_mutual_auth/esp32_client/esp32_client.ino) in the Arduino IDE.
2. Update your `WIFI_SSID`, `WIFI_PASSWORD`, and `LAPTOP_IP`.
3. Upload to your ESP32 and open Serial Monitor at **115200 baud**.

---

## Expected Output

### On the Laptop:
```text
ESP32 connected from 10.27.228.175:61848
Sent challenge to ESP32.
ESP32 authenticated successfully.
Sent HMAC proof to ESP32.
>>> Mutual Authentication Succeeded! <<<

[From ESP32]: PING #1
[From ESP32]: PING #2
```

### On the ESP32:
```text
TCP Connected.
Starting Mutual Authentication...
Received challenge from laptop.
Sent HMAC proof and own challenge to laptop.
>>> Mutual Authentication Succeeded! <<<

[Send]: PING #1  [Reply]: ACK: PING #1
```

---

## Testing Security (Failure Test)

To prove that authentication actually works:
1. Change `PSK` in `server.py` to `"wrong_key"`.
2. Re-run `server.py`.
3. Watch both sides reject and close the connection immediately!
