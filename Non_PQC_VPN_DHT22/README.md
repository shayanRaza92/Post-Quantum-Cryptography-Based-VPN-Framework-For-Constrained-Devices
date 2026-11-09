# Classical VPN: Sending DHT22 Temperature Readings

This project sends temperature and humidity readings from a DHT22 sensor on an ESP32 to the laptop gateway, through the classical VPN in [`../Non_PQC_VPN/`](../Non_PQC_VPN/README.md).

The handshake is **the same** as in `Non_PQC_VPN/`: four messages, Ed25519, X25519 and HKDF-SHA256. What is different is what gets sent after the handshake: here it is sensor readings, and every reading is **encrypted** with a key made from `K_session`.

---

## What is in this folder

* `esp32_dht22_client/`: the code for the ESP32 (Arduino IDE).
  * `esp32_dht22_client.ino`: reads the DHT22 and sends one encrypted reading every `SENSOR_INTERVAL_MS`.
  * `SecureChannel.h/.cpp`: encrypts and decrypts the readings with AES-256-GCM, using the ESP32's built-in AES hardware.
  * `TunnelLog.h/.cpp`: prints the keys, the encrypted readings and the decrypted text on the Serial Monitor.
  * `AuthManager`, `DeviceIdentity`, `config.h`: copied from `../Non_PQC_VPN/esp32_client/`. `config.h` also has the sensor settings.
* `laptop_server/`: the gateway (Python).
  * `secure_channel.py`: the laptop side of the encryption.
  * `telemetry_store.py`: checks each reading and saves it to `temperature_log.csv`.
  * `tunnel_printer.py`: prints the keys, the encrypted readings and the decrypted text.
  * `tunnel_session.py`: the handshake is unchanged; after it, this file decrypts the sensor readings.
  * Everything else is copied from `../Non_PQC_VPN/laptop_server/`.
* `sequence_diagram.png`: a picture of every step (handshake, keys, encrypted readings, disconnecting).
* `screenshots/`: screenshots from a test run (`dht1.png` to `dht5.png`).

---

## Wiring the DHT22 to the ESP32

| DHT22 pin | ESP32 pin |
|-----------|-----------|
| VCC (+)   | 3.3V |
| DATA      | GPIO 4 (`DHT_PIN` in `config.h`) |
| GND (-)   | GND |

A bare 4-pin DHT22 needs a **10 kΩ resistor** between DATA and 3.3V. Small 3-pin DHT22 boards already have one.

---

## How it works

![Sequence diagram](sequence_diagram.png)

### Step 1: the handshake (messages 1-4)
This is exactly the same as in [`../Non_PQC_VPN/README.md`](../Non_PQC_VPN/README.md). At the end, both sides have the same 32-byte secret key `K_session`. It is never sent over Wi-Fi, and it is new for every connection.

### Step 2: making the encryption keys
Nothing is sent in this step. Each side computes two keys by itself:
```
K_c2s = HMAC-SHA256(K_session, "VPN-v1|DATA|C2S")   key for ESP32 -> laptop
K_s2c = HMAC-SHA256(K_session, "VPN-v1|DATA|S2C")   key for laptop -> ESP32
```
* **Why two keys?** AES-GCM breaks badly if the same key and message number are ever used twice. Both sides start counting their messages from 0, so with one shared key the ESP32's first reading and the laptop's first reply would clash. One key per direction makes that impossible.
* `K_session` itself is never used to encrypt anything. Each key has one job.
* Both sides start their message counters at 0.

### Step 3: sending readings (every 5 seconds)

**The ESP32 reads the sensor and encrypts the reading:**
1. It reads the temperature and humidity and works out the heat index.
2. It writes them as JSON (about 94 bytes):
   ```json
   {"reading":1,"uptime_ms":5000,"temperature_c":24.60,"humidity_pct":51.30,"heat_index_c":24.50}
   ```
   If the sensor cannot be read, it still sends `{"reading":2,"uptime_ms":10000,"error":"dht22_read_failed"}`. That way the laptop knows the device is still alive and does not close the connection.
3. It encrypts the JSON with AES-256-GCM using `K_c2s`. The result has the same length as the JSON, plus a 16-byte tag. The tag also covers the length and the message number, so changing any of them is detected.

**What goes over Wi-Fi** (120 bytes for the example above):
```
+-------------+---------------+------------------------------+---------------+
| Length (2B) | Number (8B)   | Encrypted reading (94B)      | Tag (16B)     |
+-------------+---------------+------------------------------+---------------+
```
Someone listening on the Wi-Fi can see that a reading was sent and how big it is, but **not** the temperature or humidity.

**The laptop checks and decrypts it:**
1. It checks the length is between 24 and 504 bytes. If not, it closes the connection. This also means it never keeps more than one reading in memory.
2. It waits until the whole reading has arrived.
3. It checks the message number is the next expected one. A replayed, missing or out-of-order reading closes the connection.
4. It decrypts and checks the tag **before** using anything. If the tag is wrong (the data was changed, or the wrong key was used), it closes the connection.
5. It checks the values make sense: the temperature must be between -40 and 80 °C (the DHT22's range) and the humidity between 0 and 100 %.
6. It saves a row to `temperature_log.csv`. The device name in that row is the one **proved during the handshake**, not one taken from the reading. So one device cannot send readings pretending to be another.

**The laptop replies with an encrypted acknowledgement**, for example `{"seq":0,"reading":1,"status":"stored"}`. A bad reading gets `"status":"rejected"` with the reason. It is encrypted with `K_s2c`, which makes a 65-byte message. The ESP32 checks it the same way. If anything is wrong, the ESP32 closes the connection and connects again.

### Step 4: disconnecting
The laptop closes a connection when:
* a tag is wrong,
* a message number is not the expected one,
* a length is invalid,
* nothing has arrived for 30 seconds,
* the device was removed from `authorized_devices.json`,
* the same device has opened a newer connection.

The ESP32 then deletes its keys and counters, waits (3 s, then 6 s, and so on up to 30 s), and does a **new handshake**. That gives a brand-new `K_session` and new encryption keys. Recording one session's traffic never helps to decrypt another session.

### What this protects
| Protection | How |
|---|---|
| Nobody can read the data | AES-256 with new keys for every connection and each direction |
| Nobody can change the data | The 16-byte tag over the header and the encrypted data |
| Old messages cannot be replayed | The message number must go up by exactly one |
| Keys and message numbers never clash | One key per direction, and the message number never repeats |
| Old sessions stay safe if a key leaks later | `K_session` comes from fresh X25519 keys every time |
| A device cannot pretend to be another | The device name in the log comes from the handshake |

---

## How to run it

### 1. Start the gateway (laptop)
```bash
cd laptop_server
python server.py
```
The readings are printed and saved in `laptop_server/temperature_log.csv`:
```
server_time,device_id,reading,uptime_ms,temperature_c,humidity_pct,heat_index_c,error
2026-11-07T18:27:40,esp32-01,1,5000,24.6,51.3,24.5,
```

### 2. Flash the ESP32
1. In the Arduino IDE Library Manager, install **"DHT sensor library" by Adafruit** (also accept **Adafruit Unified Sensor** when it asks).
2. Open `esp32_dht22_client/esp32_dht22_client.ino`.
3. In `config.h`, set `WIFI_SSID`, `WIFI_PASSWORD`, `GATEWAY_IP`, `DEVICE_ID`, and `DHT_PIN` if you used another pin.
4. Upload, then open the Serial Monitor at **115200 baud**.

The ESP32 keeps its key in flash. A board that is already in `authorized_devices.json` works straight away. For a new board, copy the public key it prints when it starts into `laptop_server/authorized_devices.json`.

### Settings
| Setting | File | Default | Notes |
|---|---|---|---|
| `DHT_PIN` | `config.h` | 4 | The pin wired to DHT22 DATA |
| `SENSOR_INTERVAL_MS` | `config.h` | 5000 | At least 2000 (the DHT22 cannot be read faster), and less than 30000 (or the connection times out) |
| `MAX_RECORD_PLAINTEXT` | both config files | 480 | Must be the same on both sides |
| `TELEMETRY_CSV` | `config.py` | `temperature_log.csv` | Where the readings are saved |
