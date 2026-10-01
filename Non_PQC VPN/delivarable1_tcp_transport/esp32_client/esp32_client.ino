#include <WiFi.h>

// Wi-Fi and Laptop settings
const char* WIFI_SSID     = "YOUR_WIFI_NAME";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* LAPTOP_IP     = "192.168.1.38"; // Put your laptop IP here
const uint16_t PORT       = 9000;

WiFiClient client;
unsigned long lastSendTime = 0;
int counter = 0;

void setup() {
  Serial.begin(115200);
  delay(500);

  // Connect to Wi-Fi
  Serial.print("Connecting to Wi-Fi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());

  // Connect to laptop server
  connectToServer();
}

void connectToServer() {
  Serial.print("Connecting to laptop on port ");
  Serial.print(PORT);
  Serial.println("...");

  while (!client.connect(LAPTOP_IP, PORT)) {
    Serial.println("Connection failed, retrying in 2 seconds...");
    delay(2000);
  }
  Serial.println("Connected to laptop!\n");
}

void loop() {
  // Reconnect if connection was lost
  if (!client.connected()) {
    Serial.println("Connection lost. Reconnecting...");
    client.stop();
    delay(1000);
    connectToServer();
    return;
  }

  // Send a ping every 3 seconds
  if (millis() - lastSendTime > 3000) {
    lastSendTime = millis();
    counter++;

    String msg = "PING #" + String(counter);
    Serial.print("[Send]: ");
    Serial.println(msg);
    client.println(msg);

    // Read reply from laptop
    unsigned long waitStart = millis();
    while (millis() - waitStart < 2000) {
      if (client.available()) {
        String reply = client.readStringUntil('\n');
        Serial.print("[Reply]: ");
        Serial.println(reply);
        break;
      }
      delay(10);
    }
  }
}
