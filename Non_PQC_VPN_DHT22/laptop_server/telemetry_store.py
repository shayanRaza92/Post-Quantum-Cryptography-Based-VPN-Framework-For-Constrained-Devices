"""
Parses and stores DHT22 readings received through the encrypted tunnel.

The device ID written to the log is always the one proven during the handshake,
never a value taken from the payload, so one device cannot log data as another.
"""
import csv
import json
import math
import threading
from datetime import datetime

from config import TELEMETRY_CSV

CSV_COLUMNS = [
    "server_time", "device_id", "reading", "uptime_ms",
    "temperature_c", "humidity_pct", "heat_index_c", "error",
]


class TelemetryError(ValueError):
    """Payload is not a valid DHT22 reading."""


def _number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise TelemetryError(f"'{field}' must be a finite number")
    return value


def parse_reading(plaintext: bytes) -> dict:
    """Validates the JSON payload sent by esp32_dht22_client.ino."""
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise TelemetryError(f"payload is not valid JSON: {e}")
    if not isinstance(data, dict):
        raise TelemetryError("payload must be a JSON object")

    reading = {
        "reading": int(_number(data.get("reading"), "reading")),
        "uptime_ms": int(_number(data.get("uptime_ms"), "uptime_ms")),
        "temperature_c": None,
        "humidity_pct": None,
        "heat_index_c": None,
        "error": None,
    }
    if "error" in data:
        reading["error"] = str(data["error"])[:64]
        return reading

    reading["temperature_c"] = _number(data.get("temperature_c"), "temperature_c")
    reading["humidity_pct"] = _number(data.get("humidity_pct"), "humidity_pct")
    reading["heat_index_c"] = _number(data.get("heat_index_c"), "heat_index_c")
    # DHT22 datasheet range: -40..80 C, 0..100 %RH
    if not -40.0 <= reading["temperature_c"] <= 80.0:
        raise TelemetryError(f"temperature {reading['temperature_c']} C is outside the DHT22 range")
    if not 0.0 <= reading["humidity_pct"] <= 100.0:
        raise TelemetryError(f"humidity {reading['humidity_pct']} % is outside 0..100")
    return reading


class TelemetryStore:
    """Thread-safe CSV appender shared by every device session."""

    def __init__(self, path=TELEMETRY_CSV):
        self.path = path
        self._lock = threading.Lock()

    def append(self, device_id: str, reading: dict) -> str:
        row = {"server_time": datetime.now().isoformat(timespec="seconds"), "device_id": device_id}
        row.update(reading)
        with self._lock:
            new_file = not self.path.exists() or self.path.stat().st_size == 0
            with open(self.path, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                if new_file:
                    writer.writeheader()
                writer.writerow(row)
        return row["server_time"]
