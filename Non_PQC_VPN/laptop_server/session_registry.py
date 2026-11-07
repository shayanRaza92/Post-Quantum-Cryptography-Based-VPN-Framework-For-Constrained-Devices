"""
Registry of authenticated tunnels, one entry per device ID.

  * Lets the gateway know which ESP32s are online right now.
  * When a device re-authenticates (e.g. it rebooted or lost Wi-Fi and the old
    TCP connection is still half-open), the old session is closed so a device
    never has two tunnels at once.
"""
import threading
from console import safe_print as print


class SessionRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = {}  # {device_id: VpnSession}

    def register(self, device_id, session):
        """Adds a freshly authenticated session; terminates an older one for the same ID."""
        with self._lock:
            old = self._sessions.get(device_id)
            self._sessions[device_id] = session
            active = sorted(self._sessions)
        if old is not None and old is not session:
            print(f"[{device_id}] [SESSION] New authenticated session from "
                  f"{session.client_address[0]}:{session.client_address[1]} replaces old one from "
                  f"{old.client_address[0]}:{old.client_address[1]}.")
            old.terminate("replaced by a newer session of the same device")
        print(f"[SESSIONS] Active tunnels ({len(active)}): {', '.join(active)}")

    def unregister(self, device_id, session):
        """Removes the entry only if it still belongs to this session (it may have been replaced)."""
        with self._lock:
            if self._sessions.get(device_id) is not session:
                return
            del self._sessions[device_id]
            active = sorted(self._sessions)
        print(f"[SESSIONS] Active tunnels ({len(active)}): {', '.join(active) if active else '-'}")
