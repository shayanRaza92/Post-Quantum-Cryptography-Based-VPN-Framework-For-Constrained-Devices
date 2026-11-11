# Test 2 — ESP32 Private-Key Extraction & Hardware Security

## 1. Purpose
Determine whether an attacker with **physical access** to an ESP32 client can extract the
device's ML-DSA-44 private signing material and clone the device.

## 2. Vulnerability under investigation
The device's identity is a 32-byte ML-DSA-44 **seed** stored in NVS flash. The full 2,560-byte
secret key is derived from it at boot. If flash can be read (ESP32 flash encryption off) and NVS
is not encrypted, the seed is recoverable with `esptool.py`, letting an attacker forge the
device's signatures and impersonate it to the gateway.

## 3. How the test works
Configuration inspection and documentation only — **no flash is read or erased in this phase**:
1. **Source confirmation** — confirm exactly where/how the seed is stored (NVS namespace, key
   name, size, write path) by reading the firmware, so the report is accurate.
2. **Security-fuse inspection plan** — document the `espefuse.py summary` / `esptool.py` commands
   that reveal whether **Flash Encryption**, **Secure Boot v2**, and JTAG/UART-download
   restrictions are enabled. The script prints these commands (dry-run); it does not run them
   against a board in this phase.
3. **Exposure assessment** — explain what an attacker could do in each state (encryption on vs.
   off) and what the extracted seed would allow.

## 4. Part of the PQC VPN involved
* [`../../PQC_VPN/esp32_client/DeviceIdentity.cpp`](../../PQC_VPN/esp32_client/DeviceIdentity.cpp)
  — `begin()` stores/reads the seed:
  * NVS namespace: `vpn_pqc_id`
  * NVS key: `mldsa44_seed`
  * 32 bytes, written with `Preferences.putBytes`, generated via `esp_fill_random` (TRNG).
  * The derived 2,560-byte secret key lives only in RAM.
* [`../../PQC_VPN/esp32_client/DeviceIdentity.h`](../../PQC_VPN/esp32_client/DeviceIdentity.h)
  — key buffer sizes.

## 5. Files & modules in this test
* `scripts/inspect_firmware_storage.py` — reads the firmware source and prints exactly how/where
  the seed is stored (namespace, key, size, RNG). Read-only, no board needed.
* `scripts/esp32_security_checklist.py` — prints the (dry-run) `esptool.py` / `espefuse.py`
  commands that WOULD be used to check flash encryption, Secure Boot and debug interfaces, with
  an interpretation guide. Requires `--run` + an authorised board + explicit operator action
  before it would ever talk to hardware (not enabled in this phase).

## 6. Tools & dependencies
* [`esptool.py`](https://github.com/espressif/esptool) and `espefuse.py` (install deliberately:
  `pip install esptool`).
* A USB-connected ESP32 that we own (only for the future active phase).

## 7. How it will be executed (future phase)
```bash
cd PEN_Testing/02_ESP32_Hardware_Security
python scripts/inspect_firmware_storage.py           # read-only source review
python scripts/esp32_security_checklist.py           # prints the eFuse/flash check commands
# Future active phase (own board, explicit consent):
#   espefuse.py --port <port> summary
#   esptool.py --port <port> flash_id
```
Actual flash dumping (`read_flash`) and any eFuse burning are **explicitly out of scope** for
this phase and are not performed by these scripts.

## 8. Expected secure behaviour
* **Flash Encryption enabled** → a raw flash dump yields only ciphertext; the seed is not
  recoverable.
* **Secure Boot v2 enabled** → modified firmware will not boot.
* **UART download / JTAG restricted** via eFuses.
* With all of the above, the ML-DSA seed cannot be extracted and the device cannot be cloned.

## 9. What constitutes a vulnerability
* Flash Encryption **disabled** (default on dev boards) → the 32-byte seed in NVS is readable
  from a flash dump → full device impersonation. This is the key finding to document.
* Secure Boot disabled → attacker can run modified firmware.
* Open JTAG/UART download allowing memory read.

## 10. Evidence & metrics to collect
* `espefuse.py summary` output showing the FLASH_CRYPT_CNT / SECURE_BOOT / JTAG eFuse states.
* A clear statement of whether the seed is extractable in the board's current configuration.
* Remediation: enable Flash Encryption (release mode) + Secure Boot v2 + disable JTAG, and note
  the trade-offs (one-way eFuses, no further plain re-flashing).
