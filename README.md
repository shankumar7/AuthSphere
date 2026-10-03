# AuthSphere — Secure Device and User Authentication Framework for IoT

AuthSphere is an enterprise-grade device and user authentication framework for IoT, giving every IoT device (ESP32) and user entity a unique cryptographic identity based on **Elliptic Curve Cryptography (ECC, Curve P-256 / secp256r1)**.

Identities are X.509 certificates issued by AuthSphere's internal Certificate Authority. The MQTT broker accepts only connections presenting a valid AuthSphere certificate, and a Dynamic Security policy engine restricts each entity to permitted topic trees.

---

## 🌟 Architecture & Features

- **Pillars:** Authenticate, Eliminate Unauthorised, Automate, Protect, Encrypt & Decrypt, Control.
- **Mutual TLS Broker:** Eclipse Mosquitto 2.0.x enforcing client certificate authentication over mTLS (Port 8883).
- **Proof-of-Possession (PoP):** HTTP API authentication via application-layer ECDSA-SHA256 signatures (`X-AS-*` headers).
- **Automated Key Rotation:** Device key pair generation on-device, staging slot test connection, and zero-downtime commit/rollback.
- **Instant Revocation:** Live session termination in < 2 seconds + atomic CRL updates.
- **Tamper-Evident Audit Log:** Append-only Advisory-locked PostgreSQL audit log with continuous SHA-256 hash chaining.
- **ESP32 Firmware:** PlatformIO + ESP-IDF firmware with Wi-Fi manager (`SSID: Sunny`), mTLS MQTT client, automatic key rotation, and onboard local HTTP web server console.

---

## 🚀 Quick Start with Docker Compose

### 1. Initialize PKI & Secrets
```bash
python3 tools/init_pki.py
```

### 2. Launch Stack with Docker Compose
```bash
docker compose up -d
```

Services started:
- `postgres`: PostgreSQL 16 database.
- `mosquitto`: mTLS MQTT Broker on port `8883`.
- `api`: FastAPI REST & WebSocket server on port `8000`.
- `bridge`: Background worker for log parsing, expiry kicking, and rotation watching.
- `dashboard-build`: React + Vite static web UI builder.
- `caddy`: Reverse proxy on ports `80` / `443`.

---

## 🧪 Running Tests

```bash
# Backend Unit & Integration Tests
pytest backend/tests

# Run Mosquitto Verification Spike
python3 tools/spike/verify_broker_assumptions.py
```

---

## 📁 Firmware Deployment (ESP32)

Location: `firmware/esp32/`

- Configured Wi-Fi: **SSID:** `Sunny`, **Password:** `sunny485`
- Onboard Console: Accessible locally via `http://<ESP32_IP>:80/`
- Build & Flash using PlatformIO:
  ```bash
  cd firmware/esp32
  pio run --target upload
  ```

---
*AuthSphere — Designed for IoT Cryptographic Identity & Fleet Security.*
# AuthSphere
