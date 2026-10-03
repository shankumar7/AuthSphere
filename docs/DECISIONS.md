# AuthSphere — Architectural & Technical Decisions Log

This document records all key architectural decisions, formal deviations, and verification spike findings as required by `PROJECT.md` (§10 rule 2).

Format: `## D-NNN: question → decision → reason`

---

## D-001: Phase 0 Setup & Project Architecture Initialization
* **Question:** How is the repository structure organized for modular microservice deployment with Docker Compose?
* **Decision:** Follow the exact repository layout specified in `ARCHITECTURE.md` §13 with dedicated root directories for `backend/`, `broker/`, `caddy/`, `dashboard/`, `firmware/esp32/`, `clients/pi_messenger/`, and `tools/`.
* **Reason:** Ensures strict separation of concerns between backend logic, broker security configuration, frontend UI, IoT firmware, E2E chat clients, and PKI/attack automation tools.

---

## D-002: Phase 0 Broker Verification Spike Findings (A1, A2, A3)
* **Question:** Are Mosquitto 2.0.x Dynamic Security features (CN matching, dynamic kicking, CRL reloading via SIGHUP) sufficient or is fallback to EMQX required?
* **Decision:** Keep Eclipse Mosquitto 2.0.x with Dynamic Security as the primary broker (`app/broker/dynsec.py`), while abstracting all broker administration behind `BrokerAdmin` protocol interface (`app/broker/base.py`).
* **Reason:** Spike tests verified that:
  - **A1:** Certificate CN is mapped directly to MQTT username via `use_identity_as_username true`, enabling `%u` ACL matching in Dynamic Security without needing passwords.
  - **A2:** Disabling or deleting a client via Dynamic Security command drops active connections within 2 seconds.
  - **A3:** Updating `crl.pem` and sending `SIGHUP` forces OpenSSL/Mosquitto to reload revocation lists; log streaming to `$SYS/broker/log/#` captures TLS failure and ACL denial events.
