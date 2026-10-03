# AuthSphere — Project Specification

> **Audience:** an AI coding agent (Antigravity) that will build this project.
> **Companion file:** `ARCHITECTURE.md` (system design, data model, API, protocols). Read BOTH files completely before writing any code.
> **Rule of precedence:** if the two files ever disagree, `ARCHITECTURE.md` wins on technical detail, this file wins on scope and priorities.

---

## 1. What AuthSphere is

AuthSphere is a **secure device and user authentication framework for IoT**, built to be demonstrated live and to look and behave like a professional product.

It gives every IoT device (ESP32) and every user (a Raspberry Pi running a chat client) a **unique cryptographic identity based on Elliptic Curve Cryptography (ECC, curve P-256)**. Identities are X.509 certificates issued by AuthSphere's own Certificate Authority. An MQTT broker accepts only connections that present a valid AuthSphere certificate, and a policy engine restricts each identity to the topics its role allows.

AuthSphere replaces the weak practices found in typical IoT systems: hardcoded passwords, shared keys, manual provisioning, no revocation, no rotation.

(Earlier internal name: *SecureNodeX*. The product name is now **AuthSphere**. Use "AuthSphere" everywhere in code, UI, and docs.)

### The six pillars (every feature maps to one of these)

| Pillar | Meaning | Delivered by |
|---|---|---|
| **Authenticate** | Prove who a device/user is | Per-entity ECC identity, mutual TLS, signed requests |
| **Eliminate unauthorised** | Block anything not trusted | Revocation, ACL deny, rogue-cert rejection, Attack Lab |
| **Automate** | No manual credential handling | Zero-touch onboarding, automatic rotation, lifecycle states |
| **Protect** | Keep keys and records safe | Encrypted key storage, hash-chained audit log, hardening |
| **Encrypt & Decrypt** | Confidentiality and integrity | TLS transport + end-to-end encrypted ECC messenger |
| **Control** | Operators stay in charge | Role-based policies, dashboard, remote commands, rotate/revoke |

---

## 2. Goals and non-goals

### Goals
1. Working end-to-end system: ESP32 devices + Raspberry Pis + cloud backend, all talking over mutually authenticated TLS.
2. A **live demo** that shows both **success cases** (device enrolls, connects, rotates its key) and **failure cases** (attacks being rejected), with every event visible on a dashboard in real time.
3. A **professional-grade backend in Python** with a clean API, tests, migrations, audit trail, and Docker deployment.
4. A **management dashboard** (web) for fleet, policies, rotation, revocation, audit, and live security feed.
5. An **end-to-end encrypted ECC messenger** between two Raspberry Pis, using the same identities, proving the cryptography works live.
6. Everything runs from **Docker Compose** and is reachable from the internet (cloud VM).

### Non-goals (do NOT build these)
- Not Signal-grade messaging: no double ratchet, no group chats, no message history sync.
- No multi-tenancy, no high availability / clustering, no Kubernetes.
- No hardware security module (HSM) integration.
- No OTA firmware update system (may be listed as future work only).
- No RSA anywhere in the product (RSA appears only in the benchmark comparison).
- No username/password authentication for devices. Ever.

---

## 3. Technology stack (fixed — do not substitute)

| Layer | Choice |
|---|---|
| Backend language | **Python 3.12** |
| Web framework | **FastAPI** + Uvicorn |
| Validation | Pydantic v2 |
| Database | **PostgreSQL 16** via SQLAlchemy 2.0 (async, `asyncpg`) + Alembic migrations |
| Crypto | **`cryptography`** library (all PKI work: keys, CSRs, certs, CRL, ECDH, ECDSA, AES-GCM, HKDF) |
| MQTT client (backend) | `aiomqtt` (async wrapper over paho) |
| MQTT broker | **Eclipse Mosquitto 2.0.x** with the **Dynamic Security plugin** |
| Dashboard auth | argon2id (`argon2-cffi`), JWT (`pyjwt`), TOTP (`pyotp`) |
| Rate limiting | `slowapi` |
| Logging | `structlog` (JSON), with secret redaction |
| Reverse proxy / TLS for web | **Caddy 2** (automatic Let's Encrypt) |
| Dashboard | **React 18 + Vite + TypeScript + Tailwind CSS**, TanStack Query, React Router, Recharts, native WebSocket |
| Firmware (ESP32) | **PlatformIO + ESP-IDF** (C/C++), mbedTLS, `esp-mqtt` |
| Pi messenger client | Python 3.12, `cryptography`, `aiomqtt`, `textual` (terminal UI) |
| Packaging | Docker + Docker Compose |
| Quality | `pytest`, `pytest-asyncio`, `ruff`, `mypy --strict`, GitHub Actions |

---

## 4. System components (summary)

Details are in `ARCHITECTURE.md`. Names below are used consistently everywhere.

| Component | Container / folder | Purpose |
|---|---|---|
| **API** | `api` (`backend/`) | REST + WebSocket. Runs the CA, enrollment, rotation, revocation, policies, audit, directory. |
| **Bridge** | `bridge` (`backend/`, same image, different command) | Background workers: ingest MQTT events/telemetry, parse broker logs, expiry kicker, rotation watcher, retention. |
| **Broker** | `mosquitto` | MQTT over mutual TLS on port 8883, ACLs via Dynamic Security. |
| **Database** | `postgres` | All persistent state except the CA private key. |
| **Edge proxy** | `caddy` | HTTPS for API and dashboard (ports 80/443). |
| **Dashboard** | `dashboard/` (built to static files served by Caddy) | Management UI. |
| **Firmware** | `firmware/esp32/` | ESP32 firmware: enroll, connect, publish, rotate. |
| **Pi messenger** | `clients/pi_messenger/` | E2E encrypted chat client for Raspberry Pi. |
| **Tools** | `tools/` | PKI init script, device provisioning script, Attack Lab scripts. |

---

## 5. Core concepts (definitions the agent must use)

- **Entity** — anything with an identity. Three types: `device` (ESP32), `user` (messenger user on a Pi), `service` (internal: the API and the bridge).
- **Entity ID** — unique slug, regex `^[a-z0-9][a-z0-9-]{2,31}$`, with a mandatory prefix by type: `dev-…`, `usr-…`, `svc-…`. Example: `dev-greenhouse-01`. The entity ID is the certificate **Common Name (CN)** and the **MQTT username**.
- **Role** — a named policy: which MQTT topics are allowed, certificate lifetime, when to renew. Examples: `sensor`, `actuator`, `chat-user`.
- **Certificate kinds** — `bootstrap` (proves a device is allowed to ask for credentials; **cannot** connect to MQTT) and `operational` (short-lived; used for MQTT).
- **Claim token** — one-time secret, valid ~10 minutes, that lets a brand-new device obtain its first certificate (Mode A).
- **Proof of Possession (PoP)** — a request signed with the private key of the device's current certificate. Used for rotation. Defined exactly in `ARCHITECTURE.md` §7.
- **Rotation** — replacing a device's key pair and certificate with a new one, automatically, before expiry.
- **Revocation** — permanently invalidating an entity's certificates and cutting off its live connection.

---

## 6. Functional requirements

Each requirement has an ID. Tests and acceptance criteria refer to these IDs.

### 6.1 Authenticate
- **FR-A1** Every entity has exactly one unique ECC P-256 identity at a time (one active operational certificate).
- **FR-A2** The broker requires a client certificate on every connection (`require_certificate true`). No anonymous access, no passwords.
- **FR-A3** The MQTT username is taken from the certificate CN (`use_identity_as_username true`).
- **FR-A4** The firmware never contains a private key in its binary. Private keys exist only (a) generated on the device, or (b) in a per-device provisioning partition (never in the firmware image, never in git).
- **FR-A5** Dashboard users log in with email + password (argon2id) + TOTP. Roles: `admin`, `operator`, `viewer`.

### 6.2 Eliminate unauthorised
- **FR-E1** Connection attempts with no cert, a cert from an unknown CA, an expired cert, or a revoked cert MUST be rejected at the TLS layer.
- **FR-E2** A valid entity publishing/subscribing outside its role's topics MUST be denied by ACL, and the denial MUST be logged and shown in the dashboard.
- **FR-E3** Revoking an entity MUST disconnect it within **2 seconds** and block reconnection.
- **FR-E4** Claim tokens are single-use and expire. A reused or expired token MUST be rejected.
- **FR-E5** A cloned certificate without its private key MUST fail the TLS handshake.

### 6.3 Automate
- **FR-M1** Zero-touch onboarding in two modes:
  - **Mode A — claim token:** device generates its own key, uses a one-time token to get its first certificate.
  - **Mode B — factory provisioning:** a provisioning script flashes a **unique per-device identity** into a separate partition; the device becomes active on first boot without any manual step.
- **FR-M2** Automatic certificate and key rotation (see 6.7).
- **FR-M3** Entity lifecycle states are tracked and visible: `PENDING → ACTIVE → EXPIRED | REVOKED`.
- **FR-M4** The device self-reports firmware version, current certificate serial, and online/offline state (with MQTT Last Will).

### 6.4 Protect
- **FR-P1** The CA root private key is created offline and is **never** placed in any container or volume.
- **FR-P2** The intermediate CA key is a Docker secret (file mode 0400), never in the DB, never in env vars, never logged.
- **FR-P3** Claim tokens are stored only as SHA-256 hashes. Shown to the admin exactly once.
- **FR-P4** The audit log is append-only and **hash-chained**; the API exposes a verification endpoint that detects tampering.
- **FR-P5** Secrets (private keys, tokens, passwords, TOTP secrets) MUST NEVER appear in logs or API responses (except the one-time claim token on creation).
- **FR-P6** ESP32 key storage uses encrypted NVS. Flash encryption / secure boot are documented as optional hardening (irreversible; test on a sacrificial board).

### 6.5 Encrypt & Decrypt
- **FR-C1** All device-to-broker traffic uses TLS 1.2+ with ECDHE-ECDSA cipher suites.
- **FR-C2** The messenger is **end-to-end encrypted**: the broker and backend only ever see ciphertext.
- **FR-C3** Messenger crypto: ephemeral ECDH (P-256) → HKDF-SHA256 → AES-256-GCM, with an ECDSA-P256 signature from the sender (exact format in `ARCHITECTURE.md` §9).
- **FR-C4** The messenger rejects: tampered ciphertext, forged signatures, replayed messages, unknown/revoked sender certificates.
- **FR-C5** A dashboard "Messenger Inspector" shows what the server sees (ciphertext envelope) and can be switched off (`CHAT_INSPECTOR_ENABLED`).

### 6.6 Control
- **FR-K1** Roles define topic permissions, certificate lifetime, and renewal point; editable by `admin` in the dashboard.
- **FR-K2** Operators can: create entities, regenerate claim tokens, rotate now, revoke, view everything.
- **FR-K3** Admin-only: manage roles, dashboard users, demo mode, bulk emergency actions (revoke/rotate all entities of a role).
- **FR-K4** Remote command: dashboard can publish a `rotate` command to a device over MQTT.

### 6.7 Key and certificate rotation (headline feature)
- **FR-R1** Operational certificates are short-lived (role policy; default **7 days**).
- **FR-R2** The device renews automatically at **~66 %** of lifetime plus random jitter (spreads fleet load).
- **FR-R3** Rotation generates a **new key pair** (rekey), not just a new certificate.
- **FR-R4** The new credentials go to a **staging slot**; the device test-connects with them, then **commits**; on failure it **rolls back** and keeps the old credentials.
- **FR-R5** The new certificate is first `issued` (unconfirmed). When the device confirms it (by reconnecting with it and reporting the new serial), the new cert becomes `active` and the old one is revoked with reason `superseded`. If no confirmation arrives within the confirmation timeout (default 300 s; 30 s in demo mode), the new cert is revoked as `unconfirmed` and the old one stays valid, so the device can safely retry.
- **FR-R6** Manual and emergency rotation: "Rotate now" (single entity) and bulk by role.
- **FR-R7** The broker does not drop sessions when a cert expires on its own; the **expiry kicker** worker MUST disconnect any session whose certificate is past `not_after`.
- **FR-R8** **Demo mode** (`DEMO_MODE=true`): operational cert lifetime is overridden to **120 seconds** (renew at ~60 %), so rotation can be shown live.
- **FR-R9** Messenger identities rotate the same way; message envelopes carry key IDs so recipients pick the right key.
- **FR-R10** Intermediate CA and broker server certificate rotation are supported without reflashing devices (devices pin only the **root** CA). Firmware ships with **two** root slots (`current`, `next`) to allow future root rotation.

---

## 7. Demo scenarios (the product must support all of these live)

Total target time: ~12 minutes.

| # | Scene | What the audience sees |
|---|---|---|
| 1 | **Enroll a device (Mode A)** | Admin creates `dev-demo-01` → QR/token → ESP32 enrolls → card turns green "ACTIVE" |
| 2 | **Factory provisioning (Mode B)** | Run `tools/provision_device.py` → ESP32 boots straight to ACTIVE |
| 3 | **Live telemetry** | Sensor values stream into the dashboard over mTLS |
| 4 | **Live key rotation** | Demo mode ON → ESP32 rotates itself; old serial → `revoked (superseded)`, new serial → `active`; telemetry never stops |
| 5 | **Attack Lab** | Run attacks from a Pi; each one produces a **red** event in the live feed (see §8) |
| 6 | **Revoke mid-stream** | Click Revoke → device is kicked in < 2 s |
| 7 | **E2E messenger** | Pi A → Pi B message decrypts; Messenger Inspector shows only ciphertext |
| 8 | **Messenger attacks** | Tamper / forge / replay → all rejected by the receiving client |
| 9 | **RSA vs ECC benchmark** | Real timings measured on the ESP32 shown in the dashboard |
| 10 | **Plaintext vs TLS capture** | Wireshark: demo-only plaintext listener is readable, port 8883 is not |

---

## 8. Attack Lab (required)

Python scripts in `tools/attack_lab/`, runnable from any Pi/laptop. Each script prints `EXPECTED` and `ACTUAL` and exits non-zero if actual ≠ expected. `tools/attack_lab/run_all.py` runs them all.

| ID | Attack | Expected result | Dashboard event |
|---|---|---|---|
| AL-1 | Connect with no client cert | TLS handshake rejected | `broker.tls_reject` |
| AL-2 | Connect with cert signed by a rogue CA | Rejected | `broker.tls_reject` |
| AL-3 | Connect with an expired cert | Rejected | `broker.tls_reject` |
| AL-4 | Connect with a revoked cert | Rejected | `broker.tls_reject` |
| AL-5 | Valid device publishes to another device's topic | ACL deny | `broker.acl_deny` |
| AL-6 | Present a copied cert without its private key | Handshake fails | `broker.tls_reject` |
| AL-7 | Reuse an enrollment claim token | HTTP 409/410 | `pki.enroll_denied` |
| AL-8 | Rotation request with bad/old signature, or replayed nonce | HTTP 401 | `pki.rotate_denied` |
| AL-9 | Use a bootstrap cert to connect to MQTT | Rejected (no clientAuth EKU) | `broker.tls_reject` |

Messenger attacks (`clients/pi_messenger/` commands `tamper`, `forge`, `replay`): see `ARCHITECTURE.md` §9.5.

---

## 9. Build phases (build in this order; finish and test each before the next)

For every phase: write the code, write the tests, make CI green, update `README.md`. Do not start a phase until the previous phase's "Done when" is true.

### Phase 0 — Foundations and **verification spike**
Deliverables: repo skeleton (see `ARCHITECTURE.md` §13), Docker Compose with `postgres` + `mosquitto`, CI pipeline, and a short script proving the **three broker assumptions** listed in `ARCHITECTURE.md` §4.4.
**Done when:** the three assumptions are verified (or the documented fallback is chosen and recorded in `docs/DECISIONS.md`).

### Phase 1 — PKI and mTLS broker
Deliverables: `tools/init_pki.py` (root offline, intermediate, broker cert, service certs), `pki/` module (issue cert from CSR, CRL generation), Mosquitto configured for mTLS + Dynamic Security, manual test client connecting with an issued cert.
**Done when:** valid cert connects; no-cert / rogue-CA / expired-cert are rejected (AL-1..AL-3 pass as automated tests).

### Phase 2 — Entities, roles, enrollment (both modes)
Deliverables: DB models + migrations, `/entities`, `/roles`, claim tokens, `POST /pki/enroll`, `POST /provision/bootstrap`, dynsec client/role sync, PoP auth dependency, `tools/provision_device.py`, audit log with hash chain.
**Done when:** a Python test "device" can enroll in Mode A and Mode B and connect to MQTT; AL-7 passes; audit chain verifies.

### Phase 3 — Rotation and revocation
Deliverables: `POST /pki/rotate`, rotation events, confirmation-timeout watcher, CRL publishing + broker reload watcher, bridge workers (expiry kicker, rotation watcher), `POST /entities/{id}/revoke`, bulk actions, `rotate` MQTT command, demo mode.
**Done when:** a test device rotates automatically in demo mode with zero lost telemetry; revoke kicks within 2 s (FR-E3); AL-4 and AL-8 pass.

### Phase 4 — ESP32 firmware
Deliverables: `firmware/esp32/` implementing the state machine in `ARCHITECTURE.md` §10 (time sync, identity store with staging slot, CSR + PoP, enrollment, mTLS MQTT, telemetry, rotation manager, benchmark, attack mode, serial CLI).
**Done when:** a real ESP32 enrolls (both modes), publishes telemetry, and rotates in demo mode.

### Phase 5 — Dashboard
Deliverables: all pages in `ARCHITECTURE.md` §11, live WebSocket feed, RBAC in the UI, TOTP login flow.
**Done when:** scenes 1–6 and 9 of the demo run entirely through the dashboard.

### Phase 6 — Attack Lab and messenger
Deliverables: all `tools/attack_lab/` scripts + `run_all.py`; `clients/pi_messenger/` with key directory, E2E crypto, `tamper`/`forge`/`replay` commands; Messenger Inspector page.
**Done when:** AL-1..AL-9 pass; two Pis exchange encrypted messages; all messenger attacks are rejected.

### Phase 7 — Deploy, harden, document
Deliverables: production Compose profile on a cloud VM with domain + Let's Encrypt, firewall (only 443, 80, 8883 open), backups of Postgres + `pki-state`, Prometheus metrics endpoint, `README.md` with quick-start, `docs/DEMO_SCRIPT.md`.
**Done when:** the full demo (§7) works over the internet against the cloud VM.

---

## 10. Quality and coding rules for the agent

1. **Python style:** type hints everywhere, `mypy --strict` clean, `ruff` clean, async I/O for DB and MQTT, no blocking calls in request handlers.
2. **No invention:** implement only endpoints, tables, topics, and fields defined in `ARCHITECTURE.md`. If something is missing, add a short entry to `docs/DECISIONS.md` (`## D-NNN: question → decision → reason`) and add a `# DECISION: D-NNN` comment at the code site. Do not silently deviate.
3. **Secrets:** never hardcode secrets, keys, or tokens. Never print them. Use Docker secrets / environment variables as specified.
4. **Crypto:** use only the `cryptography` library (Python) and mbedTLS (firmware). Do not implement any primitive yourself. Never use RSA, MD5, SHA-1, ECB mode, or static IVs/nonces.
5. **Errors:** every API error returns the JSON shape defined in `ARCHITECTURE.md` §8.1. Never leak stack traces or internal details.
6. **Audit:** every security-relevant action writes an audit entry (list in `ARCHITECTURE.md` §6.9).
7. **Tests:** unit tests for pki, PoP, policy, log parser, messenger crypto; integration tests against a real Mosquitto container; Attack Lab doubles as an end-to-end test suite.
8. **Migrations:** every schema change is an Alembic migration. No manual DB edits.
9. **Config:** all settings come from environment variables via one `Settings` class (`pydantic-settings`). Provide `.env.example` listing every variable.
10. **Docs:** keep `README.md` accurate: how to run, how to create the first admin, how to provision a device, how to run the demo.

---

## 11. Definition of done (whole project)

- [ ] `docker compose --profile prod up -d` starts the full stack from a clean machine using only `.env` and the init-PKI output.
- [ ] A real ESP32 enrolls in both modes, publishes telemetry, and rotates its key automatically.
- [ ] All Attack Lab scripts (AL-1..AL-9) pass and appear as events on the dashboard.
- [ ] Revoking an entity disconnects it in under 2 seconds.
- [ ] Two Raspberry Pis exchange E2E-encrypted messages; tampering/forgery/replay are rejected.
- [ ] Audit log verifies (`GET /audit/verify` returns `valid: true`) and detects a manually tampered row.
- [ ] CI is green: ruff, mypy, pytest (unit + integration).
- [ ] Reachable from the internet over HTTPS (dashboard/API) and mTLS MQTT (port 8883).
- [ ] `README.md` and `docs/DEMO_SCRIPT.md` are complete.
