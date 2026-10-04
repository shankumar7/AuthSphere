#!/usr/bin/env python3
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta, timezone

def main():
    # Generate self-signed key & cert for rogue device (not signed by AuthSphere CA)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    key_pem = rogue_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "dev-esp32-01"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Rogue CA"),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(rogue_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    cert_lines = [f'        "{line}\\n"' for line in cert_pem.strip().split('\n')]
    key_lines = [f'        "{line}\\n"' for line in key_pem.strip().split('\n')]

    cert_c_str = '\n'.join(cert_lines)
    key_c_str = '\n'.join(key_lines)

    ino_content = f'''/*
 * AuthSphere ESP32 Rogue / Impersonation Test Node
 * 
 * DEMO PURPOSE:
 *   - Attempts to impersonate valid entity ID: dev-esp32-01
 *   - Uses an UNTRUSTED self-signed EC P-256 certificate (NOT signed by AuthSphere CA)
 *   - Demonstrates that AuthSphere mTLS zero-trust broker (Mosquitto:8883)
 *     STRICTLY REJECTS rogue/unauthorized device authentication attempts.
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <mqtt_client.h>

#define WIFI_SSID         "Sunny"
#define WIFI_PASS         "sunny485"
#define MQTT_BROKER_HOST  "10.123.189.104"
#define MQTT_BROKER_PORT  8883
#define TARGET_ENTITY_ID  "dev-esp32-01"
#define WEB_SERVER_PORT   80

// ==================== Embedded Root CA ====================
static const char root_ca_pem[] = \\
"-----BEGIN CERTIFICATE-----\\n" \\
"MIIB0zCCAXqgAwIBAgIUIBHqg4mFougAFJC9rmgNwVD98WwwCgYIKoZIzj0EAwIw\\n" \\
"MjEbMBkGA1UEAwwSQXV0aFNwaGVyZSBSb290IENBMRMwEQYDVQQKDApBdXRoU3Bo\\n" \\
"ZXJlMB4XDTI2MTAwMzEwMTczOFoXDTI4MTAwMjEwMTgzOFowOjEjMCEGA1UEAwwa\\n" \\
"QXV0aFNwaGVyZSBJbnRlcm1lZGlhdGUgQ0ExEzARBgNVBAoMCkF1dGhTcGhlcmUw\\n" \\
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxT5TtFEF8n/y7yrc4zS9hPXaQJPL7\\n" \\
"fVrZo6StFMYCyVuaNnr6F/f1bjkEeXP/a8koTweVt3UPK1o0mXFctb91o2YwZDAS\\n" \\
"BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUs7PO\\n" \\
"hs3j+RubAcwsRui0J8IV0jowHwYDVR0jBBgwFoAUbRP98sErzroIS/yiud0qMdD9\\n" \\
"l0IwCgYIKoZIzj0EAwIDRwAwRAIgGjAdcl8pb2jhKNDALOK7W3vxEpcp3w9aUgda\\n" \\
"R3k/U7wCIAd5qHIvd5zBP/YtU/sG8aOCUYzjCrE0+Bt/7ZGKZ+iO\\n" \\
"-----END CERTIFICATE-----\\n";

// ==================== Self-Signed Fake/Rogue Certificate ====================
static const char rogue_cert_pem[] = 
{cert_c_str};

static const char rogue_key_pem[] = 
{key_c_str};

// ==================== Globals ====================
static esp_mqtt_client_handle_t s_mqtt_client = NULL;
static bool s_mqtt_connected = false;
static int  s_failed_attempts = 0;

WebServer webServer(WEB_SERVER_PORT);

// ==================== MQTT Event Handler ====================
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {{
    case MQTT_EVENT_CONNECTED:
        Serial.println("[ROGUE_NODE] CRITICAL ERROR: Unexpected mTLS connection success!");
        s_mqtt_connected = true;
        break;
    case MQTT_EVENT_DISCONNECTED:
        s_failed_attempts++;
        Serial.printf("[ROGUE_NODE] [SECURITY DEMO] mTLS Handshake REJECTED by AuthSphere Broker! (Total Failures: %d)\\n", s_failed_attempts);
        s_mqtt_connected = false;
        break;
    case MQTT_EVENT_ERROR:
        Serial.println("[ROGUE_NODE] [SECURITY DEMO] mTLS Handshake Error (Untrusted/Unsigned Cert Rejection)");
        break;
    default:
        break;
    }}
}}

void mqtt_link_init() {{
    esp_mqtt_client_config_t mqtt_cfg = {{}};
    mqtt_cfg.broker.address.hostname  = MQTT_BROKER_HOST;
    mqtt_cfg.broker.address.port      = MQTT_BROKER_PORT;
    mqtt_cfg.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;

    mqtt_cfg.broker.verification.certificate                 = root_ca_pem;
    mqtt_cfg.broker.verification.certificate_len             = strlen(root_ca_pem) + 1;
    mqtt_cfg.broker.verification.skip_cert_common_name_check = true;

    mqtt_cfg.credentials.client_id = TARGET_ENTITY_ID;
    mqtt_cfg.credentials.authentication.certificate     = rogue_cert_pem;
    mqtt_cfg.credentials.authentication.certificate_len = strlen(rogue_cert_pem) + 1;
    mqtt_cfg.credentials.authentication.key             = rogue_key_pem;
    mqtt_cfg.credentials.authentication.key_len         = strlen(rogue_key_pem) + 1;

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_mqtt_client) {{
        esp_mqtt_client_register_event(s_mqtt_client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    }}
}}

// ==================== Web Server Dashboard ====================
static const char HTML_PAGE[] PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthSphere Rogue Device Demo</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #1e293b; padding: 24px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 2px solid #ef4444; }}
        h1 {{ color: #ef4444; font-size: 24px; margin-top: 0; display: flex; align-items: center; justify-content: space-between; }}
        .badge {{ background: #ef4444; color: #ffffff; font-size: 12px; font-weight: bold; padding: 4px 10px; border-radius: 20px; text-transform: uppercase; }}
        .card {{ background: #0f172a; padding: 16px; border-radius: 8px; margin-bottom: 16px; border: 1px solid #334155; }}
        .card-title {{ font-size: 14px; color: #94a3b8; text-transform: uppercase; font-weight: bold; margin-bottom: 8px; }}
        .stat-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1e293b; font-size: 14px; }}
        .stat-row:last-child {{ border-bottom: none; }}
        .stat-label {{ color: #94a3b8; }}
        .stat-value {{ font-family: monospace; color: #e2e8f0; font-weight: bold; }}
        .alert-box {{ background: #451a1a; border: 1px solid #991b1b; padding: 12px; border-radius: 8px; color: #fca5a5; font-size: 14px; margin-bottom: 16px; text-align: center; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1><span>&#x26A0;&#xFE0F; Rogue Impersonator Node</span> <span class="badge">REJECTED</span></h1>
        <div class="alert-box">
            &#x274C; ACCESS DENIED BY AUTTSPHERE SECURITY POLICY<br>
            Self-signed certificate is NOT trusted by Intermediate CA.
        </div>
        <div class="card">
            <div class="card-title">Impersonation Attempt Details</div>
            <div class="stat-row"><span class="stat-label">Target Entity ID:</span><span class="stat-value">dev-esp32-01</span></div>
            <div class="stat-row"><span class="stat-label">Certificate Type:</span><span class="stat-value" style="color:#ef4444;">Self-Signed (Untrusted)</span></div>
            <div class="stat-row"><span class="stat-label">Broker Status:</span><span class="stat-value" id="mqtt" style="color:#ef4444;">REJECTED / DISCONNECTED</span></div>
            <div class="stat-row"><span class="stat-label">Total Rejection Count:</span><span class="stat-value" id="fails" style="color:#f59e0b;">0</span></div>
        </div>
    </div>
    <script>
        setInterval(() => {{
            fetch('/api/status').then(r=>r.json()).then(d=>{{
                document.getElementById('fails').textContent = d.failed_attempts;
            }}).catch(e=>console.error(e));
        }}, 1500);
    </script>
</body>
</html>
)rawhtml";

void handleRoot() {{
    webServer.send(200, "text/html", HTML_PAGE);
}}

void handleApiStatus() {{
    char json[128];
    snprintf(json, sizeof(json),
        "{{\\\"connected\\\":false,\\\"failed_attempts\\\":%d}}",
        s_failed_attempts);
    webServer.send(200, "application/json", json);
}}

void setup() {{
    Serial.begin(115200);
    delay(1000);

    Serial.println("==================================================");
    Serial.println("  AuthSphere Rogue Device Impersonation Demo Node ");
    Serial.println("==================================================");

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    Serial.print("[main] Connecting to Wi-Fi...");
    while (WiFi.status() != WL_CONNECTED) {{
        delay(500);
        Serial.print(".");
    }}
    Serial.println();
    Serial.printf("[main] Connected! Rogue Node Web Dashboard IP: %s\\n", WiFi.localIP().toString().c_str());

    webServer.on("/", HTTP_GET, handleRoot);
    webServer.on("/api/status", HTTP_GET, handleApiStatus);
    webServer.begin();

    Serial.printf("[main] Attempting unauthorized mTLS link to broker %s:%d as client '%s'...\\n", MQTT_BROKER_HOST, MQTT_BROKER_PORT, TARGET_ENTITY_ID);
    mqtt_link_init();
    if (s_mqtt_client) esp_mqtt_client_start(s_mqtt_client);
}}

void loop() {{
    webServer.handleClient();
}}
'''

    out_dir = Path("/Users/shankumar/Documents/Arduino/AuthsphereESP32_Rogue")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "AuthsphereESP32_Rogue.ino"
    out_file.write_text(ino_content)

    # Also save a copy in repo
    repo_out = Path(__file__).resolve().parent.parent / "firmware" / "esp32" / "AuthsphereESP32_Rogue.ino"
    repo_out.write_text(ino_content)

    print(f"[+] Successfully created rogue device sketch at:")
    print(f"    - {out_file}")
    print(f"    - {repo_out}")

if __name__ == "__main__":
    main()
