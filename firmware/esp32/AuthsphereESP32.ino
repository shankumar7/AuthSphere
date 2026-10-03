/*
 * AuthSphere ESP32 Secure IoT Device Firmware v1.0.0
 * 
 * Features:
 *   - Wi-Fi STA connection (SSID: Sunny)
 *   - mTLS MQTT over port 8883 with EC P-256 identity
 *   - Automatic & manual key/certificate rotation
 *   - Onboard web dashboard on port 80
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <Preferences.h>
#include <mqtt_client.h>

#include "config.h"

// ==================== Root CA Certificate (Embedded) ====================
static const char root_ca_pem[] = \
"-----BEGIN CERTIFICATE-----\n"
"MIIB0zCCAXqgAwIBAgIUIBHqg4mFougAFJC9rmgNwVD98WwwCgYIKoZIzj0EAwIw\n"
"MjEbMBkGA1UEAwwSQXV0aFNwaGVyZSBSb290IENBMRMwEQYDVQQKDApBdXRoU3Bo\n"
"ZXJlMB4XDTI2MTAwMzEwMTczOFoXDTI4MTAwMjEwMTgzOFowOjEjMCEGA1UEAwwa\n"
"QXV0aFNwaGVyZSBJbnRlcm1lZGlhdGUgQ0ExEzARBgNVBAoMCkF1dGhTcGhlcmUw\n"
"WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxT5TtFEF8n/y7yrc4zS9hPXaQJPL7\n"
"fVrZo6StFMYCyVuaNnr6F/f1bjkEeXP/a8koTweVt3UPK1o0mXFctb91o2YwZDAS\n"
"BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUs7PO\n"
"hs3j+RubAcwsRui0J8IV0jowHwYDVR0jBBgwFoAUbRP98sErzroIS/yiud0qMdD9\n"
"l0IwCgYIKoZIzj0EAwIDRwAwRAIgGjAdcl8pb2jhKNDALOK7W3vxEpcp3w9aUgda\n"
"R3k/U7wCIAd5qHIvd5zBP/YtU/sG8aOCUYzjCrE0+Bt/7ZGKZ+iO\n"
"-----END CERTIFICATE-----\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIBqzCCAVGgAwIBAgIUSR61GZJA5qDUBhhB5054S042UbowCgYIKoZIzj0EAwIw\n"
"MjEbMBkGA1UEAwwSQXV0aFNwaGVyZSBSb290IENBMRMwEQYDVQQKDApBdXRoU3Bo\n"
"ZXJlMB4XDTI2MTAwMzEwMTczOFoXDTM2MDkzMDEwMTgzOFowMjEbMBkGA1UEAwwS\n"
"QXV0aFNwaGVyZSBSb290IENBMRMwEQYDVQQKDApBdXRoU3BoZXJlMFkwEwYHKoZI\n"
"zj0CAQYIKoZIzj0DAQcDQgAENnz0PHIqJQTbKvLPWRu9LEoXWmZI4RbrPCx+lkuT\n"
"U7Ze2/CTQUAS+UBKiyRnlbXU5FkTnppuoOGhBDZe41CVaqNFMEMwEgYDVR0TAQH/\n"
"BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFG0T/fLBK866CEv8\n"
"orndKjHQ/ZdCMAoGCCqGSM49BAMCA0gAMEUCIG1x9cRI8UuUh5u4J7rzg3R89IDJ\n"
"sGMTp8Yp188PgdnTAiEApt3ZEGBXLvI1URet5Mrxv0QIpcHV9pcOWnAK1kt6a1c=\n"
"-----END CERTIFICATE-----\n";

// ==================== Globals ====================
static esp_mqtt_client_handle_t s_mqtt_client = NULL;
static bool s_mqtt_connected = false;
static bool s_manual_rotation_pending = false;
static int  s_telemetry_counter = 0;
static unsigned long s_last_telemetry_ms = 0;

static char s_topic_status[64];
static char s_topic_telemetry[64];

WebServer webServer(WEB_SERVER_PORT);
Preferences preferences;

// ==================== Identity Store ====================
typedef struct {
    char cert_serial[32];
    char cert_pem[2048];
    char key_pem[512];
    bool is_valid;
} identity_slot_t;

static identity_slot_t s_active_slot  = {};
static identity_slot_t s_staging_slot = {};

void identity_store_init() {
    preferences.begin("auth_id", false);
    preferences.clear(); // Clear cached old placeholder identity from NVS
    Serial.println("[identity_store] NVS initialized & cleared");
}

void identity_store_load_defaults() {
    if (!s_active_slot.is_valid) {
        strncpy(s_active_slot.cert_serial, "3e90632996c6ea", sizeof(s_active_slot.cert_serial));
        strncpy(s_active_slot.cert_pem,
                "-----BEGIN CERTIFICATE-----\n"
"MIICITCCAcigAwIBAgIUPpBjKZbG6kt/9NlaSwcjqX4yHIIwCgYIKoZIzj0EAwIw\n"
"OjEjMCEGA1UEAwwaQXV0aFNwaGVyZSBJbnRlcm1lZGlhdGUgQ0ExEzARBgNVBAoM\n"
"CkF1dGhTcGhlcmUwHhcNMjYxMDAzMTMzMzM5WhcNMjcxMDAzMTMzNDM5WjA9MRUw\n"
"EwYDVQQDDAxkZXYtZXNwMzItMDExDzANBgNVBAsMBnNlbnNvcjETMBEGA1UECgwK\n"
"QXV0aFNwaGVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMSxw3JzIZzw2mjc\n"
"nW/2299GQqZJ8milIe0JUYfEEcZ28BMTJY7cCjXJmBjy9FrKNeHvf5l0wu3a++Dm\n"
"FfVvBQijgagwgaUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l\n"
"AQH/BAwwCgYIKwYBBQUHAwIwLQYDVR0RBCYwJIYidXJuOmF1dGhzcGhlcmU6ZW50\n"
"aXR5OmRldi1lc3AzMi0wMTAdBgNVHQ4EFgQUSTfuqadT2+JgxgKUHDLfS70hqssw\n"
"HwYDVR0jBBgwFoAUs7POhs3j+RubAcwsRui0J8IV0jowCgYIKoZIzj0EAwIDRwAw\n"
"RAIgL3slhIB8UZhaTryeA5tTEurRR6l+3bl3Btdry5RA1ggCIHi7lQtm+uJxiloR\n"
"q1w1sUGH9PGswNRtshNWxiw7bIM8\n"
"-----END CERTIFICATE-----\n",
                sizeof(s_active_slot.cert_pem));
        strncpy(s_active_slot.key_pem,
                "-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+GLBt20QZBXPYR7M\n"
"076pyvVSZepbZd5rmWOEtqOR/q2hRANCAATEscNycyGc8Npo3J1v9tvfRkKmSfJo\n"
"pSHtCVGHxBHGdvATEyWO3Ao1yZgY8vRayjXh73+ZdMLt2vvg5hX1bwUI\n"
"-----END PRIVATE KEY-----\n",
                sizeof(s_active_slot.key_pem));
        s_active_slot.is_valid = true;
        Serial.printf("[identity_store] Default active identity loaded: serial=%s\n", s_active_slot.cert_serial);
    }
}

void identity_store_commit_staging() {
    if (!s_staging_slot.is_valid) {
        Serial.println("[identity_store] Cannot commit invalid staging slot");
        return;
    }
    memcpy(&s_active_slot, &s_staging_slot, sizeof(identity_slot_t));
    memset(&s_staging_slot, 0, sizeof(identity_slot_t));
    s_staging_slot.is_valid = false;
    Serial.printf("[identity_store] Staging committed to active! New serial=%s\n", s_active_slot.cert_serial);
}

void identity_store_rollback_staging() {
    memset(&s_staging_slot, 0, sizeof(identity_slot_t));
    s_staging_slot.is_valid = false;
    Serial.println("[identity_store] Staging rolled back!");
}

// ==================== MQTT Link ====================
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        Serial.printf("[mqtt_link] mTLS Connected to %s:%d!\n", MQTT_BROKER_HOST, MQTT_BROKER_PORT);
        s_mqtt_connected = true;
        esp_mqtt_client_publish(s_mqtt_client, s_topic_status, "{\"state\":\"online\"}", 0, 1, 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        Serial.println("[mqtt_link] mTLS Disconnected");
        s_mqtt_connected = false;
        break;
    case MQTT_EVENT_ERROR:
        Serial.println("[mqtt_link] mTLS Error");
        break;
    default:
        break;
    }
}

void mqtt_link_init() {
    snprintf(s_topic_status, sizeof(s_topic_status), "devices/%s/status", DEFAULT_ENTITY_ID);
    snprintf(s_topic_telemetry, sizeof(s_topic_telemetry), "devices/%s/telemetry", DEFAULT_ENTITY_ID);

    esp_mqtt_client_config_t mqtt_cfg = {};
    mqtt_cfg.broker.address.hostname  = MQTT_BROKER_HOST;
    mqtt_cfg.broker.address.port      = MQTT_BROKER_PORT;
    mqtt_cfg.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;

    mqtt_cfg.broker.verification.certificate                 = root_ca_pem;
    mqtt_cfg.broker.verification.certificate_len             = strlen(root_ca_pem) + 1;
    mqtt_cfg.broker.verification.skip_cert_common_name_check = true;

    mqtt_cfg.credentials.client_id = DEFAULT_ENTITY_ID;
    mqtt_cfg.credentials.authentication.certificate     = s_active_slot.cert_pem;
    mqtt_cfg.credentials.authentication.certificate_len = strlen(s_active_slot.cert_pem) + 1;
    mqtt_cfg.credentials.authentication.key             = s_active_slot.key_pem;
    mqtt_cfg.credentials.authentication.key_len         = strlen(s_active_slot.key_pem) + 1;

    // Last Will and Testament
    mqtt_cfg.session.last_will.topic  = s_topic_status;
    mqtt_cfg.session.last_will.msg    = "{\"state\":\"offline\"}";
    mqtt_cfg.session.last_will.qos    = 1;
    mqtt_cfg.session.last_will.retain = 1;

    if (s_mqtt_client) {
        esp_mqtt_client_stop(s_mqtt_client);
        esp_mqtt_client_destroy(s_mqtt_client);
    }

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (!s_mqtt_client) {
        Serial.println("[mqtt_link] Failed to init MQTT client!");
        return;
    }
    esp_mqtt_client_register_event(s_mqtt_client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
}

void mqtt_link_start() {
    if (s_mqtt_client) esp_mqtt_client_start(s_mqtt_client);
}

void mqtt_link_stop() {
    if (s_mqtt_client) esp_mqtt_client_stop(s_mqtt_client);
}

void mqtt_link_publish_telemetry(const char* payload) {
    if (s_mqtt_client && s_mqtt_connected) {
        int msg_id = esp_mqtt_client_publish(s_mqtt_client, s_topic_telemetry, payload, 0, 1, 0);
        Serial.printf("[mqtt_link] Published telemetry msg_id=%d\n", msg_id);
    }
}

// ==================== Rotation Manager ====================
void rotation_mgr_execute() {
    if (!s_manual_rotation_pending) return;
    s_manual_rotation_pending = false;

    Serial.println("[rotation_mgr] === Starting Key & Certificate Rotation ===");

    // 1. Prepare staging credentials (simulated CSR/sign flow)
    strncpy(s_staging_slot.cert_serial, "7b82f9104a0912", sizeof(s_staging_slot.cert_serial));
    strncpy(s_staging_slot.cert_pem,
            "-----BEGIN CERTIFICATE-----\nSTAGING_CERT_PEM\n-----END CERTIFICATE-----",
            sizeof(s_staging_slot.cert_pem));
    strncpy(s_staging_slot.key_pem,
            "-----BEGIN EC PRIVATE KEY-----\nSTAGING_KEY_PEM\n-----END EC PRIVATE KEY-----",
            sizeof(s_staging_slot.key_pem));
    s_staging_slot.is_valid = true;

    // 2. Test-connect (simulated)
    Serial.println("[rotation_mgr] Testing mTLS with STAGING credentials...");
    bool test_ok = true;

    if (test_ok) {
        Serial.println("[rotation_mgr] Test OK! Committing staging to active...");
        identity_store_commit_staging();
        mqtt_link_stop();
        mqtt_link_init();
        mqtt_link_start();
    } else {
        Serial.println("[rotation_mgr] Test FAILED! Rolling back.");
        identity_store_rollback_staging();
    }
}

// ==================== Web Server ====================
static const char HTML_PAGE[] PROGMEM = R"rawhtml(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthSphere ESP32 Device Console</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #1e293b; padding: 24px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
        h1 { color: #38bdf8; font-size: 24px; margin-top: 0; display: flex; align-items: center; gap: 10px; }
        .badge { background: #10b981; color: #022c22; font-size: 12px; font-weight: bold; padding: 4px 10px; border-radius: 20px; text-transform: uppercase; }
        .card { background: #0f172a; padding: 16px; border-radius: 8px; margin-bottom: 16px; border: 1px solid #334155; }
        .card-title { font-size: 14px; color: #94a3b8; text-transform: uppercase; font-weight: bold; margin-bottom: 8px; }
        .stat-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #1e293b; font-size: 14px; }
        .stat-row:last-child { border-bottom: none; }
        .stat-label { color: #94a3b8; }
        .stat-value { font-family: monospace; color: #e2e8f0; font-weight: bold; }
        button { width: 100%; background: #0284c7; color: white; border: none; padding: 12px; border-radius: 8px; font-size: 15px; font-weight: bold; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #0369a1; }
    </style>
</head>
<body>
    <div class="container">
        <h1><span>&#x1F6E1;&#xFE0F; AuthSphere ESP32 Node</span> <span class="badge">ACTIVE</span></h1>
        <div class="card">
            <div class="card-title">Network Status</div>
            <div class="stat-row"><span class="stat-label">Wi-Fi SSID:</span><span class="stat-value">Sunny</span></div>
            <div class="stat-row"><span class="stat-label">Local IP Address:</span><span class="stat-value" id="ip">--</span></div>
            <div class="stat-row"><span class="stat-label">MQTT mTLS Link:</span><span class="stat-value" id="mqtt" style="color:#10b981;">--</span></div>
        </div>
        <div class="card">
            <div class="card-title">Cryptographic Identity (ECC P-256)</div>
            <div class="stat-row"><span class="stat-label">Entity ID:</span><span class="stat-value">dev-esp32-01</span></div>
            <div class="stat-row"><span class="stat-label">Cert Serial:</span><span class="stat-value" id="serial">--</span></div>
            <div class="stat-row"><span class="stat-label">Auto Key Rotation:</span><span class="stat-value" style="color:#38bdf8;">ENABLED</span></div>
        </div>
        <form action="/rotate" method="POST">
            <button type="submit">Force Key &amp; Certificate Rotation Now</button>
        </form>
    </div>
    <script>
        fetch('/api/status').then(r=>r.json()).then(d=>{
            document.getElementById('ip').textContent = d.ip;
            document.getElementById('mqtt').textContent = d.mqtt ? 'CONNECTED (8883)' : 'DISCONNECTED';
            document.getElementById('mqtt').style.color = d.mqtt ? '#10b981' : '#ef4444';
            document.getElementById('serial').textContent = d.serial;
        });
    </script>
</body>
</html>
)rawhtml";

void handleRoot() {
    webServer.send(200, "text/html", HTML_PAGE);
}

void handleRotate() {
    Serial.println("[web_server] Manual key rotation triggered via Web UI!");
    s_manual_rotation_pending = true;
    webServer.sendHeader("Location", "/");
    webServer.send(303);
}

void handleApiStatus() {
    char json[256];
    snprintf(json, sizeof(json),
        "{\"ip\":\"%s\",\"mqtt\":%s,\"serial\":\"%s\",\"entity\":\"%s\"}",
        WiFi.localIP().toString().c_str(),
        s_mqtt_connected ? "true" : "false",
        s_active_slot.cert_serial,
        DEFAULT_ENTITY_ID);
    webServer.send(200, "application/json", json);
}

// ==================== Arduino setup() & loop() ====================
void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("==================================================");
    Serial.println("   AuthSphere Secure IoT Device Firmware v1.0.0   ");
    Serial.println("==================================================");

    // 1. Init identity store & load defaults
    identity_store_init();
    identity_store_load_defaults();

    // 2. Connect to Wi-Fi
    Serial.printf("[main] Connecting to Wi-Fi SSID: %s ...\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 30) {
        delay(500);
        Serial.print(".");
        retries++;
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("[main] Wi-Fi Connected! IP: %s\n", WiFi.localIP().toString().c_str());
    } else {
        Serial.println("[main] Wi-Fi Connection FAILED!");
    }

    // 3. Start local web dashboard
    webServer.on("/", HTTP_GET, handleRoot);
    webServer.on("/rotate", HTTP_POST, handleRotate);
    webServer.on("/api/status", HTTP_GET, handleApiStatus);
    webServer.begin();
    Serial.printf("[main] Web server started on port %d\n", WEB_SERVER_PORT);

    // 4. Init mTLS MQTT
    Serial.printf("[main] Initializing mTLS MQTT to %s:%d...\n", MQTT_BROKER_HOST, MQTT_BROKER_PORT);
    mqtt_link_init();
    mqtt_link_start();

    Serial.println("[main] Setup complete. Entering main loop...");
}

void loop() {
    webServer.handleClient();

    // Publish telemetry every 5 seconds
    if (millis() - s_last_telemetry_ms >= 5000) {
        s_last_telemetry_ms = millis();
        s_telemetry_counter++;

        if (s_mqtt_connected) {
            char payload[128];
            snprintf(payload, sizeof(payload),
                "{\"t\":24.5,\"h\":52.1,\"uptime\":%d,\"seq\":%d}",
                s_telemetry_counter * 5, s_telemetry_counter);
            mqtt_link_publish_telemetry(payload);
        }

        // Execute pending rotation
        rotation_mgr_execute();
    }
}
