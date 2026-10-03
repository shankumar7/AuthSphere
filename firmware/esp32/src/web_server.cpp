#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "web_server.h"
#include "wifi_mgr.h"
#include "identity_store.h"
#include "mqtt_link.h"
#include "config.h"

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;

extern bool trigger_manual_rotation(void);

static const char HTML_PAGE[] = R"rawhtml(
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
        <h1><span>🛡️ AuthSphere ESP32 Node</span> <span class="badge">ACTIVE</span></h1>
        
        <div class="card">
            <div class="card-title">Network Status</div>
            <div class="stat-row"><span class="stat-label">Wi-Fi SSID:</span><span class="stat-value">Sunny</span></div>
            <div class="stat-row"><span class="stat-label">Local IP Address:</span><span class="stat-value" id="ip">192.168.1.150</span></div>
            <div class="stat-row"><span class="stat-label">MQTT mTLS Link:</span><span class="stat-value" style="color:#10b981;">CONNECTED (Port 8883)</span></div>
        </div>

        <div class="card">
            <div class="card-title">Cryptographic Identity (ECC P-256)</div>
            <div class="stat-row"><span class="stat-label">Entity ID:</span><span class="stat-value">dev-esp32-01</span></div>
            <div class="stat-row"><span class="stat-label">Cert Serial:</span><span class="stat-value" id="serial">3fa92c81...</span></div>
            <div class="stat-row"><span class="stat-label">Auto Key Rotation:</span><span class="stat-value" style="color:#38bdf8;">ENABLED (66% threshold)</span></div>
        </div>

        <form action="/rotate" method="POST">
            <button type="submit">⚡ Force Key & Certificate Rotation Now</button>
        </form>
    </div>
</body>
</html>
)rawhtml";

static esp_err_t root_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, HTML_PAGE, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t rotate_post_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Web UI triggered manual key rotation!");
    trigger_manual_rotation();
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

esp_err_t web_server_start(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = WEB_SERVER_PORT;

    ESP_LOGI(TAG, "Starting web server on port %d...", config.server_port);
    if (httpd_start(&s_server, &config) == ESP_OK) {
        httpd_uri_t root_uri = {
            .uri       = "/",
            .method    = HTTP_GET,
            .handler   = root_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(s_server, &root_uri);

        httpd_uri_t rotate_uri = {
            .uri       = "/rotate",
            .method    = HTTP_POST,
            .handler   = rotate_post_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(s_server, &rotate_uri);
        return ESP_OK;
    }

    ESP_LOGE(TAG, "Error starting web server!");
    return ESP_FAIL;
}

esp_err_t web_server_stop(void) {
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
    return ESP_OK;
}
