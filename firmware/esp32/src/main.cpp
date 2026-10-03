#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "config.h"
#include "wifi_mgr.h"
#include "identity_store.h"
#include "mqtt_link.h"
#include "web_server.h"
#include "rotation_mgr.h"

static const char *TAG = "main";

extern "C" void app_main(void) {
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, "   AuthSphere Secure IoT Device Firmware v1.0.0   ");
    ESP_LOGI(TAG, "==================================================");

    // 1. Initialize NVS & Identity Store
    ESP_ERROR_CHECK(identity_store_init());

    // Setup initial active identity slot if empty
    identity_slot_t active_identity;
    if (identity_store_get_active(&active_identity) != ESP_OK || !active_identity.is_valid) {
        snprintf(active_identity.cert_serial, sizeof(active_identity.cert_serial), "3fa92c815e90d1");
        snprintf(active_identity.cert_pem, sizeof(active_identity.cert_pem), "-----BEGIN CERTIFICATE-----\nOPERATIONAL_CERT_PEM\n-----END CERTIFICATE-----");
        snprintf(active_identity.key_pem, sizeof(active_identity.key_pem), "-----BEGIN EC PRIVATE KEY-----\nOPERATIONAL_KEY_PEM\n-----END EC PRIVATE KEY-----");
        active_identity.is_valid = true;
        identity_store_set_active(&active_identity);
    }

    // 2. Initialize Wi-Fi Station Mode
    ESP_LOGI(TAG, "Connecting to Wi-Fi SSID: %s...", WIFI_SSID);
    esp_err_t wifi_res = wifi_init_sta(WIFI_SSID, WIFI_PASS);
    if (wifi_res == ESP_OK) {
        ESP_LOGI(TAG, "Wi-Fi Connected successfully! Local IP: %s", wifi_get_ip_str());
    } else {
        ESP_LOGE(TAG, "Wi-Fi Connection failed!");
    }

    // 3. Start Onboard HTTP Web Dashboard
    ESP_LOGI(TAG, "Starting local device web server console on port %d...", WEB_SERVER_PORT);
    web_server_start();

    // 4. Initialize and Start mTLS MQTT Client Link
    ESP_LOGI(TAG, "Initializing mTLS MQTT Link to %s:%d...", MQTT_BROKER_HOST, MQTT_BROKER_PORT);
    mqtt_link_init(MQTT_BROKER_HOST, MQTT_BROKER_PORT, &active_identity);
    mqtt_link_start();

    // 5. Initialize Rotation Manager
    rotation_mgr_init();

    // 6. Main Application Loop
    int telemetry_counter = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        telemetry_counter++;

        if (mqtt_link_is_connected()) {
            char telemetry_json[128];
            snprintf(telemetry_json, sizeof(telemetry_json),
                     "{\"t\":24.5,\"h\":52.1,\"uptime\":%d,\"seq\":%d}",
                     telemetry_counter * 5, telemetry_counter);
            mqtt_link_publish_telemetry(telemetry_json);
        }

        // Check and execute key rotation if triggered
        rotation_mgr_execute();
    }
}
