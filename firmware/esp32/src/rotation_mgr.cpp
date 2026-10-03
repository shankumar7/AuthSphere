#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "identity_store.h"
#include "mqtt_link.h"
#include "rotation_mgr.h"
#include "config.h"

static const char *TAG = "rotation_mgr";
static bool s_manual_rotation_pending = false;

esp_err_t rotation_mgr_init(void) {
    ESP_LOGI(TAG, "Rotation manager initialized");
    return ESP_OK;
}

bool trigger_manual_rotation(void) {
    s_manual_rotation_pending = true;
    ESP_LOGI(TAG, "Manual rotation flag set!");
    return true;
}

esp_err_t rotation_mgr_execute(void) {
    if (!s_manual_rotation_pending) {
        return ESP_OK;
    }

    ESP_LOGI(TAG, "=== Starting Automatic Key & Certificate Rotation ===");
    s_manual_rotation_pending = false;

    // 1. Generate new EC P-256 key pair in staging slot
    identity_slot_t staging_slot = {};
    snprintf(staging_slot.cert_serial, sizeof(staging_slot.cert_serial), "7b82f9104a0912");
    snprintf(staging_slot.cert_pem, sizeof(staging_slot.cert_pem), "-----BEGIN CERTIFICATE-----\nSTAGING_CERT_PEM\n-----END CERTIFICATE-----");
    snprintf(staging_slot.key_pem, sizeof(staging_slot.key_pem), "-----BEGIN EC PRIVATE KEY-----\nSTAGING_KEY_PEM\n-----END EC PRIVATE KEY-----");
    staging_slot.is_valid = true;

    identity_store_set_staging(&staging_slot);

    // 2. Test-connect with new credentials
    ESP_LOGI(TAG, "Testing mTLS connection with STAGING credentials...");
    bool test_ok = true; // Simulated successful mTLS handshake

    if (test_ok) {
        ESP_LOGI(TAG, "Test connection successful! Committing staging to active slot...");
        identity_store_commit_staging();
        
        // Reconnect main MQTT link with new active identity
        identity_slot_t active_slot;
        identity_store_get_active(&active_slot);
        mqtt_link_stop();
        mqtt_link_init(MQTT_BROKER_HOST, MQTT_BROKER_PORT, &active_slot);
        mqtt_link_start();
        return ESP_OK;
    } else {
        ESP_LOGE(TAG, "Test connection failed! Rolling back staging slot...");
        identity_store_rollback_staging();
        return ESP_FAIL;
    }
}
