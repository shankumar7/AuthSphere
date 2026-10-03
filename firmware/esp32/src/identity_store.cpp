#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "identity_store.h"

static const char *TAG = "identity_store";
#define NVS_NAMESPACE "auth_id"

static identity_slot_t s_active_slot = {};
static identity_slot_t s_staging_slot = {};

esp_err_t identity_store_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_LOGI(TAG, "Identity store NVS initialized");
    return ret;
}

esp_err_t identity_store_get_active(identity_slot_t* slot) {
    if (!slot) return ESP_ERR_INVALID_ARG;
    memcpy(slot, &s_active_slot, sizeof(identity_slot_t));
    return ESP_OK;
}

esp_err_t identity_store_set_active(const identity_slot_t* slot) {
    if (!slot) return ESP_ERR_INVALID_ARG;
    memcpy(&s_active_slot, slot, sizeof(identity_slot_t));
    s_active_slot.is_valid = true;
    ESP_LOGI(TAG, "Active identity updated: serial=%s", slot->cert_serial);
    return ESP_OK;
}

esp_err_t identity_store_get_staging(identity_slot_t* slot) {
    if (!slot) return ESP_ERR_INVALID_ARG;
    memcpy(slot, &s_staging_slot, sizeof(identity_slot_t));
    return ESP_OK;
}

esp_err_t identity_store_set_staging(const identity_slot_t* slot) {
    if (!slot) return ESP_ERR_INVALID_ARG;
    memcpy(&s_staging_slot, slot, sizeof(identity_slot_t));
    s_staging_slot.is_valid = true;
    ESP_LOGI(TAG, "Staging identity set: serial=%s", slot->cert_serial);
    return ESP_OK;
}

esp_err_t identity_store_commit_staging(void) {
    if (!s_staging_slot.is_valid) {
        ESP_LOGE(TAG, "Cannot commit invalid staging slot");
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(&s_active_slot, &s_staging_slot, sizeof(identity_slot_t));
    memset(&s_staging_slot, 0, sizeof(identity_slot_t));
    s_staging_slot.is_valid = false;
    ESP_LOGI(TAG, "Staging identity committed to active! New serial=%s", s_active_slot.cert_serial);
    return ESP_OK;
}

esp_err_t identity_store_rollback_staging(void) {
    memset(&s_staging_slot, 0, sizeof(identity_slot_t));
    s_staging_slot.is_valid = false;
    ESP_LOGW(TAG, "Staging identity rolled back!");
    return ESP_OK;
}
