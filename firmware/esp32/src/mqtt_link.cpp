#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "mqtt_client.h"
#include "mqtt_link.h"
#include "config.h"

static const char *TAG = "mqtt_link";
static esp_mqtt_client_handle_t s_mqtt_client = NULL;
static bool s_is_connected = false;
static char s_topic_status[64];
static char s_topic_telemetry[64];

extern const char root_cert_pem_start[] asm("_binary_certs_root_current_pem_start");
extern const char root_cert_pem_end[]   asm("_binary_certs_root_current_pem_end");

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT mTLS Connected to %s:%d!", MQTT_BROKER_HOST, MQTT_BROKER_PORT);
        s_is_connected = true;
        // Publish online status
        esp_mqtt_client_publish(s_mqtt_client, s_topic_status, "{\"state\":\"online\"}", 0, 1, 1);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT mTLS Disconnected");
        s_is_connected = false;
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT mTLS Error event");
        break;
    default:
        break;
    }
}

esp_err_t mqtt_link_init(const char* host, int port, const identity_slot_t* identity) {
    snprintf(s_topic_status, sizeof(s_topic_status), "devices/%s/status", DEFAULT_ENTITY_ID);
    snprintf(s_topic_telemetry, sizeof(s_topic_telemetry), "devices/%s/telemetry", DEFAULT_ENTITY_ID);

    esp_mqtt_client_config_t mqtt_cfg = {};
    mqtt_cfg.broker.address.hostname = host;
    mqtt_cfg.broker.address.port = port;
    mqtt_cfg.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;

    mqtt_cfg.broker.verification.certificate = root_cert_pem_start;

    mqtt_cfg.credentials.client_id = DEFAULT_ENTITY_ID;
    mqtt_cfg.credentials.authentication.certificate = identity->cert_pem;
    mqtt_cfg.credentials.authentication.key = identity->key_pem;

    // Last Will and Testament
    mqtt_cfg.session.last_will.topic = s_topic_status;
    mqtt_cfg.session.last_will.msg = "{\"state\":\"offline\"}";
    mqtt_cfg.session.last_will.qos = 1;
    mqtt_cfg.session.last_will.retain = 1;

    s_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (!s_mqtt_client) {
        ESP_LOGE(TAG, "Failed to initialize esp-mqtt client");
        return ESP_FAIL;
    }

    esp_mqtt_client_register_event(s_mqtt_client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    return ESP_OK;
}

esp_err_t mqtt_link_start(void) {
    if (!s_mqtt_client) return ESP_ERR_INVALID_STATE;
    return esp_mqtt_client_start(s_mqtt_client);
}

esp_err_t mqtt_link_stop(void) {
    if (!s_mqtt_client) return ESP_ERR_INVALID_STATE;
    return esp_mqtt_client_stop(s_mqtt_client);
}

bool mqtt_link_is_connected(void) {
    return s_is_connected;
}

esp_err_t mqtt_link_publish_telemetry(const char* payload_json) {
    if (!s_mqtt_client || !s_is_connected) return ESP_ERR_INVALID_STATE;
    int msg_id = esp_mqtt_client_publish(s_mqtt_client, s_topic_telemetry, payload_json, 0, 1, 0);
    ESP_LOGI(TAG, "Published telemetry msg_id=%d: %s", msg_id, payload_json);
    return msg_id >= 0 ? ESP_OK : ESP_FAIL;
}
