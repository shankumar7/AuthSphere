#ifndef MQTT_LINK_H
#define MQTT_LINK_H

#include "esp_err.h"
#include "mqtt_client.h"
#include "identity_store.h"

esp_err_t mqtt_link_init(const char* host, int port, const identity_slot_t* identity);
esp_err_t mqtt_link_start(void);
esp_err_t mqtt_link_stop(void);
bool mqtt_link_is_connected(void);
esp_err_t mqtt_link_publish_telemetry(const char* payload_json);

#endif // MQTT_LINK_H
