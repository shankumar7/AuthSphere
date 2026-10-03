#ifndef WIFI_MGR_H
#define WIFI_MGR_H

#include "esp_err.h"
#include "esp_event.h"

esp_err_t wifi_init_sta(const char* ssid, const char* pass);
bool wifi_is_connected(void);
const char* wifi_get_ip_str(void);

#endif // WIFI_MGR_H
