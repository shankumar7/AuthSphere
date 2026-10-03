#ifndef ROTATION_MGR_H
#define ROTATION_MGR_H

#include "esp_err.h"

esp_err_t rotation_mgr_init(void);
esp_err_t rotation_mgr_execute(void);
bool trigger_manual_rotation(void);

#endif // ROTATION_MGR_H
