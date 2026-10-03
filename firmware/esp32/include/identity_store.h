#ifndef IDENTITY_STORE_H
#define IDENTITY_STORE_H

#include "esp_err.h"

typedef struct {
    char cert_serial[64];
    char cert_pem[2048];
    char key_pem[1024];
    char renew_at_iso[64];
    char not_after_iso[64];
    bool is_valid;
} identity_slot_t;

esp_err_t identity_store_init(void);
esp_err_t identity_store_get_active(identity_slot_t* slot);
esp_err_t identity_store_set_active(const identity_slot_t* slot);
esp_err_t identity_store_get_staging(identity_slot_t* slot);
esp_err_t identity_store_set_staging(const identity_slot_t* slot);
esp_err_t identity_store_commit_staging(void);
esp_err_t identity_store_rollback_staging(void);

#endif // IDENTITY_STORE_H
