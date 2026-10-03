import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    ENV: str = Field(default="dev")
    PUBLIC_HOSTNAME: str = Field(default="localhost")
    MQTT_PUBLIC_HOSTNAME: str = Field(default="localhost")
    DATABASE_URL: str = Field(default="postgresql+asyncpg://authsphere:authsphere_dev_pass@postgres:5432/authsphere")
    MQTT_HOST: str = Field(default="mosquitto")
    MQTT_PORT: int = Field(default=8883)
    
    DEMO_MODE: bool = Field(default=False)
    DEMO_CERT_LIFETIME_SECONDS: int = Field(default=120)
    ROTATION_CONFIRM_TIMEOUT_SECONDS: int = Field(default=300)
    CLAIM_TOKEN_TTL_SECONDS: int = Field(default=600)
    POP_MAX_SKEW_SECONDS: int = Field(default=120)
    CHAT_INSPECTOR_ENABLED: bool = Field(default=False)
    TELEMETRY_RETENTION_HOURS: int = Field(default=24)
    
    INITIAL_ADMIN_EMAIL: str = Field(default="admin@authsphere.local")
    INITIAL_ADMIN_PASSWORD: str = Field(default="AdminSecurePassword123!")
    
    LOG_LEVEL: str = Field(default="INFO")

    INTERMEDIATE_KEY_FILE: str = Field(default="/run/secrets/intermediate_key")
    SVC_API_KEY_FILE: str = Field(default="/run/secrets/svc_api_key")
    SVC_BRIDGE_KEY_FILE: str = Field(default="/run/secrets/svc_bridge_key")
    JWT_SECRET_FILE: str = Field(default="/run/secrets/jwt_secret")
    FERNET_KEY_FILE: str = Field(default="/run/secrets/fernet_key")
    POSTGRES_PASSWORD_FILE: str = Field(default="/run/secrets/postgres_password")
    DYNSEC_ADMIN_PASSWORD_FILE: str = Field(default="/run/secrets/dynsec_admin_password")

    @property
    def get_database_url(self) -> str:
        url = self.DATABASE_URL
        if "postgresql" in url and "@" in url:
            # Check if password secret exists
            pw_path = self.POSTGRES_PASSWORD_FILE
            if not os.path.exists(pw_path):
                pw_path = "./secrets/postgres_password.txt"
            
            if os.path.exists(pw_path):
                password = open(pw_path).read().strip()
                # Insert password into URL if missing
                user = "authsphere"
                if f"{user}@" in url:
                    url = url.replace(f"{user}@", f"{user}:{password}@")
        return url

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()

