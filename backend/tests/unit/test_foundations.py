import pytest
from app.config import settings

def test_settings_initialization() -> None:
    assert settings.PUBLIC_HOSTNAME is not None
    assert settings.MQTT_PORT == 8883

def test_health_check_defaults() -> None:
    assert settings.ENV in ["dev", "demo", "prod"]
