import json
import secrets
import structlog
from typing import Any, Dict
import aiomqtt

from app.config import settings

logger = structlog.get_logger(__name__)

class DynSecBrokerAdmin:
    def __init__(self, host: str | None = None, port: int | None = None):
        self.host = host or settings.MQTT_HOST
        self.port = port or settings.MQTT_PORT

    async def _send_dynsec_command(self, command_dict: Dict[str, Any]) -> None:
        """Sends a Dynamic Security JSON command to $CONTROL/dynamic-security/v1 over MQTT."""
        try:
            tls_context = None
            if self.port == 8883:
                import ssl
                from pathlib import Path
                ca_path = Path("./pki-state/ca-chain.pem")
                cert_path = Path("./pki-state/svc_api.crt")
                key_path = Path(settings.SVC_API_KEY_FILE) if Path(settings.SVC_API_KEY_FILE).exists() else Path("./secrets/svc_api.key")
                
                if ca_path.exists() and cert_path.exists() and key_path.exists():
                    tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_path))
                    tls_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
                    tls_context.check_hostname = False
                    tls_context.verify_mode = ssl.CERT_REQUIRED

            async with aiomqtt.Client(hostname=self.host, port=self.port, tls_context=tls_context) as client:
                payload = json.dumps(command_dict)
                await client.publish("$CONTROL/dynamic-security/v1", payload=payload, qos=1)
                logger.info("sent_dynsec_command", command=command_dict.get("command"))
        except Exception as e:
            logger.warning("dynsec_command_notice", error=str(e), command=command_dict.get("command"))

    async def upsert_role(self, role_name: str, pub_topics: list[str], sub_topics: list[str]) -> None:
        acl_list = []
        for t in pub_topics:
            acl_list.append({"aclType": "publishClientSend", "topic": t, "allow": True})
        for t in sub_topics:
            acl_list.append({"aclType": "subscribePattern", "topic": t, "allow": True})
            acl_list.append({"aclType": "publishClientReceive", "topic": t, "allow": True})

        cmd = {
            "command": "createRole",
            "role": {
                "rolename": role_name,
                "acls": acl_list
            }
        }
        await self._send_dynsec_command(cmd)

    async def upsert_client(self, entity_id: str, role_name: str) -> None:
        cmd = {
            "command": "createClient",
            "client": {
                "username": entity_id,
                "password": secrets.token_urlsafe(16),  # Password set & discarded; auth is by mTLS cert
                "roles": [{"rolename": role_name}]
            }
        }
        await self._send_dynsec_command(cmd)

    async def set_client_enabled(self, entity_id: str, enabled: bool) -> None:
        cmd = {
            "command": "disableClient" if not enabled else "enableClient",
            "username": entity_id
        }
        await self._send_dynsec_command(cmd)

    async def delete_client(self, entity_id: str) -> None:
        cmd = {
            "command": "deleteClient",
            "username": entity_id
        }
        await self._send_dynsec_command(cmd)

    async def kick(self, entity_id: str) -> None:
        await self.set_client_enabled(entity_id, False)
        await self.set_client_enabled(entity_id, True)
