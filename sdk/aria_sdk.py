# type: ignore
import hashlib
import hmac
import uuid
import time
import requests
from typing import Optional, Dict, Any
# type: ignore


class ARIAClient:
    """
    El SDK oficial para conectar agentes de IA a ARIA.
    Maneja registro, criptografía (HMAC) y envío seguro de eventos.
    """

    def __init__(self, base_url: str, api_key: str, agent_name: str, scope: list):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_name = agent_name
        self.scope = scope

        self.did: Optional[str] = None
        self.signing_secret: Optional[str] = None
        self.signing_version: Optional[int] = None
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def register(self) -> str:
        """Se registra en ARIA y obtiene su identidad única (DID) y llaves criptográficas."""
        payload = {
            "name": self.agent_name,
            "scope": self.scope,
        }

        res = requests.post(
            f"{self.base_url}/v1/agents",
            headers=self._headers,
            json=payload,
            timeout=10,
        )
        res.raise_for_status()

        data = res.json()
        did_value = data.get("agent", {}).get("did")
        if not isinstance(did_value, str):
            raise ValueError("Respuesta del servidor no contiene un DID válido")
        self.did = did_value

        if "secret" in data:
            self.signing_secret = data["secret"]
            self.signing_version = 1
        elif "fragmentB" in data:
            self.signing_secret = data["fragmentB"]
            self.signing_version = 2
        else:
            raise ValueError("Servidor ARIA no devolvió credenciales de firma válidas")

        return self.did

    def _sign_payload_v1(self, payload_str: str) -> str:
        """Genera la firma HMAC clásica (Modo V1)."""
        if not self.signing_secret:
            raise ValueError("signing_secret no está configurado")
        return hmac.new(
            self.signing_secret.encode("utf-8"),
            payload_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def track(
        self,
        action: str,
        outcome: str,
        duration_ms: int,
        meta: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Registra una acción del agente y la envía a ARIA de forma segura.
        Esto es lo que el desarrollador llama en su código de IA.
        """
        if not self.did or not self.signing_secret:
            raise RuntimeError(
                "Debes llamar a client.register() antes de hacer track()"
            )

        event_id = str(uuid.uuid4())
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        within_scope = action in self.scope

        payload_str = f"{event_id}:{self.did}:{action}:{outcome}:{timestamp}"

        if self.signing_version == 1:
            signature = self._sign_payload_v1(payload_str)
        elif self.signing_version == 2:
            raise NotImplementedError(
                "Firma DTS V2 requiere implementación adicional en el SDK"
            )
        else:
            raise RuntimeError("signing_version no configurado")

        event = {
            "eventId": event_id,
            "agentDid": self.did,
            "action": action,
            "outcome": outcome,
            "withinScope": within_scope,
            "durationMs": duration_ms,
            "timestamp": timestamp,
            "signature": signature,
            "meta": meta or {},
        }

        batch_res = requests.post(
            f"{self.base_url}/v1/events/batch",
            headers=self._headers,
            json={"events": [event]},
            timeout=10,
        )

        if batch_res.status_code == 429:
            time.sleep(2)
            batch_res = requests.post(
                f"{self.base_url}/v1/events/batch",
                headers=self._headers,
                json={"events": [event]},
                timeout=10,
            )

        return batch_res.status_code == 202
