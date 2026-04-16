from aria_sdk import ARIAClient
import os

client = ARIAClient(
    base_url="http://127.0.0.1:3001",
    api_key=os.environ.get("ARIA_API_KEY", "your-api-key-here"),
    agent_name="Agente Final",
    scope=["send:email"],
)

# Forzamos el bypass de auth temporalmente para probar
import requests

res = requests.post(
    "http://127.0.0.1:3001/v1/agents",
    json={"name": "Agente Final", "scope": ["send:email"]},
    headers={
        "Authorization": f"Bearer {os.environ.get('ARIA_API_KEY', 'your-api-key-here')}"
    },
)
print("Respuesta cruda de ARIA:", res.status_code, res.text)
