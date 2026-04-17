from aria_sdk import ARIAClient
import os

# Initialize the ARIA client
client = ARIAClient(
    base_url=os.environ.get("ARIA_BASE_URL", "http://127.0.0.1:3001"),
    api_key=os.environ.get("ARIA_API_KEY", "your-api-key-here"),
    agent_name="Test Agent",
    scope=["send:email"],
)

# Test registration using SDK method
try:
    did = client.register()
    print("Agent registered successfully!")
    print(f"DID: {did}")
except Exception as e:
    print(f"Registration failed: {e}")
