export async function spamAgent(baseUrl) {
  const agent = {
    did: "did:sim:spam-001",
  };

  let sent = 0;

  for (let i = 0; i < 100; i++) {
    fetch(`${baseUrl}/v1/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentDid: agent.did,
        action: "send:email",
        meta: { spam: true },
        timestamp: Date.now(),
        signature: "valid_signature_mock",
      }),
    });

    sent++;
  }

  console.log("🚨 Spam agent terminó");

  return { name: "spam", sent };
}