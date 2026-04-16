export async function honestAgent(baseUrl) {
  const agent = {
    did: "did:sim:honest-001",
  };

  let sent = 0;

  for (let i = 0; i < 5; i++) {
    await fetch(`${baseUrl}/v1/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentDid: agent.did,
        action: "read:inbox",
        meta: { test: true },
        timestamp: Date.now(),
        signature: "valid_signature_mock",
      }),
    });

    sent++;
    await sleep(500);
  }

  console.log("✅ Honest agent terminó");

  return { name: "honest", sent };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}