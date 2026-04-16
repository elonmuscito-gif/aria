export async function invalidAgent(baseUrl) {
  const agent = {
    did: "did:agentrust:00000000-0000-0000-0000-000000000000", // DID válido en formato, pero inexistente
  };

  let sent = 0;

  console.log("💀 Iniciando simulación de ataques inválidos...");

  // ATAQUE 1: Payload Gigante (Buffer Overflow / DoS de Memoria)
  // Intentamos colapsar la memoria de Express.json() enviando un string de 5 Megabytes
  try {
    const hugeString = "A".repeat(5 * 1024 * 1024); 
    await fetch(`${baseUrl}/v1/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventId: hugeString,
        agentDid: agent.did,
        action: "read:resource",
        outcome: "success",
        withinScope: true,
        durationMs: 10,
        timestamp: new Date().toISOString(),
        signature: "fake_signature_too_long_" + hugeString,
        meta: { huge_data: hugeString }
      }),
    });
    sent++;
    console.log(" -> Ataque 1 enviado: Payload Gigante (5MB)");
  } catch (err) {
    console.log(" -> Ataque 1 falló (El servidor cortó la conexión antes de procesar):", err.code);
  }

  // ATAQUE 2: Formato ISO 8601 extremo (Bug de Fechas)
  // Mandar una fecha válida para JS pero que rompa PostgreSQL
  await fetch(`${baseUrl}/v1/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      eventId: "event-date-attack",
      agentDid: agent.did,
      action: "read:resource",
      outcome: "success",
      withinScope: true,
      durationMs: 10,
      timestamp: "2099-13-32T25:99:99.999Z", // Fecha imposible
      signature: "fake",
    }),
  });
  sent++;
  console.log(" -> Ataque 2 enviado: Fecha imposible");

  // ATAQUE 3: Tipos cruzados (Type Coercion)
  // Intentar engañar a TypeScript/Postgres mandando números donde van strings
  for (let i = 0; i < 5; i++) {
    await fetch(`${baseUrl}/v1/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventId: 123456789, // Número en lugar de String
        agentDid: agent.did,
        action: ["array", "instead", "of", "string"], // Array en lugar de String
        outcome: "success",
        withinScope: "true", // String en lugar de Booleano
        durationMs: -500, // Número negativo
        timestamp: new Date().toISOString(),
        signature: false, // Booleano en lugar de String
      }),
    });
    sent++;
  }
  console.log(" -> Ataque 3 enviado: 5 peticiones con tipos de datos cruzados");

  // ATAQUE 4: Inyección SQL clásica (aunque usamos $1, hay que probar)
  await fetch(`${baseUrl}/v1/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      eventId: "event-sql-inject'; DROP TABLE events;--",
      agentDid: agent.did,
      action: "read:resource",
      outcome: "success",
      withinScope: true,
      durationMs: 10,
      timestamp: new Date().toISOString(),
      signature: "fake",
      meta: { query: "SELECT * FROM secret_keys" }
    }),
  });
  sent++;
  console.log(" -> Ataque 4 enviado: Inyección SQL clásica");

  console.log(`❌ Invalid agent terminó (${sent} ataques lanzados)\n`);

  return { name: "invalid", sent };
}