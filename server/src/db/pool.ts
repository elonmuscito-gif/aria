import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  
  // ESCALABILIDAD: Aumentamos el pool para soportar picos del simulador.
  // 50 es un número muy seguro para Node.js sin saturar PostgreSQL.
  max: 50, 
  
  // Si un proceso se queda "pegado" por un error de red, lo matamos a los 10 segundos.
  // Antes no había límite, un bug podría secuestrar una conexión para siempre.
  statement_timeout: 10_000, 
  
  // Cierra conexiones que no se usen en 30 segundos (para no gastar RAM innecesaria).
  idleTimeoutMillis: 30_000, 
  
  // Si PostgreSQL está caído, no esperamos 5 segundos, fallamos rápido (2 seg).
  connectionTimeoutMillis: 2000,
  
  // Railway requires SSL with relaxed verification
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: false } 
    : false,
});

pool.on("error", (err) => {
  // Si una conexión inactiva muere (ej. el servidor de DB se reinició),
  // esto evita que crashee todo el proceso de Node.js.
  console.error("[db] Idle pool error (conexión perdida):", err.message);
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  values?: unknown[],
): Promise<QueryResult<T>> {
  return await pool.query<T>(text, values);
}

export async function transaction<T>(
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    // CRÍTICO: Esto asegura que la conexión vuelva al pool pase lo que pase.
    // Si falta este finally, ARIA se quedaría sin conexiones en 10 segundos.
    client.release();
  }
}

export async function checkHealth(): Promise<boolean> {
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  }
}