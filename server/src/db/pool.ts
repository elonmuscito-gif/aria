import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  
  // Scale: Allow up to 50 connections to handle load spikes without saturating PostgreSQL.
  max: 50, 
  
  // Kill stuck queries after 10 seconds to prevent connection leaks.
  statement_timeout: 10_000, 
  
  // Close idle connections after 30 seconds to conserve memory.
  idleTimeoutMillis: 30_000, 
  
  // Fail fast if database is down (2 second timeout).
  connectionTimeoutMillis: 2000,
  
  // Railway requires SSL with relaxed verification
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: false } 
    : false,
});

pool.on("error", (err) => {
  // Prevent process crash when idle connection dies (e.g., DB restart).
  console.error("[db] Idle pool error:", err.message);
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
    // Critical: Return connection to pool regardless of success/failure.
    // Without this, ARIA would run out of connections after 10 seconds.
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