import { Pool } from 'pg';

async function cleanProductionDatabase() {
  // Check if DATABASE_URL is set
  if (!process.env.DATABASE_URL) {
    console.error('ERROR: DATABASE_URL environment variable is not set');
    console.error('Please set DATABASE_URL to your Railway PostgreSQL connection string');
    process.exit(1);
  }

  console.log('Starting production database cleanup...');
  console.log('Connecting to database...');

  // Create a new pool instance for this script
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Railway requires SSL with relaxed verification
    ssl: process.env.NODE_ENV === 'production' 
      ? { rejectUnauthorized: false } 
      : false,
  });

  try {
    // Test the connection
    await pool.query('SELECT 1');
    console.log('✓ Database connection established');

    // Run SQL commands in exact order as specified
    const commands = [
      'DELETE FROM anomalies_archive;',
      'DELETE FROM anomalies;',
      'DELETE FROM webhooks;',
      'DELETE FROM reputation_snapshots;',
      'DELETE FROM events;',
      'DELETE FROM agents;',
      'DELETE FROM api_keys WHERE user_id IS NULL;'
    ];

    for (const command of commands) {
      console.log(`Executing: ${command.trim()}`);
      const result = await pool.query(command);
      console.log(`✓ Completed: ${command.trim()} (Deleted ${result.rowCount} rows)`);
    }

    console.log('🎉 Production database cleanup completed successfully!');
  } catch (error) {
    console.error('❌ Error during production database cleanup:', error.message);
    process.exit(1);
  } finally {
    // Close the pool to exit cleanly
    await pool.end();
  }
}

cleanProductionDatabase();