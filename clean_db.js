import { query } from './server/src/db/pool.js';

async function cleanDatabase() {
  try {
    console.log('Starting database cleanup...');

    // Delete in the specified order
    const tables = [
      'anomalies_archive',
      'anomalies',
      'webhooks',
      'reputation_snapshots',
      'events',
      'agents',
      // For api_keys, we only delete those where user_id IS NULL
    ];

    for (const table of tables) {
      console.log(`Deleting from ${table}...`);
      await query(`DELETE FROM ${table}`);
      console.log(`✓ Deleted from ${table}`);
    }

    // Delete api_keys where user_id IS NULL
    console.log("Deleting from api_keys where user_id IS NULL...");
    await query("DELETE FROM api_keys WHERE user_id IS NULL");
    console.log("✓ Deleted from api_keys where user_id IS NULL");

    console.log('Database cleanup completed successfully!');
  } catch (error) {
    console.error('Error during database cleanup:', error);
    process.exit(1);
  }
}

cleanDatabase();