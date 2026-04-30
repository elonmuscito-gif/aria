import { query } from './src/db/pool.js';

async function cleanProductionDatabase() {
  try {
    console.log('Starting production database cleanup...');

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
      console.log(`Executing: ${command}`);
      await query(command);
      console.log(`✓ Completed: ${command}`);
    }

    console.log('Production database cleanup completed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Error during production database cleanup:', error);
    process.exit(1);
  }
}

cleanProductionDatabase();