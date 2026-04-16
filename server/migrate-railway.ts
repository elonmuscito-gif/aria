import 'dotenv/config';
import { readFileSync } from 'fs';
import { query } from './src/db/pool.js';

const runMigrations = async () => {
  const files = [
    './src/db/schema.sql',
    './src/db/migrations/001_server_verification.sql',
    './src/db/migrations/002_agent_hmac_key.sql',
    './src/db/migrations/003_api_key_fast_lookup.sql',
    './src/db/migrations/004_hardware_fingerprint.sql',
    './src/db/migrations/005_signing_version.sql',
    './src/db/migrations/006_signature_valid.sql',
  ];

  for (const file of files) {
    console.log(`Applying ${file}...`);
    const sql = readFileSync(file, 'utf8');
    await query(sql);
    console.log(`✓ ${file} applied`);
  }
  console.log('All migrations complete!');
};

runMigrations().catch(e => console.error(e));