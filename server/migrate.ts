import { readFileSync } from 'fs';
import { query } from './src/db/pool.js';
import { join } from 'path';

async function migrate() {
  console.log('Running migrations...');
  
  const schema = readFileSync(join('./src/db/schema.sql'), 'utf8');
  await query(schema);
  console.log('✓ schema.sql');

  const migrations = [
    '001_server_verification.sql',
    '002_agent_hmac_key.sql', 
    '003_api_key_fast_lookup.sql',
    '004_hardware_fingerprint.sql',
    '005_signing_version.sql',
    '006_signature_valid.sql',
  ];

  for (const file of migrations) {
    const sql = readFileSync(join('./src/db/migrations', file), 'utf8');
    await query(sql);
    console.log(`✓ ${file}`);
  }
  
  console.log('All migrations complete.');
  process.exit(0);
}

migrate().catch(e => { console.error(e); process.exit(1); });