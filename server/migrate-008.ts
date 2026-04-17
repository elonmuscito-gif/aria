import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/008_anomalies_archive.sql', 'utf8');
await query(sql);
console.log('Migration 008 complete');
process.exit(0);