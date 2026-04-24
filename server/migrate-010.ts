import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/010_webhooks.sql', 'utf8');
await query(sql);
console.log('Migration 010 complete');
process.exit(0);
