import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/009_email_verification.sql', 'utf8');
await query(sql);
console.log('Migration 009 complete');
process.exit(0);
