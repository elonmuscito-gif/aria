import 'dotenv/config';
import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/020_oauth.sql', 'utf8');
await query(sql);
console.log('Migration 020 complete');
process.exit(0);
