import 'dotenv/config';
import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/017_zeroproof.sql', 'utf8');
await query(sql);
console.log('Migration 017 complete');
process.exit(0);
