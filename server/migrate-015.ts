import 'dotenv/config';
import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/015_witness.sql', 'utf8');
await query(sql);
console.log('Migration 015 complete');
process.exit(0);
