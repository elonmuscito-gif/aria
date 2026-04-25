import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/011_reputation_score.sql', 'utf8');
await query(sql);
console.log('Migration 011 complete');
process.exit(0);
