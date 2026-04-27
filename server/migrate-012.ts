import 'dotenv/config';
import { query } from './src/db/pool.js';
import { readFileSync } from 'fs';

const sql = readFileSync('./src/db/migrations/012_agent_user_id.sql', 'utf8');
await query(sql);
console.log('Migration 012 complete');
process.exit(0);
