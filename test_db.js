import { query } from './server/src/db/pool.js';
query('SELECT 1').then(r => console.log('DB connection OK:', r.rowCount)).catch(e => console.error('DB error:', e.message));