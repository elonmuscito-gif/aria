const { spawn } = require('child_process');
const path = require('path');

console.log('Starting ARIA server...');
const server = spawn('node', ['--import', 'tsx', 'src/index.ts'], {
  cwd: path.join(__dirname, 'server'),
  stdio: ['ignore', 'pipe', 'pipe'],
  detached: true
});

server.stdout.on('data', (d) => console.log('[server]', d.toString().trim()));
server.stderr.on('data', (d) => console.error('[server error]', d.toString().trim()));

setTimeout(() => {
  console.log('Server started, running stress tests...');
}, 5000);

setTimeout(() => {
  process.kill(-server.pid);
  process.exit(0);
}, 60000);