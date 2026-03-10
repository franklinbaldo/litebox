// Ultra-simple pipe EOF test
const { spawn } = require('child_process');

// Spawn echo, which writes then exits immediately
const child = spawn('/bin/echo', ['PIPE_TEST']);

let gotData = false;
let gotEnd = false;
let gotClose = false;
let gotExit = false;

child.stdout.on('data', (d) => { gotData = true; console.log('DATA:', d.toString().trim()); });
child.stdout.on('end', () => { gotEnd = true; console.log('END'); });
child.stdout.on('close', () => { gotClose = true; console.log('CLOSE'); });
child.on('exit', (code, sig) => { gotExit = true; console.log('EXIT:', code, sig); });

// Also check after a timeout
setTimeout(() => {
  console.log('TIMEOUT - gotData:', gotData, 'gotEnd:', gotEnd, 'gotClose:', gotClose, 'gotExit:', gotExit);
  // Force check: try reading from pipe directly
  console.log('stdout readable:', child.stdout.readable);
  console.log('stdout destroyed:', child.stdout.destroyed);
  process.exit(0);
}, 5000);
