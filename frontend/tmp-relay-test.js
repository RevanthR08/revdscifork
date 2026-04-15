const WebSocket = require('ws');
const url = 'ws://127.0.0.1:8787';

const a = new WebSocket(url);
const b = new WebSocket(url);
let ready = 0;

const onReady = () => {
  ready += 1;
  if (ready === 2) {
    console.log('both connected');
    a.on('message', (data) => console.log('A got', data.toString()));
    b.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      console.log('B got', msg.type, msg.senderId, msg.payload ? msg.payload.length : 'nil');
      process.exit(0);
    });

    setTimeout(() => {
      a.send(JSON.stringify({ type: 'snapshot', senderId: 'A', payload: 'hello-from-a', sentAt: Date.now() }));
      console.log('A sent snapshot');
    }, 500);
  }
};

a.on('open', onReady);
b.on('open', onReady);
setTimeout(() => {
  console.error('TIMED OUT');
  process.exit(1);
}, 5000);
