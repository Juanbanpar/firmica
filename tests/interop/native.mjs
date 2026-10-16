import { createServer } from 'node:net';

export async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

export async function until(fn, milliseconds = 15000) {
  const deadline = Date.now() + milliseconds;
  let last;
  while (Date.now() < deadline) {
    try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
    await new Promise(resolve => setTimeout(resolve,100));
  }
  throw last || new Error('condition timed out');
}

export async function inspector(port) {
  const address = `http://127.0.0.1:${port}`;
  const socketPath = await until(async () => {
    const text = await (await fetch(address)).text();
    return text.match(/\/socket\/\d+\/\d+\/WebPage/)?.[0];
  });
  const ws = new WebSocket(`ws://127.0.0.1:${port}${socketPath}`);
  const pending = new Map();
  let nextId = 0;
  let target;
  const ready = new Promise((resolve,reject) => {
    const timer = setTimeout(() => {ws.close(); reject(new Error('inspector target timed out'));},5000);
    ws.onerror = () => {clearTimeout(timer); reject(new Error('inspector WebSocket failed'));};
    ws.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.method === 'Target.targetCreated') { target = message.params.targetInfo.targetId; clearTimeout(timer); resolve(); }
      if (message.method === 'Target.dispatchMessageFromTarget') {
        const inner = JSON.parse(message.params.message);
        if (inner.id && pending.has(inner.id)) {
          const {resolve,reject,timer} = pending.get(inner.id); clearTimeout(timer); pending.delete(inner.id);
          if (inner.error || inner.result?.wasThrown) reject(new Error(JSON.stringify(inner)));
          else resolve(inner.result.result.value);
        }
      }
    };
  });
  await ready;
  return {
    evaluate(expression) {
      return new Promise((resolve,reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error('inspector evaluation timed out')); },5000);
        pending.set(id,{resolve,reject,timer});
        ws.send(JSON.stringify({id:++nextId,method:'Target.sendMessageToTarget',params:{targetId:target,message:JSON.stringify({id,method:'Runtime.evaluate',params:{expression,returnByValue:true}})}}));
      });
    },
    close() { ws.close(); },
  };
}
