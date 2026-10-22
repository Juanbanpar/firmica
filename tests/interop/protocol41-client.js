// Explicit browser fixture; the pinned AutoScript continues to negotiate protocol 4.
async function signProtocol41(scenario) {
  const session = '0123456789abcdef';
  const endpoint = `wss://127.0.0.1:${scenario.port}/`;
  window.location.href = `afirma://websocket?v=4.1&jvc=4&ports=${scenario.port}&idsession=${session}`;
  const deadline = performance.now() + 10000;
  let socket;
  while (!socket && performance.now() < deadline) {
    socket = await new Promise(resolve => {
      const candidate = new WebSocket(endpoint);
      candidate.onopen = () => resolve(candidate);
      candidate.onerror = () => { candidate.close(); resolve(undefined); };
    });
    if (!socket) await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!socket) throw new Error('Native protocol 4.1 listener did not start');
  const exchange = message => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('WSS reply timed out')), 5000);
    socket.onmessage = event => { clearTimeout(timer); resolve(event.data); };
    socket.send(message);
  });
  try {
    if (await exchange(`echo=-idsession=${session}@EOF`) !== 'OK') throw new Error('Session rejected');
    let result = await exchange('afirma://sign?' + new URLSearchParams({
      idsession: session, ver: '4.1', dat: scenario.content,
      algorithm: scenario.algorithm === 'ec' ? 'SHA256withECDSA' : 'SHA256withRSA',
      format: scenario.format, properties: btoa(scenario.properties),
    }));
    while (result === '#wait') {
      await new Promise(resolve => setTimeout(resolve, 100));
      result = await exchange(`getresult?idsession=${session}`);
    }
    const replay = await exchange(`getresult?idsession=${session}`);
    if (replay !== 'err-00:=AF600002 - Operation not supported') throw new Error('Result was reusable');
    if (result.startsWith('err-')) return { code: result };
    const fields = result.split('|');
    if (fields.length !== 2 || fields.some(value => !value)) throw new Error('Malformed signing response');
    return { certificate: fields[0], signature: fields[1] };
  } finally {
    socket.close();
  }
}
