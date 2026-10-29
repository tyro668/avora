import net from 'node:net';

/** freePort reserves an ephemeral loopback port (the gateway issuer must be known before it listens). */
export function freePort() {
  return new Promise((ok, fail) => {
    const s = net.createServer();
    s.once('error', fail);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => ok(port)); });
  });
}
