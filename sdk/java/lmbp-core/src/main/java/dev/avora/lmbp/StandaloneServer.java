package dev.avora.lmbp;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A minimal JDK-only HTTP/1.1 + RFC 6455 server for an {@link LMBPServer} (one virtual thread
 * per connection, one request per connection, {@code Connection: close}). Meant for tests,
 * demos and sidecars; production apps mount the server in their web framework
 * (e.g. {@code lmbp-spring-boot-starter}). Requests to other paths get 404.
 */
public final class StandaloneServer implements AutoCloseable {
  static final int MAX_HEADER_BYTES = 64 << 10;
  private final LMBPServer lmbp;
  private final ServerSocket ss;
  private final Thread acceptor;

  private StandaloneServer(LMBPServer lmbp, ServerSocket ss) {
    this.lmbp = lmbp;
    this.ss = ss;
    acceptor = Thread.ofPlatform().daemon().name("lmbp-accept").start(this::acceptLoop);
  }

  /** Binds {@code host:port} (port 0 = ephemeral) and starts serving. */
  public static StandaloneServer start(LMBPServer lmbp, String host, int port) throws IOException {
    ServerSocket ss = new ServerSocket();
    ss.setReuseAddress(true);
    ss.bind(new InetSocketAddress(host == null || host.isEmpty() ? InetAddress.getByName("0.0.0.0") : InetAddress.getByName(host), port), 512);
    return new StandaloneServer(lmbp, ss);
  }

  public int port() { return ss.getLocalPort(); }

  /** Blocks until the server is closed. */
  public void join() throws InterruptedException { acceptor.join(); }

  @Override public void close() throws IOException { ss.close(); }

  private void acceptLoop() {
    while (!ss.isClosed()) {
      try {
        Socket s = ss.accept();
        Thread.ofVirtual().start(() -> conn(s));
      } catch (IOException e) { if (ss.isClosed()) return; }
    }
  }

  static String readLine(InputStream in, int[] budget) throws IOException {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    for (;;) {
      int c = in.read();
      if (c < 0) { if (b.size() == 0) return null; break; }
      if (--budget[0] < 0) throw new IOException("header too large");
      if (c == '\n') break;
      b.write(c);
    }
    String s = b.toString(StandardCharsets.ISO_8859_1);
    return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
  }

  private void conn(Socket s) {
    try (s) {
      s.setTcpNoDelay(true);
      InputStream in = new BufferedInputStream(s.getInputStream());
      OutputStream out = s.getOutputStream();
      int[] budget = {MAX_HEADER_BYTES};
      String line = readLine(in, budget);
      if (line == null) return;
      String[] rl = line.split(" ");
      if (rl.length != 3) return;
      String target = rl[1];
      int q = target.indexOf('?');
      String path = q < 0 ? target : target.substring(0, q), query = q < 0 ? "" : target.substring(q + 1);
      Map<String, String> headers = new LinkedHashMap<>();
      for (;;) {
        String h = readLine(in, budget);
        if (h == null || h.isEmpty()) break;
        int c = h.indexOf(':');
        if (c <= 0) continue;
        headers.merge(h.substring(0, c).trim().toLowerCase(), h.substring(c + 1).trim(), (a, b) -> a + ", " + b);
      }
      if ("websocket".equalsIgnoreCase(headers.getOrDefault("upgrade", ""))) { upgrade(new HttpRequest(rl[0], path, query, headers, new byte[0]), s, in, out); return; }
      HttpRequest req = new HttpRequest(rl[0], path, query, headers, readBody(in, headers)).remoteAddress(s.getInetAddress().getHostAddress());
      boolean[] started = {false};
      HttpSink sink = new HttpSink() {
        @Override public void start(int status, Map<String, String> h) throws IOException {
          started[0] = true;
          StringBuilder b = new StringBuilder("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n");
          for (Map.Entry<String, String> e : h.entrySet()) b.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
          b.append("Connection: close\r\n\r\n");
          out.write(b.toString().getBytes(StandardCharsets.ISO_8859_1));
          out.flush();
        }
        @Override public void write(byte[] b) throws IOException { out.write(b); out.flush(); }
      };
      Thread watcher = Thread.ofVirtual().start(() -> {
        try { while (in.read() >= 0) { /* one request per connection */ } } catch (IOException e) { /* closed */ }
        req.abort();
      });
      if (!lmbp.handles(path) && !path.equals("/")) {
        byte[] b = "{\"error\":\"not found\"}".getBytes(StandardCharsets.UTF_8);
        sink.start(404, Map.of("Content-Type", "application/json", "Cache-Control", "no-store", "Content-Length", String.valueOf(b.length)));
        sink.write(b);
      } else lmbp.handle(req, sink);
      watcher.interrupt();
    } catch (IOException e) {
      // connection closed
    }
  }

  static byte[] readBody(InputStream in, Map<String, String> h) throws IOException {
    int max = LMBPServer.MAX_BODY_BYTES;
    if (h.getOrDefault("transfer-encoding", "").toLowerCase().contains("chunked")) {
      ByteArrayOutputStream b = new ByteArrayOutputStream();
      boolean over = false;
      int[] budget = {MAX_HEADER_BYTES};
      for (;;) {
        String l = readLine(in, budget);
        if (l == null) break;
        int semi = l.indexOf(';');
        int n = Integer.parseInt((semi < 0 ? l : l.substring(0, semi)).trim(), 16);
        if (n == 0) { while (true) { String t = readLine(in, budget); if (t == null || t.isEmpty()) break; } break; }
        byte[] chunk = in.readNBytes(n);
        if (b.size() + chunk.length > max) over = true; else b.write(chunk);
        readLine(in, budget);
      }
      return over ? null : b.toByteArray();
    }
    String cl = h.getOrDefault("content-length", "");
    if (cl.isEmpty()) return new byte[0];
    long n;
    try { n = Long.parseLong(cl); } catch (NumberFormatException e) { return new byte[0]; }
    if (n > max) {
      long left = Math.min(n, 64L << 20);
      byte[] buf = new byte[64 << 10];
      while (left > 0) { int r = in.read(buf, 0, (int) Math.min(buf.length, left)); if (r < 0) break; left -= r; }
      return null;
    }
    return in.readNBytes((int) n);
  }

  private void upgrade(HttpRequest req, Socket sock, InputStream in, OutputStream out) throws IOException {
    WebSocketHandshake hs = lmbp.handshake(req);
    if (!hs.accepted()) {
      byte[] b = hs.body();
      StringBuilder head = new StringBuilder("HTTP/1.1 ").append(hs.status()).append(' ').append(reason(hs.status())).append("\r\n");
      for (Map.Entry<String, String> e : hs.headers().entrySet()) head.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
      head.append("Content-Length: ").append(b.length).append("\r\nConnection: close\r\n\r\n");
      out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
      out.write(b);
      out.flush();
      return;
    }
    String resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acceptKey(req.header("sec-websocket-key"))
        + "\r\nSec-WebSocket-Protocol: " + hs.subprotocol() + "\r\n\r\n";
    out.write(resp.getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
    Object wlock = new Object();
    WebSocketPeer peer = new WebSocketPeer() {
      @Override public void sendText(String text) throws IOException { write(1, text.getBytes(StandardCharsets.UTF_8)); }
      @Override public void sendPing() throws IOException { write(9, new byte[0]); }
      @Override public void close(int code, String reason) {
        byte[] r = reason.getBytes(StandardCharsets.UTF_8);
        byte[] p = new byte[2 + r.length];
        p[0] = (byte) (code >> 8); p[1] = (byte) code;
        System.arraycopy(r, 0, p, 2, r.length);
        try { write(8, p); } catch (IOException e) { /* gone */ }
        terminate();
      }
      @Override public void terminate() { try { sock.close(); } catch (IOException e) { /* ignore */ } }
      void write(int op, byte[] payload) throws IOException { synchronized (wlock) { out.write(frame(op, payload)); out.flush(); } }
    };
    WebSocketSession ws = hs.accept(peer);
    readLoop(ws, peer, in, wlock, out);
  }

  static byte[] frame(int opcode, byte[] payload) {
    int n = payload.length;
    ByteArrayOutputStream b = new ByteArrayOutputStream(n + 10);
    b.write(0x80 | opcode);
    if (n < 126) b.write(n);
    else if (n < 65536) { b.write(126); b.write(n >> 8); b.write(n & 0xff); }
    else { b.write(127); for (int i = 7; i >= 0; i--) b.write((int) (((long) n >> (8 * i)) & 0xff)); }
    b.write(payload, 0, n);
    return b.toByteArray();
  }

  private static void readLoop(WebSocketSession ws, WebSocketPeer peer, InputStream in, Object wlock, OutputStream out) {
    int max = LMBPServer.MAX_FRAME_BYTES;
    ByteArrayOutputStream msg = null;
    int msgOp = 0;
    try {
      for (;;) {
        int b0 = in.read(), b1 = in.read();
        if (b0 < 0 || b1 < 0) break;
        boolean fin = (b0 & 0x80) != 0;
        int op = b0 & 0x0f;
        if ((b0 & 0x70) != 0 || (b1 & 0x80) == 0) { peer.close(1002, "protocol error"); break; }
        long n = b1 & 0x7f;
        if (n == 126) n = (in.read() << 8) | in.read();
        else if (n == 127) { n = 0; for (int i = 0; i < 8; i++) n = (n << 8) | in.read(); }
        if (n < 0 || n > max || (msg != null && msg.size() + n > max)) { peer.close(1009, "message too big"); break; }
        byte[] mask = in.readNBytes(4);
        byte[] p = in.readNBytes((int) n);
        if (p.length != n || mask.length != 4) break;
        for (int i = 0; i < p.length; i++) p[i] ^= mask[i & 3];
        if (op >= 8) {
          if (op == 8) { peer.close(1000, ""); break; }
          if (op == 9) { synchronized (wlock) { out.write(frame(10, p)); out.flush(); } continue; }
          if (op == 10) { ws.onPong(); continue; }
          peer.close(1002, "bad opcode"); break;
        }
        if (op == 0) {
          if (msg == null) { peer.close(1002, "unexpected continuation"); break; }
          msg.write(p);
        } else {
          if (msg != null || (op != 1 && op != 2)) { peer.close(1002, "bad frame"); break; }
          msg = new ByteArrayOutputStream();
          msg.write(p);
          msgOp = op;
        }
        if (fin) {
          byte[] data = msg.toByteArray();
          msg = null;
          if (msgOp == 2) ws.onBinary(data.length); else ws.onText(new String(data, StandardCharsets.UTF_8));
        }
      }
    } catch (IOException e) {
      // connection lost
    }
    peer.terminate();
    ws.onClose();
  }

  static String acceptKey(String key) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      return Base64.getEncoder().encodeToString(md.digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.ISO_8859_1)));
    } catch (Exception e) { throw new IllegalStateException(e); }
  }

  static String reason(int s) {
    return switch (s) {
      case 101 -> "Switching Protocols"; case 200 -> "OK"; case 400 -> "Bad Request"; case 401 -> "Unauthorized"; case 403 -> "Forbidden";
      case 404 -> "Not Found"; case 405 -> "Method Not Allowed"; case 409 -> "Conflict"; case 413 -> "Payload Too Large"; case 422 -> "Unprocessable Entity";
      case 429 -> "Too Many Requests"; case 499 -> "Client Closed Request"; case 500 -> "Internal Server Error"; case 502 -> "Bad Gateway";
      case 503 -> "Service Unavailable"; case 504 -> "Gateway Timeout"; default -> "Status";
    };
  }
}
