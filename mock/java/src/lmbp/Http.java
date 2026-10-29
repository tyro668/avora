package lmbp;

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
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A small HTTP/1.1 server (one virtual thread per connection, one request
 * per connection) with RFC 6455 WebSocket support, so the mock needs nothing
 * beyond the JDK. Not a general-purpose server.
 */
final class Http {
  static final int MAX_BODY = 48 << 20;
  static final int MAX_HEADER_BYTES = 64 << 10;

  static final class Req {
    String method, target, path, query = "";
    final Map<String, String> headers = new LinkedHashMap<>();
    byte[] body; // null if over MAX_BODY
    Socket sock;
    InputStream in;
    /** TCP peer address (the per-client key of the authorize rate limit). */
    String remoteAddr = "";
    final Gateway.Abort abort = new Gateway.Abort();

    String header(String k) { String v = headers.get(k); return v == null ? "" : v; }

    String queryParam(String k) {
      for (String kv : query.split("&")) {
        if (kv.isEmpty()) continue;
        int i = kv.indexOf('=');
        String key = dec(i < 0 ? kv : kv.substring(0, i));
        if (key.equals(k)) return dec(i < 0 ? "" : kv.substring(i + 1));
      }
      return null;
    }

    static String dec(String s) {
      try { return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (IllegalArgumentException e) { return s; }
    }
  }

  /** Response writer; every socket write runs with the gateway lock released. */
  static final class Res {
    final Gateway g;
    final OutputStream out;
    final Req req;
    final Map<String, String> headers = new LinkedHashMap<>();
    boolean headersSent, ended;

    Res(Gateway g, OutputStream out, Req req) { this.g = g; this.out = out; this.req = req; }

    void setHeader(String k, String v) { headers.put(k, v); }

    String getHeader(String k) { return headers.get(k); }

    boolean writeHead(int status, Map<String, String> extra) {
      if (headersSent) return false;
      headersSent = true;
      if (extra != null) headers.putAll(extra);
      StringBuilder b = new StringBuilder("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n");
      for (Map.Entry<String, String> e : headers.entrySet()) b.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
      b.append("Connection: close\r\n\r\n");
      return raw(b.toString().getBytes(StandardCharsets.ISO_8859_1));
    }

    boolean write(String s) { return raw(s.getBytes(StandardCharsets.UTF_8)); }

    boolean raw(byte[] b) {
      if (ended || req.abort.aborted) return false;
      boolean[] ok = {true};
      g.unlocked(() -> {
        try { out.write(b); out.flush(); } catch (IOException e) { ok[0] = false; }
      });
      if (!ok[0]) g.abortReq(req.abort);
      return ok[0];
    }

    void end(byte[] body) {
      if (ended) return;
      if (body != null && body.length > 0) raw(body);
      ended = true;
    }

    void end() { end(null); }

    void send(int status, String contentType, byte[] body) {
      if (headers.get("Content-Type") == null) headers.put("Content-Type", contentType);
      headers.put("Content-Length", String.valueOf(body.length));
      writeHead(status, null);
      if (!"HEAD".equals(req.method)) end(body); else end();
    }
  }

  static String reason(int s) {
    switch (s) {
      case 101: return "Switching Protocols";
      case 200: return "OK";
      case 400: return "Bad Request";
      case 401: return "Unauthorized";
      case 403: return "Forbidden";
      case 404: return "Not Found";
      case 405: return "Method Not Allowed";
      case 409: return "Conflict";
      case 413: return "Payload Too Large";
      case 422: return "Unprocessable Entity";
      case 429: return "Too Many Requests";
      case 499: return "Client Closed Request";
      case 500: return "Internal Server Error";
      case 502: return "Bad Gateway";
      case 503: return "Service Unavailable";
      case 504: return "Gateway Timeout";
      default: return "Status";
    }
  }

  static ServerSocket listen(String host, int port) throws IOException {
    ServerSocket ss = new ServerSocket();
    ss.setReuseAddress(true);
    ss.bind(new InetSocketAddress(host.isEmpty() ? InetAddress.getByName("0.0.0.0") : InetAddress.getByName(host), port), 512);
    return ss;
  }

  static void serve(ServerSocket ss, Gateway g) throws IOException {
    for (;;) {
      Socket s = ss.accept();
      Thread.ofVirtual().start(() -> conn(s, g));
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

  static void conn(Socket s, Gateway g) {
    try (s) {
      s.setTcpNoDelay(true);
      InputStream in = new BufferedInputStream(s.getInputStream());
      OutputStream out = s.getOutputStream();
      int[] budget = {MAX_HEADER_BYTES};
      String line = readLine(in, budget);
      if (line == null) return;
      String[] rl = line.split(" ");
      if (rl.length != 3) return;
      Req req = new Req();
      req.method = rl[0];
      req.target = rl[1];
      req.sock = s;
      req.remoteAddr = s.getInetAddress() == null ? "" : s.getInetAddress().getHostAddress();
      req.in = in;
      int q = req.target.indexOf('?');
      req.path = q < 0 ? req.target : req.target.substring(0, q);
      if (q >= 0) req.query = req.target.substring(q + 1);
      for (;;) {
        String h = readLine(in, budget);
        if (h == null || h.isEmpty()) break;
        int c = h.indexOf(':');
        if (c <= 0) continue;
        String k = h.substring(0, c).trim().toLowerCase();
        String v = h.substring(c + 1).trim();
        req.headers.merge(k, v, (a, b) -> a + ", " + b);
      }
      boolean upgrade = req.header("upgrade").equalsIgnoreCase("websocket");
      if (upgrade) {
        req.body = new byte[0];
        g.upgrade(req, out);
        return;
      }
      req.body = readBody(in, req);
      Res res = new Res(g, out, req);
      // A long request (chat/messages/events) notices a client disconnect via EOF.
      Thread watcher = Thread.ofVirtual().start(() -> {
        try { while (in.read() >= 0) { /* one request per connection: ignore */ } } catch (IOException e) { /* closed */ }
        g.abortReq(req.abort);
      });
      try {
        g.handle(req, res);
      } catch (RuntimeException e) {
        g.log("handler error: " + e);
        if (!res.headersSent) Gateway.problem(res, 500, "INTERNAL", "internal error");
      }
      res.end();
      watcher.interrupt();
    } catch (IOException e) {
      // connection closed
    }
  }

  static byte[] readBody(InputStream in, Req req) throws IOException {
    String te = req.header("transfer-encoding").toLowerCase();
    if (te.contains("chunked")) {
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
        if (b.size() + chunk.length > MAX_BODY) over = true; else b.write(chunk);
        readLine(in, budget);
      }
      return over ? null : b.toByteArray();
    }
    String cl = req.header("content-length");
    if (cl.isEmpty()) return new byte[0];
    long n;
    try { n = Long.parseLong(cl); } catch (NumberFormatException e) { return new byte[0]; }
    if (n > MAX_BODY) {
      // Drain (bounded) so the client sees our 413 instead of a reset.
      long left = Math.min(n, 64L << 20);
      byte[] buf = new byte[64 << 10];
      while (left > 0) { int r = in.read(buf, 0, (int) Math.min(buf.length, left)); if (r < 0) break; left -= r; }
      return null;
    }
    return in.readNBytes((int) n);
  }

  // ---------------- WebSocket (RFC 6455) ----------------
  interface WsHandler { void message(String text, boolean binary, int size); }

  static final class Ws {
    final Gateway g;
    final Socket sock;
    final InputStream in;
    final OutputStream out;
    final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    static final byte[] POISON = new byte[0];
    volatile boolean open = true;
    boolean closeFired;
    WsHandler onMessage;
    Runnable onPong, onClose;

    Ws(Gateway g, Socket sock, InputStream in, OutputStream out) {
      this.g = g; this.sock = sock; this.in = in; this.out = out;
      Thread.ofVirtual().start(this::writer);
    }

    void writer() {
      try {
        for (;;) {
          byte[] f = queue.take();
          if (f == POISON) break;
          out.write(f);
          if (queue.isEmpty()) out.flush();
        }
        out.flush();
      } catch (Exception e) { /* closed */ }
      try { sock.close(); } catch (IOException e) { /* ignore */ }
    }

    boolean isOpen() { return open; }

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

    void send(String text) {
      if (!open) throw new IllegalStateException("closed");
      queue.add(frame(1, text.getBytes(StandardCharsets.UTF_8)));
    }

    void ping() { if (open) queue.add(frame(9, new byte[0])); }

    void close() { close(1000, ""); }

    void close(int code, String reason) {
      if (!open) return;
      open = false;
      byte[] r = reason.getBytes(StandardCharsets.UTF_8);
      byte[] p = new byte[2 + r.length];
      p[0] = (byte) (code >> 8); p[1] = (byte) code;
      System.arraycopy(r, 0, p, 2, r.length);
      queue.add(frame(8, p));
      queue.add(POISON);
    }

    void terminate() {
      open = false;
      queue.add(POISON);
      try { sock.close(); } catch (IOException e) { /* ignore */ }
    }

    /** Reader loop on the connection thread; handlers run under the gateway lock. */
    void run(int maxPayload) {
      ByteArrayOutputStream msg = null;
      int msgOp = 0;
      try {
        for (;;) {
          int b0 = in.read(), b1 = in.read();
          if (b0 < 0 || b1 < 0) break;
          boolean fin = (b0 & 0x80) != 0;
          int op = b0 & 0x0f;
          if ((b0 & 0x70) != 0 || (b1 & 0x80) == 0) { protoClose(1002, "protocol error"); break; }
          long n = b1 & 0x7f;
          if (n == 126) n = (in.read() << 8) | in.read();
          else if (n == 127) { n = 0; for (int i = 0; i < 8; i++) n = (n << 8) | in.read(); }
          if (n < 0 || n > maxPayload || (msg != null && msg.size() + n > maxPayload)) { protoClose(1009, "message too big"); break; }
          byte[] mask = in.readNBytes(4);
          byte[] p = in.readNBytes((int) n);
          if (p.length != n || mask.length != 4) break;
          for (int i = 0; i < p.length; i++) p[i] ^= mask[i & 3];
          if (op >= 8) {
            if (op == 8) { g.locked(() -> close(1000, "")); break; }
            if (op == 9) { if (open) queue.add(frame(10, p)); continue; }
            if (op == 10) { if (onPong != null) g.locked(onPong); continue; }
            protoClose(1002, "bad opcode"); break;
          }
          if (op == 0) {
            if (msg == null) { protoClose(1002, "unexpected continuation"); break; }
            msg.write(p);
          } else {
            if (msg != null || (op != 1 && op != 2)) { protoClose(1002, "bad frame"); break; }
            msg = new ByteArrayOutputStream();
            msg.write(p);
            msgOp = op;
          }
          if (fin) {
            byte[] data = msg.toByteArray();
            boolean binary = msgOp == 2;
            msg = null;
            String text = new String(data, StandardCharsets.UTF_8);
            WsHandler h = onMessage;
            if (h != null && open) g.locked(() -> h.message(text, binary, data.length));
          }
        }
      } catch (IOException e) {
        // connection lost
      }
      open = false;
      queue.add(POISON);
      try { sock.close(); } catch (IOException e) { /* ignore */ }
      g.locked(() -> {
        if (closeFired) return;
        closeFired = true;
        if (onClose != null) onClose.run();
      });
    }

    void protoClose(int code, String reason) { g.locked(() -> close(code, reason)); }
  }

  static String acceptKey(String key) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      return Base64.getEncoder().encodeToString(md.digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes(StandardCharsets.ISO_8859_1)));
    } catch (Exception e) { throw new RuntimeException(e); }
  }
}
