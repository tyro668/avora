package dev.avora.lmbp.spring;

import dev.avora.lmbp.HttpRequest;
import dev.avora.lmbp.HttpSink;
import dev.avora.lmbp.LMBPServer;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Serves the LMBP HTTP surface (<code>/.well-known/lmbp</code>, <code>/.well-known/jwks.json</code>,
 * <code>/lmbp/**</code>, <code>/v1/**</code>, <code>/healthz</code>) before Spring MVC. WebSocket upgrades to
 * <code>/lmbp/v1/connect</code> pass through to the registered WebSocket handler; everything else
 * goes down the chain unchanged.
 */
public class LmbpFilter extends OncePerRequestFilter {
  /** Request attribute holding a {@link BooleanSupplier} that reports a closed client connection. */
  static final String PROBE_ATTR = "dev.avora.lmbp.disconnectProbe";
  /** How often the probe runs while a request waits (spec §6.5 asks for a prompt task.cancel). */
  static final long PROBE_INTERVAL_MS = 250;
  private final LMBPServer lmbp;

  public LmbpFilter(LMBPServer lmbp) { this.lmbp = lmbp; }

  @Override protected boolean shouldNotFilterAsyncDispatch() { return true; }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
    String path = req.getRequestURI().substring(req.getContextPath().length());
    if (!lmbp.handles(path)) { chain.doFilter(req, res); return; }
    if (path.equals(LMBPServer.CONNECT_PATH) && "websocket".equalsIgnoreCase(req.getHeader("Upgrade"))) { chain.doFilter(req, res); return; }
    HttpRequest r = new HttpRequest(req.getMethod(), path, req.getQueryString(), headers(req), body(req)).remoteAddress(req.getRemoteAddr());
    // Async mode frees the container thread; a client disconnect surfaces as a failed write
    // (SSE keep-alives every lmbp.keepalive-ms), as AsyncListener.onError, or through the
    // container probe below (non-streaming requests).
    AsyncContext ac = req.startAsync(req, res);
    ac.setTimeout(0);
    ac.addListener(new AsyncListener() {
      @Override public void onComplete(AsyncEvent e) { }
      @Override public void onTimeout(AsyncEvent e) { r.abort(); }
      @Override public void onError(AsyncEvent e) { r.abort(); }
      @Override public void onStartAsync(AsyncEvent e) { }
    });
    ServletOutputStream out = res.getOutputStream();
    // A non-streaming response writes nothing until the task ends, so a write failure cannot
    // reveal a disconnect; poll the container's probe (Tomcat) instead.
    Object probeLock = new Object();
    boolean[] done = {false};
    if (req.getAttribute(PROBE_ATTR) instanceof BooleanSupplier probe) {
      Thread.ofVirtual().name("lmbp-probe").start(() -> {
        try {
          for (;;) {
            Thread.sleep(PROBE_INTERVAL_MS);
            synchronized (probeLock) {
              if (done[0]) return;
              if (probe.getAsBoolean()) { r.abort(); return; }
            }
          }
        } catch (InterruptedException e) { /* stop */ }
      });
    }
    Thread.ofVirtual().name("lmbp-http").start(() -> {
      try {
        lmbp.handle(r, new HttpSink() {
          @Override public void start(int status, Map<String, String> h) throws IOException {
            res.setStatus(status);
            for (Map.Entry<String, String> e : h.entrySet()) {
              if (e.getKey().equalsIgnoreCase("Content-Length")) res.setContentLengthLong(Long.parseLong(e.getValue()));
              else res.setHeader(e.getKey(), e.getValue());
            }
            res.flushBuffer();
          }

          @Override public void write(byte[] b) throws IOException {
            out.write(b);
            out.flush();
          }
        });
      } finally {
        synchronized (probeLock) { done[0] = true; }
        try { ac.complete(); } catch (IllegalStateException e) { /* already completed after an error */ }
      }
    });
  }

  static Map<String, String> headers(HttpServletRequest req) {
    Map<String, String> h = new LinkedHashMap<>();
    for (Enumeration<String> names = req.getHeaderNames(); names.hasMoreElements();) {
      String n = names.nextElement();
      StringBuilder v = new StringBuilder();
      for (Enumeration<String> vs = req.getHeaders(n); vs.hasMoreElements();) { if (v.length() > 0) v.append(", "); v.append(vs.nextElement()); }
      h.put(n, v.toString());
    }
    return h;
  }

  /** Reads at most MAX_BODY_BYTES; null when the client sent more (the engine answers 413). */
  static byte[] body(HttpServletRequest req) throws IOException {
    long cl = req.getContentLengthLong();
    if (cl > LMBPServer.MAX_BODY_BYTES) return null;
    try (InputStream in = req.getInputStream()) {
      byte[] b = in.readNBytes(LMBPServer.MAX_BODY_BYTES + 1);
      return b.length > LMBPServer.MAX_BODY_BYTES ? null : b;
    }
  }
}
