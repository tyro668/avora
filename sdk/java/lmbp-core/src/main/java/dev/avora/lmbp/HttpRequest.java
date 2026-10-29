package dev.avora.lmbp;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * One HTTP request handed to {@link LMBPServer#handle(HttpRequest, HttpSink)} by a transport
 * adapter (servlet filter, the bundled standalone server, ...). Header names are matched
 * case-insensitively. The body must already be read, capped at {@link LMBPServer#MAX_BODY_BYTES};
 * pass {@code null} when the client sent more than that (the engine answers 413).
 *
 * <p>When the client disconnects, the adapter should call {@link #abort()}: a waiting
 * request then stops, and the engine decides the task's outcome (a lone streaming
 * subscriber leaving cancels the task).
 */
public final class HttpRequest {
  final String method, path, query;
  final Map<String, String> headers = new LinkedHashMap<>();
  final byte[] body;
  final Gateway.Abort abort = new Gateway.Abort();
  volatile Gateway gateway;
  /** TCP peer address (set by the transport adapter; forwarding headers are not trusted). */
  String remoteAddr = "";
  /** Set by the in-process client: the call is already authenticated as this tenant/user. */
  String trustedTenant, trustedUser;

  public HttpRequest(String method, String path, String query, Map<String, String> headers, byte[] body) {
    this.method = method == null ? "GET" : method.toUpperCase(Locale.ROOT);
    this.path = path == null || path.isEmpty() ? "/" : path;
    this.query = query == null ? "" : query;
    if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) {
      if (e.getKey() == null || e.getValue() == null) continue;
      this.headers.merge(e.getKey().toLowerCase(Locale.ROOT), e.getValue(), (a, b) -> a + ", " + b);
    }
    this.body = body;
  }

  /** Records the client's TCP peer address (used for the §6.2 pairing rate limit). */
  public HttpRequest remoteAddress(String addr) { this.remoteAddr = addr == null ? "" : addr; return this; }

  public String method() { return method; }
  public String path() { return path; }
  public String query() { return query; }
  public Map<String, String> headers() { return Collections.unmodifiableMap(headers); }

  /** Signals a client disconnect; safe to call from any thread, any number of times. */
  public void abort() {
    Gateway g = gateway;
    if (g != null) g.abortReq(abort); else abort.aborted = true;
  }

  public boolean isAborted() { return abort.aborted; }

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
