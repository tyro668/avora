package lmbp;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Self-tests for the Java mock (no test framework, JDK only): shared JOSE
 * vectors, JS-compatible JSON, origins, parameter validation and the chat
 * page (CSP headers, disabled mode) over real HTTP. Prints one result line
 * per test and a final "selftest: N passed, M failed" summary that
 * scripts/strict-test.py java judges.
 */
public final class SelfTest {
  interface T { void run() throws Exception; }

  static int passed, failed;
  static final Path ROOT = Path.of(System.getProperty("lmbp.root", "../.."));

  static void test(String name, T t) {
    try { t.run(); passed++; System.out.println("ok   " + name); }
    catch (Throwable e) { failed++; System.out.println("FAIL " + name + ": " + e); }
  }

  static void check(boolean c, String msg) { if (!c) throw new AssertionError(msg); }

  static void eq(Object a, Object b) { if (!java.util.Objects.equals(a, b)) throw new AssertionError("expected " + b + ", got " + a); }

  static final Set<String> KINDS = Set.of("proof", "client_assertion", "access_token", "e2ee_key");

  static void verify(Map<String, Object> f, Map<String, Object> v) {
    byte[] key = Lmbp.unb64(Json.str(Json.get(Json.get(f, "keys"), Json.str(v, "verify_with_key")), "public_b64url"));
    long now = Json.longOf(f.get("now"));
    Object c = v.get("context");
    Object compact = v.get("compact");
    switch (Json.str(v, "kind")) {
      case "proof" -> Lmbp.verifyProof(key, compact, Json.str(c, "iss"), Json.str(c, "aud"), Json.str(c, "credential"), now);
      case "client_assertion" -> Lmbp.verifyJWT(key, compact, Lmbp.TYP_ASSERTION, Json.str(c, "aud"), now);
      case "access_token" -> Lmbp.verifyJWT(key, compact, Lmbp.TYP_ACCESS, Json.str(c, "aud"), now);
      case "e2ee_key" -> Lmbp.verifyE2EEKey(key, Json.str(c, "device_id"), compact, now);
      default -> throw new IllegalStateException();
    }
  }

  static String[] get(int port, String path) throws Exception {
    try (Socket s = new Socket("127.0.0.1", port)) {
      OutputStream o = s.getOutputStream();
      o.write(("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
      o.flush();
      InputStream in = s.getInputStream();
      String r = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      return new String[] {r.split(" ")[1], r};
    }
  }

  public static void main(String[] args) throws Exception {
    Map<String, Object> f = Json.asObj(Json.parse(Files.readString(ROOT.resolve("spec/testvectors/jose.json"))));

    test("jose vectors: valid accepted, negative rejected", () -> {
      List<String> bad = new ArrayList<>();
      int n = 0;
      for (Object o : Json.asList(f.get("valid"))) {
        Map<String, Object> v = Json.asObj(o);
        if (!KINDS.contains(Json.str(v, "kind"))) continue;
        try { verify(f, v); } catch (RuntimeException e) { bad.add("valid " + v.get("name") + " rejected: " + e.getMessage()); }
      }
      for (Object o : Json.asList(f.get("negative"))) {
        Map<String, Object> v = Json.asObj(o);
        if (!KINDS.contains(Json.str(v, "kind"))) continue;
        n++;
        try { verify(f, v); bad.add("negative " + v.get("name") + " accepted (" + v.get("must_reject_because") + ")"); } catch (RuntimeException e) { /* expected */ }
      }
      check(n > 50, "only " + n + " negative vectors");
      check(bad.isEmpty(), String.join("\n", bad));
    });

    test("ed25519 key, thumbprint and JWK match the vector", () -> {
      Object d = Json.get(f.get("keys"), "device");
      Lmbp.SigningKey k = Lmbp.signingKey(Lmbp.unb64(Json.str(d, "seed_b64url")));
      eq(Lmbp.b64(k.pub()), Json.str(d, "public_b64url"));
      eq(Lmbp.thumbprint(k.pub()), Json.str(d, "jkt"));
      eq(Json.stringify(Lmbp.publicJWK(k.pub())), Json.stringify(Json.get(d, "jwk")));
    });

    test("sign/verify round trip", () -> {
      Lmbp.SigningKey k = Lmbp.signingKey(new byte[32]);
      long t = Lmbp.now();
      String jws = Lmbp.signJWS(k.priv(), Lmbp.TYP_ACCESS, Lmbp.thumbprint(k.pub()), Json.obj("iss", "i", "sub", "s", "aud", "a", "jti", "j", "iat", t, "exp", t + 60));
      Lmbp.verifyJWT(k.pub(), jws, Lmbp.TYP_ACCESS, "a", t);
      boolean rejected = false;
      try { Lmbp.verifyJWT(k.pub(), jws, Lmbp.TYP_ACCESS, "b", t); } catch (IllegalArgumentException e) { rejected = true; }
      check(rejected, "wrong audience accepted");
    });

    test("JSON like JavaScript", () -> {
      eq(Json.stringify(Json.parse("{\"b\":1,\"a\":[1.0,0.5,-0.0,1e21,\"\\u2028x\"],\"c\":null}")), "{\"b\":1,\"a\":[1,0.5,0,1e+21,\"\u2028x\"],\"c\":null}");
      check(Json.truthy(0.5) && !Json.truthy(0L) && !Json.truthy(""), "truthiness");
    });

    test("origins", () -> {
      eq(Lmbp.origin("HTTPS://GW.Example.com:443/"), "https://gw.example.com");
      eq(Lmbp.origin("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
      for (String bad : new String[] {"http://gw.example.com", "https://gw.example.com/path", "https://u@gw.example.com"}) {
        boolean rejected = false;
        try { Lmbp.origin(bad); } catch (IllegalArgumentException e) { rejected = true; }
        check(rejected, bad + " accepted");
      }
    });

    test("chat parameters", () -> {
      try { Params.validateChatParams(Json.asObj(Json.parse("{\"model\":\"x\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"temperature\":3}"))); throw new AssertionError("accepted"); }
      catch (Params.ParamError e) { eq(e.param, "temperature"); eq(e.getMessage(), "temperature: must be between 0 and 2, got 3"); }
      Params.Sampling p = Params.validateChatParams(Json.asObj(Json.parse("{\"model\":\"x\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_completion_tokens\":5,\"stop\":\"x\"}")));
      eq(p.maxTokens, 5L);
      eq(p.stop.size(), 1);
    });

    test("chat page with CSP, core endpoints, disabled chat page", () -> {
      ServerSocket ss = Http.listen("127.0.0.1", 0);
      int port = ss.getLocalPort();
      Gateway.Config cfg = new Gateway.Config();
      cfg.issuer = "http://127.0.0.1:" + port;
      cfg.webDir = ROOT.resolve("mock/web").toString();
      Gateway g = new Gateway(cfg, new byte[32]);
      Thread.ofVirtual().start(() -> { try { Http.serve(ss, g); } catch (Exception e) { /* closed */ } });
      String[][] pages = {{"/", "text/html"}, {"/chat", "text/html"}, {"/chat/chat.js", "text/javascript"}, {"/chat/qrcode.js", "text/javascript"}};
      for (String[] pg : pages) {
        String[] r = get(port, pg[0]);
        eq(r[0], "200");
        check(r[1].contains("Content-Type: " + pg[1]), pg[0] + " content type");
        check(r[1].contains("Content-Security-Policy: " + Gateway.WEB_CSP), pg[0] + " CSP");
        check(r[1].contains("X-Content-Type-Options: nosniff"), pg[0] + " nosniff");
      }
      String[] r = get(port, "/.well-known/jwks.json");
      eq(r[0], "200");
      check(r[1].contains("\"kty\":\"OKP\""), "jwks");
      r = get(port, "/.well-known/lmbp");
      check(r[1].contains("\"connect_endpoint\":\"ws://127.0.0.1:" + port + "/lmbp/v1/connect\""), "metadata");
      r = get(port, "/lmbp/v1/connect");
      eq(r[0], "400");
      check(r[1].contains("application/problem+json") && r[1].contains("VERSION_UNSUPPORTED"), "problem details");
      g.locked(() -> cfg.webDir = "");
      eq(get(port, "/chat")[0], "404");
      ss.close();
    });

    test("outbox: forget fails the task's queued sends before waking others (audit3 P1)", () -> {
      Gateway.Config cfg = new Gateway.Config();
      cfg.issuer = "http://127.0.0.1";
      Gateway g = new Gateway(cfg, new byte[32]);
      Lmbp.Outbox o = new Lmbp.Outbox(g);
      g.locked(() -> {
        o.setFlow(new Lmbp.Flow(Lmbp.MAX_FRAME_BYTES, Lmbp.MAX_FRAME_BYTES));
        String big = "x".repeat(130 << 10);
        java.util.List<Lmbp.Outbox.Waiter> ws = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
          Lmbp.Outbox.Waiter w = new Lmbp.Outbox.Waiter();
          w.task = "t1";
          w.mk = seq -> "{\"seq\":" + seq + ",\"d\":\"" + big + "\"}";
          o.waiters.add(w);
          ws.add(w);
        }
        o.wake();
        check(ws.get(0).done && !ws.get(1).done, "second chunk should wait for credit");
        o.forget("t1");
        check(!o.tasks.containsKey("t1"), "forgotten task re-created its outbox entry");
        eq(o.connUsed, 0L);
        check(o.waiters.isEmpty() && ws.get(1).done && ws.get(1).err != null && ws.get(2).err != null, "queued sends of the forgotten task not failed");
        boolean rejected = false;
        try { o.send("t1", seq -> Json.obj("type", "blob.chunk"), null); } catch (IllegalStateException e) { rejected = true; }
        check(rejected, "send after forget admitted");
      });
    });

    System.out.println("selftest: " + passed + " passed, " + failed + " failed");
    System.exit(failed == 0 ? 0 : 1);
  }
}
