package lmbp;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** LMBP mock SaaS gateway (Java): flags mirror mock/python/gateway.py. In-memory state only. */
public final class Main {
  public static void main(String[] args) throws Exception {
    String listen = env("LMBP_LISTEN", "127.0.0.1:8080"), issuer = env("LMBP_ISSUER", ""), profiles = env("LMBP_TENANT_PROFILES", "");
    String seedEnv = "LMBP_SIGNING_SEED";
    String webDir = env("LMBP_WEB_DIR", "");
    boolean noChat = false;
    int maxConc = 16;
    long retention = 0; // ms; 0 keeps the default (7 days), negative disables
    List<String> tenants = new ArrayList<>();
    for (int i = 0; i < args.length; i++) {
      String a = args[i];
      String v = a.contains("=") ? a.substring(a.indexOf('=') + 1) : null;
      String k = a.contains("=") ? a.substring(0, a.indexOf('=')) : a;
      if (!k.equals("--no-chat-ui") && !k.equals("-h") && !k.equals("--help") && v == null) {
        if (i + 1 >= args.length) die("flag " + k + " needs a value");
        v = args[++i];
      }
      switch (k) {
        case "--listen" -> listen = v;
        case "--issuer" -> issuer = v;
        case "--tenant" -> tenants.add(v);
        case "--tenant-profiles" -> profiles = v;
        case "--signing-key-env" -> seedEnv = v;
        case "--max-concurrency" -> maxConc = Integer.parseInt(v);
        case "--retention-seconds" -> retention = (long) (Double.parseDouble(v) * 1000);
        case "--web-dir" -> webDir = v;
        case "--no-chat-ui" -> noChat = true;
        case "--db" -> die("--db is not supported by the Java mock (state is in memory; the signing key comes from " + seedEnv + ")");
        case "-h", "--help" -> {
          System.out.println("usage: lmbp-mock-java [--listen host:port] [--issuer origin] [--tenant ID:ENV]... [--tenant-profiles file]\n"
              + "                     [--signing-key-env ENV] [--max-concurrency N] [--retention-seconds N] [--web-dir dir] [--no-chat-ui]");
          return;
        }
        default -> die("unknown flag " + k);
      }
    }
    String seedHex = System.getenv(seedEnv);
    byte[] seed = null;
    if (seedHex != null && !seedHex.isEmpty()) seed = HexFormat.of().parseHex(seedHex.trim());
    else System.err.println("warning: no signing key; using an ephemeral key (tokens do not survive restarts)");
    if (seed != null && seed.length != 32) die(seedEnv + " must hold 32 bytes of hex");
    Gateway.Config cfg = new Gateway.Config();
    cfg.issuer = issuer.isEmpty() ? loopbackIssuer(listen) : issuer;
    cfg.maxConc = maxConc;
    if (retention != 0) cfg.retention = retention;
    if (webDir.isEmpty()) {
      Path guess = Path.of(System.getProperty("lmbp.home", "."), "mock", "web");
      if (!Files.isDirectory(guess)) guess = Path.of("..", "web");
      webDir = guess.toString();
    }
    cfg.webDir = noChat ? "" : webDir;
    Gateway g = new Gateway(cfg, seed);
    g.startRetention();
    int n = 0;
    for (String spec : tenants) {
      int c = spec.indexOf(':');
      String id = c < 0 ? spec : spec.substring(0, c), envName = c < 0 ? "" : spec.substring(c + 1);
      String key = System.getenv(envName);
      if (key == null || key.isEmpty()) die("tenant " + id + ": env " + envName + " is empty");
      g.registerTenant(id, key, Json.obj());
      n++;
    }
    if (!profiles.isEmpty()) {
      Map<String, Object> m = Json.asObj(Json.parse(Files.readString(Path.of(profiles))));
      if (m == null) die("tenant profiles must be a JSON object");
      for (Map.Entry<String, Object> e : m.entrySet()) {
        Map<String, Object> p = Json.asObj(e.getValue());
        String envName = p == null ? "" : String.valueOf(p.getOrDefault("api_key_env", ""));
        String key = System.getenv(envName);
        if (key == null || key.isEmpty()) die("tenant " + e.getKey() + ": api_key_env " + envName + " is empty");
        g.registerTenant(e.getKey(), key, p);
        n++;
      }
    }
    if (n == 0) System.err.println("warning: no tenants registered (use --tenant id:ENV_VAR)");
    int colon = listen.lastIndexOf(':');
    String host = colon < 0 ? "" : listen.substring(0, colon);
    int port = Integer.parseInt(colon < 0 ? listen : listen.substring(colon + 1));
    ServerSocket ss = Http.listen(host, port);
    System.err.println("lmbp java mock gateway listening on " + listen + " issuer=" + cfg.issuer + " kid=" + g.kid);
    Http.serve(ss, g);
  }

  /** The default issuer for a loopback --listen address; any other address needs --issuer (spec §18.1). */
  static String loopbackIssuer(String listen) {
    int i = listen.lastIndexOf(':');
    String h = (i < 0 ? listen : listen.substring(0, i)).replaceAll("^\\[|\\]$", "");
    if (h.equals("localhost") || h.equals("::1") || h.startsWith("127.")) return "http://" + listen;
    die("--issuer (or LMBP_ISSUER) is required when listening on " + listen);
    return "";
  }

  static String env(String k, String d) { String v = System.getenv(k); return v == null || v.isEmpty() ? d : v; }

  static void die(String msg) { System.err.println(msg); System.exit(2); }
}
