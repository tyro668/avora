package dev.avora.lmbp;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Pairing and device management for business code (§19). Obtain via {@link LMBPServer#pairing()}. */
public final class Pairing {
  private final LMBPServer s;

  Pairing(LMBPServer s) { this.s = s; }

  /** Pending pairing shown to the user before approving. */
  public record Pending(String userCode, String deviceName, String jkt, String status, Instant expiresAt) {}

  /** Result of approve/deny. {@code jkt} is the device key thumbprint to pin for E2EE. */
  public record Decision(String status, String deviceId, String deviceName, String jkt) {}

  /** A paired device as seen by its owner. */
  public record Device(String deviceId, String name, String status, Instant createdAt, String jkt, boolean online, List<Object> models,
      Map<String, Object> modelCapabilities, String e2eeKey) {}

  /** Failure of approve/deny; {@code code} is BAD_REQUEST, NOT_FOUND, FORBIDDEN, CONSENT_DENIED or RATE_LIMITED. */
  public static final class PairingException extends RuntimeException {
    private final String code;
    public PairingException(String code, String message) { super(message); this.code = code; }
    public String code() { return code; }
  }

  /** §19.4 deep link for the desktop app ({@code lmbp://pair?...}) on the configured issuer. */
  public String link(String tenant) {
    if (!s.g.tenants.containsKey(tenant)) throw new IllegalArgumentException("unknown tenant " + tenant);
    return "lmbp://pair?v=" + Lmbp.PAIR_LINK_VERSION + "&gateway=" + URLEncoder.encode(s.g.cfg.issuer, StandardCharsets.UTF_8) + "&tenant=" + URLEncoder.encode(tenant, StandardCharsets.UTF_8);
  }

  /**
   * Pending pairing for the user code {@code endUser} typed (shown on their desktop), to show the
   * device before approving. {@code deviceName} is untrusted text chosen by the device: render it as
   * plain text. A code that is not pending returns null and counts as a failed attempt of
   * {@code endUser} ({@link PairingException} RATE_LIMITED after 10 a minute).
   */
  public Pending lookup(String tenant, String endUser, String userCode) {
    checkCaller(tenant, endUser);
    Gateway.PairResult[] r = {null};
    s.g.locked(() -> r[0] = s.g.pairLookup(tenant, endUser, userCode));
    if (r[0].status == 429) throw new PairingException("RATE_LIMITED", r[0].message);
    if (r[0].d == null) return null;
    Store.DeviceAuth d = r[0].d;
    return new Pending(d.userCode, d.name, Lmbp.thumbprint(d.pub), d.status, Instant.ofEpochMilli(d.expires));
  }

  private void checkCaller(String tenant, String endUser) {
    if (!s.g.tenants.containsKey(tenant)) throw new PairingException("BAD_REQUEST", "unknown tenant");
    if (!Lmbp.validHeader(endUser, 128)) throw new PairingException("BAD_REQUEST", "end user must be 1-128 printable ASCII characters (it travels as X-End-User)");
  }

  /** Approves the code shown on the user's desktop for {@code endUser}; optional {@code jkt} pins the expected device key. */
  public Decision approve(String tenant, String endUser, String userCode) { return decide(tenant, endUser, userCode, false, null); }

  public Decision approve(String tenant, String endUser, String userCode, String jkt) { return decide(tenant, endUser, userCode, false, jkt); }

  /** Declines; a declined code cannot be approved later (the desktop sees CONSENT_DENIED). */
  public Decision deny(String tenant, String endUser, String userCode) { return decide(tenant, endUser, userCode, true, null); }

  private Decision decide(String tenant, String endUser, String userCode, boolean deny, String jkt) {
    checkCaller(tenant, endUser);
    Gateway.PairResult[] r = {null};
    s.g.locked(() -> r[0] = s.g.pairDecide(tenant, endUser, userCode == null ? "" : userCode, deny, jkt));
    Gateway.PairResult p = r[0];
    if (p.status != 0) {
      String code = switch (p.status) { case 429 -> "RATE_LIMITED"; case 404 -> "NOT_FOUND"; case 403 -> p.code; case 409 -> "FORBIDDEN"; default -> "BAD_REQUEST"; };
      throw new PairingException(code, p.message);
    }
    return new Decision(p.d.status, p.d.deviceID, p.d.name, Lmbp.thumbprint(p.d.pub));
  }

  public List<Device> listDevices(String tenant, String endUser) {
    List<Device> out = new ArrayList<>();
    s.g.locked(() -> {
      for (Store.Device d : s.g.store.listDevices(tenant, endUser)) {
        Gateway.DState o = s.g.online(d.id);
        out.add(new Device(d.id, d.name, d.status, d.created, Lmbp.thumbprint(d.pub), o != null, o == null ? List.of() : java.util.Collections.unmodifiableList(new ArrayList<>(o.models)),
            o == null ? Map.of() : java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(o.modelCaps)), d.e2eeKey == null ? "" : d.e2eeKey));
      }
    });
    return out;
  }

  /** Revokes a device: its session ends at once and refresh is refused. */
  public boolean revokeDevice(String tenant, String endUser, String deviceId) {
    boolean[] r = {false};
    s.g.locked(() -> r[0] = s.g.revokeDevice(tenant, endUser, deviceId));
    return r[0];
  }
}
