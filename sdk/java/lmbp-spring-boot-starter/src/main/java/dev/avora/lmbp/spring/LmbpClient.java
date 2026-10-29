package dev.avora.lmbp.spring;

import dev.avora.lmbp.InProcessClient;
import dev.avora.lmbp.Json;
import dev.avora.lmbp.LMBPServer;
import dev.avora.lmbp.LmbpApiException;
import dev.avora.lmbp.LmbpStream;
import dev.avora.lmbp.Pairing;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * Injectable facade for business code, bound to the configured tenant ({@code lmbp.tenant}).
 * Methods without a user id use {@link LmbpUserResolver} on the current request.
 *
 * <pre>{@code
 * @PostMapping("/app/ask") Map<String, Object> ask(@RequestBody Map<String, Object> req) { return lmbp.chat(req); }
 * @PostMapping("/app/ask/stream") SseEmitter stream(@RequestBody Map<String, Object> req) { return lmbp.stream(req); }
 * }</pre>
 */
public class LmbpClient {
  private final LMBPServer lmbp;
  private final LmbpProperties props;
  private final LmbpUserResolver users;

  public LmbpClient(LMBPServer lmbp, LmbpProperties props, LmbpUserResolver users) { this.lmbp = lmbp; this.props = props; this.users = users; }

  public String tenant() { return props.getTenant(); }

  /** The underlying server (pairing, keys, raw handle). */
  public LMBPServer server() { return lmbp; }

  /** In-process client for {@code userId} (call, stream, cancel, resume, Anthropic messages). */
  public InProcessClient forUser(String userId) { return lmbp.client(props.getTenant(), require(userId)); }

  // ---- pairing ----
  /**
   * Deep link ({@code lmbp://pair?...}) to show {@code userId} as a link or QR code. The link itself is
   * the same for every user; the device is bound to {@code userId} when you call {@link #approve(String, String)}
   * with the code the desktop app displays. Uses {@code lmbp.issuer} (never the request's Host).
   */
  public String pairLink(String userId) {
    require(userId);
    return lmbp.pairing().link(props.getTenant());
  }

  /**
   * The pending pairing for the code {@code userId} typed; its device name is untrusted text. Wrong codes count
   * as failed attempts of {@code userId}.
   */
  public Pairing.Pending lookup(String userId, String userCode) { return lmbp.pairing().lookup(props.getTenant(), require(userId), userCode); }

  /** Approves the code shown on the desktop for {@code userId}; throws {@link Pairing.PairingException}. */
  public Pairing.Decision approve(String userId, String userCode) { return lmbp.pairing().approve(props.getTenant(), require(userId), userCode); }

  public Pairing.Decision deny(String userId, String userCode) { return lmbp.pairing().deny(props.getTenant(), require(userId), userCode); }

  public List<Pairing.Device> devices(String userId) { return lmbp.pairing().listDevices(props.getTenant(), require(userId)); }

  public boolean revoke(String userId, String deviceId) { return lmbp.pairing().revokeDevice(props.getTenant(), require(userId), deviceId); }

  // ---- model calls ----
  public List<Object> models(String userId) { return forUser(userId).models(); }

  /** Non-streaming chat completion (OpenAI request/response shape); throws {@link LmbpApiException}. */
  public Map<String, Object> chat(String userId, Map<String, ?> request) { return forUser(userId).call(request); }

  public Map<String, Object> chat(Map<String, ?> request) { return chat(currentUser(), request); }

  /**
   * Streams a chat completion to the browser as SSE: one {@code data:} event per OpenAI chunk (with the
   * resume cursor as event id), then {@code data: [DONE]}. On failure an {@code event: error} with
   * {@code {"code","message"}} is sent instead. A browser disconnect or timeout cancels the task.
   */
  public SseEmitter stream(String userId, Map<String, ?> request) { return emit(forUser(userId).stream(request)); }

  public SseEmitter stream(Map<String, ?> request) { return stream(currentUser(), request); }

  /** Cancels a running task of {@code userId}. */
  public boolean cancel(String userId, String taskId) { return forUser(userId).cancel(taskId); }

  /** Re-attaches to a task stream after {@code lastEventId}. */
  public SseEmitter resume(String userId, String taskId, String lastEventId) { return emit(forUser(userId).resume(taskId, lastEventId)); }

  private SseEmitter emit(LmbpStream st) {
    SseEmitter em = new SseEmitter(props.getSseTimeoutMs());
    em.onCompletion(st::close);
    em.onTimeout(st::close);
    em.onError(e -> st.close());
    Thread.ofVirtual().name("lmbp-sse").start(() -> {
      try (st) {
        for (Map<String, Object> chunk : st) {
          em.send(SseEmitter.event().id(st.lastEventId()).data(Json.stringify(chunk), MediaType.APPLICATION_JSON));
        }
        em.send(SseEmitter.event().data("[DONE]"));
        em.complete();
      } catch (LmbpApiException e) {
        try {
          em.send(SseEmitter.event().name("error").data(Json.stringify(Json.obj("code", e.code(), "message", String.valueOf(e.getMessage()), "task_id", st.taskId(),
              "last_event_id", st.lastEventId())), MediaType.APPLICATION_JSON));
          em.complete();
        } catch (IOException | RuntimeException x) { em.completeWithError(x); }
      } catch (IOException | RuntimeException e) {
        em.completeWithError(e);
      }
    });
    return em;
  }

  // ---- current user ----
  public String currentUser() {
    HttpServletRequest r = current();
    String u = r == null || users == null ? null : users.resolve(r);
    if (u == null || u.isEmpty()) throw new LmbpApiException(401, "UNAUTHENTICATED", "no signed-in user for this request", null);
    return u;
  }

  private static HttpServletRequest current() {
    return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes a ? a.getRequest() : null;
  }

  /** X-End-User rule (spec §4.1): 1-128 printable ASCII characters. */
  static boolean validUser(String s) {
    if (s == null || s.isEmpty() || s.length() > 128) return false;
    for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (c < 0x20 || c > 0x7E) return false; }
    return true;
  }

  private static String require(String userId) {
    if (!validUser(userId)) throw new IllegalArgumentException("user id must be 1-128 printable ASCII characters (it travels as X-End-User)");
    return userId;
  }
}
