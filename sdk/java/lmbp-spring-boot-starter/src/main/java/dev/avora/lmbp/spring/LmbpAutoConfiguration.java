package dev.avora.lmbp.spring;

import dev.avora.lmbp.JdbcStore;
import dev.avora.lmbp.Json;
import dev.avora.lmbp.LMBPServer;
import dev.avora.lmbp.MemoryStore;
import dev.avora.lmbp.Store;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.standard.ServletServerContainerFactoryBean;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;

/**
 * Registers an {@link LMBPServer}, the HTTP filter for every LMBP route, the connector WebSocket at
 * <code>/lmbp/v1/connect</code> (subprotocol {@code lmbp}, 256 KiB message cap) and an injectable {@link LmbpClient}.
 * Override any bean by declaring your own.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(LmbpProperties.class)
public class LmbpAutoConfiguration {
  private static final Logger log = LoggerFactory.getLogger("lmbp");

  @Bean @ConditionalOnMissingBean
  public Store lmbpStore(LmbpProperties p, ObjectProvider<DataSource> dataSource) {
    String s = p.getStore() == null ? "memory" : p.getStore().trim();
    if (s.isEmpty() || s.equals("memory")) return new MemoryStore();
    if (s.equals("jdbc")) {
      DataSource ds = dataSource.getIfAvailable();
      if (ds == null) throw new IllegalStateException("lmbp.store=jdbc needs a DataSource bean");
      return new JdbcStore(ds, p.getJdbcTextType());
    }
    if (s.startsWith("jdbc:")) return JdbcStore.open(s);
    throw new IllegalStateException("lmbp.store must be memory, jdbc or a jdbc: URL");
  }

  @Bean(destroyMethod = "close") @ConditionalOnMissingBean
  public LMBPServer lmbpServer(LmbpProperties p, Store store) throws IOException {
    if (p.getApiKey() == null || p.getApiKey().length() < 32) throw new IllegalStateException("lmbp.api-key must be set (>= 32 characters)");
    Map<String, Object> profile = new LinkedHashMap<>();
    if (p.getProfileFile() != null && !p.getProfileFile().isEmpty()) {
      Map<String, Object> all = Json.asObj(Json.parse(Files.readString(Path.of(p.getProfileFile()))));
      Map<String, Object> mine = all == null ? null : Json.asObj(all.get(p.getTenant()));
      if (mine != null) profile.putAll(mine);
      profile.remove("api_key_env");
    }
    if (p.getDisplayName() != null && !p.getDisplayName().isEmpty()) profile.put("display_name", p.getDisplayName());
    if (p.getIssuer() == null || p.getIssuer().isEmpty()) throw new IllegalStateException("lmbp.issuer must be set: the gateway's public origin (never derived from the Host header)");
    return LMBPServer.builder().issuer(p.getIssuer()).tenant(p.getTenant(), p.getApiKey(), profile).store(store).signingSeedHex(p.getSigningSeed())
        .maxConcurrency(p.getMaxConcurrency()).keepaliveMillis(p.getKeepaliveMs()).retentionMillis(p.getRetentionSeconds() < 0 ? -1 : p.getRetentionSeconds() * 1000).chatUiDir(p.getChatUiDir()).logger(log::info).build();
  }

  @Bean @ConditionalOnMissingBean
  public LmbpUserResolver lmbpUserResolver() { return req -> req.getUserPrincipal() == null ? null : req.getUserPrincipal().getName(); }

  @Bean @ConditionalOnMissingBean
  public LmbpClient lmbpClient(LMBPServer lmbp, LmbpProperties p, ObjectProvider<LmbpUserResolver> users) {
    // resolved lazily so a controller can both declare the resolver and inject the client
    return new LmbpClient(lmbp, p, req -> users.getObject().resolve(req));
  }

  @Bean
  public FilterRegistrationBean<LmbpFilter> lmbpFilter(LMBPServer lmbp) {
    FilterRegistrationBean<LmbpFilter> r = new FilterRegistrationBean<>(new LmbpFilter(lmbp));
    r.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
    r.addUrlPatterns("/*");
    r.setName("lmbpFilter");
    r.setAsyncSupported(true);
    return r;
  }

  /** Tomcat only: lets the filter see a client disconnect while a non-streaming request waits (spec §6.5). */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "org.apache.catalina.startup.Tomcat")
  static class LmbpTomcatConfig {
    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> lmbpDisconnectProbe() {
      return f -> f.addEngineValves(new TomcatDisconnectProbe());
    }
  }

  @Bean
  public LmbpWebSocketHandler lmbpWebSocketHandler(LMBPServer lmbp) { return new LmbpWebSocketHandler(lmbp); }

  /** Connector WebSocket registration. */
  @Configuration(proxyBeanMethods = false)
  @EnableWebSocket
  static class LmbpWebSocketConfig implements WebSocketConfigurer {
    private final LmbpWebSocketHandler handler;

    LmbpWebSocketConfig(LmbpWebSocketHandler handler) { this.handler = handler; }

    @Override public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
      DefaultHandshakeHandler hh = new DefaultHandshakeHandler();
      hh.setSupportedProtocols(LMBPServer.SUBPROTOCOL);
      // The engine rejects every browser Origin itself (403 problem); Spring's same-origin check is disabled.
      registry.addHandler(handler, LMBPServer.CONNECT_PATH).setHandshakeHandler(hh).addInterceptors(handler).setAllowedOriginPatterns("*");
    }

    @Bean @ConditionalOnMissingBean
    ServletServerContainerFactoryBean lmbpWebSocketContainer() {
      ServletServerContainerFactoryBean f = new ServletServerContainerFactoryBean();
      f.setMaxTextMessageBufferSize(LMBPServer.MAX_FRAME_BYTES);
      f.setMaxBinaryMessageBufferSize(LMBPServer.MAX_FRAME_BYTES);
      return f;
    }
  }
}
