package gateway

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/store"
)

// metadataTTL is the validity of signed_metadata.
const metadataTTL = time.Hour

// Issuer returns the configured issuer origin ("" in development mode).
func (g *Gateway) Issuer() string { return g.cfg.Issuer }

// issuer is the configured origin, or (development mode only) the origin the
// request was addressed to.
// loopbackOnly guards the development mode without a configured issuer
// (§18.1): the issuer is then taken from a loopback Host only; any other Host
// is refused so a forged Host can never become a signed iss/aud.
func loopbackOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			writeJSON(w, http.StatusMisdirectedRequest, map[string]string{"error": "invalid_request", "error_description": "gateway issuer is not configured; only loopback hosts are served"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (g *Gateway) issuer(r *http.Request) string {
	if g.cfg.Issuer != "" {
		return g.cfg.Issuer
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if o, err := lmbp.Origin(scheme + "://" + r.Host); err == nil {
		return o
	}
	return scheme + "://" + strings.ToLower(r.Host)
}

// verifyAccess checks an access token: signature by the gateway key, typ,
// iss == this gateway, aud == TokenAudience(iss, tenant) and lifetime.
func (g *Gateway) verifyAccess(tok, iss string) (lmbp.Claims, error) {
	uc, err := lmbp.UnverifiedClaims(tok)
	if err != nil {
		return uc, err
	}
	c, err := lmbp.VerifyJWT(g.pub, tok, lmbp.TypAccessToken, lmbp.TokenAudience(iss, uc.Tenant), time.Now())
	if err != nil {
		return c, err
	}
	if c.Iss != iss {
		return c, errors.New("token issuer mismatch")
	}
	return c, nil
}

// Metadata builds the gateway metadata document; with a tenant it adds the
// SaaS identity block and the gateway-signed signed_metadata JWS.
func (g *Gateway) Metadata(iss string, t *store.Tenant) lmbp.GatewayMetadata {
	ws := "ws" + strings.TrimPrefix(iss, "http")
	m := lmbp.GatewayMetadata{Issuer: iss, JWKSURI: iss + "/.well-known/jwks.json", DeviceAuthorizationEndpoint: iss + "/lmbp/v1/device/authorize",
		TokenEndpoint: iss + "/lmbp/v1/token", ConnectEndpoint: ws + "/lmbp/v1/connect", ChatCompletionsEndpoint: iss + "/v1/chat/completions",
		ProtocolVersions: lmbp.ProtocolVersions, Profiles: g.profiles(), Capabilities: g.capabilities(), ScopesSupported: lmbp.Scopes}
	if t == nil {
		return m
	}
	p := t.Profile
	name := p.DisplayName
	if name == "" {
		name = t.Name
	}
	scopes := p.RequestedScopes
	if len(scopes) == 0 {
		scopes = []string{lmbp.ScopeChat}
	}
	now := time.Now()
	m.Tenant, m.Audience = t.ID, lmbp.TokenAudience(iss, t.ID)
	m.SaaS = &lmbp.SaaSInfo{Name: name, LogoURI: p.LogoURI, HomepageURI: p.HomepageURI, PolicyURI: p.PolicyURI, TosURI: p.TosURI, PairingURI: p.PairingURI}
	m.RequestedModels, m.RequestedScopes = p.RequestedModels, scopes
	m.Iat, m.Exp = now.Unix(), now.Add(metadataTTL).Unix()
	m.SignedMetadata = lmbp.SignMetadata(g.cfg.SigningKey, g.kid, m)
	return m
}

func (g *Gateway) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		problem(w, 405, lmbp.ErrBadRequest, "GET required")
		return
	}
	var t *store.Tenant
	if id := r.URL.Query().Get("tenant"); id != "" {
		tt, err := g.cfg.Store.GetTenant(r.Context(), id)
		if err != nil || !lmbp.TenantIDPattern.MatchString(id) {
			problem(w, 404, lmbp.ErrBadRequest, "unknown tenant")
			return
		}
		t = &tt
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	m := g.Metadata(g.issuer(r), t)
	w.Header().Set("Content-Type", "application/json")
	writeJSONCache(w, m)
}
