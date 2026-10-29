// Package gateway is the Go reference implementation of an lmbp gateway
// (docs/lmbp-spec.md): RFC 8628 pairing, key-bound EdDSA tokens, the
// device WebSocket with resume and credit-window flow control, gateway-signed
// task.run frames, binary blob transfer, tools/multimodal routing, blind
// relaying of end-to-end encrypted tasks, idempotent task submission and an
// OpenAI-compatible SSE surface with Last-Event-ID re-attachment.
package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/store"
)

const (
	userCodeChars  = "BCDFGHJKLMNPQRSTVWXZ" // RFC 8628 §6.1 recommendation
	maxFrame       = lmbp.MaxFrameBytes
	deviceGrant    = "urn:ietf:params:oauth:grant-type:device_code"
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type Config struct {
	Store store.Store
	// Issuer is the gateway's public https origin (e.g. https://gw.example.com).
	// It is the iss of every token and the base of every audience. Empty means
	// development mode: the issuer is derived from each request's Host, which
	// MUST NOT be used in production.
	Issuer       string
	SigningKey   ed25519.PrivateKey // gateway key; generated if nil
	TokenTTL     time.Duration      // default 15m
	CodeTTL      time.Duration      // default 10m
	Retention    time.Duration      // default 7 days; 0 keeps the default, <0 disables purge
	TaskTimeout  time.Duration      // default 10m
	PingInterval time.Duration      // default 20s; also the token-expiry check period
	ResumeWindow time.Duration      // default 30s; how long tasks survive a device disconnect
	AttachGrace  time.Duration      // default 30s; idempotent tasks survive a client disconnect this long
	SlowConsumer time.Duration      // default 60s; a subscriber that stalls the stream this long fails the task
	QueueTimeout time.Duration      // default 15s; how long a request waits for a device concurrency slot
	MaxConc      int                // gateway cap on per-device concurrency (default 16)
	Flow         lmbp.Flow          // windows the gateway advertises (defaults DefaultTaskWindow/ConnWindow)
	// CoreOnly runs a Core-only gateway (spec §13.1): it negotiates only
	// session.token and models.update, advertises profiles core and openai,
	// and serves no /v1/messages. Used to prove Core conformance on its own.
	CoreOnly bool
	Logger   *log.Logger
}

type Gateway struct {
	cfg       Config
	kid       string
	pub       ed25519.PublicKey
	mu        sync.Mutex
	devs      map[string]*dstate // device_id → live or resumable device session
	tasks     map[string]*gtask  // task_id → task (kept AttachGrace+10m after completion)
	jtis      *jtiCache
	pairMu    sync.Mutex                      // serializes pairing decisions (single use, failure counting)
	fail      map[string][]time.Time          // tenant + end user → recent failed decisions (under pairMu)
	pending   map[string]map[string]time.Time // tenant → device_code hash → expiry (under mu)
	authRate  windowCounter                   // device authorizations per client address
	refreshes atomic.Int64
	resumes   atomic.Int64
}

// Resumes counts accepted session resumptions.
func (g *Gateway) Resumes() int64 { return g.resumes.Load() }

// TokenRefreshes counts accepted mid-connection session.token swaps.
func (g *Gateway) TokenRefreshes() int64 { return g.refreshes.Load() }

func New(cfg Config) (*Gateway, error) {
	if cfg.Store == nil {
		return nil, errors.New("store required")
	}
	if cfg.SigningKey == nil {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg.SigningKey = k
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 15 * time.Minute
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 10 * time.Minute
	}
	if cfg.Retention == 0 {
		cfg.Retention = 7 * 24 * time.Hour
	}
	if cfg.TaskTimeout == 0 {
		cfg.TaskTimeout = 10 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 20 * time.Second
	}
	if cfg.ResumeWindow == 0 {
		cfg.ResumeWindow = lmbp.DefaultResumeSeconds * time.Second
	}
	if cfg.AttachGrace == 0 {
		cfg.AttachGrace = 30 * time.Second
	}
	if cfg.QueueTimeout == 0 {
		cfg.QueueTimeout = 15 * time.Second
	}
	if cfg.SlowConsumer == 0 {
		cfg.SlowConsumer = 60 * time.Second
	}
	if cfg.MaxConc <= 0 || cfg.MaxConc > 16 {
		cfg.MaxConc = 16
	}
	if cfg.Flow.TaskWindow == 0 {
		cfg.Flow = lmbp.Flow{TaskWindow: lmbp.DefaultTaskWindow, ConnWindow: lmbp.DefaultConnWindow}
	}
	if cfg.Issuer != "" {
		o, err := lmbp.Origin(cfg.Issuer)
		if err != nil {
			return nil, err
		}
		cfg.Issuer = o
	}
	pub := cfg.SigningKey.Public().(ed25519.PublicKey)
	g := &Gateway{cfg: cfg, pub: pub, kid: lmbp.Thumbprint(pub), devs: map[string]*dstate{}, tasks: map[string]*gtask{}, jtis: newJTICache(), fail: map[string][]time.Time{}, pending: map[string]map[string]time.Time{}}
	g.recoverOrphans(context.Background())
	return g, nil
}

// recoverOrphans persists OUTCOME_UNKNOWN for tasks a previous process left
// without a terminal state (crash while QUEUED/RUNNING). A new gateway owns
// no task yet, so all of them are orphans. Persisting the terminal event and
// state (FinishTask, atomically) makes replays report the same outcome as
// before and lets retention purge the prompt and output like any finished
// task; without it RUNNING rows bypassed retention forever (audit3 P2-5).
func (g *Gateway) recoverOrphans(ctx context.Context) {
	ul, ok := g.cfg.Store.(store.UnfinishedLister)
	if !ok {
		return
	}
	ts, err := ul.UnfinishedTasks(ctx)
	if err != nil {
		g.cfg.Logger.Printf("lmbp: listing unfinished tasks: %v", err)
		return
	}
	body, _ := json.Marshal(lmbp.ErrorBody{Code: lmbp.ErrOutcomeUnknown, Message: "gateway restarted; task outcome unknown"})
	for _, t := range ts {
		evs, err := g.cfg.Store.ListEvents(ctx, t.ID)
		if err != nil {
			g.cfg.Logger.Printf("lmbp: orphaned task %s: %v", t.ID, err)
			continue
		}
		var last int64
		for _, e := range evs {
			last = max(last, e.Seq)
		}
		if err := g.cfg.Store.FinishTask(ctx, store.Event{TaskID: t.ID, Seq: last + 1, Kind: lmbp.TypeTaskError, Data: body, At: time.Now()}, "FAILED"); err != nil && err != store.ErrExists {
			g.cfg.Logger.Printf("lmbp: orphaned task %s: persisting %s: %v", t.ID, lmbp.ErrOutcomeUnknown, err)
		}
	}
	if len(ts) > 0 {
		g.cfg.Logger.Printf("lmbp: %d orphaned task(s) from a previous run recorded as %s", len(ts), lmbp.ErrOutcomeUnknown)
	}
}

// PublicKey returns the key devices pin to verify task.run frames.
func (g *Gateway) PublicKey() ed25519.PublicKey { return g.pub }

// RetentionEvery is how often the retention pass runs for a retention
// period: half of it, between one second and one hour (same in every SDK).
func RetentionEvery(ret time.Duration) time.Duration {
	return min(time.Hour, max(time.Second, ret/2))
}

// RunRetention purges finished data older than Retention until ctx ends,
// every interval (<= 0: RetentionEvery(Retention)).
func (g *Gateway) RunRetention(ctx context.Context, every time.Duration) {
	if g.cfg.Retention < 0 {
		return
	}
	if every <= 0 {
		every = RetentionEvery(g.cfg.Retention)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		g.Purge(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Purge is one retention pass (spec §14.4, errata E6): finished tasks older than
// Retention go from the store together with their idempotency records, and
// from the in-memory registry. It returns the number of stored tasks removed.
func (g *Gateway) Purge(ctx context.Context, now time.Time) int {
	cutoff := now.Add(-g.cfg.Retention)
	n, err := g.cfg.Store.Purge(ctx, cutoff)
	if err != nil {
		g.cfg.Logger.Printf("retention purge: %v", err)
		return 0
	}
	g.mu.Lock()
	for id, t := range g.tasks {
		t.mu.Lock()
		old := !t.finishedAt.IsZero() && t.finishedAt.Before(cutoff)
		t.mu.Unlock()
		if old {
			delete(g.tasks, id)
		}
	}
	g.mu.Unlock()
	if n > 0 {
		g.cfg.Logger.Printf("retention purge: removed %d tasks", n)
	}
	return n
}

func (g *Gateway) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []lmbp.JWK{lmbp.PublicJWK(g.pub)}})
	})
	m.HandleFunc(lmbp.MetadataPath, g.metadata)
	m.HandleFunc("/lmbp/v1/device/authorize", g.authorize)
	m.HandleFunc("/lmbp/v1/token", g.token)
	m.HandleFunc("/lmbp/v1/connect", g.connect)
	m.HandleFunc("/lmbp/v1/tenant/devices/approvals", g.approve)
	m.HandleFunc("/lmbp/v1/tenant/devices", g.listDevices)
	m.HandleFunc("/lmbp/v1/tenant/devices/", g.revoke)
	m.HandleFunc("/lmbp/v1/tenant/tasks/", g.taskEvents)
	m.HandleFunc("/v1/models", g.models)
	m.HandleFunc("/v1/chat/completions", g.chat)
	if !g.cfg.CoreOnly {
		m.HandleFunc("/v1/messages", g.messages)
	}
	if g.cfg.Issuer == "" {
		return loopbackOnly(m)
	}
	return m
}

// ---------- helpers ----------

// capabilities and profiles this gateway implements (Core-only or full).
func (g *Gateway) capabilities() []string {
	if g.cfg.CoreOnly {
		return lmbp.CoreCapabilities
	}
	return lmbp.Capabilities
}

func (g *Gateway) profiles() []string {
	if g.cfg.CoreOnly {
		return lmbp.CoreProfiles
	}
	return lmbp.Profiles
}

// writeJSONCache writes a cacheable 200 JSON body (Cache-Control set by the caller).
func writeJSONCache(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// apiError writes an OpenAI-style error body carrying an lmbp code.
func apiError(w http.ResponseWriter, status int, code, msg string) {
	if isAnthropic(w) {
		anthropicError(w, status, code, msg)
		return
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "type": "lmbp_error", "code": code}})
}

// httpError writes RFC 9457 problem details for gateway endpoints and the
// OpenAI error object for the OpenAI-compatible /v1/* surface.
func httpError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	if strings.HasPrefix(r.URL.Path, "/v1/") || isAnthropic(w) {
		apiError(w, status, code, msg)
		return
	}
	problem(w, status, code, msg)
}

func problem(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": ProblemBase + strings.ToLower(strings.ReplaceAll(code, "_", "-")),
		"title": code, "status": status, "detail": msg, "code": code})
}

// ProblemBase prefixes RFC 9457 problem type URIs.
const ProblemBase = "https://avora.dev/problems/"

// params reads an OAuth request either as application/x-www-form-urlencoded
// (RFC 6749 §4.1.3 / RFC 8628 §3.1, normative) or as a JSON object (accepted).
func params(r *http.Request, max int64) (map[string]string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, max)
	out := map[string]string{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		for k, v := range r.PostForm {
			if len(v) != 1 {
				return nil, errors.New("duplicate parameter " + k)
			}
			out[k] = v[0]
		}
		return out, nil
	}
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		return nil, err
	}
	for k, v := range m {
		if sv, ok := v.(string); ok {
			out[k] = sv
		}
	}
	return out, nil
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code})
}

func decode(r *http.Request, v any, max int64) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, max)).Decode(v)
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func userCode() string {
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeChars))))
		b[i] = userCodeChars[n.Int64()]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

func normCode(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), "-", ""), " ", ""))
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

// tenantAuth authenticates the SaaS backend (tenant API key) and the end user
// it acts for (X-End-User, asserted by the authenticated tenant backend).
func (g *Gateway) tenantAuth(w http.ResponseWriter, r *http.Request) (store.Tenant, string, bool) {
	a := r.Header.Get("Authorization")
	if a == "" && r.Header.Get("X-Api-Key") != "" { // Anthropic clients send x-api-key
		a = "Bearer " + r.Header.Get("X-Api-Key")
	}
	if !strings.HasPrefix(a, "Bearer ") {
		httpError(w, r, 401, lmbp.ErrUnauthenticated, "tenant API key required")
		return store.Tenant{}, "", false
	}
	t, err := g.cfg.Store.TenantByAPIKeyHash(r.Context(), sha(strings.TrimPrefix(a, "Bearer ")))
	if err != nil {
		httpError(w, r, 401, lmbp.ErrUnauthenticated, "invalid tenant API key")
		return t, "", false
	}
	user := r.Header.Get("X-End-User")
	if !lmbp.ValidHeaderValue(user, 128) { // 1-128 printable ASCII (§4.1)
		httpError(w, r, 400, lmbp.ErrBadRequest, "X-End-User header required (1-128 printable ASCII characters)")
		return t, "", false
	}
	return t, user, true
}

// ---------- RFC 8628 device authorization ----------

func (g *Gateway) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, 405, "invalid_request")
		return
	}
	// §6.2: limited per client address before anything is parsed or stored.
	if !g.authRate.allow(clientAddr(r), AuthorizePerMinute, time.Now()) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, 429, "slow_down")
		return
	}
	ps, err := params(r, 4096)
	req := struct{ Tenant, PublicKey, DeviceName string }{ps["tenant"], ps["public_key"], ps["device_name"]}
	if err != nil || req.Tenant == "" || !lmbp.ValidDeviceName(req.DeviceName) {
		oauthError(w, 400, "invalid_request")
		return
	}
	pub, err := lmbp.UnB64(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		oauthError(w, 400, "invalid_request")
		return
	}
	if !lmbp.TenantIDPattern.MatchString(req.Tenant) {
		oauthError(w, 400, "invalid_client")
		return
	}
	if _, err := g.cfg.Store.GetTenant(r.Context(), req.Tenant); err != nil {
		oauthError(w, 400, "invalid_client") // §6.2: only registered tenants get pairings
		return
	}
	dc := lmbp.RandomID("dc_")
	d := store.DeviceAuth{DeviceCodeHash: sha(dc), UserCode: userCode(), TenantID: req.Tenant, PublicKey: pub, DeviceName: req.DeviceName,
		Status: "pending", ExpiresAt: time.Now().Add(g.cfg.CodeTTL), Interval: initialInterval}
	if !g.reservePending(d.TenantID, d.DeviceCodeHash, d.ExpiresAt) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, 429, "slow_down")
		return
	}
	if err := g.cfg.Store.CreateDeviceAuth(r.Context(), d); err != nil {
		g.releasePending(d.TenantID, d.DeviceCodeHash)
		oauthError(w, 500, "server_error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"device_code": dc, "user_code": d.UserCode, "expires_in": int(g.cfg.CodeTTL.Seconds()), "interval": d.Interval})
}

func (g *Gateway) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, r, 405, lmbp.ErrBadRequest, "POST required")
		return
	}
	t, user, ok := g.tenantAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		UserCode string `json:"user_code"`
		Deny     bool   `json:"deny"`
		JKT      string `json:"jkt"` // device key thumbprint relayed by the user's browser (pins the key for E2EE)
	}
	if decode(r, &req, 4096) != nil {
		httpError(w, r, 400, lmbp.ErrBadRequest, "invalid JSON")
		return
	}
	d, err := g.Decide(r.Context(), t.ID, user, req.UserCode, req.JKT, req.Deny)
	switch {
	case errors.Is(err, ErrRateLimited):
		httpError(w, r, 429, lmbp.ErrRateLimited, "too many failed codes; wait a minute")
		return
	case errors.Is(err, ErrCodeDenied):
		// §19: a declined pairing cannot be overridden by a later approval.
		httpError(w, r, 403, lmbp.ErrConsentDenied, err.Error())
		return
	case errors.Is(err, ErrCodeInvalid):
		httpError(w, r, 404, lmbp.ErrBadRequest, err.Error())
		return
	case errors.Is(err, ErrJKTMismatch):
		httpError(w, r, 409, lmbp.ErrForbidden, err.Error())
		return
	case err != nil:
		httpError(w, r, 500, lmbp.ErrInternal, "storage error")
		return
	}
	writeJSON(w, 200, map[string]string{"status": d.Status, "device_id": d.DeviceID, "device_name": d.DeviceName, "jkt": lmbp.Thumbprint(d.PublicKey)})
}

// reservePending counts a new pending pairing against its tenant's cap
// (MaxPendingPerTenant live codes); expired entries are dropped first.
func (g *Gateway) reservePending(tenant, hash string, exp time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	m := g.pending[tenant]
	if m == nil {
		m = map[string]time.Time{}
		g.pending[tenant] = m
	}
	for h, at := range m {
		if now.After(at) {
			delete(m, h)
		}
	}
	if len(m) >= MaxPendingPerTenant {
		return false
	}
	m[hash] = exp
	return true
}

// releasePending forgets a pairing that is no longer pending.
func (g *Gateway) releasePending(tenant, hash string) {
	g.mu.Lock()
	if m := g.pending[tenant]; m != nil {
		delete(m, hash)
		if len(m) == 0 {
			delete(g.pending, tenant)
		}
	}
	g.mu.Unlock()
}

// failKey scopes decision failures to one end user of one tenant (§6.4).
func failKey(tenant, user string) string { return tenant + "\x00" + user }

// allowAttemptLocked reports whether the end user may make another pairing
// decision. Called with pairMu held, so the check and the failure that may
// follow are one atomic step: concurrent requests cannot all pass the check
// before any failure is recorded.
func (g *Gateway) allowAttemptLocked(key string) bool {
	cut := time.Now().Add(-time.Minute)
	keep := g.fail[key][:0]
	for _, t := range g.fail[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(g.fail, key)
	} else {
		g.fail[key] = keep
	}
	return len(keep) < FailuresPerMinute
}

func (g *Gateway) recordFailureLocked(key string) {
	g.fail[key] = append(g.fail[key], time.Now())
}

func (g *Gateway) issue(d store.Device, iss string) map[string]any {
	now := time.Now()
	c := lmbp.Claims{Iss: iss, Sub: d.ID, Aud: lmbp.TokenAudience(iss, d.TenantID), Tenant: d.TenantID, Iat: now.Unix(), Exp: now.Add(g.cfg.TokenTTL).Unix(),
		Jti: lmbp.RandomID("jti_"), Cnf: map[string]string{"jkt": lmbp.Thumbprint(d.PublicKey)}}
	return map[string]any{"access_token": lmbp.SignJWT(g.cfg.SigningKey, lmbp.TypAccessToken, g.kid, c), "token_type": "Bearer", "expires_in": int(g.cfg.TokenTTL.Seconds()),
		"device_id": d.ID, "gateway_key": lmbp.PublicJWK(g.pub), "issuer": iss}
}

func (g *Gateway) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, 405, "invalid_request")
		return
	}
	ps, err := params(r, 8192)
	// proof: proof JWT by the device key, aud "lmbp:token", ath = hash(device_code).
	req := struct{ GrantType, DeviceCode, Proof, Assertion string }{ps["grant_type"], ps["device_code"], ps["proof"], ps["assertion"]}
	if err != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	ctx := r.Context()
	switch req.GrantType {
	case deviceGrant:
		d, err := g.cfg.Store.DeviceAuthByCodeHash(ctx, sha(req.DeviceCode))
		if err != nil {
			oauthError(w, 400, "invalid_grant")
			return
		}
		pc, err := lmbp.VerifyProof(d.PublicKey, req.Proof, "", lmbp.ProofToken, req.DeviceCode, time.Now())
		if err != nil || g.jtis.Seen(pc.Jti) {
			oauthError(w, 400, "invalid_grant")
			return
		}
		// A code that can no longer yield a token answers without remembering
		// the proof's jti: polling a dead code costs the gateway nothing.
		if time.Now().After(d.ExpiresAt) {
			oauthError(w, 400, "expired_token")
			return
		}
		switch d.Status {
		case "denied":
			oauthError(w, 400, "access_denied")
			return
		case "consumed":
			oauthError(w, 400, "invalid_grant")
			return
		}
		if !g.jtis.Use(pc.Jti, time.Now().Add(3*time.Minute)) {
			oauthError(w, 400, "invalid_grant")
			return
		}
		if d.Status == "pending" {
			now := time.Now()
			slow := now.Sub(d.LastPoll) < time.Duration(d.Interval)*time.Second-200*time.Millisecond
			d.LastPoll = now
			if slow {
				d.Interval += 5
			}
			// §6.3: a device that keeps ignoring slow_down loses its code.
			dead := (d.Interval-initialInterval)/5 > MaxSlowDowns
			if dead {
				d.ExpiresAt = now
				g.releasePending(d.TenantID, d.DeviceCodeHash)
			}
			_ = g.cfg.Store.UpdateDeviceAuth(ctx, d)
			switch {
			case dead:
				oauthError(w, 400, "expired_token")
			case slow:
				oauthError(w, 400, "slow_down")
			default:
				oauthError(w, 400, "authorization_pending")
			}
			return
		}
		dev, err := g.cfg.Store.GetDevice(ctx, d.DeviceID)
		if err != nil {
			oauthError(w, 500, "server_error")
			return
		}
		d.Status = "consumed" // the device code is single-use
		if err := g.cfg.Store.UpdateDeviceAuth(ctx, d); err != nil {
			oauthError(w, 500, "server_error")
			return
		}
		writeJSON(w, 200, g.issue(dev, g.issuer(r)))
	case jwtBearerGrant:
		// Client assertion signed by the device key (RFC 7523 style). The device
		// private key is the long-lived credential; access tokens stay short.
		uc, err := lmbp.UnverifiedClaims(req.Assertion)
		if err != nil {
			oauthError(w, 400, "invalid_grant")
			return
		}
		dev, err := g.cfg.Store.GetDevice(ctx, uc.Sub)
		if err != nil || dev.Status != "active" {
			oauthError(w, 400, "invalid_grant")
			return
		}
		c, err := lmbp.VerifyJWT(dev.PublicKey, req.Assertion, lmbp.TypAssertion, lmbp.AssertionAudience(g.issuer(r)), time.Now())
		if err != nil || c.Iss != dev.ID || c.Exp-c.Iat > 300 || c.Jti == "" || !g.jtis.Use(c.Jti, time.Unix(c.Exp+60, 0)) {
			oauthError(w, 400, "invalid_grant")
			return
		}
		writeJSON(w, 200, g.issue(dev, g.issuer(r)))
	default:
		oauthError(w, 400, "unsupported_grant_type")
	}
}

// ---------- tenant device management ----------

// online returns the device's session if it is currently connected.
func (g *Gateway) online(id string) *dstate {
	g.mu.Lock()
	ds := g.devs[id]
	g.mu.Unlock()
	if ds == nil || !ds.connected() {
		return nil
	}
	return ds
}

func (g *Gateway) listDevices(w http.ResponseWriter, r *http.Request) {
	t, user, ok := g.tenantAuth(w, r)
	if !ok {
		return
	}
	ds, err := g.cfg.Store.ListDevices(r.Context(), t.ID, user)
	if err != nil {
		httpError(w, r, 500, lmbp.ErrInternal, "storage error")
		return
	}
	out := []map[string]any{}
	for _, d := range ds {
		item := map[string]any{"device_id": d.ID, "name": d.Name, "status": d.Status, "created_at": d.CreatedAt.UTC().Format(time.RFC3339), "online": false, "models": []string{},
			"public_key": lmbp.PublicJWK(d.PublicKey), "jkt": lmbp.Thumbprint(d.PublicKey)}
		if d.E2EEKey != "" {
			item["e2ee_key"] = d.E2EEKey
		}
		if s := g.online(d.ID); s != nil {
			item["online"], item["models"] = true, s.modelList()
			item["model_capabilities"], item["capabilities"], item["max_concurrency"] = s.modelCaps(), s.capabilities(), s.concurrency()
			if n := s.names(); len(n) > 0 {
				item["model_names"] = n
			}
		}
		out = append(out, item)
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

func (g *Gateway) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/lmbp/v1/tenant/devices/"), "/revoke")
	if !ok || r.Method != http.MethodPost {
		httpError(w, r, 404, lmbp.ErrBadRequest, "not found")
		return
	}
	t, user, ok := g.tenantAuth(w, r)
	if !ok {
		return
	}
	if err := g.RevokeDevice(r.Context(), t.ID, user, id); err != nil {
		if errors.Is(err, ErrDeviceUnknown) {
			httpError(w, r, 404, lmbp.ErrForbidden, "device not found")
		} else {
			httpError(w, r, 500, lmbp.ErrInternal, "storage error")
		}
		return
	}
	writeJSON(w, 200, map[string]string{"device_id": id, "status": "revoked"})
}

func absI(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func intersect(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if contains(b, x) && !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// RegisterTenant stores a tenant with the SHA-256 of its API key.
func (g *Gateway) RegisterTenant(ctx context.Context, id, name, apiKey string) error {
	if len(apiKey) < 32 {
		return errors.New("tenant API key must be at least 32 characters")
	}
	return g.RegisterTenantProfile(ctx, id, apiKey, store.TenantProfile{DisplayName: name})
}

// RegisterTenantProfile is RegisterTenant plus the SaaS identity published in
// the signed gateway metadata (shown on the desktop consent screen).
func (g *Gateway) RegisterTenantProfile(ctx context.Context, id, apiKey string, p store.TenantProfile) error {
	if !lmbp.TenantIDPattern.MatchString(id) {
		return errors.New("invalid tenant id")
	}
	if len(apiKey) < 32 {
		return errors.New("tenant API key must be at least 32 characters")
	}
	for _, sc := range p.RequestedScopes {
		if !contains(lmbp.Scopes, sc) {
			return errors.New("unknown scope " + sc)
		}
	}
	name := p.DisplayName
	if name == "" {
		name = id
	}
	return g.cfg.Store.PutTenant(ctx, store.Tenant{ID: id, Name: name, APIKeyHash: sha(apiKey), Profile: p})
}
