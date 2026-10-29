// Package conformance is a language-agnostic black-box test suite for lmbp
// gateways. It plays the device (connector) and the tenant back end against
// any gateway URL and reports which normative requirements hold. Run it via
// cmd/lmbp-conformance.
package conformance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tyro668/avora/internal/lmbp"
)

type Config struct {
	GatewayURL string // http(s)://host[:port]
	Issuer     string // expected issuer origin; default: origin of GatewayURL
	Tenant     string
	TenantKey  string
	EndUser    string
	SchemaDir  string // spec/schemas; empty disables frame validation
	Timeout    time.Duration
	// Retention is the gateway's configured retention period. When > 0 the
	// suite checks that finished tasks and their idempotency records are
	// purged after it (E6); 0 skips that check.
	Retention time.Duration
	Log       io.Writer
}

type Result struct {
	ID      string `json:"id"`
	Req     string `json:"requirement"` // §13.2 requirement ID
	Profile string `json:"profile"`
	Title   string `json:"title"`
	Pass    bool   `json:"pass"`
	Skip    bool   `json:"skip,omitempty"` // not applicable to this run (Pass is true)
	Detail  string `json:"detail,omitempty"`
}

// skip records a check that does not apply to this run (for example E6
// without -retention). It never fails the suite.
func (r *runner) skip(id, title, why string) {
	rq, _ := RequirementOf(id)
	r.results = append(r.results, Result{ID: id, Req: rq.ID, Profile: rq.Profile, Title: title, Pass: true, Skip: true, Detail: why})
	if r.cfg.Log != nil {
		fmt.Fprintf(r.cfg.Log, "SKIP  %-6s %s (%s)\n", id, title, why)
	}
}

type runner struct {
	cfg     Config
	hc      *http.Client
	results []Result
	schema  *jsonschema.Schema
	payload *jsonschema.Schema
	meta    *jsonschema.Schema
	gwKey   ed25519.PublicKey
	devKey  ed25519.PrivateKey
	devID   string
	issuer  string
	runSeq  int64 // envelope seq of the last task.run read by awaitRun
	// profiles the gateway declares in its metadata (§13.1). Checks of an
	// undeclared profile are reported as skipped, never as failures.
	profiles []string
}

// declares reports whether the gateway declared profile p (core always).
func (r *runner) declares(p string) bool {
	return p == lmbp.ProfileCore || containsS(r.profiles, p)
}

// skipUndeclared records the given checks as skipped when profile p is not
// declared; it returns true if the caller should run them.
func (r *runner) runs(p string, ids ...string) bool {
	if r.declares(p) {
		return true
	}
	for _, id := range ids {
		r.skip(id, "(not run)", "profile "+p+" not declared")
	}
	return false
}

var errStop = errors.New("prerequisite failed")

func (r *runner) check(id, title string, err error) bool {
	rq, _ := RequirementOf(id)
	if rq.Profile != "" && !r.declares(rq.Profile) {
		r.skip(id, title, "profile "+rq.Profile+" not declared")
		return err == nil
	}
	res := Result{ID: id, Req: rq.ID, Profile: rq.Profile, Title: title, Pass: err == nil}
	if err != nil {
		res.Detail = err.Error()
	}
	r.results = append(r.results, res)
	if r.cfg.Log != nil {
		mark := "PASS"
		if !res.Pass {
			mark = "FAIL"
		}
		fmt.Fprintf(r.cfg.Log, "%s  %-6s %s %s\n", mark, id, title, res.Detail)
	}
	return res.Pass
}

// Run executes the suite; it never panics on a misbehaving gateway.
func Run(ctx context.Context, cfg Config) []Result {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.EndUser == "" {
		cfg.EndUser = "conformance-user"
	}
	cfg.GatewayURL = strings.TrimRight(cfg.GatewayURL, "/")
	r := &runner{cfg: cfg, hc: &http.Client{Timeout: cfg.Timeout}}
	if cfg.SchemaDir != "" {
		var err error
		r.schema, r.payload, r.meta, err = loadSchemas(cfg.SchemaDir)
		if !r.check("S0", "spec/schemas compile (JSON Schema 2020-12)", err) {
			return r.results
		}
	}
	_ = r.run(ctx)
	// F0/F1 are recorded on every offending frame; a clean run records one pass each.
	seen := map[string]bool{}
	for _, x := range r.results {
		seen[x.ID] = true
	}
	if !seen["F0"] {
		r.check("F0", "gateway sends only text frames", nil)
	}
	if !seen["F1"] && r.schema != nil {
		r.check("F1", "every gateway frame matches envelope.json", nil)
	}
	// No early exit may hide a check: every catalogued check that did not
	// run fails (core or declared profile) or is skipped (undeclared profile).
	for _, x := range r.results {
		seen[x.ID] = true
	}
	for _, rq := range Catalog {
		for _, c := range rq.Checks {
			if seen[c] || (c == "S0" && r.schema == nil) || (c == "F1" && r.schema == nil) || ((c == "M6" || c == "M7") && r.meta == nil) {
				continue
			}
			r.check(c, "(not run)", errors.New("not run: an earlier step failed"))
		}
	}
	return r.results
}

func loadSchemas(dir string) (*jsonschema.Schema, *jsonschema.Schema, *jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".json" {
			continue // schemas.go embeds the directory
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, nil, nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, nil, nil, err
		}
		if err := c.AddResource("https://avora.dev/spec/lmbp/"+e.Name(), doc); err != nil {
			return nil, nil, nil, err
		}
	}
	env, err := c.Compile("https://avora.dev/spec/lmbp/envelope.json")
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := c.Compile("https://avora.dev/spec/lmbp/task.run.payload.json")
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := c.Compile("https://avora.dev/spec/lmbp/gateway-metadata.json")
	return env, p, m, err
}

func (r *runner) validate(s *jsonschema.Schema, raw []byte) error {
	if s == nil {
		return nil
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

func (r *runner) form(path string, f url.Values) (int, map[string]any, http.Header, error) {
	req, _ := http.NewRequest(http.MethodPost, r.cfg.GatewayURL+path, strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r.do(req)
}

func (r *runner) tenant(method, path string, body any) (int, map[string]any, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.cfg.GatewayURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+r.cfg.TenantKey)
	req.Header.Set("X-End-User", r.cfg.EndUser)
	req.Header.Set("Content-Type", "application/json")
	return r.do(req)
}

func (r *runner) do(req *http.Request) (int, map[string]any, http.Header, error) {
	resp, err := r.hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	var m map[string]any
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m, resp.Header, nil
}

func want(cond bool, f string, a ...any) error {
	if cond {
		return nil
	}
	return fmt.Errorf(f, a...)
}

var userCodeRe = regexp.MustCompile(`^[B-DF-HJ-NP-TV-XZ]{4}-[B-DF-HJ-NP-TV-XZ]{4}$`)

func (r *runner) run(ctx context.Context) error {
	// --- discovery
	st, jwks, h, err := r.tenant(http.MethodGet, "/.well-known/jwks.json", nil)
	var jwkX string
	if err == nil && st == 200 {
		if ks, _ := jwks["keys"].([]any); len(ks) > 0 {
			k, _ := ks[0].(map[string]any)
			if k["kty"] == "OKP" && k["crv"] == "Ed25519" {
				jwkX, _ = k["x"].(string)
			}
		}
	}
	_ = h
	r.check("D1", "GET /.well-known/jwks.json returns an OKP/Ed25519 JWK Set", want(err == nil && jwkX != "", "status %d err %v", st, err))
	if err := r.metadata(); err != nil {
		return err
	}

	// --- pairing (RFC 8628)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	r.devKey = key
	st, auth, h, err := r.form("/lmbp/v1/device/authorize", url.Values{"tenant": {r.cfg.Tenant}, "public_key": {lmbp.B64(pub)}, "device_name": {"lmbp-conformance"}})
	dc, _ := auth["device_code"].(string)
	uc, _ := auth["user_code"].(string)
	interval, _ := auth["interval"].(float64)
	if !r.check("P1", "device authorization (form-encoded) returns device_code/user_code/expires_in/interval",
		want(err == nil && st == 200 && dc != "" && uc != "" && auth["expires_in"] != nil && interval >= 1, "status %d body %v err %v", st, auth, err)) {
		return errStop
	}
	r.check("P2", "user_code matches XXXX-XXXX over BCDFGHJKLMNPQRSTVWXZ", want(userCodeRe.MatchString(uc), "got %q", uc))
	r.check("P3", "device authorization response has Cache-Control: no-store", want(strings.Contains(h.Get("Cache-Control"), "no-store"), "got %q", h.Get("Cache-Control")))
	r.runV2Pairing()
	r.runHardenPairing(uc)
	tok := func(proof string) (int, map[string]any) {
		st, m, _, _ := r.form("/lmbp/v1/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc}, "proof": {proof}})
		return st, m
	}
	proof := func() string { return lmbp.SignProof(key, "", lmbp.ProofToken, dc, time.Now()) }
	_, m := tok(proof())
	r.check("P4", "polling before approval yields authorization_pending or slow_down", want(m["error"] == "authorization_pending" || m["error"] == "slow_down", "got %v", m))
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	_, m = tok(lmbp.SignProof(other, "", lmbp.ProofToken, dc, time.Now()))
	r.check("P5", "token request with a proof from a different key is rejected (invalid_grant)", want(m["error"] == "invalid_grant", "got %v", m))
	st, _, _, _ = r.tenant(http.MethodPost, "/lmbp/v1/tenant/devices/approvals", map[string]any{"user_code": "BBBB-BBBB"})
	r.check("P6", "approving an unknown user_code fails with 404", want(st == 404, "status %d", st))
	st, _, _, _ = r.tenant(http.MethodPost, "/lmbp/v1/tenant/devices/approvals", map[string]any{"user_code": uc, "jkt": lmbp.Thumbprint(other.Public().(ed25519.PublicKey))})
	r.check("P8", "approval carrying a jkt that does not match the device key is refused with 409 (E2EE pin, §17.2)", want(st == 409, "status %d", st))
	st, ap, _, err := r.tenant(http.MethodPost, "/lmbp/v1/tenant/devices/approvals", map[string]any{"user_code": strings.ToLower(strings.ReplaceAll(uc, "-", "")), "jkt": lmbp.Thumbprint(pub)})
	if !r.check("P7", "tenant back end approves the code (case/separator-insensitive, matching jkt)", want(err == nil && st == 200 && ap["status"] == "approved" && ap["jkt"] == lmbp.Thumbprint(pub), "status %d body %v", st, ap)) {
		return errStop
	}
	var tr map[string]any
	deadline := time.Now().Add(r.cfg.Timeout + time.Duration(interval)*time.Second*3)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval)*time.Second + 100*time.Millisecond)
		var s int
		s, tr = tok(proof())
		if s == 200 {
			break
		}
		if tr["error"] == "slow_down" {
			interval += 5
		} else if tr["error"] != "authorization_pending" {
			break
		}
	}
	at, _ := tr["access_token"].(string)
	r.devID, _ = tr["device_id"].(string)
	gk, _ := tr["gateway_key"].(map[string]any)
	x, _ := gk["x"].(string)
	gb, _ := lmbp.UnB64(x)
	r.gwKey = gb
	if !r.check("T1", "device_code grant returns access_token, token_type Bearer, device_id, gateway_key JWK", want(at != "" && tr["token_type"] == "Bearer" && r.devID != "" && len(gb) == 32, "body %v", tr)) {
		return errStop
	}
	r.check("T2", "gateway_key equals the JWKS key", want(jwkX == "" || jwkX == x, "jwks %s token %s", jwkX, x))
	claims, err := lmbp.VerifyJWT(r.gwKey, at, lmbp.TypAccessToken, lmbp.TokenAudience(r.issuer, r.cfg.Tenant), time.Now())
	r.check("T3", "access token is an EdDSA JWT with typ at+jwt signed by gateway_key, aud = <issuer>/tenants/<tenant> (§18.3)", err)
	r.check("I1", "access token iss = gateway issuer origin and tenant claim = tenant (§18.3)",
		want(claims.Iss == r.issuer && claims.Tenant == r.cfg.Tenant, "iss %q tenant %q", claims.Iss, claims.Tenant))
	r.check("I2", "token response issuer equals the metadata issuer", want(tr["issuer"] == r.issuer, "got %v", tr["issuer"]))
	r.check("T4", "access token sub = device_id and cnf.jkt = RFC 7638 thumbprint of the device key",
		want(claims.Sub == r.devID && claims.Cnf["jkt"] == lmbp.Thumbprint(pub), "sub %q jkt %q", claims.Sub, claims.Cnf["jkt"]))
	_, m = tok(proof())
	r.check("T5", "device_code is single-use", want(m["error"] == "invalid_grant", "got %v", m))
	assertion := func() string {
		now := time.Now()
		return lmbp.SignJWT(key, lmbp.TypAssertion, lmbp.Thumbprint(pub), lmbp.Claims{Iss: r.devID, Sub: r.devID, Aud: lmbp.AssertionAudience(r.issuer), Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(), Jti: lmbp.RandomID("a_")})
	}
	a1 := assertion()
	refresh := func(a string) (int, map[string]any) {
		st, m, _, _ := r.form("/lmbp/v1/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a}})
		return st, m
	}
	now := time.Now()
	foreign := lmbp.SignJWT(key, lmbp.TypAssertion, lmbp.Thumbprint(pub), lmbp.Claims{Iss: r.devID, Sub: r.devID, Aud: "https://other-gateway.invalid/lmbp/v1/token", Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(), Jti: lmbp.RandomID("a_")})
	r.auditAssertions(key, refresh)
	st, m = refresh(foreign)
	r.check("I3", "assertion whose aud is not this gateway's token endpoint is rejected (invalid_grant)", want(m["error"] == "invalid_grant", "status %d %v", st, m))
	st, m = refresh(a1)
	r.check("T6", "jwt-bearer grant with a device-signed assertion issues a new token", want(st == 200 && m["access_token"] != nil, "status %d %v", st, m))
	_, m = refresh(a1)
	r.check("T7", "replayed assertion (same jti) is rejected", want(m["error"] == "invalid_grant", "got %v", m))

	// --- WebSocket
	wsURL := "ws" + strings.TrimPrefix(r.cfg.GatewayURL, "http") + "/lmbp/v1/connect"
	_, resp, err := (&websocket.Dialer{HandshakeTimeout: r.cfg.Timeout}).Dial(wsURL, http.Header{"Authorization": {"Bearer " + at}})
	r.check("W1", "upgrade without subprotocol lmbp is refused", want(err != nil && resp != nil && resp.StatusCode >= 400, "connected or no HTTP error"))
	d := websocket.Dialer{Subprotocols: []string{lmbp.Subprotocol}, HandshakeTimeout: r.cfg.Timeout}
	_, resp, err = d.Dial(wsURL, http.Header{"Authorization": {"Bearer " + at + "x"}})
	r.check("W2", "upgrade with an invalid access token is refused with 401", want(err != nil && resp != nil && resp.StatusCode == 401, "resp %v", status(resp)))
	conn, resp, err := d.Dial(wsURL, http.Header{"Authorization": {"Bearer " + at}})
	if err == nil {
		_ = r.writeFrame(conn, "hello", "h1", "", lmbp.Hello{DeviceID: r.devID, Client: "lmbp-conformance", Models: []string{"m"}, MaxConcurrency: 1,
			Proof: lmbp.SignProof(key, r.devID, lmbp.ProofHello, "some-other-token", time.Now())})
		f, _ := r.readFrame(conn)
		r.check("W3", "hello whose proof is bound to another token is rejected (error/close, no welcome)", want(f.Type != lmbp.TypeWelcome, "got welcome"))
		conn.Close()
		r.auditHelloProofs(key, at)
		r.runV2Handshake(key, at)
	} else {
		r.check("W3", "hello whose proof is bound to another token is rejected", fmt.Errorf("could not connect: %v %s", err, status(resp)))
	}
	conn, resp, err = d.Dial(wsURL, http.Header{"Authorization": {"Bearer " + at}})
	if !r.check("W4", "upgrade with valid token selects subprotocol lmbp", want(err == nil && conn.Subprotocol() == lmbp.Subprotocol, "err %v %s", err, status(resp))) {
		return errStop
	}
	defer conn.Close()
	model := "conformance-model"
	_ = r.writeFrame(conn, "hello", "h1", "", lmbp.Hello{DeviceID: r.devID, Client: "lmbp-conformance", Models: []string{model}, MaxConcurrency: 2,
		Capabilities: []string{"session.token", "models.update", "x-unknown-cap"}, Proof: lmbp.SignProof(key, r.devID, lmbp.ProofHello, at, time.Now())})
	f, err := r.readFrame(conn)
	var wel lmbp.Welcome
	_ = json.Unmarshal(f.Data, &wel)
	if !r.check("W5", "valid hello is answered by welcome with the same id", want(err == nil && f.Type == lmbp.TypeWelcome && f.ID == "h1" && wel.SessionID != "", "frame %+v err %v", f, err)) {
		return errStop
	}
	r.check("W6", "welcome.capabilities ⊆ offered capabilities (unknown ones dropped)", want(!containsS(wel.Capabilities, "x-unknown-cap"), "got %v", wel.Capabilities))
	_ = r.writeFrame(conn, "x.vendor.unknown", "u1", "", map[string]any{"a": 1})
	_ = r.writeFrame(conn, "ping", "p1", "", nil)
	var gotPong bool
	for i := 0; i < 3 && !gotPong; i++ {
		f, err = r.readFrame(conn)
		gotPong = err == nil && f.Type == lmbp.TypePong && f.ID == "p1"
	}
	r.check("W7", "unknown message type does not kill the session; ping is answered by pong with same id", want(gotPong, "last frame %+v err %v", f, err))
	r.runV2Session(conn, wel, 2)

	// models visible through the OpenAI surface
	st, ml, _, _ := r.tenant(http.MethodGet, "/v1/models", nil)
	full := r.devID + "/" + model
	found := false
	if data, _ := ml["data"].([]any); data != nil {
		for _, it := range data {
			if mm, _ := it.(map[string]any); mm["id"] == full {
				found = true
			}
		}
	}
	r.check("O1", "GET /v1/models lists <device_id>/<model> for the owner", want(st == 200 && found, "status %d %v", st, ml))
	r.runV2Headers()

	// streaming task
	frames := make(chan lmbp.Envelope, 64)
	go func() {
		defer close(frames)
		for {
			f, err := r.readFrame(conn)
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	sse := make(chan []string, 1)
	go func() { sse <- r.chat(ctx, full, true) }()
	run, err := r.awaitRun(frames)
	r.check("R1", "task.run arrives with no data member and a jws whose typ is lmbp-task+jws", err)
	r.check("R3", "task.run is a data frame with envelope seq 1 even without flow/resume (§7.2)", want(err == nil && r.runSeq == 1, "seq %d", r.runSeq))
	if err == nil {
		r.check("R2", "task.run JWS verifies with gateway_key; payload task_id/device_id/model/exp are correct",
			want(run.DeviceID == r.devID && run.Model == model && run.Exp > time.Now().Unix() && len(run.Nonce) >= 16, "payload %+v", run))
		for i, t := range []string{"Hel", "lo"} {
			_ = r.writeFrame(conn, "task.delta", "", run.TaskID, lmbp.TaskDelta{Text: t}, int64(i+1))
		}
		_ = r.writeFrame(conn, "task.done", "", run.TaskID, lmbp.TaskDone{FinishReason: "stop", Usage: &lmbp.Usage{PromptTokens: 1, CompletionTokens: 2}}, 3)
		lines := <-sse
		joined := strings.Join(lines, "\n")
		r.check("O2", "SSE stream relays deltas as chat.completion.chunk and ends with data: [DONE]",
			want(strings.Contains(joined, `"content":"Hel"`) && strings.Contains(joined, `"content":"lo"`) && len(lines) > 0 && lines[len(lines)-1] == "data: [DONE]", "got %q", joined))
		r.check("S4", "without flow or resume, device data frames are acknowledged with a cumulative task.ack up to the terminal frame (ACK is Core, §8.6, §14.1)",
			r.awaitAck(frames, run.TaskID, 3))
	}
	r.checkCoreGap(ctx, conn, frames, full)
	r.checkCoreBadTerminal(ctx, conn, frames, full)
	r.checkOutputCap(ctx, conn, frames, full)
	// cancellation
	cctx, ccancel := context.WithCancel(ctx)
	go func() { r.chat(cctx, full, true) }()
	run2, err := r.awaitRun(frames)
	if err == nil {
		_ = r.writeFrame(conn, "task.delta", "", run2.TaskID, lmbp.TaskDelta{Text: "x"}, 1)
		time.Sleep(200 * time.Millisecond)
		ccancel()
		got := false
		tm := time.After(r.cfg.Timeout)
	wait:
		for {
			select {
			case f, ok := <-frames:
				if !ok {
					break wait
				}
				if f.Type == lmbp.TypeTaskCancel && f.TaskID == run2.TaskID {
					got = true
					break wait
				}
			case <-tm:
				break wait
			}
		}
		r.check("C1", "client disconnect mid-stream produces task.cancel for that task_id", want(got, "no task.cancel"))
	} else {
		ccancel()
		r.check("C1", "client disconnect mid-stream produces task.cancel", err)
	}
	// session.token
	st, m = refresh(assertion())
	newTok, _ := m["access_token"].(string)
	_ = r.writeFrame(conn, "session.token", "t1", "", lmbp.SessionToken{AccessToken: newTok, Proof: lmbp.SignProof(key, r.devID, lmbp.ProofSessionToken, newTok, time.Now())})
	got := false
	tm := time.After(r.cfg.Timeout)
loop:
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				break loop
			}
			var stt lmbp.SessionToken
			_ = json.Unmarshal(f.Data, &stt)
			if f.Type == lmbp.TypeSessionToken && f.ID == "t1" && stt.ExpiresAt > 0 {
				got = true
				break loop
			}
		case <-tm:
			break loop
		}
	}
	r.check("K1", "session.token with a fresh token + proof is acknowledged with token_expires_at", want(st == 200 && got, "no acknowledgement"))
	// negotiated extensions on a fresh connection (§14–§17)
	if newTok != "" {
		at = newTok
	}
	conn.Close()
	for range frames {
	}
	conn2, frames2 := r.runExt(ctx, key, at)
	extOK := conn2 != nil
	if conn2 == nil { // an extension step failed: the Core checks below still run on a plain session
		h := lmbp.Hello{DeviceID: r.devID, Client: "lmbp-conformance", Models: []string{model}, MaxConcurrency: 1, Capabilities: lmbp.CoreCapabilities,
			Proof: lmbp.SignProof(key, r.devID, lmbp.ProofHello, at, time.Now())}
		d, _, err := r.dialExt(at, h)
		if err != nil {
			r.check("V1", "revoking the device closes its live session", fmt.Errorf("could not open a session: %v", err))
			return errStop
		}
		conn2, frames2 = d.conn, d.frames
	}
	defer conn2.Close()
	frames = frames2
	// V3: a task is in flight when the device is revoked
	vModel := model
	if extOK {
		vModel = "conf-plain"
	}
	type vres struct {
		st   int
		body []byte
	}
	// The previous session's close may still be in flight at the gateway: wait until the model
	// of this session is listed before starting the task.
	for until := time.Now().Add(r.cfg.Timeout); time.Now().Before(until); time.Sleep(50 * time.Millisecond) {
		if _, ml, _, _ := r.tenant(http.MethodGet, "/v1/models", nil); listsModel(ml, r.devID+"/"+vModel) {
			break
		}
	}
	inflight := make(chan vres, 1)
	go func() {
		s, _, b := r.chatRaw(ctx, map[string]any{"model": r.devID + "/" + vModel, "messages": []any{map[string]any{"role": "user", "content": "revoked mid-task"}}}, nil)
		inflight <- vres{s, b}
	}()
	gotRun := false
	tm = time.After(r.cfg.Timeout)
vwait:
	for !gotRun {
		select {
		case f, ok := <-frames:
			if !ok {
				break vwait
			}
			gotRun = f.Type == lmbp.TypeTaskRun
		case <-tm:
			break vwait
		}
	}
	// revoke
	st, _, _, _ = r.tenant(http.MethodPost, "/lmbp/v1/tenant/devices/"+url.PathEscape(r.devID)+"/revoke", nil)
	closed := false
	tm = time.After(r.cfg.Timeout)
	for !closed {
		select {
		case _, ok := <-frames:
			closed = !ok
		case <-tm:
			goto done
		}
	}
done:
	r.check("V1", "revoking the device closes its live session", want(st == 200 && closed, "status %d closed %v", st, closed))
	var vr vres
	select {
	case vr = <-inflight:
	case <-time.After(r.cfg.Timeout):
	}
	r.check("V3", "revoking a device while its task.run is in flight ends the caller's request with 502 OUTCOME_UNKNOWN, never 401 (§6.4, §7.5)",
		want(gotRun && vr.st == 502 && errCode(vr.body) == lmbp.ErrOutcomeUnknown, "task.run seen %v, status %d body %s", gotRun, vr.st, vr.body))
	st, m = refresh(assertion())
	r.check("V2", "revoked device cannot obtain new tokens", want(m["error"] == "invalid_grant", "status %d %v", st, m))
	return nil
}

// awaitAck waits for a task.ack of taskID covering seq (other frames are dropped).
func (r *runner) awaitAck(frames <-chan lmbp.Envelope, taskID string, seq int64) error {
	tm := time.After(r.cfg.Timeout)
	var best int64
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return errors.New("session closed")
			}
			if f.Type == lmbp.TypeTaskAck && f.TaskID == taskID {
				var a lmbp.TaskAck
				_ = json.Unmarshal(f.Data, &a)
				if a.Seq > best {
					best = a.Seq
				}
				if best >= seq {
					return nil
				}
			}
		case <-tm:
			return fmt.Errorf("no task.ack covering seq %d (highest %d)", seq, best)
		}
	}
}

// checkCoreGap (S5, §8.6 R3): without flow or resume, a device data frame
// that skips a seq fails the task: no silent loss, task.cancel(protocol_error).
func (r *runner) checkCoreGap(ctx context.Context, conn *websocket.Conn, frames <-chan lmbp.Envelope, model string) {
	const title = "without flow or resume, a device data frame that skips a seq fails the task and is answered by task.cancel(protocol_error) (§8.6 R3)"
	sse := make(chan []string, 1)
	go func() { sse <- r.chat(ctx, model, true) }()
	run, err := r.awaitRun(frames)
	if err != nil {
		r.check("S5", title, err)
		<-sse
		return
	}
	_ = r.writeFrame(conn, "task.delta", "", run.TaskID, lmbp.TaskDelta{Text: "skipped one"}, 2)
	reason := ""
	tm := time.After(r.cfg.Timeout)
wait:
	for reason == "" {
		select {
		case f, ok := <-frames:
			if !ok {
				break wait
			}
			if f.Type == lmbp.TypeTaskCancel && f.TaskID == run.TaskID {
				var c lmbp.TaskCancel
				_ = json.Unmarshal(f.Data, &c)
				reason = c.Reason
			}
		case <-tm:
			break wait
		}
	}
	// the device ends the task as it would after any cancel
	_ = r.writeFrame(conn, "task.error", "", run.TaskID, lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"}, 3)
	body := strings.Join(<-sse, "\n")
	r.check("S5", title, want(reason == "protocol_error" && !strings.Contains(body, "skipped one") && strings.Contains(body, `"error"`), "cancel reason %q body %q", reason, body))
}

// checkCoreBadTerminal (S6, §8.6): a terminal frame whose body does not match
// task.done.json (here {}) is rejected before its seq is accepted: the task
// fails with task.cancel(protocol_error); it is never reported as a success.
func (r *runner) checkCoreBadTerminal(ctx context.Context, conn *websocket.Conn, frames <-chan lmbp.Envelope, model string) {
	const title = "a task.done whose body does not match task.done.json ({}) is not accepted: the task fails with task.cancel(protocol_error), never finish_reason stop (§8.6, §7.3)"
	sse := make(chan []string, 1)
	go func() { sse <- r.chat(ctx, model, true) }()
	run, err := r.awaitRun(frames)
	if err != nil {
		r.check("S6", title, err)
		<-sse
		return
	}
	_ = r.writeFrame(conn, "task.delta", "", run.TaskID, lmbp.TaskDelta{Text: "almost"}, 1)
	_ = r.writeFrame(conn, "task.done", "", run.TaskID, json.RawMessage(`{}`), 2)
	reason := ""
	tm := time.After(r.cfg.Timeout)
wait:
	for reason == "" {
		select {
		case f, ok := <-frames:
			if !ok {
				break wait
			}
			if f.Type == lmbp.TypeTaskCancel && f.TaskID == run.TaskID {
				var c lmbp.TaskCancel
				_ = json.Unmarshal(f.Data, &c)
				reason = c.Reason
			}
		case <-tm:
			break wait
		}
	}
	// the device ends the task as it would after any cancel
	_ = r.writeFrame(conn, "task.error", "", run.TaskID, lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"}, 2)
	body := strings.Join(<-sse, "\n")
	r.check("S6", title, want(reason == "protocol_error" && !strings.Contains(body, `"finish_reason":"stop"`) && strings.Contains(body, `"error"`), "cancel reason %q body %q", reason, body))
}

func (r *runner) awaitRun(frames <-chan lmbp.Envelope) (lmbp.TaskRun, error) {
	tm := time.After(r.cfg.Timeout)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return lmbp.TaskRun{}, errors.New("session closed")
			}
			if f.Type != lmbp.TypeTaskRun {
				continue
			}
			r.runSeq = f.Seq
			if len(f.Data) > 0 {
				return lmbp.TaskRun{}, errors.New("task.run carries data")
			}
			parts := strings.Split(f.JWS, ".")
			if len(parts) == 3 {
				if p, err := lmbp.UnB64(parts[1]); err == nil {
					if err := r.validate(r.payload, p); err != nil {
						return lmbp.TaskRun{}, fmt.Errorf("payload schema: %v", err)
					}
				}
			}
			return lmbp.VerifyTaskRun(r.gwKey, f.TaskID, f.JWS)
		case <-tm:
			return lmbp.TaskRun{}, errors.New("timeout waiting for task.run")
		}
	}
}

func (r *runner) chat(ctx context.Context, model string, stream bool) []string {
	b, _ := json.Marshal(map[string]any{"model": model, "stream": stream, "messages": []map[string]string{{"role": "user", "content": "hi"}}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.GatewayURL+"/v1/chat/completions", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+r.cfg.TenantKey)
	req.Header.Set("X-End-User", r.cfg.EndUser)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var lines []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "data: ") {
			lines = append(lines, l)
		}
	}
	return lines
}

func (r *runner) writeFrame(c *websocket.Conn, typ, id, taskID string, data any, seq ...int64) error {
	e := lmbp.Envelope{V: lmbp.Version, Type: typ, ID: id, TaskID: taskID}
	if len(seq) > 0 {
		e.Seq = seq[0]
	}
	if data != nil {
		e.Data, _ = json.Marshal(data)
	}
	_ = c.SetWriteDeadline(time.Now().Add(r.cfg.Timeout))
	return c.WriteJSON(e)
}

// readFrame reads one text frame and validates it against the envelope schema.
func (r *runner) readFrame(c *websocket.Conn) (lmbp.Envelope, error) {
	e, _, err := r.readFrameRaw(c)
	return e, err
}

// readFrameRaw is readFrame that also reports the frame's encoded size,
// which is what flow-control windows count.
func (r *runner) readFrameRaw(c *websocket.Conn) (lmbp.Envelope, int, error) {
	var e lmbp.Envelope
	_ = c.SetReadDeadline(time.Now().Add(r.cfg.Timeout + 30*time.Second))
	mt, b, err := c.ReadMessage()
	if err != nil {
		return e, 0, err
	}
	if mt != websocket.TextMessage {
		r.check("F0", "gateway sends only text frames", errors.New("binary frame"))
	}
	if err := r.validate(r.schema, b); err != nil {
		r.check("F1", "gateway frame matches envelope.json", fmt.Errorf("%s: %v", b, err))
	}
	return e, len(b), json.Unmarshal(b, &e)
}

func status(r *http.Response) string {
	if r == nil {
		return "no response"
	}
	return r.Status
}

func containsS(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// metadata checks §18 gateway metadata and §19 signed tenant metadata.
func (r *runner) metadata() error {
	iss := r.cfg.Issuer
	if iss == "" {
		iss = r.cfg.GatewayURL
	}
	o, err := lmbp.Origin(iss)
	if err != nil {
		o = strings.TrimRight(iss, "/")
	}
	r.issuer = o
	var base lmbp.GatewayMetadata
	st, m, _, err := r.tenant(http.MethodGet, lmbp.MetadataPath, nil)
	b, _ := json.Marshal(m)
	_ = json.Unmarshal(b, &base)
	if !r.check("M1", "GET /.well-known/lmbp returns metadata whose issuer is the gateway origin", want(err == nil && st == 200 && base.Issuer == r.issuer, "status %d issuer %q want %q", st, base.Issuer, r.issuer)) {
		return errStop
	}
	ok := true
	for _, u := range []string{base.JWKSURI, base.DeviceAuthorizationEndpoint, base.TokenEndpoint, base.ConnectEndpoint} {
		ok = ok && lmbp.SameOrigin(u, r.issuer)
	}
	r.check("M2", "jwks_uri, device_authorization_endpoint, token_endpoint and connect_endpoint are on the issuer origin", want(ok && len(base.ProtocolVersions) > 0, "%+v", base))
	r.profiles = base.Profiles
	profOK := containsS(base.Profiles, lmbp.ProfileCore)
	for _, p := range base.Profiles {
		profOK = profOK && containsS(lmbp.Profiles, p)
	}
	r.check("M8", "metadata protocol_versions lists 2.0 and not 1.0; profiles lists core and only registered profiles (§11, §13)",
		want(containsS(base.ProtocolVersions, "2.0") && !containsS(base.ProtocolVersions, "1.0") && profOK, "protocol_versions %v profiles %v", base.ProtocolVersions, base.Profiles))
	r.checkForgedHost()
	st, _, _, _ = r.tenant(http.MethodGet, lmbp.MetadataPath+"?tenant=no-such-tenant-"+lmbp.RandomID(""), nil)
	if r.meta != nil {
		r.check("M6", "gateway metadata validates against spec/schemas/gateway-metadata.json", r.validate(r.meta, b))
	}
	r.check("M3", "metadata for an unknown tenant is 404", want(st == 404, "status %d", st))
	st, m, _, err = r.tenant(http.MethodGet, lmbp.MetadataPath+"?tenant="+url.QueryEscape(r.cfg.Tenant), nil)
	var tm lmbp.GatewayMetadata
	b, _ = json.Marshal(m)
	_ = json.Unmarshal(b, &tm)
	if r.meta != nil {
		r.check("M7", "tenant metadata validates against spec/schemas/gateway-metadata.json", r.validate(r.meta, b))
	}
	_, jwks, _, _ := r.tenant(http.MethodGet, "/.well-known/jwks.json", nil)
	var verr error = errors.New("no JWKS key verifies signed_metadata")
	var sm lmbp.GatewayMetadata
	if ks, _ := jwks["keys"].([]any); err == nil && st == 200 {
		for _, k := range ks {
			km, _ := k.(map[string]any)
			xs, _ := km["x"].(string)
			x, _ := lmbp.UnB64(xs)
			if sm, verr = lmbp.VerifyMetadata(x, tm.SignedMetadata, r.issuer, r.cfg.Tenant, time.Now()); verr == nil {
				break
			}
		}
	}
	r.check("M4", "tenant metadata carries signed_metadata (typ lmbp-metadata+jwt) verifiable with a JWKS key and bound to issuer, tenant and audience (§19.1)", verr)
	if verr == nil {
		badScope := ""
		for _, sc := range sm.RequestedScopes {
			if !containsS(lmbp.Scopes, sc) {
				badScope = sc
			}
		}
		r.check("M5", "signed SaaS identity has name, requested_scopes from the registry, exp-iat <= 24h", want(sm.SaaS.Name != "" && len(sm.RequestedScopes) > 0 && badScope == "", "saas %+v scopes %v", sm.SaaS, sm.RequestedScopes))
	}
	return nil
}

// checkOutputCap (Z9, §10): a task whose device output exceeds 64 MiB fails:
// task.cancel(protocol_error) to the device and an error to the caller.
func (r *runner) checkOutputCap(ctx context.Context, conn *websocket.Conn, frames <-chan lmbp.Envelope, model string) {
	const title = "device output beyond the per-task budget (64 MiB of task.delta) fails the task: task.cancel(protocol_error), caller gets 502 INTERNAL (§10)"
	type res struct {
		st   int
		body []byte
	}
	out := make(chan res, 1)
	go func() {
		s, _, b := r.chatRaw(ctx, map[string]any{"model": model, "messages": []any{map[string]any{"role": "user", "content": "flood"}}}, nil)
		out <- res{s, b}
	}()
	run, err := r.awaitRun(frames)
	if err != nil {
		r.check("Z9", title, err)
		<-out
		return
	}
	chunk := strings.Repeat("a", 200<<10)
	limit := int64(lmbp.MaxTaskOutputBytes/len(chunk) + 8)
	var stop atomic.Bool
	var sent atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for seq := int64(1); seq <= limit && !stop.Load(); seq++ {
			if r.writeFrame(conn, "task.delta", "", run.TaskID, lmbp.TaskDelta{Text: chunk}, seq) != nil {
				return
			}
			sent.Store(seq)
		}
	}()
	reason := ""
	tm := time.After(r.cfg.Timeout + 60*time.Second)
wait:
	for reason == "" {
		select {
		case f, ok := <-frames:
			if !ok {
				break wait
			}
			if f.Type == lmbp.TypeTaskCancel && f.TaskID == run.TaskID {
				var c lmbp.TaskCancel
				_ = json.Unmarshal(f.Data, &c)
				reason = c.Reason
			}
		case <-tm:
			break wait
		}
	}
	stop.Store(true)
	<-done
	_ = r.writeFrame(conn, "task.error", "", run.TaskID, lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"}, sent.Load()+1)
	rs := res{}
	select {
	case rs = <-out:
	case <-time.After(r.cfg.Timeout):
	}
	_ = r.awaitAck(frames, run.TaskID, sent.Load()+1)
	r.check("Z9", title, want(reason == "protocol_error" && rs.st == 502 && errCode(rs.body) == lmbp.ErrInternal, "cancel %q after %d frames, status %d body %.200s", reason, sent.Load(), rs.st, rs.body))
}

// listsModel reports whether a /v1/models response lists the model id.
func listsModel(ml map[string]any, id string) bool {
	data, _ := ml["data"].([]any)
	for _, it := range data {
		if mm, _ := it.(map[string]any); mm["id"] == id {
			return true
		}
	}
	return false
}
