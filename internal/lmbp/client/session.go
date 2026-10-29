package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"

	"github.com/tyro668/avora/internal/lmbp"
)

type Config struct {
	Executor       Executor
	MaxConcurrency int // tasks this device runs in parallel (default 1)
	Client         string
	HTTP           *http.Client
	Logger         *log.Logger
	OnState        func(connected bool)
	// Flow is the receive window this device advertises (defaults
	// DefaultTaskWindow / DefaultConnWindow).
	Flow *lmbp.Flow
	// Capabilities overrides the advertised extensions (default: all).
	Capabilities []string
}

type Client struct {
	cfg Config
	// quit closes when Run stops for good; pending terminal frames that
	// still wait for flow credit give up only then.
	quit     chan struct{}
	quitOnce sync.Once
	runDone  <-chan struct{} // Done of the current Run ctx (under mu)
	id       Identity
	key      ed25519.PrivateKey
	gw       ed25519.PublicKey
	xpriv    []byte
	xpub     []byte

	mu    sync.Mutex
	tasks map[string]*ctask
	seen  map[string]time.Time // task nonces and E2EE request ids (replay)
	// started bounds the in-memory replay cache across restarts: task.run
	// frames and sealed requests issued before it (creation time minus
	// replaySkew, Unix seconds) are refused, so a restart cannot reopen the
	// replay window of anything a previous process may have accepted.
	started     int64
	out         *lmbp.Outbox  // device→gateway data frames
	in          *lmbp.Inbound // gateway→device data frames
	resumeToken string
	resumeUntil time.Time
	maxConc     int    // effective: min(want, gateway cap)
	wantConc    int    // what this device declares (SetMaxConcurrency)
	gwConc      int    // cap from the last welcome (0: none)
	live        bool   // welcome received on the current session
	liveGen     uint64 // bumped at every welcome: binds an announcement to its session
	liveConn    *websocket.Conn
	pendingAnn  bool       // ModelsChanged requested before the welcome
	annMu       sync.Mutex // serializes models.update build+send
	caps        []string
	resumes     int

	wmu  sync.Mutex
	conn *websocket.Conn
}

// ctask is one task on the device: received, collecting blobs, running or
// finished-but-unacknowledged (kept for retransmission on resume).
type ctask struct {
	id       string
	run      lmbp.TaskRun
	out      *lmbp.Outbox
	blobs    map[string]*bytes.Buffer
	started  bool
	finished bool
	// terminal is set once task.done / task.error is enqueued. Task state
	// is reclaimed only after that AND every frame up to it is acked; an
	// ACK of the last content chunk alone must not reclaim it (the
	// terminal frame would then be re-sent from seq 1 and be dropped).
	terminal bool
	cancel   context.CancelFunc
}

// replaySkew tolerates whole-second iat truncation and sub-second clock
// differences between this device and the gateway or SaaS.
const replaySkew = 2

func New(cfg Config, id Identity) (*Client, error) {
	k, g, err := id.keys()
	if err != nil {
		return nil, err
	}
	if cfg.Executor == nil {
		return nil, errors.New("executor required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = defaultHTTP()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	cfg.MaxConcurrency = clampConc(cfg.MaxConcurrency)
	if cfg.Client == "" {
		cfg.Client = "github.com/tyro668/avora/lmbp"
	}
	if cfg.Flow == nil {
		cfg.Flow = &lmbp.Flow{TaskWindow: lmbp.DefaultTaskWindow, ConnWindow: lmbp.DefaultConnWindow}
	}
	if cfg.Capabilities == nil {
		cfg.Capabilities = lmbp.Capabilities
	}
	c := &Client{quit: make(chan struct{}), cfg: cfg, id: id, key: k, gw: g, tasks: map[string]*ctask{}, seen: map[string]time.Time{}, started: time.Now().Unix() - replaySkew, out: lmbp.NewOutbox(), in: lmbp.NewInbound(cfg.Flow), maxConc: cfg.MaxConcurrency, wantConc: cfg.MaxConcurrency}
	if id.E2EEKey != "" {
		if x, err := lmbp.UnB64(id.E2EEKey); err == nil {
			if pub, err := lmbp.X25519Public(x); err == nil {
				c.xpriv, c.xpub = x, pub
			}
		}
	}
	return c, nil
}

func (c *Client) DeviceID() string { return c.id.DeviceID }

// E2EEPublicKey is the device's X25519 public key (nil if E2EE is disabled).
func (c *Client) E2EEPublicKey() []byte { return c.xpub }

// Running returns the number of executing tasks.
func (c *Client) Running() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.tasks {
		if !t.finished {
			n++
		}
	}
	return n
}

// Resumes counts sessions that were resumed after a reconnect.
func (c *Client) Resumes() int { c.mu.Lock(); defer c.mu.Unlock(); return c.resumes }

// Disconnect drops the current connection (used to exercise resume).
func (c *Client) Disconnect() {
	c.wmu.Lock()
	conn := c.conn
	c.wmu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// accessToken exchanges a device-key-signed assertion for a short-lived token.
func (c *Client) accessToken(ctx context.Context) (string, lmbp.Claims, error) {
	now := time.Now()
	a := lmbp.SignJWT(c.key, lmbp.TypAssertion, lmbp.Thumbprint(c.key.Public().(ed25519.PublicKey)), lmbp.Claims{Iss: c.id.DeviceID, Sub: c.id.DeviceID, Aud: lmbp.AssertionAudience(c.id.Issuer), Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(), Jti: lmbp.RandomID("a_")})
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	st, err := postForm(ctx, c.cfg.HTTP, c.id.GatewayURL+"/lmbp/v1/token", map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": a}, &tok)
	if err != nil || st != 200 {
		if tok.Error == "invalid_grant" {
			return "", lmbp.Claims{}, ErrRevoked
		}
		return "", lmbp.Claims{}, fmt.Errorf("token refresh failed: %v %s", err, tok.Error)
	}
	cl, err := verifyAccessToken(c.id, c.gw, c.key.Public().(ed25519.PublicKey), tok.AccessToken)
	return tok.AccessToken, cl, err
}

// ErrRevoked means the gateway no longer accepts this device; re-pairing is required.
var ErrRevoked = errors.New("device credential rejected (revoked or unknown); pair again")

// Run keeps one session alive with backoff until ctx ends or the device is
// revoked. The first reconnect is immediate so that resume can succeed.
func (c *Client) Run(ctx context.Context, ready chan<- error) error {
	defer c.quitOnce.Do(func() { close(c.quit) })
	c.mu.Lock()
	c.runDone = ctx.Done()
	c.mu.Unlock()
	backoff := 200 * time.Millisecond
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx, ready)
		c.setState(false)
		if ctx.Err() != nil {
			c.abortTasks()
			return ctx.Err()
		}
		if errors.Is(err, ErrRevoked) || errors.Is(err, ErrGatewayIdentity) {
			c.abortTasks()
			return err
		}
		c.cfg.Logger.Printf("lmbp: session ended: %v", err)
		if time.Since(start) > 30*time.Second {
			backoff = 200 * time.Millisecond
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	c.abortTasks()
	return ctx.Err()
}

func (c *Client) setState(v bool) {
	if c.cfg.OnState != nil {
		c.cfg.OnState(v)
	}
}

func (c *Client) writeRaw(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.conn == nil {
		return errors.New("not connected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, b)
}

// control writes a non-sequenced frame.
func (c *Client) control(e lmbp.Envelope) error {
	e.V = lmbp.Version
	b, _ := json.Marshal(e)
	return c.writeRaw(b)
}

// models and modelCaps are the last line of defence for the unique-items
// rule of hello/models.update (models, model_capabilities values): a repeat
// would make the gateway reject the whole announcement, so it is dropped here
// (first occurrence kept) whatever the executor reports.
func (c *Client) models() []string {
	m, _ := lmbp.Unique(c.cfg.Executor.Models())
	return m
}

func (c *Client) modelCaps() map[string][]string {
	r, ok := c.cfg.Executor.(CapabilityReporter)
	if !ok {
		return nil
	}
	in := r.ModelCapabilities()
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for m, caps := range in {
		out[m], _ = lmbp.Unique(caps)
	}
	return out
}

// modelNames returns the executor's display names shaped to the schema
// (1..128 code points, spec §16.1): the gateway rejects anything else, so
// labels are trimmed and shortened here, on the device that owns them.
func (c *Client) modelNames() map[string]string {
	r, ok := c.cfg.Executor.(NameReporter)
	if !ok {
		return nil
	}
	var out map[string]string
	for m, n := range r.ModelNames() {
		n = strings.TrimSpace(n)
		if rs := []rune(n); len(rs) > 128 {
			n = strings.TrimSpace(string(rs[:128]))
		}
		if n == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[m] = n
	}
	return out
}

func (c *Client) keyStatement() string {
	if c.xpriv == nil || !contains(c.cfg.Capabilities, lmbp.CapE2EE) {
		return ""
	}
	return lmbp.SignE2EEKey(c.key, c.id.DeviceID, c.xpub, time.Now())
}

// handshakeHook runs after hello is sent, before the welcome is read (tests).
var handshakeHook func()

// announceHook runs after a models.update is built, before it is sent (tests).
var announceHook func([]byte)

// clampConc keeps the device's own declaration inside the protocol range
// 1..16: the gateway rejects anything else (spec §7.4), so a local setting
// above 16 is announced as 16.
func clampConc(n int) int { return max(lmbp.MinConcurrency, min(n, lmbp.MaxConcurrency)) }

func (c *Client) declaredConc() int { c.mu.Lock(); defer c.mu.Unlock(); return c.wantConc }

// SetMaxConcurrency changes the declared parallel task limit at runtime. It
// takes effect locally at once, is announced on the live session
// (models.update.max_concurrency) and is used by every later hello.
func (c *Client) SetMaxConcurrency(n int) {
	n = clampConc(n)
	c.mu.Lock()
	c.wantConc, c.maxConc = n, n
	if c.gwConc > 0 && c.gwConc < n {
		c.maxConc = c.gwConc
	}
	c.mu.Unlock()
	c.ModelsChanged()
}

// abortTasks cancels every running task (permanent stop: revoked or Run's
// context ended). Transient session drops keep tasks for resume.
func (c *Client) abortTasks() {
	c.mu.Lock()
	var cs []context.CancelFunc
	for _, t := range c.tasks {
		if t.cancel != nil && !t.finished {
			cs = append(cs, t.cancel)
		}
	}
	c.mu.Unlock()
	for _, f := range cs {
		f()
	}
}

// OutboxUsage reports device→gateway frames and bytes not yet ACKed
// (diagnostics: a leak here means the gateway stopped acknowledging).
func (c *Client) OutboxUsage() (frames, bytes int) {
	c.mu.Lock()
	o := c.out
	c.mu.Unlock()
	return o.Usage()
}

// ModelsChanged re-announces the executor's models on the live session.
//
// Announcements are serialized (annMu): the config is read and sent under
// the same lock, so a later change can never be overtaken by an earlier,
// staler models.update.
func (c *Client) ModelsChanged() {
	c.annMu.Lock()
	defer c.annMu.Unlock()
	for {
		c.mu.Lock()
		live, gen, conn := c.live, c.liveGen, c.liveConn
		if !live {
			c.pendingAnn = true
		}
		c.mu.Unlock()
		if !live { // before the welcome: the handshake re-checks and resends
			return
		}
		b, _ := json.Marshal(lmbp.ModelsUpdate{Models: c.models(), ModelCapabilities: c.modelCaps(), ModelNames: c.modelNames(), MaxConcurrency: c.declaredConc(), E2EEKey: c.keyStatement()})
		if announceHook != nil {
			announceHook(b)
		}
		if n := frameLen(lmbp.TypeModelsUpdate, "", b); n > lmbp.MaxFrameBytes {
			// never publish a frame the gateway must close with 1009 (audit3 P2-1)
			c.cfg.Logger.Printf("lmbp: models.update not sent: %d bytes exceeds max_frame_bytes %d; reduce the model list", n, lmbp.MaxFrameBytes)
			return
		}
		// The update is bound to the session (generation) it was built for
		// and re-checked at write time: after a reconnect it would land on
		// the new connection, before its welcome or after a newer hello,
		// and overwrite that hello with stale data (audit3 P2-2).
		if c.writeOn(gen, conn, lmbp.Envelope{Type: lmbp.TypeModelsUpdate, Data: b}) {
			return
		}
	}
}

// frameLen is the encoded size of a control frame carrying data.
func frameLen(typ, id string, data []byte) int {
	b, _ := json.Marshal(lmbp.Envelope{V: lmbp.Version, Type: typ, ID: id, Data: data})
	return len(b)
}

// writeOn writes a control frame only while session gen on conn is still
// the live one; false means the session changed: the caller rebuilds (or,
// before the next welcome, leaves it to the handshake via pendingAnn).
func (c *Client) writeOn(gen uint64, conn *websocket.Conn, e lmbp.Envelope) bool {
	e.V = lmbp.Version
	b, _ := json.Marshal(e)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.mu.Lock()
	ok := c.live && c.liveGen == gen && c.liveConn == conn && c.conn == conn
	c.mu.Unlock()
	if !ok {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = conn.WriteMessage(websocket.TextMessage, b)
	return true
}

// resetLocked aborts all local task state (the gateway did not resume us).
func (c *Client) resetLocked() {
	for _, t := range c.tasks {
		if t.cancel != nil {
			t.cancel()
		}
	}
	c.tasks = map[string]*ctask{}
	c.out.Close()
	c.out = lmbp.NewOutbox()
	c.in = lmbp.NewInbound(c.cfg.Flow)
}

func (c *Client) session(ctx context.Context, ready chan<- error) error {
	tok, _, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	wsURL := "ws" + strings.TrimPrefix(c.id.GatewayURL, "http") + "/lmbp/v1/connect"
	d := websocket.Dialer{Subprotocols: []string{lmbp.Subprotocol}, HandshakeTimeout: 10 * time.Second}
	conn, resp, err := d.DialContext(ctx, wsURL, http.Header{"Authorization": {"Bearer " + tok}})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusBadRequest {
			return fmt.Errorf("gateway refused LMBP 2.0 (subprotocol %s): %w", lmbp.Subprotocol, err)
		}
		return err
	}
	defer conn.Close()
	if conn.Subprotocol() != lmbp.Subprotocol { // spec §7.1
		return fmt.Errorf("gateway selected subprotocol %q, want %q", conn.Subprotocol(), lmbp.Subprotocol)
	}
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	stop := context.AfterFunc(sctx, func() { conn.Close() })
	defer stop()
	conn.SetReadLimit(lmbp.MaxFrameBytes) // normative frame limit (spec §10)

	caps := append([]string(nil), c.cfg.Capabilities...)
	if c.xpriv == nil {
		caps = removeS(caps, lmbp.CapE2EE)
	}
	hello := lmbp.Hello{DeviceID: c.id.DeviceID, Client: c.cfg.Client, Models: c.models(), ModelCapabilities: c.modelCaps(), ModelNames: c.modelNames(), MaxConcurrency: c.declaredConc(),
		Capabilities: caps, E2EEKey: c.keyStatement(), Proof: lmbp.SignProof(c.key, c.id.DeviceID, lmbp.ProofHello, tok, time.Now())}
	if contains(caps, lmbp.CapFlow) {
		hello.Flow = c.cfg.Flow
	}
	c.mu.Lock()
	if contains(caps, lmbp.CapResume) && c.resumeToken != "" && time.Now().Before(c.resumeUntil) {
		hello.Resume = &lmbp.HelloResume{Token: c.resumeToken, Tasks: []lmbp.ResumeTask{}}
		for id := range c.tasks {
			hello.Resume.Tasks = append(hello.Resume.Tasks, lmbp.ResumeTask{TaskID: id, RecvSeq: c.in.Recv(id)})
		}
	}
	c.mu.Unlock()
	hb, _ := json.Marshal(hello)
	if n := frameLen(lmbp.TypeHello, "h1", hb); n > lmbp.MaxFrameBytes {
		return fmt.Errorf("hello is %d bytes, over max_frame_bytes %d: reduce the published model list (audit3 P2-1)", n, lmbp.MaxFrameBytes)
	}
	c.wmu.Lock()
	c.conn = conn
	c.wmu.Unlock()
	defer func() { c.wmu.Lock(); c.conn = nil; c.wmu.Unlock() }()
	if err := c.control(lmbp.Envelope{Type: lmbp.TypeHello, ID: "h1", Data: hb}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer func() { c.mu.Lock(); c.live = false; c.liveConn = nil; c.mu.Unlock() }()
	if handshakeHook != nil {
		handshakeHook()
	}
	var w lmbp.Envelope
	if err := conn.ReadJSON(&w); err != nil {
		return err
	}
	if w.Type != lmbp.TypeWelcome {
		return fmt.Errorf("handshake rejected: %s", w.Data)
	}
	if w.V != lmbp.Version {
		return fmt.Errorf("welcome has protocol version %d, want %d", w.V, lmbp.Version)
	}
	var welcome lmbp.Welcome
	_ = json.Unmarshal(w.Data, &welcome)

	c.mu.Lock()
	c.caps = welcome.Capabilities
	// The welcome answers the hello that was sent, which may already be
	// stale (SetMaxConcurrency during the handshake). Only a value below
	// what that hello declared is a real gateway cap; an equal value is an
	// echo and says nothing about the latest setting.
	c.gwConc = 0
	if welcome.MaxConcurrency > 0 && welcome.MaxConcurrency < hello.MaxConcurrency {
		c.gwConc = welcome.MaxConcurrency
	}
	c.maxConc = c.wantConc
	if c.gwConc > 0 && c.gwConc < c.maxConc {
		c.maxConc = c.gwConc
	}
	resendConc := c.wantConc != hello.MaxConcurrency || c.pendingAnn // hello was stale
	c.pendingAnn = false
	c.live = true
	c.liveGen++
	c.liveConn = conn
	var retransmit []lmbp.ResumeTask
	if hello.Resume != nil && welcome.Resume != nil && welcome.Resume.Resumed {
		keep := map[string]bool{}
		for _, rt := range welcome.Resume.Tasks {
			keep[rt.TaskID] = true
		}
		for id, t := range c.tasks {
			if !keep[id] { // gateway no longer knows it: abort
				if t.cancel != nil {
					t.cancel()
				}
				delete(c.tasks, id)
				c.out.Forget(id)
				c.in.Forget(id)
			}
		}
		c.in.ResetWindows()
		retransmit = welcome.Resume.Tasks
		c.resumes++
	} else {
		c.resetLocked()
	}
	c.resumeToken = welcome.ResumeToken
	resumeFor := time.Duration(welcome.ResumeSeconds) * time.Second
	out := c.out
	c.mu.Unlock()
	if contains(welcome.Capabilities, lmbp.CapFlow) {
		f := welcome.Flow
		if f == nil {
			f = &lmbp.Flow{TaskWindow: lmbp.DefaultTaskWindow, ConnWindow: lmbp.DefaultConnWindow}
		}
		out.SetFlow(f)
	} else {
		out.SetFlow(nil)
	}
	wgen := out.AttachOwned(c.writeRaw)
	defer func() {
		out.Detach(wgen)
		c.mu.Lock()
		c.resumeUntil = time.Now().Add(resumeFor)
		c.mu.Unlock()
	}()
	for _, rt := range retransmit {
		if err := out.Retransmit(rt.TaskID, rt.RecvSeq); err != nil {
			return err
		}
	}
	if len(retransmit) > 0 || hello.Resume != nil {
		c.cfg.Logger.Printf("lmbp: resumed session (%d task(s))", len(retransmit))
	} else {
		c.cfg.Logger.Printf("lmbp: connected as %s (caps=%v, concurrency=%d)", c.id.DeviceID, welcome.Capabilities, c.maxConc)
	}
	c.setState(true)
	if resendConc {
		c.ModelsChanged() // announce the setting changed during the handshake
	}
	if ready != nil {
		select {
		case ready <- nil:
		default:
		}
	}
	go c.refreshLoop(sctx, welcome.TokenExpiresAt)
	conn.SetPingHandler(func(m string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		c.wmu.Lock()
		defer c.wmu.Unlock()
		return conn.WriteControl(websocket.PongMessage, []byte(m), time.Now().Add(5*time.Second))
	})
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		mt, raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		if mt != websocket.TextMessage {
			continue
		}
		var e lmbp.Envelope
		if json.Unmarshal(raw, &e) != nil || e.V != lmbp.Version { // malformed or not 2.0: dropped (§7.4)
			continue
		}
		switch e.Type {
		case lmbp.TypeTaskRun, lmbp.TypeBlobChunk:
			c.mu.Lock()
			in := c.in
			c.mu.Unlock()
			switch in.Accept(e.TaskID, e.Seq, len(raw)) {
			case lmbp.Duplicate:
				c.ack(e.TaskID, in.Recv(e.TaskID))
				continue
			case lmbp.Gap:
				return fmt.Errorf("sequence gap on %s", e.TaskID) // reconnect + resume repairs it
			case lmbp.Overflow:
				b, _ := json.Marshal(lmbp.ErrorBody{Code: lmbp.ErrFlowControl, Message: "flow-control window exceeded"})
				_ = c.control(lmbp.Envelope{Type: lmbp.TypeError, Data: b})
				return errors.New("gateway exceeded flow-control window")
			}
			if e.Type == lmbp.TypeTaskRun {
				c.onRun(e)
			} else {
				c.onChunk(e)
			}
			c.ack(e.TaskID, e.Seq)
		case lmbp.TypeTaskAck:
			var a lmbp.TaskAck
			if json.Unmarshal(e.Data, &a) == nil {
				c.onAck(e.TaskID, a.Seq)
			}
		case lmbp.TypeTaskCancel:
			c.mu.Lock()
			t := c.tasks[e.TaskID]
			c.mu.Unlock()
			if t == nil {
				continue
			}
			if t.cancel != nil {
				t.cancel()
			} else if !t.finished { // still collecting blobs
				c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"})
			}
		case lmbp.TypePing:
			_ = c.control(lmbp.Envelope{Type: lmbp.TypePong, ID: e.ID})
		case lmbp.TypeSessionToken, lmbp.TypePong:
		case lmbp.TypeError:
			c.cfg.Logger.Printf("lmbp: gateway error: %s", e.Data)
		}
	}
}

func (c *Client) ack(taskID string, seq int64) {
	c.mu.Lock()
	in := c.in
	c.mu.Unlock()
	in.Acked(taskID, seq)
	b, _ := json.Marshal(lmbp.TaskAck{Seq: seq})
	_ = c.control(lmbp.Envelope{Type: lmbp.TypeTaskAck, TaskID: taskID, Data: b})
}

func (c *Client) onAck(taskID string, seq int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out.Ack(taskID, seq)
	c.reclaimLocked(taskID)
}

// reclaimLocked forgets a task whose terminal frame is enqueued and acked.
func (c *Client) reclaimLocked(taskID string) {
	if t := c.tasks[taskID]; t != nil && t.terminal {
		if n, _ := c.out.Unacked(taskID); n == 0 {
			delete(c.tasks, taskID)
			c.out.Forget(taskID)
			c.in.Forget(taskID)
		}
	}
}

// finishHook runs between marking a task finished and enqueuing its
// terminal frame (tests).
var finishHook atomic.Pointer[func(taskID string)]

// terminalCtxHook observes the context a terminal frame waits under (tests).
var terminalCtxHook atomic.Pointer[func(context.Context)]

// refreshLoop swaps in a new access token before the current one expires.
func (c *Client) refreshLoop(ctx context.Context, exp int64) {
	for {
		left := time.Until(time.Unix(exp, 0))
		wait := left - 60*time.Second
		if wait < left/2 {
			wait = left / 2
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		tok, claims, err := c.accessToken(ctx)
		if err != nil {
			c.cfg.Logger.Printf("lmbp: mid-session token refresh failed: %v", err)
			if errors.Is(err, ErrRevoked) || errors.Is(err, ErrGatewayIdentity) {
				return
			}
			exp = time.Now().Add(20 * time.Second).Unix() // retry soon; gateway grants a short grace
			continue
		}
		b, _ := json.Marshal(lmbp.SessionToken{AccessToken: tok, Proof: lmbp.SignProof(c.key, c.id.DeviceID, lmbp.ProofSessionToken, tok, time.Now())})
		if c.control(lmbp.Envelope{Type: lmbp.TypeSessionToken, ID: lmbp.RandomID("t_"), Data: b}) != nil {
			return
		}
		exp = claims.Exp
	}
}

// onRun enforces the local policy before any model call.
func (c *Client) onRun(e lmbp.Envelope) {
	c.mu.Lock()
	out := c.out
	if c.tasks[e.TaskID] != nil {
		c.mu.Unlock()
		return // at-most-once: never start a task twice
	}
	t := &ctask{id: e.TaskID, out: out}
	c.tasks[e.TaskID] = t
	c.mu.Unlock()
	run, err := lmbp.VerifyTaskRun(c.gw, e.TaskID, e.JWS)
	if err != nil {
		c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrBadSignature, Message: "task.run signature invalid"})
		return
	}
	if run.DeviceID != c.id.DeviceID || time.Now().Unix() > run.Exp {
		c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrBadRequest, Message: "task not for this device or expired"})
		return
	}
	if run.Iat < c.started {
		// Issued before this process: its nonce may have been used by a
		// previous run whose replay cache is gone (§12.4).
		c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrForbidden, Message: "task.run predates this device session (possible replay)"})
		return
	}
	allowed := contains(c.cfg.Executor.Models(), run.Model)
	c.mu.Lock()
	now := time.Now()
	for k, v := range c.seen {
		if now.After(v) {
			delete(c.seen, k)
		}
	}
	_, replay := c.seen["n:"+run.Nonce]
	running := 0
	for _, x := range c.tasks {
		if !x.finished && x != t {
			running++
		}
	}
	busy := running >= c.maxConc
	if allowed && !replay && !busy {
		c.seen["n:"+run.Nonce] = time.Unix(run.Exp+60, 0)
	}
	c.mu.Unlock()
	if !allowed || replay || busy {
		code := lmbp.ErrForbidden
		if allowed && !replay {
			code = lmbp.ErrDeviceBusy
		}
		c.finish(t, nil, &lmbp.ErrorBody{Code: code, Message: "rejected by local policy"})
		return
	}
	var total int64
	for _, b := range run.Blobs {
		total += b.Size
	}
	if total > lmbp.MaxTaskBlobBytes {
		c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrPayloadTooLarge, Message: "blobs exceed the task limit"})
		return
	}
	c.mu.Lock()
	t.run = run
	t.blobs = map[string]*bytes.Buffer{}
	for _, b := range run.Blobs {
		t.blobs[b.ID] = &bytes.Buffer{}
	}
	c.mu.Unlock()
	c.maybeStart(t)
}

// onChunk appends a blob.chunk to its blob (offsets MUST be contiguous).
func (c *Client) onChunk(e lmbp.Envelope) {
	var ch lmbp.BlobChunk
	c.mu.Lock()
	t := c.tasks[e.TaskID]
	c.mu.Unlock()
	if t == nil || t.finished || t.started || json.Unmarshal(e.Data, &ch) != nil {
		return
	}
	data, err := lmbp.UnB64(ch.Data)
	c.mu.Lock()
	buf := t.blobs[ch.BlobID]
	var ref lmbp.BlobRef
	for _, r := range t.run.Blobs {
		if r.ID == ch.BlobID {
			ref = r
		}
	}
	bad := buf == nil || err != nil || int64(buf.Len()) != ch.Offset || int64(buf.Len()+len(data)) > ref.Size
	if !bad {
		buf.Write(data)
	}
	c.mu.Unlock()
	if bad {
		c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrBadRequest, Message: "malformed blob.chunk"})
		return
	}
	c.maybeStart(t)
}

// maybeStart runs the task once every blob is complete and verified.
func (c *Client) maybeStart(t *ctask) {
	c.mu.Lock()
	if t.started || t.finished {
		c.mu.Unlock()
		return
	}
	blobs := map[string][]byte{}
	for _, r := range t.run.Blobs {
		b := t.blobs[r.ID]
		if int64(b.Len()) < r.Size {
			c.mu.Unlock()
			return
		}
		blobs[r.ID] = b.Bytes()
	}
	t.started = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.cancel = cancel
	run := t.run
	c.mu.Unlock()
	for _, r := range run.Blobs {
		h := sha256.Sum256(blobs[r.ID])
		if lmbp.B64(h[:]) != r.SHA256 {
			c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrBadRequest, Message: "blob digest mismatch"})
			return
		}
	}
	var sealer *sealer
	if run.E2EE != nil {
		var fail *lmbp.ErrorBody
		run, sealer, fail = c.openE2EE(run, blobs)
		if fail != nil {
			c.finish(t, nil, fail)
			return
		}
	} else if err := resolveBlobs(&run, blobs); err != nil {
		c.finish(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrBadRequest, Message: err.Error()})
		return
	}
	go func() {
		defer cancel()
		var tooLarge bool
		var emit func(d lmbp.TaskDelta) error
		emit = func(d lmbp.TaskDelta) error {
			_, err := t.out.SendFunc(ctx, t.id, func(seq int64) lmbp.Envelope {
				wire := d
				if sealer != nil {
					wire = lmbp.TaskDelta{E2EE: sealer.seal(lmbp.TypeTaskDelta, seq, d)}
				}
				b, _ := json.Marshal(wire)
				return lmbp.Envelope{Type: lmbp.TypeTaskDelta, Data: b}
			})
			if errors.Is(err, lmbp.ErrFrameTooLarge) {
				// Review7 #13: the encoded frame (after sealing) is over the
				// limit: split it; an unsplittable piece fails the task.
				parts, ok := splitDelta(d)
				if !ok {
					tooLarge = true
					cancel()
					return err
				}
				for _, p := range parts {
					if err := emit(p); err != nil {
						return err
					}
				}
				return nil
			}
			return err
		}
		done, fail := c.cfg.Executor.Execute(ctx, run, emit)
		if tooLarge {
			done, fail = nil, &lmbp.ErrorBody{Code: lmbp.ErrInternal, Message: "model output frame exceeds max_frame_bytes and cannot be split"}
		}
		if fail == nil && ctx.Err() != nil {
			fail = &lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"}
		}
		if fail == nil && done == nil {
			done = &lmbp.TaskDone{FinishReason: "stop"}
		}
		c.finishSealed(t, done, fail, sealer)
	}()
}

func (c *Client) finish(t *ctask, done *lmbp.TaskDone, fail *lmbp.ErrorBody) {
	c.finishSealed(t, done, fail, nil)
}

// finishSealed sends the terminal data frame. In E2EE mode task.done keeps
// finish_reason and usage in cleartext (for accounting) and additionally
// carries the sealed finish_reason; task.error is always cleartext and
// generic.
func (c *Client) finishSealed(t *ctask, done *lmbp.TaskDone, fail *lmbp.ErrorBody, s *sealer) {
	c.mu.Lock()
	if t.finished {
		c.mu.Unlock()
		return
	}
	t.finished = true
	runDone := c.runDone
	c.mu.Unlock()
	// Callers include the WS read loop (immediate rejects, cancels during
	// blob collection). Waiting for credit there would deadlock: the ACKs
	// that free credit are read by that same loop. So the credit wait and
	// the send run on their own goroutine; only "finished" is synchronous.
	go c.sendTerminal(t, done, fail, s, runDone)
}

func (c *Client) sendTerminal(t *ctask, done *lmbp.TaskDone, fail *lmbp.ErrorBody, s *sealer, runDone <-chan struct{}) {
	if h := finishHook.Load(); h != nil {
		(*h)(t.id)
	}
	// The terminal frame waits for flow credit as long as the client runs
	// (no deadline: giving up would leave the task finished locally with
	// no terminal result on either side). It is dropped only on a
	// permanent stop, or when a non-resumed reconnect resets the outbox,
	// in which case the gateway has discarded the task too.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // react to Run's ctx directly, not to Run returning
		select {
		case <-runDone: // nil before any Run: never fires
			cancel()
		case <-c.quit:
			cancel()
		case <-ctx.Done():
		}
	}()
	if h := terminalCtxHook.Load(); h != nil {
		(*h)(ctx)
	}
	_, serr := t.out.SendFunc(ctx, t.id, func(seq int64) lmbp.Envelope {
		if fail != nil {
			b, _ := json.Marshal(fail)
			return lmbp.Envelope{Type: lmbp.TypeTaskError, Data: b}
		}
		d := *done
		if s != nil {
			d.E2EE = s.seal(lmbp.TypeTaskDone, seq, map[string]string{"finish_reason": d.FinishReason})
		}
		b, _ := json.Marshal(d)
		return lmbp.Envelope{Type: lmbp.TypeTaskDone, Data: b}
	})
	if errors.Is(serr, lmbp.ErrFrameTooLarge) && (fail == nil || fail.Code != lmbp.ErrInternal || fail.Message != oversizeTerminal) {
		// never enqueue an oversized terminal: replace it with a small error
		c.sendTerminal(t, nil, &lmbp.ErrorBody{Code: lmbp.ErrInternal, Message: oversizeTerminal}, nil, runDone)
		return
	}
	if serr != nil {
		return // not queued: kept for resume
	}
	// The terminal frame is queued: from now on (also if its ACK already
	// arrived) the task can be reclaimed.
	c.mu.Lock()
	t.terminal = true
	if c.tasks[t.id] == t {
		c.reclaimLocked(t.id)
	}
	c.mu.Unlock()
}

const oversizeTerminal = "terminal frame exceeds max_frame_bytes"

// splitDelta halves a delta: text and tool calls go to separate deltas,
// several tool calls to one each, a long text or arguments string into two
// rune-safe halves (the continuation keeps only the tool-call index, as in
// OpenAI streaming). ok=false when nothing can be split further.
func splitDelta(d lmbp.TaskDelta) ([]lmbp.TaskDelta, bool) {
	switch {
	case d.Text != "" && len(d.ToolCalls) > 0:
		return []lmbp.TaskDelta{{Text: d.Text}, {ToolCalls: d.ToolCalls}}, true
	case len(d.ToolCalls) > 1:
		out := make([]lmbp.TaskDelta, len(d.ToolCalls))
		for i, tc := range d.ToolCalls {
			out[i] = lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{tc}}
		}
		return out, true
	case len(d.ToolCalls) == 1:
		tc := d.ToolCalls[0]
		a, b, ok := halve(tc.Function.Arguments)
		if !ok || tc.Index == nil {
			return nil, false
		}
		first := tc
		first.Function.Arguments = a
		rest := lmbp.ToolCall{Index: tc.Index, Function: lmbp.FunctionCall{Arguments: b}}
		return []lmbp.TaskDelta{{ToolCalls: []lmbp.ToolCall{first}}, {ToolCalls: []lmbp.ToolCall{rest}}}, true
	default:
		a, b, ok := halve(d.Text)
		if !ok {
			return nil, false
		}
		return []lmbp.TaskDelta{{Text: a}, {Text: b}}, true
	}
}

func halve(s string) (string, string, bool) {
	if len(s) < 2 {
		return "", "", false
	}
	i := len(s) / 2
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	if i == 0 {
		return "", "", false
	}
	return s[:i], s[i:], true
}

type sealer struct {
	rid string
	key []byte
}

func (s *sealer) seal(typ string, seq int64, v any) string {
	pt, _ := json.Marshal(v)
	return lmbp.SealChunk(s.key, s.rid, typ, seq, pt)
}

// openE2EE decrypts the sealed request and checks freshness, replay and that
// the cleartext routing (model) matches the sealed request.
func (c *Client) openE2EE(run lmbp.TaskRun, blobs map[string][]byte) (lmbp.TaskRun, *sealer, *lmbp.ErrorBody) {
	bad := func(msg string) (lmbp.TaskRun, *sealer, *lmbp.ErrorBody) {
		return run, nil, &lmbp.ErrorBody{Code: lmbp.ErrDecrypt, Message: msg}
	}
	if c.xpriv == nil {
		return bad("device has no e2ee key")
	}
	var ref *lmbp.BlobRef
	for i := range run.Blobs {
		if run.Blobs[i].ID == run.E2EE.Blob {
			ref = &run.Blobs[i]
		}
	}
	if ref == nil || ref.MediaType != lmbp.E2EEMediaType {
		return bad("sealed request blob missing")
	}
	hdr, pt, err := lmbp.OpenJWE(c.xpriv, string(blobs[ref.ID]))
	if err != nil || hdr.Cty != lmbp.CtyE2EERequest || hdr.Kid != lmbp.X25519Thumbprint(c.xpub) {
		return bad("cannot decrypt request")
	}
	var req lmbp.E2EERequest
	if json.Unmarshal(pt, &req) != nil || req.RID == "" {
		return bad("malformed sealed request")
	}
	now := time.Now().Unix()
	if now-req.Iat > lmbp.E2EEMaxAge || req.Iat > now+60 {
		return bad("sealed request is stale")
	}
	if req.Iat < c.started {
		return bad("sealed request predates this device session (possible replay)")
	}
	key, err := lmbp.UnB64(req.ResponseKey)
	if err != nil || len(key) != 32 {
		return bad("bad response key")
	}
	if req.Model != run.Model {
		return bad("sealed model does not match routed model")
	}
	c.mu.Lock()
	_, replay := c.seen["r:"+req.RID]
	c.seen["r:"+req.RID] = time.Unix(req.Iat+lmbp.E2EEMaxAge+60, 0)
	c.mu.Unlock()
	if replay {
		return bad("sealed request replayed")
	}
	run.Messages, run.Tools, run.ToolChoice, run.MaxTokens, run.Temperature = req.Messages, req.Tools, req.ToolChoice, req.MaxTokens, req.Temperature
	run.TopP, run.Stop = req.TopP, req.Stop
	run.Blobs, run.E2EE, run.Sealed = nil, nil, true
	return run, &sealer{rid: req.RID, key: key}, nil
}

// resolveBlobs swaps lmbp-blob: references for inline data.
func resolveBlobs(run *lmbp.TaskRun, blobs map[string][]byte) error {
	mt := map[string]string{}
	for _, r := range run.Blobs {
		mt[r.ID] = r.MediaType
	}
	for i := range run.Messages {
		for j := range run.Messages[i].Content.Parts {
			p := &run.Messages[i].Content.Parts[j]
			if p.ImageURL != nil && strings.HasPrefix(p.ImageURL.URL, lmbp.BlobScheme) {
				id := strings.TrimPrefix(p.ImageURL.URL, lmbp.BlobScheme)
				b, ok := blobs[id]
				if !ok {
					return errors.New("unknown blob " + id)
				}
				p.ImageURL.URL = "data:" + mt[id] + ";base64," + base64.StdEncoding.EncodeToString(b)
			}
			if p.InputAudio != nil && strings.HasPrefix(p.InputAudio.Data, lmbp.BlobScheme) {
				id := strings.TrimPrefix(p.InputAudio.Data, lmbp.BlobScheme)
				b, ok := blobs[id]
				if !ok {
					return errors.New("unknown blob " + id)
				}
				p.InputAudio.Data = base64.StdEncoding.EncodeToString(b)
			}
		}
	}
	run.Blobs = nil
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func removeS(xs []string, x string) []string {
	out := xs[:0:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
