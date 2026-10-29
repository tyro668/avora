package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/client"
	"github.com/tyro668/avora/internal/lmbp/store"
)

// fakeExec is a deterministic executor:
//   - "echo": echoes the last user text and describes image inputs;
//   - "tool": calls get_weather unless the last message is a tool result;
//   - "slow": streams slowN numbered chunks with a small delay.
type fakeExec struct {
	execs   sync.Map // task_id → *atomic.Int32
	runs    sync.Map // task_id → lmbp.TaskRun as received
	emitted atomic.Int64
	slowN   int
	delay   time.Duration
}

func (f *fakeExec) Models() []string {
	return []string{"echo", "tool", "slow", "textonly", "temp", "badidx", "huge"}
}
func (f *fakeExec) ModelCapabilities() map[string][]string {
	// "textonly" declares that it honours no request parameter (like the
	// Codex adapter); "temp" honours only temperature (fourth audit A2).
	return map[string][]string{"echo": {"vision", "audio", "tools"}, "tool": {"tools"}, "slow": {},
		"textonly": {"params"}, "temp": {"params", "temperature"}}
}

func slowChunk(i int) string { return fmt.Sprintf("[%04d]%s", i, strings.Repeat("x", 200)) }

func (f *fakeExec) count(taskID string) int32 {
	if n, ok := f.execs.Load(taskID); ok {
		return n.(*atomic.Int32).Load()
	}
	return 0
}

func (f *fakeExec) Execute(ctx context.Context, run lmbp.TaskRun, emit func(lmbp.TaskDelta) error) (*lmbp.TaskDone, *lmbp.ErrorBody) {
	f.runs.Store(run.TaskID, run)
	n, _ := f.execs.LoadOrStore(run.TaskID, &atomic.Int32{})
	n.(*atomic.Int32).Add(1)
	send := func(d lmbp.TaskDelta) *lmbp.ErrorBody {
		if err := emit(d); err != nil {
			return &lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"}
		}
		f.emitted.Add(1)
		return nil
	}
	last := run.Messages[len(run.Messages)-1]
	switch run.Model {
	case "echo", "textonly", "temp":
		for _, p := range last.Content.Parts {
			if p.ImageURL != nil {
				u := p.ImageURL.URL
				mt := u[5:strings.IndexByte(u, ';')]
				raw, _ := base64.StdEncoding.DecodeString(u[strings.IndexByte(u, ',')+1:])
				if e := send(lmbp.TaskDelta{Text: fmt.Sprintf("image:%s:%d;", mt, len(raw))}); e != nil {
					return nil, e
				}
			}
		}
		for _, w := range strings.SplitAfter(last.Content.PlainText(), " ") {
			if e := send(lmbp.TaskDelta{Text: w}); e != nil {
				return nil, e
			}
		}
		return &lmbp.TaskDone{FinishReason: "stop", Usage: &lmbp.Usage{PromptTokens: 3, CompletionTokens: 4}}, nil
	case "huge": // review7 #13: deltas far over max_frame_bytes
		switch last.Content.PlainText() {
		case "text":
			if e := send(lmbp.TaskDelta{Text: hugeText}); e != nil {
				return nil, e
			}
			return &lmbp.TaskDone{FinishReason: "stop"}, nil
		case "args":
			i0, i1 := 0, 1
			if e := send(lmbp.TaskDelta{Text: "calling", ToolCalls: []lmbp.ToolCall{
				{Index: &i0, ID: "a", Type: "function", Function: lmbp.FunctionCall{Name: "f", Arguments: hugeArgs("a")}},
				{Index: &i1, ID: "b", Type: "function", Function: lmbp.FunctionCall{Name: "g", Arguments: hugeArgs("b")}}}}); e != nil {
				return nil, e
			}
			return &lmbp.TaskDone{FinishReason: "tool_calls"}, nil
		default: // unsplittable: tool call without an index
			if e := send(lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{ID: "c", Type: "function", Function: lmbp.FunctionCall{Name: "f", Arguments: hugeArgs("c")}}}}); e != nil {
				return nil, e
			}
			return &lmbp.TaskDone{FinishReason: "tool_calls"}, nil
		}
	case "badidx": // tool-call index taken from the prompt (review7 #4)
		idx, _ := strconv.Atoi(last.Content.PlainText())
		if e := send(lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{Index: &idx, ID: "c", Type: "function", Function: lmbp.FunctionCall{Name: "f", Arguments: "{}"}}}}); e != nil {
			return nil, e
		}
		return &lmbp.TaskDone{FinishReason: "tool_calls"}, nil
	case "tool":
		if last.Role == "tool" {
			if e := send(lmbp.TaskDelta{Text: "It is " + last.Content.PlainText()}); e != nil {
				return nil, e
			}
			return &lmbp.TaskDone{FinishReason: "stop"}, nil
		}
		zero := 0
		if e := send(lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{Index: &zero, ID: "call_1", Type: "function", Function: lmbp.FunctionCall{Name: "get_weather", Arguments: `{"city":`}}}}); e != nil {
			return nil, e
		}
		if e := send(lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{Index: &zero, Function: lmbp.FunctionCall{Arguments: `"Paris"}`}}}}); e != nil {
			return nil, e
		}
		return &lmbp.TaskDone{FinishReason: "tool_calls"}, nil
	case "slow":
		for i := 0; i < f.slowN; i++ {
			if e := send(lmbp.TaskDelta{Text: slowChunk(i)}); e != nil {
				return nil, e
			}
			select {
			case <-ctx.Done():
				return nil, &lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"}
			case <-time.After(f.delay):
			}
		}
		return &lmbp.TaskDone{FinishReason: "stop"}, nil
	}
	return nil, &lmbp.ErrorBody{Code: lmbp.ErrModelNotFound, Message: "no model"}
}

type rig struct {
	g      *Gateway
	srv    *httptest.Server
	dev    *client.Client
	exec   *fakeExec
	devID  string
	jkt    string
	dbPath string
	logs   *syncBuf
	id     client.Identity    // the paired device identity (raw-hello tests)
	stop   context.CancelFunc // stops the rig's device client
	done   chan struct{}      // closed when the device client's Run returns
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

const tenantKey = "tk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newRig(t *testing.T, flow lmbp.Flow, slowN int, delay time.Duration) *rig {
	t.Helper()
	return newRigWith(t, flow, slowN, delay, nil)
}

// newRigWith wraps the gateway's store (e.g. to inject write failures).
func newRigWith(t *testing.T, flow lmbp.Flow, slowN int, delay time.Duration, wrap func(store.Store) store.Store) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{exec: &fakeExec{slowN: slowN, delay: delay}, dbPath: filepath.Join(dir, "gw.db"), logs: &syncBuf{}}
	st, err := store.OpenSQLite(r.dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New(r.logs, "", 0)
	var gst store.Store = st
	if wrap != nil {
		gst = wrap(st)
	}
	r.g, _ = New(Config{Store: gst, Logger: logger, Flow: flow, AttachGrace: 5 * time.Second, PingInterval: time.Second})
	_ = r.g.RegisterTenant(context.Background(), "acme", "Acme", tenantKey)
	mux := http.NewServeMux()
	mux.Handle("/", r.g.Handler())
	var base string
	mux.HandleFunc("/.well-known/avora", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(client.Discovery{GatewayURL: base, Tenant: "acme", LinkURL: base + "/link", Protocol: "lmbp"})
	})
	r.srv = httptest.NewServer(mux)
	base = r.srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); r.srv.CloseClientConnections(); r.srv.Close(); st.Close() })

	p, err := client.StartPairing(ctx, nil, base, "test-pc")
	if err != nil {
		t.Fatal(err)
	}
	r.jkt = p.JKT
	if !strings.Contains(p.LinkURL, "jkt="+p.JKT) {
		t.Fatalf("link url lacks jkt: %s", p.LinkURL)
	}
	// §12.6: pending pairings are never listed, not even to their tenant.
	if code, dl := r.api(t, "GET", "/lmbp/v1/tenant/devices", nil, nil); code != 200 || dl["pending_pairings"] != nil || len(dl["devices"].([]any)) != 0 {
		t.Fatalf("device list before approval: %d %v", code, dl)
	}
	if code, _ := r.api(t, "POST", "/lmbp/v1/tenant/devices/approvals", map[string]string{"user_code": p.UserCode, "jkt": "wrong"}, nil); code != 409 {
		t.Fatalf("approval with wrong jkt: %d", code)
	}
	if code, m := r.api(t, "POST", "/lmbp/v1/tenant/devices/approvals", map[string]string{"user_code": p.UserCode, "jkt": p.JKT}, nil); code != 200 {
		t.Fatalf("approve: %d %v", code, m)
	}
	if code, dl := r.api(t, "GET", "/lmbp/v1/tenant/devices", nil, nil); code != 200 || dl["pending_pairings"] != nil || len(dl["devices"].([]any)) != 1 {
		t.Fatalf("device list after approval: %d %v", code, dl)
	}
	id, err := p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.devID, r.id = id.DeviceID, id
	r.dev, err = client.New(client.Config{Executor: r.exec, MaxConcurrency: 4, Logger: logger}, id)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	dctx, dcancel := context.WithCancel(ctx)
	r.stop, r.done = dcancel, make(chan struct{})
	go func() { defer close(r.done); _ = r.dev.Run(dctx, ready) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("device did not connect")
	}
	// The device sees the welcome a moment before the gateway marks the
	// session routable; wait for that so tests never race the handshake.
	for i := 0; ; i++ {
		_, dl := r.api(t, "GET", "/lmbp/v1/tenant/devices", nil, nil)
		if ds, _ := dl["devices"].([]any); len(ds) > 0 {
			if d, _ := ds[0].(map[string]any); d["online"] == true {
				break
			}
		}
		if i > 250 {
			t.Fatal("gateway never reported the device online")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return r
}

var httpc = &http.Client{Timeout: 30 * time.Second}

func (r *rig) req(method, path string, body any, hdr map[string]string) *http.Request {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+tenantKey)
	req.Header.Set("X-End-User", "alice")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func doReq(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (r *rig) api(t *testing.T, method, path string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	resp := doReq(t, r.req(method, path, body, hdr))
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (r *rig) model(m string) string { return r.devID + "/" + m }

type sse struct {
	id   string
	data string
}

// readSSE parses events until [DONE], EOF, or stop returns true.
func readSSE(body io.Reader, stop func(sse) bool) []sse {
	var out []sse
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	var cur sse
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "id: "):
			cur.id = l[4:]
		case strings.HasPrefix(l, "data: "):
			cur.data = l[6:]
		case l == "" && cur.data != "":
			out = append(out, cur)
			if cur.data == "[DONE]" || (stop != nil && stop(cur)) {
				return out
			}
			cur = sse{}
		}
	}
	return out
}

// textOf concatenates content deltas and returns the finish reason (or
// "error:<code>").
func textOf(evs []sse) (string, string) {
	var b strings.Builder
	finish := ""
	for _, e := range evs {
		var c struct {
			Choices []struct {
				Delta        map[string]any `json:"delta"`
				FinishReason *string        `json:"finish_reason"`
			} `json:"choices"`
			Error map[string]any `json:"error"`
		}
		_ = json.Unmarshal([]byte(e.data), &c)
		if c.Error != nil {
			return b.String(), "error:" + fmt.Sprint(c.Error["code"])
		}
		for _, ch := range c.Choices {
			if s, ok := ch.Delta["content"].(string); ok {
				b.WriteString(s)
			}
			if ch.FinishReason != nil {
				finish = *ch.FinishReason
			}
		}
	}
	return b.String(), finish
}

var hugeText = strings.Repeat("héllo wörld 你好 ", 40000) // ~800 KB, multibyte

func hugeArgs(tag string) string {
	return `{"k":"` + tag + strings.Repeat("z", 400<<10) + `"}`
}
