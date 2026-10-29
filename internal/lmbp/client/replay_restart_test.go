package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
)

type countExec struct{ n atomic.Int32 }

func (*countExec) Models() []string { return []string{"m"} }
func (e *countExec) Execute(ctx context.Context, run lmbp.TaskRun, emit func(lmbp.TaskDelta) error) (*lmbp.TaskDone, *lmbp.ErrorBody) {
	e.n.Add(1)
	return &lmbp.TaskDone{FinishReason: "stop"}, nil
}

// restartIdentity is one paired device whose process is started twice.
func restartIdentity() (Identity, ed25519.PrivateKey, []byte) {
	dev := ed25519.NewKeyFromSeed(make([]byte, 32))
	gwPub, gwKey, _ := ed25519.GenerateKey(nil)
	x, _ := lmbp.NewX25519()
	return Identity{GatewayURL: "http://127.0.0.1:1", Tenant: "acme", DeviceID: "dev_1", PrivateKey: lmbp.B64(dev), GatewayKey: lmbp.B64(gwPub),
		Issuer: "http://127.0.0.1:1", Audience: lmbp.TokenAudience("http://127.0.0.1:1", "acme"), E2EEKey: lmbp.B64(x)}, gwKey, x
}

func capture(t *testing.T, c *Client) func() []lmbp.Envelope {
	t.Helper()
	var mu sync.Mutex
	var sent []lmbp.Envelope
	c.out.SetFlow(nil)
	c.out.Attach(func(b []byte) error {
		var e lmbp.Envelope
		_ = json.Unmarshal(b, &e)
		mu.Lock()
		sent = append(sent, e)
		mu.Unlock()
		return nil
	})
	return func() []lmbp.Envelope { mu.Lock(); defer mu.Unlock(); return append([]lmbp.Envelope(nil), sent...) }
}

func waitTerminal(t *testing.T, frames func() []lmbp.Envelope, task string) lmbp.Envelope {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, e := range frames() {
			if e.TaskID == task && (e.Type == lmbp.TypeTaskDone || e.Type == lmbp.TypeTaskError) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no terminal frame for %s", task)
	return lmbp.Envelope{}
}

// §12.4: the nonce cache is in memory. A task.run accepted by one device
// process and replayed (still unexpired) to the next process after a restart
// must be refused, not executed a second time.
func TestTaskRunReplayAfterRestartRefused(t *testing.T) {
	id, gwKey, _ := restartIdentity()
	exec := &countExec{}
	c1, err := New(Config{Executor: exec}, id)
	if err != nil {
		t.Fatal(err)
	}
	f1 := capture(t, c1)
	now := time.Now()
	run := lmbp.TaskRun{TaskID: "task_1", DeviceID: "dev_1", Model: "m", Iat: now.Unix(), Exp: now.Add(55 * time.Second).Unix(), Nonce: "nonce-1",
		Messages: []lmbp.Message{{Role: "user", Content: lmbp.Text("hi")}}}
	env := lmbp.Envelope{V: lmbp.Version, Type: lmbp.TypeTaskRun, TaskID: "task_1", Seq: 1, JWS: lmbp.SignTaskRun(gwKey, lmbp.Thumbprint(gwKey.Public().(ed25519.PublicKey)), run)}
	c1.onRun(env)
	if e := waitTerminal(t, f1, "task_1"); e.Type != lmbp.TypeTaskDone || exec.n.Load() != 1 {
		t.Fatalf("first delivery: %+v executions %d", e, exec.n.Load())
	}
	time.Sleep(3 * time.Second) // the device restarts later
	c2, err := New(Config{Executor: exec}, id)
	if err != nil {
		t.Fatal(err)
	}
	f2 := capture(t, c2)
	c2.onRun(env) // the same frame, replayed to the new process
	e := waitTerminal(t, f2, "task_1")
	var eb lmbp.ErrorBody
	_ = json.Unmarshal(e.Data, &eb)
	if e.Type != lmbp.TypeTaskError || eb.Code != lmbp.ErrForbidden || exec.n.Load() != 1 {
		t.Fatalf("replay after restart: %s %+v, executions %d (want FORBIDDEN, 1)", e.Type, eb, exec.n.Load())
	}
}

// §17: the same for a sealed request: its rid cache is in memory too.
func TestSealedRequestReplayAfterRestartRefused(t *testing.T) {
	id, _, x := restartIdentity()
	xpub, _ := lmbp.X25519Public(x)
	req, _ := json.Marshal(lmbp.E2EERequest{RID: "rid-1", Iat: time.Now().Unix(), Model: "m", Messages: []lmbp.Message{{Role: "user", Content: lmbp.Text("hi")}},
		ResponseKey: lmbp.B64(make([]byte, 32))})
	jwe, err := lmbp.SealJWE(xpub, lmbp.X25519Thumbprint(xpub), req)
	if err != nil {
		t.Fatal(err)
	}
	run := lmbp.TaskRun{TaskID: "task_1", DeviceID: "dev_1", Model: "m", E2EE: &lmbp.E2EERef{Blob: "b1"}, Blobs: []lmbp.BlobRef{{ID: "b1", MediaType: lmbp.E2EEMediaType, Size: int64(len(jwe))}}}
	blobs := map[string][]byte{"b1": []byte(jwe)}
	c1, err := New(Config{Executor: &countExec{}}, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fail := c1.openE2EE(run, blobs); fail != nil {
		t.Fatalf("first open: %+v", fail)
	}
	time.Sleep(3 * time.Second)
	c2, err := New(Config{Executor: &countExec{}}, id)
	if err != nil {
		t.Fatal(err)
	}
	_, _, fail := c2.openE2EE(run, blobs)
	if fail == nil || fail.Code != lmbp.ErrDecrypt || !strings.Contains(fail.Message, "replay") {
		t.Fatalf("replayed sealed request after restart accepted: %+v", fail)
	}
}
