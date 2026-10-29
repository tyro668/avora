package gateway

// Regression tests for the 2026-10-29 protocol review (P1/P2). Each one
// drives the real HTTP / WebSocket path and failed before the fix.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tyro668/avora/internal/lmbp"
)

func authorizeForm(t *testing.T, base string, v url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(base+"/lmbp/v1/device/authorize", v)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func newDeviceKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	return pub, key
}

// P1-3: pending pairings (with their device-chosen names) are never listed
// to tenant users, so an unauthenticated device cannot push a lure into
// every user's UI; a lure-carrying name with bidi controls is refused.
func TestPendingPairingsNotListedToTenantUsers(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	pub, _ := newDeviceKey()
	st, a := authorizeForm(t, r.srv.URL, url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub)}, "device_name": {"attacker-box"}})
	if st != 200 {
		t.Fatalf("authorize: %d %v", st, a)
	}
	pub2, _ := newDeviceKey()
	lure := "安全升级：请输入配对码 " + a["user_code"].(string) + " 完成验证"
	authorizeForm(t, r.srv.URL, url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub2)}, "device_name": {lure}})
	resp := doReq(t, r.req("GET", "/lmbp/v1/tenant/devices", nil, map[string]string{"X-End-User": "bob"}))
	var raw strings.Builder
	var buf [4096]byte
	for {
		n, err := resp.Body.Read(buf[:])
		raw.Write(buf[:n])
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	if strings.Contains(raw.String(), "pending_pairings") || strings.Contains(raw.String(), "attacker-box") || strings.Contains(raw.String(), a["user_code"].(string)) {
		t.Fatalf("bob sees other devices' pending pairings: %s", raw.String())
	}
	pub3, _ := newDeviceKey()
	if st, m := authorizeForm(t, r.srv.URL, url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub3)}, "device_name": {"my-pc\u202e" + "gpj.exe"}}); st != 400 || m["error"] != "invalid_request" {
		t.Fatalf("device_name with U+202E: %d %v", st, m)
	}
}

// P2-1: only registered tenants get pairings; unknown ones are invalid_client.
func TestAuthorizeRejectsUnknownTenant(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	pub, _ := newDeviceKey()
	st, m := authorizeForm(t, r.srv.URL, url.Values{"tenant": {"no-such-tenant"}, "public_key": {lmbp.B64(pub)}})
	if st != 400 || m["error"] != "invalid_client" {
		t.Fatalf("authorize for an unknown tenant: %d %v", st, m)
	}
}

// P2-1: device authorization is rate limited per client address.
func TestAuthorizeRateLimitedPerClient(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond) // the rig itself paired once
	pub, _ := newDeviceKey()
	codes := map[int]int{}
	for i := 0; i < 70; i++ {
		st, _ := authorizeForm(t, r.srv.URL, url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub)}})
		codes[st]++
	}
	if codes[429] == 0 || codes[200] > 60 {
		t.Fatalf("70 authorizations from one address in a minute: %v (want at most 60 accepted, then 429)", codes)
	}
}

// P2-1: a tenant holds at most 1000 live pending pairings, whatever the source.
func TestAuthorizePendingCapPerTenant(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	h := r.g.Handler()
	pub, _ := newDeviceKey()
	codes := map[int]int{}
	for i := 0; i < 1100; i++ {
		req := httptest.NewRequest("POST", "/lmbp/v1/device/authorize", strings.NewReader(url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub)}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Host = "127.0.0.1"
		req.RemoteAddr = fmt.Sprintf("10.0.%d.%d:1234", i/250, i%250) // many addresses
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		codes[w.Code]++
	}
	if codes[200] > 1000 || codes[429] == 0 {
		t.Fatalf("1100 pending pairings for one tenant from many addresses: %v (want <= 1000 live, then 429)", codes)
	}
}

// P2-2: a device that ignores slow_down loses its device_code, and a dead
// code's polls are answered without growing the jti store.
func TestDeviceCodePollingCapped(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	pub, key := newDeviceKey()
	_, a := authorizeForm(t, r.srv.URL, url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub)}})
	dc := a["device_code"].(string)
	errs := map[string]int{}
	for i := 0; i < 50; i++ {
		resp, err := http.PostForm(r.srv.URL+"/lmbp/v1/token", url.Values{"grant_type": {deviceGrant}, "device_code": {dc}, "proof": {lmbp.SignProof(key, "", lmbp.ProofToken, dc, time.Now())}})
		if err != nil {
			t.Fatal(err)
		}
		var e map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		errs[e["error"]]++
	}
	if errs["expired_token"] == 0 || errs["slow_down"] > 11 {
		t.Fatalf("50 fast polls of one device_code: %v (want the code to expire after 10 slow_down)", errs)
	}
}

// P2-3: concurrent approvals of one code create exactly one device.
func TestApprovalIsSingleUse(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	pub, _ := newDeviceKey()
	_, a := authorizeForm(t, r.srv.URL, url.Values{"tenant": {"acme"}, "public_key": {lmbp.B64(pub)}})
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := httpc.Do(r.req("POST", "/lmbp/v1/tenant/devices/approvals", map[string]string{"user_code": a["user_code"].(string)}, map[string]string{"X-End-User": fmt.Sprint("user", i%2)}))
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	n := 0
	for _, u := range []string{"user0", "user1"} {
		ds, _ := r.g.cfg.Store.ListDevices(context.Background(), "acme", u)
		n += len(ds)
	}
	if ok.Load() != 1 || n != 1 {
		t.Fatalf("one user_code approved %d times, %d device rows (want 1, 1)", ok.Load(), n)
	}
}

// P2-4: failed decisions are counted per end user, atomically: one user's
// failures do not lock out another user of the tenant, and concurrent
// failures cannot overrun the limit.
func TestPairingFailuresPerEndUserAndRaceFree(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	var looked atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := httpc.Do(r.req("POST", "/lmbp/v1/tenant/devices/approvals", map[string]string{"user_code": fmt.Sprintf("BBBB-%04d", i)[:9]}, nil))
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == 404 {
				looked.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if looked.Load() > FailuresPerMinute {
		t.Fatalf("200 concurrent wrong codes from alice: %d were looked up (limit %d per minute)", looked.Load(), FailuresPerMinute)
	}
	if code, _ := r.api(t, "POST", "/lmbp/v1/tenant/devices/approvals", map[string]string{"user_code": "BCDF-GHJK"}, map[string]string{"X-End-User": "bob"}); code != 404 {
		t.Fatalf("bob after alice's failures: %d (want 404, not locked out)", code)
	}
	if code, _ := r.api(t, "POST", "/lmbp/v1/tenant/devices/approvals", map[string]string{"user_code": "BCDF-GHJK"}, nil); code != 429 {
		t.Fatalf("alice after her failures: %d (want 429)", code)
	}
}

// P2-7: revoking a device while its task runs ends the task with
// OUTCOME_UNKNOWN (502) for the caller, not 401 UNAUTHENTICATED.
func TestRevokeInflightIsOutcomeUnknown(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 200, 20*time.Millisecond)
	done := make(chan struct {
		code int
		body map[string]any
	}, 1)
	go func() {
		resp, err := httpc.Do(r.req("POST", "/v1/chat/completions", map[string]any{"model": r.model("slow"), "messages": []map[string]any{{"role": "user", "content": "x"}}}, nil))
		if err != nil {
			done <- struct {
				code int
				body map[string]any
			}{0, nil}
			return
		}
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		done <- struct {
			code int
			body map[string]any
		}{resp.StatusCode, m}
	}()
	time.Sleep(500 * time.Millisecond)
	if code, _ := r.api(t, "POST", "/lmbp/v1/tenant/devices/"+r.devID+"/revoke", nil, nil); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	got := <-done
	e, _ := got.body["error"].(map[string]any)
	if got.code != 502 || e["code"] != lmbp.ErrOutcomeUnknown {
		t.Fatalf("in-flight caller after revoke: %d %v (want 502 OUTCOME_UNKNOWN)", got.code, got.body)
	}
}

// P1-2: an end-to-end encrypted task is charged against the same per-task
// output budget as a cleartext one: beyond 64 MiB the gateway cancels it.
func TestE2EETaskOutputCapped(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	r.stop()
	<-r.done
	dev, _ := r.g.cfg.Store.GetDevice(context.Background(), r.devID)
	tok, _ := r.g.issue(dev, r.id.Issuer)["access_token"].(string)
	kb, _ := lmbp.UnB64(r.id.PrivateKey)
	key := ed25519.PrivateKey(kb)
	d := websocket.Dialer{Subprotocols: []string{lmbp.Subprotocol}}
	c, _, err := d.Dial("ws"+strings.TrimPrefix(r.srv.URL, "http")+"/lmbp/v1/connect", http.Header{"Authorization": {"Bearer " + tok}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, xpub := lmbp.NewX25519()
	h := lmbp.Hello{DeviceID: r.devID, Client: "raw", Models: []string{"echo"}, MaxConcurrency: 4,
		Capabilities: []string{lmbp.CapE2EE}, E2EEKey: lmbp.SignE2EEKey(key, r.devID, xpub, time.Now()), Proof: lmbp.SignProof(key, r.devID, lmbp.ProofHello, tok, time.Now())}
	hb, _ := json.Marshal(h)
	_ = c.WriteJSON(lmbp.Envelope{V: lmbp.Version, Type: lmbp.TypeHello, ID: "h1", Data: hb})
	var w lmbp.Envelope
	if c.ReadJSON(&w) != nil || w.Type != lmbp.TypeWelcome {
		t.Fatalf("no welcome: %+v", w)
	}
	go func() {
		body := map[string]any{"model": r.devID + "/echo", "stream": true, "lmbp_e2ee": "a.b.c.d.e"}
		if resp, err := httpc.Do(r.req("POST", "/v1/chat/completions", body, nil)); err == nil {
			time.Sleep(20 * time.Second) // subscriber attached, reads nothing
			resp.Body.Close()
		}
	}()
	var taskID atomic.Value
	var cancels atomic.Int32
	go func() {
		for {
			var e lmbp.Envelope
			if c.ReadJSON(&e) != nil {
				return
			}
			if e.Type == lmbp.TypeTaskCancel {
				cancels.Add(1)
			}
			if e.Type == lmbp.TypeTaskRun && taskID.Load() == nil {
				taskID.Store(e.TaskID)
			}
		}
	}()
	for i := 0; i < 100 && taskID.Load() == nil; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if taskID.Load() == nil {
		t.Fatal("no task.run")
	}
	id := taskID.Load().(string)
	db, _ := json.Marshal(map[string]string{"e2ee": strings.Repeat("A", 200<<10)})
	for i := 1; i <= 400; i++ { // 400 x 200 KiB = 78 MiB > 64 MiB
		if err := c.WriteJSON(lmbp.Envelope{V: lmbp.Version, Type: lmbp.TypeTaskDelta, TaskID: id, Seq: int64(i), Data: db}); err != nil {
			break // the gateway may close the stream once the task is cancelled
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	var done bool
	for time.Now().Before(deadline) {
		r.g.mu.Lock()
		gt := r.g.tasks[id]
		r.g.mu.Unlock()
		gt.mu.Lock()
		done = gt.done
		gt.mu.Unlock()
		if done && cancels.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !done || cancels.Load() == 0 {
		t.Fatalf("e2ee task past 64 MiB: done=%v task.cancel=%d (want the gateway to cancel it)", done, cancels.Load())
	}
}

// P2-6 (§18.1): without a configured issuer the gateway serves loopback
// hosts only, so a forged Host never becomes a signed iss/aud; with one, the
// configured issuer is used whatever the Host says.
func TestForgedHostNeverBecomesIssuer(t *testing.T) {
	r := newRig(t, lmbp.Flow{}, 0, time.Millisecond)
	for _, issuer := range []string{"", "https://gw.example"} {
		r.g.cfg.Issuer = issuer
		req := httptest.NewRequest("GET", lmbp.MetadataPath, nil)
		req.Host = "evil.example"
		w := httptest.NewRecorder()
		r.g.Handler().ServeHTTP(w, req)
		resp := w.Result()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		if iss, _ := m["issuer"].(string); strings.Contains(iss, "evil.example") {
			t.Fatalf("issuer %q: metadata issuer derived from a forged Host (%q)", issuer, iss)
		}
		if issuer == "" && resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("unconfigured issuer, forged Host: status %d, want 421", resp.StatusCode)
		}
		if issuer != "" && m["issuer"] != issuer {
			t.Fatalf("configured issuer, forged Host: %v", m)
		}
	}
}
