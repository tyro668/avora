package conformance

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/tyro668/avora/internal/lmbp"
)

// Checks for the negotiated extensions: resume (X-R*), flow control (X-F*),
// tools and multimodal (X-T*, X-M*), end-to-end encryption (X-E*) and the
// HTTP re-attach/idempotency surface (X-H*).

type extDev struct {
	r      *runner
	conn   *websocket.Conn
	wmu    sync.Mutex
	mu     sync.Mutex
	recv   map[string]int64 // highest contiguous gateway seq per task
	gaps   []string
	frames chan lmbp.Envelope
	// batchAcks: ack every 30ms instead of per frame, and track the bytes
	// received since the last ack (a lower bound of the gateway's in-flight
	// bytes) to check the gateway honours our windows (Z2).
	batchAcks    bool
	inflight     map[string]int
	peakTask     int
	connInflight int
	peakConn     int
}

func (d *extDev) write(e lmbp.Envelope) error {
	e.V = lmbp.Version
	d.wmu.Lock()
	defer d.wmu.Unlock()
	_ = d.conn.SetWriteDeadline(time.Now().Add(d.r.cfg.Timeout))
	return d.conn.WriteJSON(e)
}

func (d *extDev) send(typ, taskID string, seq int64, data any) error {
	b, _ := json.Marshal(data)
	return d.write(lmbp.Envelope{Type: typ, TaskID: taskID, Seq: seq, Data: b})
}

// pump reads frames, tracks gateway data-frame seqs and acks them (a device
// that negotiated flow MUST ack, otherwise the gateway stalls).
func (d *extDev) pump() {
	defer close(d.frames)
	for {
		f, n, err := d.r.readFrameRaw(d.conn)
		if err != nil {
			return
		}
		if f.Seq > 0 && f.TaskID != "" {
			d.mu.Lock()
			if d.batchAcks {
				d.inflight[f.TaskID] += n
				d.connInflight += n
				d.peakTask = max(d.peakTask, d.inflight[f.TaskID])
				d.peakConn = max(d.peakConn, d.connInflight)
				if f.Seq == d.recv[f.TaskID]+1 {
					d.recv[f.TaskID] = f.Seq
				}
				d.mu.Unlock()
				d.frames <- f
				continue
			}
			if f.Seq == d.recv[f.TaskID]+1 {
				d.recv[f.TaskID] = f.Seq
			} else if f.Seq > d.recv[f.TaskID]+1 {
				d.gaps = append(d.gaps, fmt.Sprintf("%s: %d after %d", f.TaskID, f.Seq, d.recv[f.TaskID]))
			}
			seq := d.recv[f.TaskID]
			d.mu.Unlock()
			b, _ := json.Marshal(lmbp.TaskAck{Seq: seq})
			_ = d.write(lmbp.Envelope{Type: lmbp.TypeTaskAck, TaskID: f.TaskID, Data: b})
		}
		d.frames <- f
	}
}

func (d *extDev) await(typ string, pred func(lmbp.Envelope) bool) (lmbp.Envelope, []lmbp.Envelope, error) {
	var before []lmbp.Envelope
	tm := time.After(d.r.cfg.Timeout)
	for {
		select {
		case f, ok := <-d.frames:
			if !ok {
				return f, before, errors.New("session closed")
			}
			if f.Type == typ && (pred == nil || pred(f)) {
				return f, before, nil
			}
			before = append(before, f)
		case <-tm:
			return lmbp.Envelope{}, before, fmt.Errorf("timeout waiting for %s", typ)
		}
	}
}

// blobs collects the blob.chunk frames of run's task until every blob
// listed in the signed payload is complete.
func (d *extDev) blobs(run lmbp.TaskRun) []lmbp.Envelope {
	var out []lmbp.Envelope
	need := map[string]bool{}
	for _, b := range run.Blobs {
		need[b.ID] = true
	}
	for len(need) > 0 {
		f, _, err := d.await(lmbp.TypeBlobChunk, func(e lmbp.Envelope) bool { return e.TaskID == run.TaskID })
		if err != nil {
			return out
		}
		out = append(out, f)
		var c lmbp.BlobChunk
		_ = json.Unmarshal(f.Data, &c)
		if c.Last {
			delete(need, c.BlobID)
		}
	}
	return out
}

func (r *runner) dialExt(at string, hello lmbp.Hello) (*extDev, lmbp.Welcome, error) {
	var wel lmbp.Welcome
	wsURL := "ws" + strings.TrimPrefix(r.cfg.GatewayURL, "http") + "/lmbp/v1/connect"
	d := websocket.Dialer{Subprotocols: []string{lmbp.Subprotocol}, HandshakeTimeout: r.cfg.Timeout}
	conn, resp, err := d.Dial(wsURL, http.Header{"Authorization": {"Bearer " + at}})
	if err != nil {
		return nil, wel, fmt.Errorf("dial: %v %s", err, status(resp))
	}
	dev := &extDev{r: r, conn: conn, recv: map[string]int64{}, frames: make(chan lmbp.Envelope, 256)}
	b, _ := json.Marshal(hello)
	if err := dev.write(lmbp.Envelope{Type: lmbp.TypeHello, ID: "h2", Data: b}); err != nil {
		return nil, wel, err
	}
	f, err := r.readFrame(conn)
	if err != nil || f.Type != lmbp.TypeWelcome {
		conn.Close()
		return nil, wel, fmt.Errorf("no welcome: %+v %v", f, err)
	}
	_ = json.Unmarshal(f.Data, &wel)
	go dev.pump()
	return dev, wel, nil
}

// ackLoop acks, every 30ms, everything received so far (batchAcks mode).
func (d *extDev) ackLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(30 * time.Millisecond):
		}
		d.mu.Lock()
		acks := map[string]int64{}
		for id := range d.inflight {
			acks[id] = d.recv[id]
		}
		d.inflight = map[string]int{}
		d.connInflight = 0
		d.mu.Unlock()
		for id, seq := range acks {
			b, _ := json.Marshal(lmbp.TaskAck{Seq: seq})
			_ = d.write(lmbp.Envelope{Type: lmbp.TypeTaskAck, TaskID: id, Data: b})
		}
	}
}

// chatRaw posts a chat request and returns status, headers and the body.
func (r *runner) chatRaw(ctx context.Context, body any, hdr map[string]string) (int, http.Header, []byte) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.GatewayURL+"/v1/chat/completions", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+r.cfg.TenantKey)
	req.Header.Set("X-End-User", r.cfg.EndUser)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, resp.Header, buf.Bytes()
}

func errCode(b []byte) string {
	var m struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &m)
	return m.Error.Code
}

type sseEvent struct {
	id   string
	data string
}

func parseSSE(b []byte) []sseEvent {
	var out []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "id: "):
			cur.id = l[4:]
		case strings.HasPrefix(l, "data: "):
			cur.data = l[6:]
		case l == "":
			if cur.data != "" {
				out = append(out, cur)
			}
			cur = sseEvent{}
		}
	}
	if cur.data != "" {
		out = append(out, cur)
	}
	return out
}

func sseText(evs []sseEvent) string {
	var sb strings.Builder
	for _, e := range evs {
		var c struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(e.data), &c) == nil && len(c.Choices) > 0 {
			sb.WriteString(c.Choices[0].Delta.Content)
		}
	}
	return sb.String()
}

func (r *runner) runExt(ctx context.Context, key ed25519.PrivateKey, at string) (*websocket.Conn, chan lmbp.Envelope) {
	xpriv, xpub := lmbp.NewX25519()
	stmt := lmbp.SignE2EEKey(key, r.devID, xpub, time.Now())
	mTools, mPlain := "conf-vision-tools", "conf-plain"
	flow := &lmbp.Flow{TaskWindow: 256 << 10, ConnWindow: 1 << 20}
	hello := lmbp.Hello{DeviceID: r.devID, Client: "lmbp-conformance", Models: []string{mTools, mPlain, mParamCaps}, MaxConcurrency: 4,
		ModelCapabilities: map[string][]string{mTools: {lmbp.ModelCapTools, lmbp.ModelCapVision}, mParamCaps: {lmbp.ModelCapParams, lmbp.ModelCapTemperature}},
		ModelNames:        map[string]string{mTools: "Conformance 视觉方案", "not-advertised": "ghost"},
		Capabilities:      lmbp.Capabilities, Flow: flow, E2EEKey: stmt,
		Proof: lmbp.SignProof(key, r.devID, lmbp.ProofHello, at, time.Now())}
	dev, wel, err := r.dialExt(at, hello)
	neg := func(c string) bool { return containsS(wel.Capabilities, c) }
	subset := true
	for _, c := range wel.Capabilities {
		subset = subset && containsS(hello.Capabilities, c)
	}
	flowOK := !neg(lmbp.CapFlow) || (wel.Flow != nil && wel.Flow.TaskWindow >= 65536 && wel.Flow.ConnWindow >= wel.Flow.TaskWindow)
	resumeOK := !neg(lmbp.CapResume) || (wel.ResumeToken != "" && wel.ResumeSeconds > 0)
	// X1 is Core (any welcome is a correct intersection); X1r/X1t/X1m/X1e
	// require the capabilities of each declared extension profile.
	if !r.check("X1", "hello offering every capability is answered by welcome whose capabilities ⊆ offered; negotiated flow carries windows, negotiated resume a resume_token",
		want(err == nil && subset && flowOK && resumeOK, "err %v welcome %+v", err, wel)) {
		return nil, nil
	}
	r.check("X1r", "reliable: welcome negotiates resume and flow", want(neg(lmbp.CapResume) && neg(lmbp.CapFlow), "capabilities %v", wel.Capabilities))
	r.check("X1t", "tools: welcome negotiates tools", want(neg(lmbp.CapTools), "capabilities %v", wel.Capabilities))
	r.check("X1m", "multimodal: welcome negotiates multimodal", want(neg(lmbp.CapMultimodal), "capabilities %v", wel.Capabilities))
	r.check("X1e", "e2ee: welcome negotiates e2ee", want(neg(lmbp.CapE2EE), "capabilities %v", wel.Capabilities))
	full := func(m string) string { return r.devID + "/" + m }

	// devices / models surface
	st, dl, _, _ := r.tenant(http.MethodGet, "/lmbp/v1/tenant/devices", nil)
	var dj map[string]any
	if ds, _ := dl["devices"].([]any); len(ds) > 0 {
		for _, x := range ds {
			if m, _ := x.(map[string]any); m["device_id"] == r.devID {
				dj = m
			}
		}
	}
	r.check("X-E1", "device list exposes jkt and the latest e2ee key statement", want(st == 200 && dj != nil && dj["jkt"] == lmbp.Thumbprint(key.Public().(ed25519.PublicKey)) && dj["e2ee_key"] == stmt, "status %d %v", st, dj))
	st, ml, _, _ := r.tenant(http.MethodGet, "/v1/models", nil)
	capsOK := false
	if data, _ := ml["data"].([]any); data != nil {
		for _, it := range data {
			if mm, _ := it.(map[string]any); mm["id"] == full(mTools) {
				cs, _ := mm["capabilities"].([]any)
				capsOK = len(cs) == 2
			}
		}
	}
	r.check("X-T1", "GET /v1/models reports per-model capabilities", want(st == 200 && capsOK, "status %d %v", st, ml))
	namesOK := false
	if data, _ := ml["data"].([]any); data != nil {
		named, plain := "", "unset"
		for _, it := range data {
			mm, _ := it.(map[string]any)
			switch mm["id"] {
			case full(mTools):
				named, _ = mm["display_name"].(string)
			case full(mPlain):
				plain, _ = mm["display_name"].(string)
			}
		}
		dn, _ := dj["model_names"].(map[string]any)
		namesOK = named == "Conformance 视觉方案" && plain == "" && dn[mTools] == "Conformance 视觉方案" && dn["not-advertised"] == nil
	}
	r.check("X-N1", "optional model_names surface as display_name in /v1/models and model_names in the device list (unadvertised entries dropped)", want(st == 200 && namesOK, "status %d %v devices %v", st, ml, dj))

	// tools round trip
	tools := []map[string]any{{"type": "function", "function": map[string]any{"name": "get_weather", "parameters": map[string]any{"type": "object", "properties": map[string]any{"city": map[string]string{"type": "string"}}}}}}
	type res struct {
		st   int
		h    http.Header
		body []byte
	}
	call := func(body any, hdr map[string]string) chan res {
		ch := make(chan res, 1)
		go func() { s, h, b := r.chatRaw(ctx, body, hdr); ch <- res{s, h, b} }()
		return ch
	}
	var f lmbp.Envelope
	var run lmbp.TaskRun
	if r.runs(lmbp.ProfileTools, "X-T2", "X-T3", "X-F1", "X-T4") {
		tc := call(map[string]any{"model": full(mTools), "tools": tools, "tool_choice": "auto", "messages": []any{map[string]any{"role": "user", "content": "weather?"}}}, nil)
		f, _, err = dev.await(lmbp.TypeTaskRun, nil)
		if err == nil {
			run, err = lmbp.VerifyTaskRun(r.gwKey, f.TaskID, f.JWS)
		}
		r.check("X-T2", "tools and tool_choice are carried in the signed task.run; task.run is a data frame with seq", want(err == nil && len(run.Tools) == 1 && run.Tools[0].Function.Name == "get_weather" && f.Seq >= 1, "err %v run %+v", err, run))
		if err == nil {
			idx := 0
			_ = dev.send(lmbp.TypeTaskDelta, run.TaskID, 1, lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{Index: &idx, ID: "call_1", Type: "function", Function: lmbp.FunctionCall{Name: "get_weather", Arguments: `{"city":`}}}})
			_ = dev.send(lmbp.TypeTaskDelta, run.TaskID, 2, lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{Index: &idx, Function: lmbp.FunctionCall{Arguments: `"Paris"}`}}}})
			_ = dev.send(lmbp.TypeTaskDone, run.TaskID, 3, lmbp.TaskDone{FinishReason: "tool_calls"})
			_, _, aerr := dev.await(lmbp.TypeTaskAck, func(e lmbp.Envelope) bool {
				var a lmbp.TaskAck
				_ = json.Unmarshal(e.Data, &a)
				return e.TaskID == run.TaskID && a.Seq >= 3
			})
			rs := <-tc
			var cc struct {
				Choices []struct {
					Message      lmbp.Message `json:"message"`
					FinishReason string       `json:"finish_reason"`
				} `json:"choices"`
			}
			_ = json.Unmarshal(rs.body, &cc)
			ok := len(cc.Choices) == 1 && cc.Choices[0].FinishReason == "tool_calls" && len(cc.Choices[0].Message.ToolCalls) == 1 &&
				cc.Choices[0].Message.ToolCalls[0].Function.Arguments == `{"city":"Paris"}` && cc.Choices[0].Message.ToolCalls[0].ID == "call_1"
			r.check("X-T3", "streamed tool_call fragments are merged into message.tool_calls with finish_reason tool_calls", want(rs.st == 200 && ok, "status %d body %s", rs.st, rs.body))
			r.check("X-F1", "gateway acknowledges device data frames with task.ack (flow negotiated)", aerr)
		}
		s2, _, b2 := r.chatRaw(ctx, map[string]any{"model": full(mPlain), "tools": tools, "messages": []any{map[string]any{"role": "user", "content": "x"}}}, nil)
		r.check("X-T4", "tools sent to a model without the tools capability fail with 400 CAPABILITY_UNSUPPORTED", want(s2 == 400 && errCode(b2) == lmbp.ErrUnsupported, "status %d %s", s2, b2))
		// X-T5: an out-of-range tool_calls index fails the task
		tc5 := call(map[string]any{"model": full(mTools), "tools": tools, "messages": []any{map[string]any{"role": "user", "content": "index?"}}}, nil)
		f5, _, err5 := dev.await(lmbp.TypeTaskRun, nil)
		reason := ""
		if err5 == nil {
			idx := lmbp.MaxToolCallIndex + 1
			_ = dev.send(lmbp.TypeTaskDelta, f5.TaskID, 1, lmbp.TaskDelta{ToolCalls: []lmbp.ToolCall{{Index: &idx, ID: "call_x", Type: "function", Function: lmbp.FunctionCall{Name: "get_weather", Arguments: "{}"}}}})
			cf, _, cerr := dev.await(lmbp.TypeTaskCancel, func(e lmbp.Envelope) bool { return e.TaskID == f5.TaskID })
			if cerr == nil {
				var c lmbp.TaskCancel
				_ = json.Unmarshal(cf.Data, &c)
				reason = c.Reason
			}
			_ = dev.send(lmbp.TypeTaskError, f5.TaskID, 2, lmbp.ErrorBody{Code: lmbp.ErrCancelled, Message: "cancelled"})
		}
		rs5 := <-tc5
		r.check("X-T5", "a device tool_calls index of 128 (outside 0..127) fails the task: task.cancel(protocol_error) to the device, 502 INTERNAL to the caller (§10, §16.1)",
			want(err5 == nil && reason == "protocol_error" && rs5.st == 502 && errCode(rs5.body) == lmbp.ErrInternal, "err %v cancel %q status %d body %s", err5, reason, rs5.st, rs5.body))
	}
	if r.runs(lmbp.ProfileAnthropic, "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10") {
		r.runAnthropic(ctx, dev, full, mTools)
	}
	r.runAudit(ctx, dev, full, mTools)
	r.runErrata(ctx, dev, full, mTools, mPlain)
	r.runV2Ext(ctx, dev, full, mPlain)

	// image → blob.chunk
	if r.runs(lmbp.ProfileMultimodal, "X-M1", "X-M2", "X-F2") {
		img := make([]byte, 40<<10)
		_, _ = rand.Read(img)
		uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(img)
		s3, _, b3 := r.chatRaw(ctx, map[string]any{"model": full(mPlain), "messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": uri}}}}}}, nil)
		r.check("X-M1", "image input to a model without vision fails with 400 CAPABILITY_UNSUPPORTED", want(s3 == 400 && errCode(b3) == lmbp.ErrUnsupported, "status %d %s", s3, b3))
		ic := call(map[string]any{"model": full(mTools), "messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "what is this"}, map[string]any{"type": "image_url", "image_url": map[string]any{"url": uri}}}}}}, nil)
		f, _, err = dev.await(lmbp.TypeTaskRun, nil)
		if err == nil {
			run, err = lmbp.VerifyTaskRun(r.gwKey, f.TaskID, f.JWS)
		}
		before := dev.blobs(run)
		var got []byte
		var seqs []int64
		for _, e := range before {
			if e.Type == lmbp.TypeBlobChunk && e.TaskID == run.TaskID {
				var c lmbp.BlobChunk
				_ = json.Unmarshal(e.Data, &c)
				p, _ := lmbp.UnB64(c.Data)
				got = append(got, p...)
				seqs = append(seqs, e.Seq)
			}
		}
		sum := sha256.Sum256(got)
		blobOK := err == nil && len(run.Blobs) == 1 && run.Blobs[0].Size == int64(len(img)) && run.Blobs[0].SHA256 == lmbp.B64(sum[:]) && bytes.Equal(got, img) &&
			len(run.Messages) == 1 && len(run.Messages[0].Content.Parts) == 2 && run.Messages[0].Content.Parts[1].ImageURL.URL == lmbp.BlobScheme+run.Blobs[0].ID
		r.check("X-M2", "data: URIs above 16 KiB travel as blob.chunk data frames after task.run; the signed blob ref (size, sha256) matches and the part references lmbp-blob:<id>", want(blobOK, "err %v run %+v blobs %d bytes", err, run.Blobs, len(got)))
		contig := len(seqs) > 0 && f.Seq == 1
		for i, s := range seqs {
			contig = contig && s == int64(i+2)
		}
		r.check("X-F2", "gateway data frames of a task are numbered 1..n without gaps (task.run = 1, then blob.chunk)", want(contig && len(dev.gaps) == 0, "run seq %d blob seqs %v gaps %v", f.Seq, seqs, dev.gaps))
		if err == nil {
			_ = dev.send(lmbp.TypeTaskDone, run.TaskID, 1, lmbp.TaskDone{FinishReason: "stop"})
			<-ic
		}
	}

	// E2EE
	if r.runs(lmbp.ProfileE2EE, "X-E2", "X-E3", "X-E4", "X-E5") {
		rkey := make([]byte, 32)
		_, _ = rand.Read(rkey)
		rid := lmbp.RandomID("rid_")
		plain, _ := json.Marshal(lmbp.E2EERequest{RID: rid, Iat: time.Now().Unix(), Model: mTools, Messages: []lmbp.Message{{Role: "user", Content: lmbp.Text("secret prompt")}}, ResponseKey: lmbp.B64(rkey)})
		jwe, _ := lmbp.SealJWE(xpub, lmbp.X25519Thumbprint(xpub), plain)
		s4, _, b4 := r.chatRaw(ctx, map[string]any{"model": full(mTools), "lmbp_e2ee": jwe, "messages": []any{map[string]any{"role": "user", "content": "leak"}}}, nil)
		r.check("X-E2", "lmbp_e2ee together with cleartext messages is rejected with 400", want(s4 == 400, "status %d %s", s4, b4))
		ec := call(map[string]any{"model": full(mTools), "stream": true, "lmbp_e2ee": jwe}, nil)
		f, _, err = dev.await(lmbp.TypeTaskRun, nil)
		if err == nil {
			run, err = lmbp.VerifyTaskRun(r.gwKey, f.TaskID, f.JWS)
		}
		before := dev.blobs(run)
		var sealed []byte
		for _, e := range before {
			if e.Type == lmbp.TypeBlobChunk && e.TaskID == run.TaskID {
				var c lmbp.BlobChunk
				_ = json.Unmarshal(e.Data, &c)
				p, _ := lmbp.UnB64(c.Data)
				sealed = append(sealed, p...)
			}
		}
		blind := err == nil && run.E2EE != nil && len(run.Messages) == 0 && len(run.Blobs) == 1 && run.Blobs[0].ID == run.E2EE.Blob && run.Blobs[0].MediaType == lmbp.E2EEMediaType && string(sealed) == jwe
		r.check("X-E3", "gateway relays the JWE unchanged as an application/jose blob referenced by task.run.e2ee and carries no cleartext messages", want(blind, "err %v run %+v", err, run))
		if err == nil {
			_, pt, oerr := lmbp.OpenJWE(xpriv, string(sealed))
			r.check("X-E4", "relayed JWE opens with the device X25519 key (ECDH-ES, A256GCM)", want(oerr == nil && bytes.Equal(pt, plain), "err %v", oerr))
			d1, _ := json.Marshal(lmbp.TaskDelta{Text: "top secret answer"})
			_ = dev.send(lmbp.TypeTaskDelta, run.TaskID, 1, lmbp.TaskDelta{E2EE: lmbp.SealChunk(rkey, rid, lmbp.TypeTaskDelta, 1, d1)})
			d2, _ := json.Marshal(map[string]string{"finish_reason": "stop"})
			_ = dev.send(lmbp.TypeTaskDone, run.TaskID, 2, lmbp.TaskDone{FinishReason: "stop", Usage: &lmbp.Usage{PromptTokens: 3, CompletionTokens: 3}, E2EE: lmbp.SealChunk(rkey, rid, lmbp.TypeTaskDone, 2, d2)})
			rs := <-ec
			var text string
			leak := bytes.Contains(rs.body, []byte("top secret"))
			opened := 0
			for _, e := range parseSSE(rs.body) {
				var c struct {
					E struct {
						Seq  int64  `json:"seq"`
						Type string `json:"type"`
						Data string `json:"data"`
					} `json:"lmbp_e2ee"`
				}
				if json.Unmarshal([]byte(e.data), &c) == nil && c.E.Data != "" {
					p, err := lmbp.OpenChunk(rkey, rid, c.E.Type, c.E.Seq, c.E.Data)
					if err == nil {
						opened++
						var d lmbp.TaskDelta
						_ = json.Unmarshal(p, &d)
						text += d.Text
					}
				}
			}
			r.check("X-E5", "SSE carries sealed frames as lmbp_e2ee {seq,type,data} that open with the response key; no plaintext in the stream", want(rs.st == 200 && !leak && opened == 2 && text == "top secret answer", "status %d opened %d leak %v body %s", rs.st, opened, leak, rs.body))
		}
	}

	// idempotency, resume, sequence gap after resume (reliable). The closure
	// returns the session still open (nil if none): a failure here never
	// skips the Core checks that follow.
	live := dev
	if r.runs(lmbp.ProfileReliable, "X-H1", "X-R1", "X-R2", "X-H2", "X-H3", "X-H4", "X-F3") {
		live = func() *extDev {
			key1 := lmbp.RandomID("idem_")
			ic2 := call(map[string]any{"model": full(mTools), "stream": true, "messages": []any{map[string]any{"role": "user", "content": "resume me"}}}, map[string]string{"Idempotency-Key": key1})
			f, _, err = dev.await(lmbp.TypeTaskRun, nil)
			if err == nil {
				run, err = lmbp.VerifyTaskRun(r.gwKey, f.TaskID, f.JWS)
			}
			s5, _, b5 := r.chatRaw(ctx, map[string]any{"model": full(mTools), "stream": true, "messages": []any{map[string]any{"role": "user", "content": "different"}}}, map[string]string{"Idempotency-Key": key1})
			r.check("X-H1", "same Idempotency-Key with a different body fails with 422 IDEMPOTENCY_KEY_REUSED", want(s5 == 422 && errCode(b5) == lmbp.ErrIdempotency, "status %d %s", s5, b5))
			if err != nil {
				r.check("X-R1", "resume", err)
				return dev
			}
			_ = dev.send(lmbp.TypeTaskDelta, run.TaskID, 1, lmbp.TaskDelta{Text: "A"})
			_, _, _ = dev.await(lmbp.TypeTaskAck, func(e lmbp.Envelope) bool {
				return e.TaskID == run.TaskID && strings.Contains(string(e.Data), `"seq":1`)
			})

			// resume: drop the connection mid-task and reconnect within the window
			dev.mu.Lock()
			gwSeq := dev.recv[run.TaskID]
			dev.mu.Unlock()
			dev.conn.Close()
			for range dev.frames {
			}
			hello.Resume = &lmbp.HelloResume{Token: wel.ResumeToken, Tasks: []lmbp.ResumeTask{{TaskID: run.TaskID, RecvSeq: gwSeq}}}
			hello.Proof = lmbp.SignProof(key, r.devID, lmbp.ProofHello, at, time.Now())
			dev2, wel2, err := r.dialExt(at, hello)
			var rt lmbp.ResumeTask
			if wel2.Resume != nil && len(wel2.Resume.Tasks) == 1 {
				rt = wel2.Resume.Tasks[0]
			}
			if !r.check("X-R1", "hello.resume within the window is answered with welcome.resume {resumed:true, tasks:[{task_id, recv_seq}]} reporting the last device frame received",
				want(err == nil && wel2.Resume != nil && wel2.Resume.Resumed && rt.TaskID == run.TaskID && rt.RecvSeq == 1, "err %v welcome %+v", err, wel2)) {
				return dev2
			}
			dev2.mu.Lock()
			dev2.recv[run.TaskID] = gwSeq
			dev2.mu.Unlock()
			_ = dev2.send(lmbp.TypeTaskDelta, run.TaskID, 1, lmbp.TaskDelta{Text: "A"}) // duplicate retransmit: MUST be dropped
			_ = dev2.send(lmbp.TypeTaskDelta, run.TaskID, 2, lmbp.TaskDelta{Text: "B"})
			_ = dev2.send(lmbp.TypeTaskDone, run.TaskID, 3, lmbp.TaskDone{FinishReason: "stop"})
			rs := <-ic2
			evs := parseSSE(rs.body)
			r.check("X-R2", "after resume, retransmitted duplicates are dropped and the client sees each delta exactly once", want(rs.st == 200 && sseText(evs) == "AB" && evs[len(evs)-1].data == "[DONE]", "status %d text %q", rs.st, sseText(evs)))
			ids := true
			var firstContent string
			for _, e := range evs[:len(evs)-1] {
				ids = ids && e.id != ""
				if firstContent == "" && e.id != "" && e.id != "0" {
					firstContent = e.id
				}
			}
			r.check("X-H2", "every SSE event carries an id (role preamble id 0, then the data-frame seq)", want(len(evs) > 1 && ids, "events %+v", evs))
			// re-attach with Last-Event-ID
			if len(evs) > 2 {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.GatewayURL+"/lmbp/v1/tenant/tasks/"+run.TaskID+"/events", nil)
				req.Header.Set("Authorization", "Bearer "+r.cfg.TenantKey)
				req.Header.Set("X-End-User", r.cfg.EndUser)
				req.Header.Set("Last-Event-ID", firstContent)
				resp, err := (&http.Client{Timeout: r.cfg.Timeout}).Do(req)
				var after []sseEvent
				if err == nil {
					var buf bytes.Buffer
					_, _ = buf.ReadFrom(resp.Body)
					resp.Body.Close()
					after = parseSSE(buf.Bytes())
				}
				r.check("X-H3", "GET /lmbp/v1/tenant/tasks/{id}/events with Last-Event-ID replays exactly the later events", want(err == nil && sseText(after) == "B" && len(after) > 0 && after[len(after)-1].data == "[DONE]", "err %v events %+v", err, after))
				s6, _, b6 := r.chatRaw(ctx, map[string]any{"model": full(mTools), "stream": true, "messages": []any{map[string]any{"role": "user", "content": "resume me"}}}, map[string]string{"Idempotency-Key": key1, "Last-Event-ID": firstContent})
				r.check("X-H4", "replaying the same Idempotency-Key and body re-attaches to the task instead of running it again", want(s6 == 200 && sseText(parseSSE(b6)) == "B", "status %d %s", s6, b6))
			}
			// sequence gap
			gc := call(map[string]any{"model": full(mTools), "stream": true, "messages": []any{map[string]any{"role": "user", "content": "gap"}}}, nil)
			f, _, err = dev2.await(lmbp.TypeTaskRun, nil)
			if err == nil {
				_ = dev2.send(lmbp.TypeTaskDelta, f.TaskID, 2, lmbp.TaskDelta{Text: "skipped one"})
				rs := <-gc
				r.check("X-F3", "a data frame that skips a seq fails the task (no silent loss)", want(!bytes.Contains(rs.body, []byte("skipped one")) && bytes.Contains(rs.body, []byte(`"error"`)), "body %s", rs.body))
			}
			return dev2
		}()
	}
	if live != nil {
		live.conn.Close()
		for range live.frames {
		}
	}
	hello.Resume = nil
	var dev3 *extDev
	if r.runs(lmbp.ProfileReliable, "Z2") {
		dev3 = r.auditFlow(ctx, key, at, hello, full(mTools))
	}
	if dev3 == nil {
		dev3 = r.redial(key, at, hello)
	}
	if dev3 != nil {
		dev3 = r.auditFrameLimits(ctx, key, at, hello, full(mTools), dev3)
	}
	if dev3 == nil {
		dev3 = r.redial(key, at, hello)
	}
	if dev3 == nil {
		return nil, nil
	}
	if dev3 = r.auditQueuedDuplicate(ctx, key, at, hello, full(mTools), dev3); dev3 == nil {
		return nil, nil
	}
	return dev3.conn, dev3.frames
}
