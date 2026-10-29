package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/store"
)

// models lists "device_id/model" plus bare model names for the caller's own
// online devices only (tenant + owner scoped).
func (g *Gateway) models(w http.ResponseWriter, r *http.Request) {
	t, user, ok := g.tenantAuth(w, r)
	if !ok {
		return
	}
	ds, err := g.cfg.Store.ListDevices(r.Context(), t.ID, user)
	if err != nil {
		apiError(w, 500, lmbp.ErrInternal, "storage error")
		return
	}
	data := []map[string]any{}
	for _, d := range ds {
		if s := g.online(d.ID); s != nil && d.Status == "active" {
			names := s.names()
			for _, m := range s.modelList() {
				caps := s.modelCaps()[m]
				if caps == nil {
					caps = []string{}
				}
				item := map[string]any{"id": d.ID + "/" + m, "object": "model", "owned_by": d.Name, "capabilities": caps}
				if n := names[m]; n != "" {
					item["display_name"] = n
				}
				data = append(data, item)
			}
		}
	}
	if r.Header.Get("Anthropic-Version") != "" {
		anthropicModels(w, data)
		return
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": data})
}

// resolve picks the caller's device for "device_id/model" or a bare model name.
func (g *Gateway) resolve(ctx context.Context, tenant, user, model string) (*dstate, string, string, int) {
	ds, err := g.cfg.Store.ListDevices(ctx, tenant, user)
	if err != nil {
		return nil, "", lmbp.ErrInternal, 500
	}
	want, bare := model, true
	devID := ""
	if i := strings.Index(model, "/"); i > 0 && strings.HasPrefix(model, "dev_") {
		devID, want, bare = model[:i], model[i+1:], false
	}
	known, up := false, false
	for _, d := range ds {
		if d.Status != "active" || (!bare && d.ID != devID) {
			continue
		}
		known = known || !bare
		if s := g.online(d.ID); s != nil {
			if contains(s.modelList(), want) {
				return s, want, "", 0
			}
			up = true
		}
	}
	// §6.6: a named device that is online but does not declare the model is
	// MODEL_NOT_FOUND (404, not retryable); only an offline one is 503.
	if known && !up {
		return nil, "", lmbp.ErrDeviceOffline, 503
	}
	if known {
		return nil, "", lmbp.ErrModelNotFound, 404
	}
	if len(ds) > 0 && bare {
		online := false
		for _, d := range ds {
			online = online || g.online(d.ID) != nil
		}
		if !online {
			return nil, "", lmbp.ErrDeviceOffline, 503
		}
	}
	return nil, "", lmbp.ErrModelNotFound, 404
}

type chatRequest struct {
	Model       string          `json:"model"`
	Messages    []lmbp.Message  `json:"messages"`
	Tools       []lmbp.Tool     `json:"tools,omitempty"`
	ToolChoice  json.RawMessage `json:"tool_choice,omitempty"`
	Stream      bool            `json:"stream"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
	// E2EE is a JWE (compact) sealing an lmbp.E2EERequest to the device's
	// X25519 key; when set, messages/tools MUST be absent (gateway is blind).
	E2EE string `json:"lmbp_e2ee,omitempty"`
	// Unknown OpenAI fields are ignored rather than rejected.
}

type blobData struct {
	ref  lmbp.BlobRef
	data []byte
}

var statusOf = map[string]int{
	lmbp.ErrBadRequest: 400, lmbp.ErrUnsupported: 400, lmbp.ErrPayloadTooLarge: 413, lmbp.ErrIdempotency: 422,
	lmbp.ErrModelNotFound: 404, lmbp.ErrDeviceOffline: 503, lmbp.ErrDeviceBusy: 429, lmbp.ErrTimeout: 504,
	lmbp.ErrCancelled: 499, lmbp.ErrRateLimited: 429, lmbp.ErrUnauthenticated: 401, lmbp.ErrForbidden: 403,
}

func errStatus(code string) int {
	if s, ok := statusOf[code]; ok {
		return s
	}
	return 502
}

// extractBlobs moves large inline binaries (data: URIs, input_audio) out of
// the messages into blobs and checks URL schemes and size limits.
func extractBlobs(msgs []lmbp.Message) ([]blobData, bool, bool, string, string) {
	var blobs []blobData
	var total int64
	vision, audio := false, false
	add := func(data []byte, mt string) (string, string) {
		if len(data) > lmbp.MaxBlobBytes {
			return "", lmbp.ErrPayloadTooLarge
		}
		total += int64(len(data))
		if total > lmbp.MaxTaskBlobBytes {
			return "", lmbp.ErrPayloadTooLarge
		}
		h := sha256.Sum256(data)
		id := lmbp.RandomID("blob_")
		blobs = append(blobs, blobData{ref: lmbp.BlobRef{ID: id, Size: int64(len(data)), SHA256: lmbp.B64(h[:]), MediaType: mt}, data: data})
		return lmbp.BlobScheme + id, ""
	}
	for i := range msgs {
		for j := range msgs[i].Content.Parts {
			p := &msgs[i].Content.Parts[j]
			switch p.Type {
			case "text":
			case "image_url":
				vision = true
				if p.ImageURL == nil {
					return nil, false, false, lmbp.ErrBadRequest, "image_url part without url"
				}
				u := p.ImageURL.URL
				switch {
				case strings.HasPrefix(u, "https://"):
				case strings.HasPrefix(u, "data:"):
					comma := strings.IndexByte(u, ',')
					meta := u[5:max(comma, 5)]
					if comma < 0 || !strings.HasSuffix(meta, ";base64") || !strings.HasPrefix(meta, "image/") {
						return nil, false, false, lmbp.ErrBadRequest, "image data URI must be data:image/*;base64,"
					}
					if len(u) <= lmbp.InlineDataURIBytes {
						continue
					}
					raw, err := base64.StdEncoding.DecodeString(u[comma+1:])
					if err != nil {
						return nil, false, false, lmbp.ErrBadRequest, "invalid base64 in image data URI"
					}
					ref, code := add(raw, strings.TrimSuffix(meta, ";base64"))
					if code != "" {
						return nil, false, false, code, "image exceeds size limits"
					}
					p.ImageURL.URL = ref
				default:
					return nil, false, false, lmbp.ErrBadRequest, "image_url must be https:// or a data: URI"
				}
			case "input_audio":
				audio = true
				if p.InputAudio == nil || (p.InputAudio.Format != "wav" && p.InputAudio.Format != "mp3") {
					return nil, false, false, lmbp.ErrBadRequest, "input_audio needs data and format wav|mp3"
				}
				if len(p.InputAudio.Data) <= lmbp.InlineDataURIBytes {
					continue
				}
				raw, err := base64.StdEncoding.DecodeString(p.InputAudio.Data)
				if err != nil {
					return nil, false, false, lmbp.ErrBadRequest, "invalid base64 in input_audio"
				}
				ref, code := add(raw, "audio/"+p.InputAudio.Format)
				if code != "" {
					return nil, false, false, code, "audio exceeds size limits"
				}
				p.InputAudio.Data = ref
			default:
				return nil, false, false, lmbp.ErrBadRequest, "unsupported content part " + p.Type
			}
		}
	}
	return blobs, vision, audio, "", ""
}

func (g *Gateway) chat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, 405, lmbp.ErrBadRequest, "POST required")
		return
	}
	t, user, ok := g.tenantAuth(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 48<<20+1))
	if err != nil || len(body) > 48<<20 {
		apiError(w, 413, lmbp.ErrPayloadTooLarge, "request body too large")
		return
	}
	// Every parameter is validated before anything is stored, queued or
	// signed (third audit #2; spec/testvectors/params.json).
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil || raw == nil {
		apiError(w, 400, lmbp.ErrBadRequest, "invalid JSON body")
		return
	}
	params, perr := ValidateChatParams(raw)
	if perr != nil {
		writeParamError(w, perr)
		return
	}
	var req chatRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&req); err != nil || req.Model == "" {
		apiError(w, 400, lmbp.ErrBadRequest, "invalid JSON body or missing model")
		return
	}
	// Idempotent re-attach.
	idemKey := r.Header.Get("Idempotency-Key")
	if idemKey != "" && !lmbp.ValidHeaderValue(idemKey, 255) { // 1-255 printable ASCII (§4.1)
		apiError(w, 400, lmbp.ErrBadRequest, "Idempotency-Key must be 1-255 printable ASCII characters")
		return
	}
	bh := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(bh[:])
	if idemKey != "" {
		if rec, err := g.cfg.Store.GetIdempotency(r.Context(), t.ID, user, idemKey); err == nil {
			if rec.BodyHash != bodyHash {
				apiError(w, 422, lmbp.ErrIdempotency, "Idempotency-Key was used with a different request body")
				return
			}
			g.reattach(w, r, t.ID, user, rec.TaskID, req.Model, req.Stream)
			return
		}
	}
	if req.E2EE != "" {
		if len(req.Messages) > 0 || len(req.Tools) > 0 {
			apiError(w, 400, lmbp.ErrBadRequest, "lmbp_e2ee requests must not carry cleartext messages or tools")
			return
		}
	} else {
		if len(req.Messages) == 0 || len(req.Messages) > lmbp.MaxMessages {
			apiError(w, 400, lmbp.ErrBadRequest, fmt.Sprintf("1-%d messages required", lmbp.MaxMessages))
			return
		}
		for _, m := range req.Messages {
			switch m.Role {
			case "system", "user", "assistant", "tool", "developer":
			default:
				apiError(w, 400, lmbp.ErrBadRequest, "unsupported role "+m.Role)
				return
			}
			if m.Role == "tool" && m.ToolCallID == "" {
				apiError(w, 400, lmbp.ErrBadRequest, "tool messages need tool_call_id")
				return
			}
		}
	}
	ds, model, code, status := g.resolve(r.Context(), t.ID, user, req.Model)
	if ds == nil {
		apiError(w, status, code, map[string]string{lmbp.ErrDeviceOffline: "your device is offline", lmbp.ErrModelNotFound: "model not found on your devices", lmbp.ErrInternal: "storage error"}[code])
		return
	}
	run := lmbp.TaskRun{DeviceID: ds.deviceID, Model: model, MaxTokens: params.MaxTokens, Temperature: params.Temperature, TopP: params.TopP, Stop: params.Stop}
	// Per-model parameter support (§16.4): a model that declares it ("params")
	// gets every other parameter rejected, like tools/images/audio. The
	// Messages API makes max_tokens mandatory, so there it is dropped instead
	// (the model cannot honour it). Undeclared models: the device enforces.
	if ds.modelHas(model, lmbp.ModelCapParams) {
		if run.MaxTokens > 0 && isAnthropic(w) && !ds.modelHas(model, lmbp.ModelCapMaxTokens) {
			run.MaxTokens = 0
		}
		for _, p := range []struct {
			flag string
			set  bool
		}{{lmbp.ModelCapTemperature, run.Temperature != nil}, {lmbp.ModelCapTopP, run.TopP != nil}, {lmbp.ModelCapStop, len(run.Stop) > 0}, {lmbp.ModelCapMaxTokens, run.MaxTokens > 0}} {
			if p.set && !ds.modelHas(model, p.flag) {
				name := p.flag
				if isAnthropic(w) && name == lmbp.ModelCapStop {
					name = "stop_sequences"
				}
				apiError(w, 400, lmbp.ErrUnsupported, "model "+model+" does not support the "+name+" parameter")
				return
			}
		}
	}
	var blobs []blobData
	if req.E2EE != "" {
		if !ds.has(lmbp.CapE2EE) {
			apiError(w, 400, lmbp.ErrUnsupported, "device does not support end-to-end encryption")
			return
		}
		if strings.Count(req.E2EE, ".") != 4 || len(req.E2EE) > lmbp.MaxTaskBlobBytes {
			apiError(w, 400, lmbp.ErrBadRequest, "lmbp_e2ee must be a compact JWE")
			return
		}
		h := sha256.Sum256([]byte(req.E2EE))
		id := lmbp.RandomID("blob_")
		blobs = []blobData{{ref: lmbp.BlobRef{ID: id, Size: int64(len(req.E2EE)), SHA256: lmbp.B64(h[:]), MediaType: "application/jose"}, data: []byte(req.E2EE)}}
		run.E2EE = &lmbp.E2EERef{Blob: id}
	} else {
		var vision, audio bool
		var msg string
		blobs, vision, audio, code, msg = extractBlobs(req.Messages)
		if code != "" {
			apiError(w, errStatus(code), code, msg)
			return
		}
		if len(req.Tools) > 0 || len(req.ToolChoice) > 0 {
			if !ds.has(lmbp.CapTools) || !ds.modelHas(model, lmbp.ModelCapTools) {
				apiError(w, 400, lmbp.ErrUnsupported, "model "+model+" does not support tools")
				return
			}
			for _, tl := range req.Tools {
				if tl.Type != "function" || tl.Function.Name == "" {
					apiError(w, 400, lmbp.ErrBadRequest, "tools must be type function with a name")
					return
				}
			}
		}
		if (vision || audio) && !ds.has(lmbp.CapMultimodal) {
			apiError(w, 400, lmbp.ErrUnsupported, "device does not support multimodal input")
			return
		}
		if vision && !ds.modelHas(model, lmbp.ModelCapVision) {
			apiError(w, 400, lmbp.ErrUnsupported, "model "+model+" does not accept images")
			return
		}
		if audio && !ds.modelHas(model, lmbp.ModelCapAudio) {
			apiError(w, 400, lmbp.ErrUnsupported, "model "+model+" does not accept audio")
			return
		}
		run.Messages, run.Tools, run.ToolChoice = req.Messages, req.Tools, req.ToolChoice
	}
	for _, b := range blobs {
		run.Blobs = append(run.Blobs, b.ref)
	}

	taskID := lmbp.RandomID("task_")
	// Stage 2/3 of the limits (spec §10): the signed task.run, encoded as a
	// frame, MUST fit max_frame_bytes. Checked with same-length values before
	// anything is stored or queued.
	{
		trial := run
		n := time.Now()
		trial.TaskID, trial.Iat, trial.Exp, trial.Nonce = taskID, n.Unix(), n.Add(time.Minute).Unix(), lmbp.RandomID("n_")
		if size := lmbp.TaskRunFrameSize(lmbp.SignTaskRun(g.cfg.SigningKey, g.kid, trial), taskID); size > lmbp.MaxFrameBytes {
			apiError(w, 413, lmbp.ErrPayloadTooLarge, fmt.Sprintf("request too large: the signed task.run frame would be %d bytes, over max_frame_bytes %d; send large content as images/attachments", size, lmbp.MaxFrameBytes))
			return
		}
		// The payload that will be signed MUST satisfy the published schema.
		if e := ValidateTaskRun(trial); e != nil {
			writeParamError(w, e)
			return
		}
	}
	// Register the in-memory hub first (state "pending" until it gets a
	// device slot): from the moment the idempotency record exists, a
	// duplicate re-attaches to this live task (reattach checks memory before
	// storage) instead of finding a half-created or event-less task and
	// answering 404 / OUTCOME_UNKNOWN. Every way out of the queue below ends
	// the task with a recorded terminal event, so replays see the same outcome.
	task := g.newTask(ds, taskID, t.ID, user, req.Model, run.E2EE != nil, idemKey != "")
	// What is stored: the routed request without large binaries; for E2EE only
	// cleartext metadata (the sealed request is never persisted).
	stored, _ := json.Marshal(run)
	if run.E2EE != nil {
		stored, _ = json.Marshal(map[string]any{"model": model, "e2ee": true, "max_tokens": req.MaxTokens})
	}
	now := time.Now()
	var idem *store.Idempotency
	if idemKey != "" {
		idem = &store.Idempotency{TenantID: t.ID, OwnerID: user, Key: idemKey, TaskID: taskID, BodyHash: bodyHash, CreatedAt: now}
	}
	// Task row and idempotency record in one transaction: a crash can never
	// leave a key that points at no task.
	if err := g.cfg.Store.CreateTask(r.Context(), store.Task{ID: taskID, TenantID: t.ID, OwnerID: user, DeviceID: ds.deviceID, Model: model, State: "QUEUED", Request: stored, CreatedAt: now, UpdatedAt: now}, idem); err != nil {
		task.abandon()
		if err == store.ErrExists && idem != nil { // lost a race with a concurrent request using the same key
			if rec, err := g.cfg.Store.GetIdempotency(r.Context(), t.ID, user, idemKey); err == nil && rec.BodyHash == bodyHash {
				g.reattach(w, r, t.ID, user, rec.TaskID, req.Model, req.Stream)
				return
			}
			apiError(w, 422, lmbp.ErrIdempotency, "Idempotency-Key was used with a different request body")
			return
		}
		apiError(w, 500, lmbp.ErrInternal, "storage error")
		return
	}
	// Fair FIFO wait for one of the device's negotiated concurrency slots.
	wctx, wcancel := context.WithTimeout(r.Context(), g.cfg.QueueTimeout)
	got := ds.acquire(wctx)
	wcancel()
	if !got || !ds.connected() || task.isDone() {
		if got {
			ds.release()
		}
		w.Header().Set("X-Task-Id", taskID)
		// Decide our local outcome; if another path already ended the task
		// (timeout, cancel, ...) the caller gets that recorded outcome, never
		// a made-up one. Review7 #10.
		hook(task, "queue-exit")
		switch {
		case task.isDone():
		case r.Context().Err() != nil: // caller went away while queued
			if task.failLocal(lmbp.ErrCancelled, "client disconnected while queued", false) {
				return // nobody is listening; replays see CANCELLED
			}
		case !ds.connected():
			if task.failLocal(lmbp.ErrDeviceOffline, "device disconnected", true) {
				apiError(w, 503, lmbp.ErrDeviceOffline, "device disconnected")
				return
			}
		default:
			if task.failLocal(lmbp.ErrDeviceBusy, "device is at max concurrency", true) {
				w.Header().Set("Retry-After", "2")
				apiError(w, 429, lmbp.ErrDeviceBusy, "device is at max concurrency")
				return
			}
		}
		g.serve(w, r, task, 0, req.Stream) // report what was recorded
		return
	}
	hook(task, "slot-acquired")
	// Terminal check and slot handoff in one step under task.mu: a terminal
	// path that already decided (or finished) never sees a slot it must not
	// release, and is never followed by task.run. Review9 P2-5.
	task.mu.Lock()
	ended := task.done || task.decided
	if !ended {
		task.slot = true
	}
	task.mu.Unlock()
	if ended {
		ds.release()
		w.Header().Set("X-Task-Id", taskID)
		g.serve(w, r, task, 0, req.Stream) // report what was recorded
		return
	}
	if err := g.cfg.Store.SetTaskState(context.Background(), taskID, "RUNNING"); err != nil {
		// The task row could not be marked RUNNING (storage error, or the
		// row is gone): never run a task whose state cannot be persisted.
		// failLocal releases the slot it now holds. audit3 P2-4.
		g.cfg.Logger.Printf("lmbp: task %s: persisting RUNNING: %v", taskID, err)
		w.Header().Set("X-Task-Id", taskID)
		if task.failLocal(lmbp.ErrInternal, "gateway could not persist task state", true) {
			apiError(w, 500, lmbp.ErrInternal, "storage error")
			return
		}
		g.serve(w, r, task, 0, req.Stream)
		return
	}
	run.TaskID, run.Iat, run.Exp, run.Nonce = taskID, now.Unix(), now.Add(time.Minute).Unix(), lmbp.RandomID("n_")
	jws := lmbp.SignTaskRun(g.cfg.SigningKey, g.kid, run)
	go g.dispatch(task, jws, blobs)
	w.Header().Set("X-Task-Id", taskID)
	g.serve(w, r, task, 0, req.Stream)
}

// dispatch sends task.run and then the blob chunks through the flow-controlled
// outbox (they block while the device's windows are full).
func (g *Gateway) dispatch(t *gtask, jws string, blobs []blobData) {
	t.mu.Lock()
	ended := t.done || t.decided
	if !ended {
		t.sentRun.Store(true)
	}
	t.mu.Unlock()
	if ended {
		return // decided before task.run went out: the device never runs it
	}
	if _, err := t.ds.out.Send(t.ctx, lmbp.Envelope{Type: lmbp.TypeTaskRun, TaskID: t.id, JWS: jws}); err != nil {
		t.sentRun.Store(false)
		t.failOffline(lmbp.ErrDeviceOffline, "device disconnected")
		return
	}
	for _, b := range blobs {
		for off := 0; off < len(b.data) || off == 0; off += lmbp.BlobChunkBytes {
			end := min(off+lmbp.BlobChunkBytes, len(b.data))
			data, _ := json.Marshal(lmbp.BlobChunk{BlobID: b.ref.ID, Offset: int64(off), Data: lmbp.B64(b.data[off:end]), Last: end == len(b.data)})
			if _, err := t.ds.out.Send(t.ctx, lmbp.Envelope{Type: lmbp.TypeBlobChunk, TaskID: t.id, Data: data}); err != nil {
				return // task ended or device gone (handled elsewhere)
			}
			if end == len(b.data) {
				break
			}
		}
	}
}

// reattach serves an existing task (Idempotency-Key replay / Last-Event-ID).
// reattach serves an existing task to a re-attaching caller. Every replay
// re-verifies that the stored task belongs to (tenantID, owner): an
// idempotency record or task id alone never grants access.
func (g *Gateway) reattach(w http.ResponseWriter, r *http.Request, tenantID, owner, taskID, reqModel string, stream bool) {
	// A live (possibly still pending) task is served from memory: its row
	// may not be written yet. Ownership is checked on either path.
	g.mu.Lock()
	t := g.tasks[taskID]
	g.mu.Unlock()
	if t != nil && (t.tenant != tenantID || t.owner != owner) {
		httpError(w, r, 404, lmbp.ErrBadRequest, "task no longer available")
		return
	}
	if t == nil {
		st, err := g.cfg.Store.GetTask(r.Context(), taskID)
		if err != nil || st.TenantID != tenantID || st.OwnerID != owner {
			httpError(w, r, 404, lmbp.ErrBadRequest, "task no longer available")
			return
		}
		if t, err = g.finishedTask(st, reqModel); err != nil {
			httpError(w, r, 500, lmbp.ErrInternal, "storage error")
			return
		}
	}
	after, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	w.Header().Set("X-Task-Id", taskID)
	g.serve(w, r, t, after, stream)
}

// taskEvents is GET /lmbp/v1/tenant/tasks/{id}/events: SSE re-attachment.
func (g *Gateway) taskEvents(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/lmbp/v1/tenant/tasks/")
	id, ok := strings.CutSuffix(rest, "/events")
	if !ok || r.Method != http.MethodGet || id == "" {
		httpError(w, r, 404, lmbp.ErrBadRequest, "not found")
		return
	}
	t, user, ok := g.tenantAuth(w, r)
	if !ok {
		return
	}
	st, err := g.cfg.Store.GetTask(r.Context(), id)
	if err != nil || st.TenantID != t.ID || st.OwnerID != user {
		httpError(w, r, 404, lmbp.ErrBadRequest, "task not found")
		return
	}
	g.reattach(w, r, t.ID, user, id, st.DeviceID+"/"+st.Model, true)
}

// serve renders a task's events as an OpenAI response (SSE or aggregated JSON).
func (g *Gateway) serve(w http.ResponseWriter, r *http.Request, t *gtask, after int64, stream bool) {
	if isAnthropic(w) {
		g.serveAnthropic(w, r, t, after, stream)
		return
	}
	created := t.created
	chunk := func(delta map[string]any, finish any, usage *lmbp.Usage, extra map[string]any) []byte {
		m := map[string]any{"id": "chatcmpl-" + t.id, "object": "chat.completion.chunk", "created": created, "model": t.reqModel,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
		if usage != nil {
			m["usage"] = usage
		}
		for k, v := range extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		return b
	}
	sealed := func(e event, field string) map[string]any {
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(e.Data, &raw)
		var s string
		_ = json.Unmarshal(raw[field], &s)
		if s == "" {
			return nil
		}
		return map[string]any{"lmbp_e2ee": map[string]any{"seq": e.Seq, "type": e.Type, "data": s}}
	}
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher, _ := w.(http.Flusher)
		flush := func() {
			if flusher != nil {
				flusher.Flush()
			}
		}
		if after == 0 {
			fmt.Fprintf(w, "id: 0\ndata: %s\n\n", chunk(map[string]any{"role": "assistant", "content": ""}, nil, nil, nil))
			flush()
		}
		wrote := false
		defer func() {
			// Re-attach with Last-Event-ID at or beyond the terminal event:
			// nothing left to send, but the stream still ends with its
			// terminator so clients can tell completion from truncation.
			if !wrote && r.Context().Err() == nil && t.terminal() {
				fmt.Fprint(w, "data: [DONE]\n\n")
				flush()
			}
		}()
		_ = t.stream(r.Context(), after, func() error {
			_, err := fmt.Fprint(w, ": keep-alive\n\n")
			flush()
			return err
		}, func(e event) error {
			wrote = true
			var b []byte
			tail := ""
			switch e.Type {
			case lmbp.TypeTaskDelta:
				var d lmbp.TaskDelta
				_ = json.Unmarshal(e.Data, &d)
				if t.e2ee {
					b = chunk(map[string]any{}, nil, nil, sealed(e, "e2ee"))
				} else {
					delta := map[string]any{}
					if d.Text != "" {
						delta["content"] = d.Text
					}
					if len(d.ToolCalls) > 0 {
						delta["tool_calls"] = d.ToolCalls
					}
					b = chunk(delta, nil, nil, nil)
				}
			case lmbp.TypeTaskDone:
				var d lmbp.TaskDone
				_ = json.Unmarshal(e.Data, &d)
				if d.FinishReason == "" {
					d.FinishReason = "stop"
				}
				var extra map[string]any
				if t.e2ee {
					extra = sealed(e, "e2ee")
				}
				b, tail = chunk(map[string]any{}, d.FinishReason, d.Usage, extra), "data: [DONE]\n\n"
			case lmbp.TypeTaskError:
				var eb lmbp.ErrorBody
				_ = json.Unmarshal(e.Data, &eb)
				b, _ = json.Marshal(map[string]any{"error": map[string]any{"message": eb.Message, "type": "lmbp_error", "code": eb.Code, "retryable": eb.Retryable}})
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n%s", e.Seq, b, tail); err != nil {
				return err
			}
			flush()
			return nil
		})
		return
	}
	// Non-streaming aggregation. A resume cursor (Last-Event-ID) has no
	// meaning for one aggregated JSON body: it always covers the whole task,
	// so an idempotent replay returns the same complete response (audit3 P2-3).
	var text strings.Builder
	var calls []lmbp.ToolCall
	var sealedFrames []any
	var done *lmbp.TaskDone
	var fail *lmbp.ErrorBody
	err := t.stream(r.Context(), 0, nil, func(e event) error {
		switch e.Type {
		case lmbp.TypeTaskDelta:
			if t.e2ee {
				sealedFrames = append(sealedFrames, sealed(e, "e2ee")["lmbp_e2ee"])
				return nil
			}
			var d lmbp.TaskDelta
			_ = json.Unmarshal(e.Data, &d)
			text.WriteString(d.Text)
			for _, c := range d.ToolCalls {
				idx := 0
				if c.Index != nil {
					idx = *c.Index
				}
				if idx < 0 || idx > lmbp.MaxToolCallIndex {
					continue // rejected on ingress; never index with it
				}
				for len(calls) <= idx {
					calls = append(calls, lmbp.ToolCall{Type: "function"})
				}
				if c.ID != "" {
					calls[idx].ID = c.ID
				}
				calls[idx].Function.Name += c.Function.Name
				calls[idx].Function.Arguments += c.Function.Arguments
			}
		case lmbp.TypeTaskDone:
			done = &lmbp.TaskDone{}
			_ = json.Unmarshal(e.Data, done)
			if t.e2ee {
				if s := sealed(e, "e2ee"); s != nil {
					sealedFrames = append(sealedFrames, s["lmbp_e2ee"])
				}
			}
		case lmbp.TypeTaskError:
			fail = &lmbp.ErrorBody{}
			_ = json.Unmarshal(e.Data, fail)
		}
		return nil
	})
	if err != nil {
		return
	}
	if fail != nil {
		apiError(w, errStatus(fail.Code), fail.Code, fail.Message)
		return
	}
	if done == nil { // never dereference a missing terminal event
		apiError(w, 500, lmbp.ErrInternal, "task ended without a terminal event")
		return
	}
	if done.FinishReason == "" {
		done.FinishReason = "stop"
	}
	msg := map[string]any{"role": "assistant", "content": text.String()}
	if len(calls) > 0 {
		msg["tool_calls"] = calls
		if text.Len() == 0 {
			msg["content"] = nil
		}
	}
	resp := map[string]any{"id": "chatcmpl-" + t.id, "object": "chat.completion", "created": created, "model": t.reqModel,
		"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": done.FinishReason}}}
	if t.e2ee {
		resp["choices"] = []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": nil}, "finish_reason": done.FinishReason}}
		resp["lmbp_e2ee"] = sealedFrames
	}
	if done.Usage != nil {
		resp["usage"] = done.Usage
	}
	writeJSON(w, 200, resp)
}
