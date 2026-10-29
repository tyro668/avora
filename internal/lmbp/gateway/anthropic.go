package gateway

// Anthropic Messages compatibility (/v1/messages, docs/lmbp-spec.md §6.7).
// A Messages request is translated to the OpenAI chat shape and runs through
// the same pipeline as /v1/chat/completions (routing, signing, blobs, flow,
// resume, Idempotency-Key); only the request translation, the response
// rendering and the error shape differ. The translation is shared verbatim by
// the Node and Python SDKs.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tyro668/avora/internal/lmbp"
)

// anthropicW marks a response as Anthropic-shaped for apiError/httpError/serve.
type anthropicW struct{ http.ResponseWriter }

func (a *anthropicW) Flush() {
	if f, ok := a.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func isAnthropic(w http.ResponseWriter) bool { _, ok := w.(*anthropicW); return ok }

// AnthropicErrorType maps an HTTP status to the Anthropic error type.
func AnthropicErrorType(status int) string {
	switch status {
	case 400, 422:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 413:
		return "request_too_large"
	case 429:
		return "rate_limit_error"
	case 503, 529:
		return "overloaded_error"
	}
	return "api_error"
}

func anthropicError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"type": "error", "error": map[string]any{"type": AnthropicErrorType(status), "message": msg, "lmbp_code": code}})
}

// AnthropicToOpenAI translates a Messages request body into a chat
// completions body. The error is a client error message (400).
func AnthropicToOpenAI(in map[string]any) (map[string]any, error) {
	model, _ := in["model"].(string)
	if model == "" {
		return nil, fmt.Errorf("model: field required")
	}
	mt, ok := in["max_tokens"].(float64)
	if !ok || mt < 1 || mt != float64(int64(mt)) {
		return nil, fmt.Errorf("max_tokens: field required (positive integer)")
	}
	if _, e2ee := in["lmbp_e2ee"]; e2ee {
		return nil, fmt.Errorf("lmbp_e2ee is only supported on /v1/chat/completions")
	}
	out := map[string]any{"model": model, "max_tokens": int64(mt), "stream": in["stream"] == true}
	for _, k := range []string{"temperature", "top_p"} {
		if v, ok := in[k]; ok && v != nil {
			out[k] = v
		}
	}
	if v, ok := in["stop_sequences"]; ok && v != nil {
		out["stop"] = v
	}
	var msgs []any
	switch s := in["system"].(type) {
	case nil:
	case string:
		if s != "" {
			msgs = append(msgs, map[string]any{"role": "system", "content": s})
		}
	case []any:
		var parts []string
		for _, b := range s {
			bm, _ := b.(map[string]any)
			if bm["type"] != "text" {
				return nil, fmt.Errorf("system: only text blocks are supported")
			}
			t, _ := bm["text"].(string)
			parts = append(parts, t)
		}
		msgs = append(msgs, map[string]any{"role": "system", "content": strings.Join(parts, "\n\n")})
	default:
		return nil, fmt.Errorf("system: must be a string or an array of text blocks")
	}
	list, _ := in["messages"].([]any)
	if len(list) == 0 {
		return nil, fmt.Errorf("messages: at least one message is required")
	}
	for i, x := range list {
		m, _ := x.(map[string]any)
		role, _ := m["role"].(string)
		if role != "user" && role != "assistant" {
			return nil, fmt.Errorf("messages.%d.role: must be user or assistant", i)
		}
		if s, ok := m["content"].(string); ok {
			msgs = append(msgs, map[string]any{"role": role, "content": s})
			continue
		}
		blocks, ok := m["content"].([]any)
		if !ok {
			return nil, fmt.Errorf("messages.%d.content: must be a string or an array of blocks", i)
		}
		var parts, calls, results, toolImages []any
		var text []string
		for j, y := range blocks {
			b, _ := y.(map[string]any)
			switch b["type"] {
			case "text":
				t, _ := b["text"].(string)
				parts = append(parts, map[string]any{"type": "text", "text": t})
				text = append(text, t)
			case "image":
				url, err := anthropicImageURL(b)
				if err != nil {
					return nil, fmt.Errorf("messages.%d.content.%d.%v", i, j, err)
				}
				parts = append(parts, map[string]any{"type": "image_url", "image_url": map[string]any{"url": url}})
			case "tool_use":
				if role != "assistant" {
					return nil, fmt.Errorf("messages.%d: tool_use blocks belong to assistant messages", i)
				}
				id, _ := b["id"].(string)
				name, _ := b["name"].(string)
				args, _ := json.Marshal(b["input"])
				if b["input"] == nil {
					args = []byte("{}")
				}
				calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": string(args)}})
			case "tool_result":
				if role != "user" {
					return nil, fmt.Errorf("messages.%d: tool_result blocks belong to user messages", i)
				}
				id, _ := b["tool_use_id"].(string)
				var content string
				switch c := b["content"].(type) {
				case nil:
				case string:
					content = c
				case []any:
					// Every block is converted or the request is rejected: an
					// image never disappears silently. OpenAI-style tool
					// messages carry text only, so images follow the tool
					// results as image_url parts of the next user message.
					var ts []string
					for k, z := range c {
						zm, _ := z.(map[string]any)
						switch zm["type"] {
						case "text":
							t, _ := zm["text"].(string)
							ts = append(ts, t)
						case "image":
							u, err := anthropicImageURL(zm)
							if err != nil {
								return nil, fmt.Errorf("messages.%d.content.%d.content.%d: %v", i, j, k, err)
							}
							toolImages = append(toolImages, map[string]any{"type": "image_url", "image_url": map[string]any{"url": u}})
							ts = append(ts, fmt.Sprintf("[image %d from tool result %s: attached in the next user message]", len(toolImages), id))
						default:
							return nil, fmt.Errorf("messages.%d.content.%d.content.%d: unsupported tool_result content type %v (text and image are supported)", i, j, k, zm["type"])
						}
					}
					content = strings.Join(ts, "\n")
				default:
					return nil, fmt.Errorf("messages.%d.content.%d.content: must be a string or an array of blocks", i, j)
				}
				if b["is_error"] == true {
					content = "Error: " + content
				}
				results = append(results, map[string]any{"role": "tool", "tool_call_id": id, "content": content})
			case "thinking", "redacted_thinking":
				// not forwarded to local models
			default:
				return nil, fmt.Errorf("messages.%d.content.%d: unsupported block type %v", i, j, b["type"])
			}
		}
		msgs = append(msgs, results...)
		if len(toolImages) > 0 {
			parts = append(append([]any{map[string]any{"type": "text", "text": "Images returned by the tool results above:"}}, toolImages...), parts...)
		}
		switch {
		case role == "assistant":
			if len(text) == 0 && len(calls) == 0 {
				continue
			}
			am := map[string]any{"role": "assistant", "content": strings.Join(text, "")}
			if len(calls) > 0 {
				am["tool_calls"] = calls
				if len(text) == 0 {
					am["content"] = nil
				}
			}
			msgs = append(msgs, am)
		case len(parts) > 0:
			msgs = append(msgs, map[string]any{"role": "user", "content": parts})
		}
	}
	out["messages"] = msgs
	if tl, ok := in["tools"].([]any); ok && len(tl) > 0 {
		var tools []any
		for i, x := range tl {
			t, _ := x.(map[string]any)
			if ty, has := t["type"]; has && ty != "custom" {
				return nil, fmt.Errorf("tools.%d: server tool %v is not supported", i, ty)
			}
			name, _ := t["name"].(string)
			if name == "" {
				return nil, fmt.Errorf("tools.%d.name: field required", i)
			}
			fn := map[string]any{"name": name, "parameters": t["input_schema"]}
			if d, ok := t["description"].(string); ok {
				fn["description"] = d
			}
			tools = append(tools, map[string]any{"type": "function", "function": fn})
		}
		out["tools"] = tools
	}
	if tc, ok := in["tool_choice"].(map[string]any); ok {
		switch tc["type"] {
		case "auto":
			out["tool_choice"] = "auto"
		case "any":
			out["tool_choice"] = "required"
		case "none":
			out["tool_choice"] = "none"
		case "tool":
			out["tool_choice"] = map[string]any{"type": "function", "function": map[string]any{"name": tc["name"]}}
		}
	}
	return out, nil
}

// AnthropicStopReason maps an OpenAI finish_reason.
func AnthropicStopReason(finish string) string {
	switch finish {
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	}
	return "end_turn"
}

func (g *Gateway) messages(w http.ResponseWriter, r *http.Request) {
	aw := &anthropicW{w}
	if r.Method != http.MethodPost {
		anthropicError(aw, 405, lmbp.ErrBadRequest, "POST required")
		return
	}
	if _, _, ok := g.tenantAuth(aw, r); !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 48<<20+1))
	if err != nil || len(body) > 48<<20 {
		anthropicError(aw, 413, lmbp.ErrPayloadTooLarge, "request body too large")
		return
	}
	var in map[string]any
	if json.Unmarshal(body, &in) != nil || in == nil {
		anthropicError(aw, 400, lmbp.ErrBadRequest, "invalid JSON body")
		return
	}
	if e := ValidateAnthropicParams(in); e != nil {
		writeParamError(aw, e)
		return
	}
	out, err := AnthropicToOpenAI(in)
	if err != nil {
		anthropicError(aw, 400, lmbp.ErrBadRequest, err.Error())
		return
	}
	nb, _ := json.Marshal(out)
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(nb))
	r2.ContentLength = int64(len(nb))
	g.chat(aw, r2)
}

// serveAnthropic renders a task's events as an Anthropic Messages response.
func (g *Gateway) serveAnthropic(w http.ResponseWriter, r *http.Request, t *gtask, after int64, stream bool) {
	msgID := "msg_" + strings.TrimPrefix(t.id, "task_")
	if !stream {
		var text strings.Builder
		var calls []lmbp.ToolCall
		var done *lmbp.TaskDone
		var fail *lmbp.ErrorBody
		if err := t.stream(r.Context(), 0, nil, func(e event) error {
			switch e.Type {
			case lmbp.TypeTaskDelta:
				var d lmbp.TaskDelta
				_ = json.Unmarshal(e.Data, &d)
				text.WriteString(d.Text)
				calls = mergeToolCalls(calls, d.ToolCalls)
			case lmbp.TypeTaskDone:
				done = &lmbp.TaskDone{}
				_ = json.Unmarshal(e.Data, done)
			case lmbp.TypeTaskError:
				fail = &lmbp.ErrorBody{}
				_ = json.Unmarshal(e.Data, fail)
			}
			return nil
		}); err != nil {
			return
		}
		if fail != nil {
			anthropicError(w, errStatus(fail.Code), fail.Code, fail.Message)
			return
		}
		if done == nil { // never dereference a missing terminal event
			anthropicError(w, 500, lmbp.ErrInternal, "task ended without a terminal event")
			return
		}
		content := []any{}
		if text.Len() > 0 {
			content = append(content, map[string]any{"type": "text", "text": text.String()})
		}
		for _, c := range calls {
			content = append(content, map[string]any{"type": "tool_use", "id": c.ID, "name": c.Function.Name, "input": toolInput(c.Function.Arguments)})
		}
		usage := map[string]any{"input_tokens": 0, "output_tokens": 0}
		if done.Usage != nil {
			usage = map[string]any{"input_tokens": done.Usage.PromptTokens, "output_tokens": done.Usage.CompletionTokens}
		}
		writeJSON(w, 200, map[string]any{"id": msgID, "type": "message", "role": "assistant", "model": t.reqModel, "content": content,
			"stop_reason": AnthropicStopReason(done.FinishReason), "stop_sequence": nil, "usage": usage})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, _ := w.(http.Flusher)
	// SSE events derived from one task event are written as a group and only
	// the last one carries that task event's seq as its id, so a Last-Event-ID
	// always names a fully delivered group. On reattach the stream is replayed
	// from the start to rebuild content-block state and only groups after that
	// id are written.
	var cur int64
	var group [][2]string
	wrote := false
	defer func() {
		// Last-Event-ID at or beyond the terminal event: end with the
		// terminator (see serve) instead of an empty body.
		if !wrote && r.Context().Err() == nil && t.terminal() {
			fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		}
	}()
	send := func(typ string, v any) error {
		b, _ := json.Marshal(v)
		group = append(group, [2]string{typ, string(b)})
		return nil
	}
	flush := func() error {
		defer func() { group = group[:0] }()
		if after > 0 && cur <= after {
			return nil
		}
		wrote = true
		for i, e := range group {
			id := ""
			if i == len(group)-1 && cur > 0 {
				id = fmt.Sprintf("id: %d\n", cur)
			}
			if _, err := fmt.Fprintf(w, "event: %s\n%sdata: %s\n\n", e[0], id, e[1]); err != nil {
				return err
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	_ = send("message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": msgID, "type": "message", "role": "assistant",
		"model": t.reqModel, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0}}})
	_ = flush()
	// Content-block state (audit finding 5). Anthropic blocks are strictly
	// sequential: one open block, no delta after content_block_stop. OpenAI
	// tool_call deltas may interleave, so a live tool block stays open until
	// task.done (its arguments may continue later); content for any other
	// block arriving meanwhile is buffered and emitted, complete, at done.
	// A text block can always be closed: later text starts a new text block.
	type ablock struct {
		tool     bool
		id, name string
		buf      strings.Builder
	}
	idx, liveKind, liveTI := -1, "", -1
	var pending []*ablock
	pendingTool := map[int]*ablock{}
	toolID := func(ti int, id string) string {
		if id == "" {
			id = fmt.Sprintf("toolu_%s_%d", strings.TrimPrefix(t.id, "task_"), ti)
		}
		return id
	}
	start := func(cb map[string]any) {
		idx++
		_ = send("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": cb})
	}
	textDelta := func(s string) {
		_ = send("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "text_delta", "text": s}})
	}
	argsDelta := func(s string) {
		_ = send("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "input_json_delta", "partial_json": s}})
	}
	stop := func() {
		_ = send("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx})
	}
	closeLive := func() {
		if liveKind != "" {
			stop()
			liveKind, liveTI = "", -1
		}
	}
	finishBlocks := func() {
		closeLive()
		for _, b := range pending {
			if b.tool {
				start(map[string]any{"type": "tool_use", "id": b.id, "name": b.name, "input": map[string]any{}})
				if b.buf.Len() > 0 {
					argsDelta(b.buf.String())
				}
			} else {
				start(map[string]any{"type": "text", "text": ""})
				textDelta(b.buf.String())
			}
			stop()
		}
		pending = nil
	}
	onText := func(s string) {
		switch liveKind {
		case "text":
		case "":
			start(map[string]any{"type": "text", "text": ""})
			liveKind = "text"
		default: // a tool is live: buffer
			if n := len(pending); n > 0 && !pending[n-1].tool {
				pending[n-1].buf.WriteString(s)
			} else {
				b := &ablock{}
				b.buf.WriteString(s)
				pending = append(pending, b)
			}
			return
		}
		textDelta(s)
	}
	onTool := func(ti int, c lmbp.ToolCall) {
		if liveKind == "tool" && liveTI == ti {
			if c.Function.Arguments != "" {
				argsDelta(c.Function.Arguments)
			}
			return
		}
		if b := pendingTool[ti]; b != nil {
			if b.name == "" {
				b.name = c.Function.Name
			}
			b.buf.WriteString(c.Function.Arguments)
			return
		}
		if liveKind == "tool" { // another tool is live: buffer this one
			b := &ablock{tool: true, id: toolID(ti, c.ID), name: c.Function.Name}
			b.buf.WriteString(c.Function.Arguments)
			pending = append(pending, b)
			pendingTool[ti] = b
			return
		}
		closeLive()
		start(map[string]any{"type": "tool_use", "id": toolID(ti, c.ID), "name": c.Function.Name, "input": map[string]any{}})
		liveKind, liveTI = "tool", ti
		if c.Function.Arguments != "" {
			argsDelta(c.Function.Arguments)
		}
	}
	ping := func() error {
		if _, err := fmt.Fprint(w, "event: ping\ndata: {\"type\":\"ping\"}\n\n"); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	handle := func(e event) error {
		switch e.Type {
		case lmbp.TypeTaskDelta:
			var d lmbp.TaskDelta
			_ = json.Unmarshal(e.Data, &d)
			if d.Text != "" {
				onText(d.Text)
			}
			for _, c := range d.ToolCalls {
				ti := 0
				if c.Index != nil {
					ti = *c.Index
				}
				onTool(ti, c)
			}
		case lmbp.TypeTaskDone:
			var d lmbp.TaskDone
			_ = json.Unmarshal(e.Data, &d)
			finishBlocks()
			usage := map[string]any{"output_tokens": 0}
			if d.Usage != nil {
				usage = map[string]any{"input_tokens": d.Usage.PromptTokens, "output_tokens": d.Usage.CompletionTokens}
			}
			_ = send("message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": AnthropicStopReason(d.FinishReason), "stop_sequence": nil}, "usage": usage})
			return send("message_stop", map[string]any{"type": "message_stop"})
		case lmbp.TypeTaskError:
			var eb lmbp.ErrorBody
			_ = json.Unmarshal(e.Data, &eb)
			return send("error", map[string]any{"type": "error", "error": map[string]any{"type": AnthropicErrorType(errStatus(eb.Code)), "message": eb.Message, "lmbp_code": eb.Code}})
		}
		return nil
	}
	_ = t.stream(r.Context(), 0, ping, func(e event) error {
		cur = e.Seq
		if err := handle(e); err != nil {
			return err
		}
		return flush()
	})
}

func mergeToolCalls(calls, deltas []lmbp.ToolCall) []lmbp.ToolCall {
	for _, c := range deltas {
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
	return calls
}

func toolInput(args string) any {
	var v any
	if args == "" || json.Unmarshal([]byte(args), &v) != nil {
		return map[string]any{}
	}
	return v
}

// anthropicModels renders /v1/models in the Anthropic list shape.
func anthropicModels(w http.ResponseWriter, data []map[string]any) {
	out := []any{}
	for _, m := range data {
		dn := m["id"]
		if n, ok := m["display_name"].(string); ok && n != "" {
			dn = n
		}
		out = append(out, map[string]any{"type": "model", "id": m["id"], "display_name": dn, "created_at": "1970-01-01T00:00:00Z"})
	}
	var first, last any
	if len(out) > 0 {
		first, last = data[0]["id"], data[len(data)-1]["id"]
	}
	writeJSON(w, 200, map[string]any{"data": out, "has_more": false, "first_id": first, "last_id": last})
}

// anthropicImageURL converts an Anthropic image block's source to an
// OpenAI-compatible image URL (data: URL for base64).
func anthropicImageURL(b map[string]any) (string, error) {
	src, _ := b["source"].(map[string]any)
	switch src["type"] {
	case "base64":
		mtp, _ := src["media_type"].(string)
		d, _ := src["data"].(string)
		return "data:" + mtp + ";base64," + d, nil
	case "url":
		u, _ := src["url"].(string)
		return u, nil
	}
	return "", fmt.Errorf("source.type: base64 or url required")
}
