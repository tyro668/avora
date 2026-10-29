package gateway

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
)

// Review7 #4: a device tool-call index that is negative or huge must be
// rejected on ingress (no panic, no giant allocation) for both the OpenAI
// and Anthropic non-streaming aggregations.
func TestDeviceToolCallIndexValidated(t *testing.T) {
	r := newRig(t, lmbp.Flow{TaskWindow: lmbp.DefaultTaskWindow, ConnWindow: lmbp.DefaultConnWindow}, 1, time.Millisecond)
	for _, idx := range []int{-1, 1 << 30, lmbp.MaxToolCallIndex + 1} {
		for _, path := range []string{"/v1/chat/completions", "/v1/messages"} {
			body := map[string]any{"model": r.model("badidx"), "max_tokens": 10, "messages": []map[string]string{{"role": "user", "content": strconv.Itoa(idx)}}}
			code, m := r.api(t, "POST", path, body, nil)
			if code == 200 || !strings.Contains(strings.ToLower(toString(m)), "invalid") {
				t.Fatalf("%s idx %d: %d %v", path, idx, code, m)
			}
		}
	}
	// a valid index still works
	code, m := r.api(t, "POST", "/v1/chat/completions", map[string]any{"model": r.model("badidx"), "messages": []map[string]string{{"role": "user", "content": "3"}}}, nil)
	if code != 200 {
		t.Fatalf("valid index: %d %v", code, m)
	}
}

func toString(m map[string]any) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		b.WriteString("=")
		if mm, ok := v.(map[string]any); ok {
			b.WriteString(toString(mm))
		} else if s, ok := v.(string); ok {
			b.WriteString(s)
		}
		b.WriteString(";")
	}
	return b.String()
}
