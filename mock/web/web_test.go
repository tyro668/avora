package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestWrapServesUIAndPassesAPI(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "api") })
	h := Wrap(api)
	for path, want := range map[string]string{"/": "text/html", "/chat": "text/html", "/chat/chat.js": "text/javascript", "/chat/qrcode.js": "text/javascript"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), want) || rec.Header().Get("Content-Security-Policy") != CSP {
			t.Fatalf("%s: %d %v", path, rec.Code, rec.Header())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/models", nil))
	if rec.Body.String() != "api" {
		t.Fatal("API path not passed through")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/chat", nil))
	if rec.Code != 404 {
		t.Fatal("POST /chat should 404")
	}
}

// The Node and Python SDK engines serve the same files with the same CSP.
func TestSiblingImplementationsShareCSP(t *testing.T) {
	for _, f := range []string{"../../sdk/node/src/engine/gateway.js", "../../sdk/python/src/lmbp_server/engine.py"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		flat := strings.NewReplacer("\"\n           \"", "", "\" \"", "").Replace(string(b))
		if !strings.Contains(flat, CSP) {
			t.Errorf("%s: CSP differs from web.CSP", f)
		}
		for p := range Files {
			if !strings.Contains(string(b), "'"+p+"'") && !strings.Contains(string(b), "\""+p+"\"") {
				t.Errorf("%s: missing UI path %s", f, p)
			}
		}
	}
}

func TestChatUILayoutRequirements(t *testing.T) {
	hb, err := files.ReadFile("chat.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(hb)
	if strings.Contains(html, `id="qr"`) {
		t.Fatal("chat.html should not render QR code container")
	}
	for _, want := range []string{`id="pairLink"`, `id="copyLink"`, `id="copyCmd"`, `id="pairModal"`, `class="modal-mask hidden"`, `id="devModal"`, `id="advToggle"`, `id="hist"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("chat.html missing %s", want)
		}
	}
	barIdx := strings.Index(html, `<div class="composer-bar">`)
	modelIdx := strings.Index(html, `id="model"`)
	sendIdx := strings.Index(html, `id="send"`)
	if barIdx < 0 || modelIdx < barIdx || sendIdx < modelIdx {
		t.Fatalf("model selector must be inside .composer-bar before #send (bar=%d model=%d send=%d)", barIdx, modelIdx, sendIdx)
	}
	jb, err := files.ReadFile("chat.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(jb)
	if strings.Contains(js, "pending_pairings") {
		t.Fatal("chat.js must not read pending_pairings (pending pairings are never listed; review 2026-10-29)")
	}
	for _, want := range []string{"设备自报名称", "revoked-group", "revoked-toggle", "openPairModal", "closePairModal", "localStorage", "X-Task-Id", "tool_calls"} {
		if !strings.Contains(js, want) {
			t.Fatalf("chat.js missing %s", want)
		}
	}
}

// Model text must never be parsed as HTML: chat.js may use innerHTML only for
// its constant icon markup, never with message content.
func TestChatJSNoHTMLInjection(t *testing.T) {
	jb, _ := files.ReadFile("chat.js")
	for _, line := range strings.Split(string(jb), "\n") {
		if strings.Contains(line, "innerHTML") && !strings.Contains(line, "<svg") {
			t.Fatalf("unexpected innerHTML use: %s", strings.TrimSpace(line))
		}
		if strings.Contains(line, "insertAdjacentHTML") || strings.Contains(line, "document.write") {
			t.Fatalf("unexpected HTML sink: %s", strings.TrimSpace(line))
		}
	}
}

// TestChatJSUnit runs the Node unit tests of chat.js's pure helpers
// (Markdown, highlighting, tool_calls merging, step timeline, history).
func TestChatJSUnit(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "--test", "test/chat.test.mjs").CombinedOutput()
	if err != nil {
		t.Fatalf("node --test failed: %v\n%s", err, out)
	}
}
