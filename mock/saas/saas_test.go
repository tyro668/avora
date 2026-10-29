package saas

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The device list shows device_name and model ids, which a device chooses
// itself: they must reach the page as text, never as HTML (review 2026-10-29,
// P1-3). The test runs the page's own script in Node against a minimal DOM
// that records every innerHTML write and every element created.
func TestHomeRendersDeviceNamesAsText(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	var buf bytes.Buffer
	if err := page.ExecuteTemplate(&buf, "home", map[string]string{"User": "alice", "Tenant": "acme", "Public": "http://127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script>(.*)</script>`).FindStringSubmatch(buf.String())
	if m == nil {
		t.Fatal("home page has no script")
	}
	harness := `
const evil = '<img src=x onerror="globalThis.pwned=1">';
const created = [], htmlWrites = [];
function mk(tag) {
  const e = { tag, children: [], style: {}, value: '', title: '', _text: '',
    get textContent() { return this._text + this.children.map((c) => typeof c === 'string' ? c : c.textContent).join(''); },
    set textContent(v) { this._text = String(v); this.children = []; },
    set innerHTML(v) { htmlWrites.push(String(v)); },
    append(...c) { this.children.push(...c); }, replaceChildren(...c) { this.children = c; },
    addEventListener() {}, click() {}, scrollTop: 0, scrollHeight: 0 };
  created.push(e); return e;
}
const byId = {};
globalThis.document = { getElementById: (id) => (byId[id] ||= mk('#' + id)), createElement: mk };
globalThis.setInterval = () => 0;
globalThis.fetch = async (u) => ({ json: async () => u === '/api/devices'
  ? { devices: [{ device_id: 'dev_1', name: evil, online: true, models: [evil] }] }
  : { data: [{ id: 'dev_1/' + evil }] } });
` + m[1] + `
setTimeout(() => {
  const all = created.map((e) => e.textContent).join('\n');
  const ok = htmlWrites.length === 0 && byId.devices.textContent.includes(evil) && byId.model.textContent.includes(evil)
    && created.some((e) => e.tag === 'b' && e.textContent === evil && e.title.includes('设备自报名称'));
  console.log(JSON.stringify({ ok, htmlWrites, devices: byId.devices.textContent }));
  process.exit(ok ? 0 : 1);
}, 50);
`
	f := filepath.Join(t.TempDir(), "home.mjs")
	if err := os.WriteFile(f, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, f).CombinedOutput()
	if err != nil {
		t.Fatalf("device data reached the page as HTML: %v\n%s", err, out)
	}
}

// The link page labels the approved device's name as reported by the device;
// html/template escapes it.
func TestLinkResultLabelsDeviceName(t *testing.T) {
	var buf bytes.Buffer
	data := map[string]any{"User": "alice", "Result": map[string]any{"status": "approved", "device_name": `<b>x</b>`, "device_id": "dev_1"}}
	if err := page.ExecuteTemplate(&buf, "link", data); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "设备自报名称：&lt;b&gt;x&lt;/b&gt;") {
		t.Fatalf("link result does not label/escape the device name:\n%s", s)
	}
}
