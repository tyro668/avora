package conformance

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
)

// Hardening checks (§6.2–§6.4, §18.1): untrusted device_name, unknown tenants,
// pending pairings never listed, single-use approval, per-user failure
// counting, the slow_down cap and a forged Host.

// tenantAs is r.tenant with another X-End-User.
func (r *runner) tenantAs(user, method, path string, body any) (int, map[string]any) {
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, r.cfg.GatewayURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+r.cfg.TenantKey)
	req.Header.Set("X-End-User", user)
	req.Header.Set("Content-Type", "application/json")
	st, m, _, _ := r.do(req)
	return st, m
}

func (r *runner) authorizeNew(name string) (int, map[string]any) {
	pub, _, _ := ed25519.GenerateKey(nil)
	st, m, _, _ := r.form("/lmbp/v1/device/authorize", url.Values{"tenant": {r.cfg.Tenant}, "public_key": {lmbp.B64(pub)}, "device_name": {name}})
	return st, m
}

// runHardenPairing runs L4, P9, P10, P11, P12 and P13. pendingCode is a
// user_code that is pending right now (P1).
func (r *runner) runHardenPairing(pendingCode string) {
	st, _ := r.authorizeNew("Office PC\u202Egpj.exe")
	st2, _ := r.authorizeNew("a\nb")
	r.check("L4", "device_name with a control or bidi format character (U+202E, LF) is rejected with 400 invalid_request (§6.2)",
		want(st == 400 && st2 == 400, "U+202E → %d, LF → %d", st, st2))

	pub, _, _ := ed25519.GenerateKey(nil)
	st, m, _, _ := r.form("/lmbp/v1/device/authorize", url.Values{"tenant": {"no-such-tenant-" + strings.ToLower(lmbp.RandomID(""))}, "public_key": {lmbp.B64(pub)}})
	r.check("P9", "device authorization for an unregistered tenant is refused with 400 invalid_client (§6.2)",
		want(st == 400 && m["error"] == "invalid_client", "status %d body %v", st, m))

	st, dl, _, _ := r.tenant(http.MethodGet, "/lmbp/v1/tenant/devices", nil)
	b, _ := json.Marshal(dl)
	_, hasPending := dl["pending_pairings"]
	r.check("P10", "the tenant device list never exposes pending pairings (no pending_pairings, no user_code) (§6.4, §12.6)",
		want(st == 200 && !hasPending && !strings.Contains(string(b), pendingCode) && !strings.Contains(string(b), strings.ReplaceAll(pendingCode, "-", "")), "status %d body %s", st, b))

	// P11: concurrent approvals of one user_code: exactly one wins.
	_, a := r.authorizeNew("lmbp-conformance-race")
	uc, _ := a["user_code"].(string)
	user := "conformance-race-" + lmbp.RandomID("")
	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = r.tenantAs(user, http.MethodPost, "/lmbp/v1/tenant/devices/approvals", map[string]any{"user_code": uc})
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	r.check("P11", "concurrent approvals of one user_code: exactly one succeeds (single use, §6.4)", want(uc != "" && ok == 1, "user_code %q statuses %v", uc, codes))

	// P12: wrong codes are counted per end user.
	ua, ub := "conformance-lock-a-"+lmbp.RandomID(""), "conformance-lock-b-"+lmbp.RandomID("")
	var seq []int
	for i := 0; i < 11; i++ {
		s, _ := r.tenantAs(ua, http.MethodPost, "/lmbp/v1/tenant/devices/approvals", map[string]any{"user_code": "BBBB-BBBB"})
		seq = append(seq, s)
	}
	sb, _ := r.tenantAs(ub, http.MethodPost, "/lmbp/v1/tenant/devices/approvals", map[string]any{"user_code": "BBBB-BBBB"})
	lockOK := seq[10] == 429 && sb == 404
	for _, s := range seq[:10] {
		lockOK = lockOK && s == 404
	}
	r.check("P12", "approval failures are counted per end user: the 11th wrong code in a minute is 429 for that user only; another user of the tenant still gets 404 (§6.4, §10)",
		want(lockOK, "user A %v, user B %d", seq, sb))

	// P13: a device that ignores slow_down loses its device_code.
	pub, key, _ := ed25519.GenerateKey(nil)
	_, a, _, _ = r.form("/lmbp/v1/device/authorize", url.Values{"tenant": {r.cfg.Tenant}, "public_key": {lmbp.B64(pub)}, "device_name": {"lmbp-conformance-poll"}})
	dc, _ := a["device_code"].(string)
	var errs []string
	expired := false
	for i := 0; i < 15 && !expired; i++ {
		_, tm, _, _ := r.form("/lmbp/v1/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {dc}, "proof": {lmbp.SignProof(key, "", lmbp.ProofToken, dc, time.Now())}})
		e, _ := tm["error"].(string)
		errs = append(errs, e)
		expired = e == "expired_token"
	}
	slow := 0
	for _, e := range errs {
		if e == "slow_down" {
			slow++
		}
	}
	r.check("P13", "a device that keeps polling after slow_down gets expired_token once more than 10 slow_down responses were sent (§6.3, §10)",
		want(dc != "" && expired && slow == 10, "responses %v", errs))
}

// checkForgedHost (M9, §18.1): a request whose Host names another origin
// never yields that origin as issuer.
func (r *runner) checkForgedHost() {
	req, _ := http.NewRequest(http.MethodGet, r.cfg.GatewayURL+lmbp.MetadataPath, nil)
	req.Host = "forged.invalid"
	st, m, _, err := r.do(req)
	iss, _ := m["issuer"].(string)
	r.check("M9", "metadata requested with a forged Host still carries the configured issuer (or is refused); the issuer is never derived from Host (§18.1)",
		want(err == nil && !strings.Contains(iss, "forged.invalid") && (st >= 400 || iss == r.issuer), "status %d issuer %q err %v", st, iss, err))
}
