// net/http SaaS example: the lmbpserver SDK mounted next to your own routes.
//
// What the business code does (and nothing else):
//  1. pairing   GET /app/pair → link + QR; POST /app/pair/approve {user_code}; devices list/revoke
//  2. LLM calls the official openai-go / anthropic-sdk-go clients with their base URL pointed at
//     this server (or, as here, wired in-process via the SDK's Transport), or the SDK's own Client.
//
// Everything protocol-related (/lmbp/v1/*, /.well-known/*, /v1/*) is served by srv.Middleware.
//
//	TENANT_API_KEY=$(openssl rand -hex 24) go run .
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	aopt "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/openai/openai-go/v3"
	oopt "github.com/openai/openai-go/v3/option"

	lmbpserver "github.com/tyro668/avora/sdk/go"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	tenant := env("TENANT_ID", "acme")
	apiKey := os.Getenv("TENANT_API_KEY")
	if len(apiKey) < 32 {
		log.Fatal("set TENANT_API_KEY (>= 32 chars; server-side secret)")
	}
	profile := lmbpserver.TenantProfile{DisplayName: "Acme Chat (net/http)", RequestedScopes: []string{"lmbp.chat", "lmbp.tools", "lmbp.vision"}}
	if f := os.Getenv("TENANT_PROFILE_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		var all map[string]lmbpserver.TenantProfile
		if err := json.Unmarshal(b, &all); err != nil {
			log.Fatal(err)
		}
		profile = all[tenant]
	}
	var st lmbpserver.Store
	if db := os.Getenv("LMBP_DB"); db != "" {
		var err error
		if st, err = lmbpserver.OpenSQLiteStore(db, nil); err != nil {
			log.Fatal(err)
		}
	}
	// Finished tasks + idempotency records: 7 days unless set (negative disables).
	var retention time.Duration
	if s := os.Getenv("LMBP_RETENTION_SECONDS"); s != "" {
		n, err := strconv.ParseFloat(s, 64)
		if err != nil {
			log.Fatalf("LMBP_RETENTION_SECONDS: %v", err)
		}
		retention = time.Duration(n * float64(time.Second))
	}
	srv, err := lmbpserver.New(ctx, lmbpserver.Options{
		Tenants:   []lmbpserver.Tenant{{ID: tenant, APIKey: apiKey, Profile: profile}},
		Issuer:    os.Getenv("LMBP_ISSUER"), // REQUIRED, e.g. https://saas.example.com
		Store:     st,
		Retention: retention,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	// Official clients, unchanged. The SDK's Transport serves them in-process; with a
	// separate gateway you would use option.WithBaseURL("https://gw.example/v1") instead.
	hc := &http.Client{Transport: srv.Transport()}
	oai := openai.NewClient(oopt.WithBaseURL("http://in-process/v1/"), oopt.WithAPIKey(apiKey), oopt.WithHTTPClient(hc))
	claude := anthropic.NewClient(aopt.WithBaseURL("http://in-process/"), aopt.WithAPIKey(apiKey), aopt.WithHTTPClient(hc))

	// Your own login decides who the end user is. Demo: a header.
	user := func(r *http.Request) string { return env2(r.Header.Get("X-Demo-User"), "demo-user") }

	app := http.NewServeMux()
	// ---- 1. pairing ----
	app.HandleFunc("GET /app/pair", func(w http.ResponseWriter, r *http.Request) {
		info, err := srv.Pairing.Create(tenant)
		reply(w, map[string]string{"link": info.Link, "qr_svg": info.QRSVG}, err)
	})
	app.HandleFunc("POST /app/pair/approve", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			UserCode string `json:"user_code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		res, err := srv.Pairing.Approve(r.Context(), tenant, user(r), in.UserCode, "")
		reply(w, res, err)
	})
	app.HandleFunc("GET /app/devices", func(w http.ResponseWriter, r *http.Request) {
		ds, err := srv.Pairing.ListDevices(r.Context(), tenant, user(r))
		reply(w, ds, err)
	})
	app.HandleFunc("POST /app/devices/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		err := srv.Pairing.RevokeDevice(r.Context(), tenant, user(r), r.PathValue("id"))
		reply(w, map[string]bool{"revoked": err == nil}, err)
	})
	// ---- 2. LLM calls ----
	type ask struct{ Model, Prompt string }
	read := func(r *http.Request) (a ask) { _ = json.NewDecoder(r.Body).Decode(&a); return }
	app.HandleFunc("POST /app/ask", func(w http.ResponseWriter, r *http.Request) {
		a := read(r)
		c, err := oai.Chat.Completions.New(r.Context(), openai.ChatCompletionNewParams{Model: a.Model,
			Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage(a.Prompt)}}, oopt.WithHeader("X-End-User", user(r)))
		if err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, map[string]string{"answer": c.Choices[0].Message.Content}, nil)
	})
	app.HandleFunc("POST /app/ask/claude", func(w http.ResponseWriter, r *http.Request) {
		a := read(r)
		m, err := claude.Messages.New(r.Context(), anthropic.MessageNewParams{Model: anthropic.Model(a.Model), MaxTokens: 512,
			Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(a.Prompt))}}, aopt.WithHeader("X-End-User", user(r)))
		if err != nil {
			reply(w, nil, err)
			return
		}
		var sb strings.Builder
		for _, b := range m.Content {
			sb.WriteString(b.Text)
		}
		reply(w, map[string]string{"answer": sb.String()}, nil)
	})
	// ...or the SDK's own typed client:
	app.HandleFunc("POST /app/ask/inprocess", func(w http.ResponseWriter, r *http.Request) {
		a := read(r)
		c, err := srv.Client(tenant, user(r))
		if err != nil {
			reply(w, nil, err)
			return
		}
		m, err := c.Messages(r.Context(), lmbpserver.MessagesRequest{Model: a.Model, MaxTokens: 512,
			Messages: []lmbpserver.AnthropicMessage{{Role: "user", Content: a.Prompt}}})
		if err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, map[string]string{"answer": m.Content[0].Text}, nil)
	})

	addr := env("HOST", "127.0.0.1") + ":" + env("PORT", "3000")
	hs := &http.Server{Addr: addr, Handler: srv.Middleware(app)}
	go func() { <-ctx.Done(); _ = hs.Close() }()
	log.Printf("net/http example on http://%s (tenant %s)", addr, tenant)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		code := http.StatusBadRequest
		var ae *lmbpserver.APIError
		switch {
		case errors.As(err, &ae):
			code = ae.Status
		case errors.Is(err, lmbpserver.ErrCodeInvalid), errors.Is(err, lmbpserver.ErrDeviceUnknown):
			code = http.StatusNotFound
		case strings.Contains(err.Error(), "status"):
			code = http.StatusBadGateway
		}
		w.WriteHeader(code)
		v = map[string]string{"error": err.Error()}
	}
	_ = json.NewEncoder(w).Encode(v)
}

func env(k, d string) string { return env2(os.Getenv(k), d) }
func env2(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
