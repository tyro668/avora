// Package lmbpserver lets a SaaS backend use models that run on its users'
// own machines through the Avora desktop app.
//
// Business code does two things only:
//
//  1. pairing: show a pair link / QR code (Server.Pairing.Create), then
//     approve the user code the user reads off the desktop app
//     (Server.Pairing.Approve);
//  2. LLM calls: standard OpenAI (/v1/chat/completions, /v1/models) or
//     Anthropic (/v1/messages) requests, over HTTP with the official client
//     libraries, or in-process with Server.Client.
//
// The WebSocket session, JOSE, resume, flow control and E2EE pass-through
// stay inside the SDK (it embeds the reference gateway, internal/lmbp/gateway).
package lmbpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/gateway"
	"github.com/tyro668/avora/internal/lmbp/store"
)

// Store is the persistence interface (see NewMemoryStore, OpenSQLiteStore).
// Implement it to use another database; implementing SecretStore as well
// lets the server keep its signing key there.
type (
	Store         = store.Store
	SecretStore   = store.SecretStore
	TenantProfile = store.TenantProfile
)

// NewMemoryStore returns an in-memory store (state is lost on restart).
func NewMemoryStore() Store { return store.NewMemory() }

// OpenSQLiteStore opens (or creates) a SQLite database. encryptionKey, when
// 32 bytes, seals prompts, outputs and secrets at rest with AES-256-GCM.
func OpenSQLiteStore(path string, encryptionKey []byte) (Store, error) {
	var c *store.Cipher
	if len(encryptionKey) > 0 {
		var err error
		if c, err = store.NewCipher(encryptionKey); err != nil {
			return nil, err
		}
	}
	return store.OpenSQLite(path, c)
}

// Tenant is one SaaS product served by the gateway.
type Tenant struct {
	ID      string
	APIKey  string // >= 32 chars; server-side secret
	Profile TenantProfile
}

// Options configure a Server.
type Options struct {
	Tenants []Tenant
	// Issuer is the gateway's public origin (https, or http on loopback for
	// development), REQUIRED: every token, audience, metadata document and
	// pair link is bound to it. It is never derived from a request's Host.
	Issuer string
	// Store defaults to NewMemoryStore().
	Store Store
	// SigningKey defaults to the key kept in Store (if it is a SecretStore),
	// generated on first start.
	SigningKey     ed25519.PrivateKey
	MaxConcurrency int
	Logger         *log.Logger
	// Retention of finished tasks (default 7 days); the purge loop runs while ctx passed to New lives.
	Retention time.Duration
}

// Server is an embedded LMBP gateway.
type Server struct {
	gw      *gateway.Gateway
	store   Store
	keys    map[string]string // tenant → API key (for the in-process client)
	handler http.Handler
	priv    ed25519.PrivateKey

	Pairing *Pairing
	Keys    *Keys
}

const seedSecret = "gateway_signing_seed"

// New builds a server. ctx bounds background work (retention purge).
func New(ctx context.Context, o Options) (*Server, error) {
	if o.Issuer == "" {
		return nil, errors.New("lmbpserver: Options.Issuer is required (the gateway's public origin)")
	}
	if o.Store == nil {
		o.Store = NewMemoryStore()
	}
	key := o.SigningKey
	if key == nil {
		var err error
		if key, err = loadOrCreateKey(ctx, o.Store); err != nil {
			return nil, err
		}
	}
	gw, err := gateway.New(gateway.Config{Store: o.Store, Issuer: o.Issuer, SigningKey: key, MaxConc: o.MaxConcurrency, Logger: o.Logger, Retention: o.Retention})
	if err != nil {
		return nil, err
	}
	s := &Server{gw: gw, store: o.Store, keys: map[string]string{}, handler: gw.Handler(), priv: key}
	for _, t := range o.Tenants {
		if err := gw.RegisterTenantProfile(ctx, t.ID, t.APIKey, t.Profile); err != nil {
			return nil, fmt.Errorf("tenant %s: %w", t.ID, err)
		}
		s.keys[t.ID] = t.APIKey
	}
	s.Pairing = &Pairing{s: s}
	s.Keys = &Keys{pub: gw.PublicKey()}
	go gw.RunRetention(ctx, 0)
	return s, nil
}

func loadOrCreateKey(ctx context.Context, st Store) (ed25519.PrivateKey, error) {
	ss, ok := st.(SecretStore)
	if ok {
		seed, err := ss.GetSecret(ctx, seedSecret)
		if err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if ok {
		if err := ss.PutSecret(ctx, seedSecret, seed); err != nil {
			return nil, err
		}
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Handler serves the protocol endpoints (/.well-known/*, /lmbp/v1/*, /healthz)
// and /v1/chat/completions, /v1/models, /v1/messages. Mount it at the root.
func (s *Server) Handler() http.Handler { return s.handler }

// Middleware serves the gateway's paths and passes everything else to next.
func (s *Server) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gateway.Owns(r.URL.Path) {
			s.handler.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Close releases the store.
func (s *Server) Close() error { return s.store.Close() }

// Keys exposes the gateway signing key's public half.
type Keys struct{ pub ed25519.PublicKey }

// KID is the RFC 7638 thumbprint of the gateway signing key.
func (k *Keys) KID() string { return lmbp.Thumbprint(k.pub) }

// PublicJWK is the public JWK served at /.well-known/jwks.json.
func (k *Keys) PublicJWK() lmbp.JWK { return lmbp.PublicJWK(k.pub) }

// JWKS is the document served at /.well-known/jwks.json.
func (k *Keys) JWKS() map[string]any {
	return map[string]any{"keys": []lmbp.JWK{lmbp.PublicJWK(k.pub)}}
}

// GenerateSigningKey creates a new Ed25519 gateway key (keep the seed in your secret manager).
func GenerateSigningKey() (ed25519.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	return k, err
}

// GenerateTenantKey creates a tenant API key (server-side secret).
func GenerateTenantKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "lmbp_" + base64.RawURLEncoding.EncodeToString(b)
}
