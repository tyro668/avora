package gateway

// Exported operations for embedding the gateway (sdk/go): the same code paths
// the HTTP handlers use, callable directly by the SaaS backend.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/store"
)

// Pairing decision errors.
var (
	ErrCodeInvalid   = errors.New("code invalid, expired or already used")
	ErrRateLimited   = errors.New("too many failed pairing codes; wait a minute")
	ErrCodeDenied    = errors.New("pairing consent was denied for this code")
	ErrJKTMismatch   = errors.New("device key thumbprint does not match the pairing request")
	ErrDeviceUnknown = errors.New("device not found")
)

// NormUserCode normalises a user code as typed by a person (case, dashes, spaces).
func NormUserCode(s string) string { return normCode(s) }

// PendingPairing returns the pending device authorization for a user code,
// for a signed-in end user who typed it (to show the device before deciding).
// A code that is not pending counts as a failed attempt of that user, like a
// failed Decide: the lookup is no oracle for guessing codes.
func (g *Gateway) PendingPairing(ctx context.Context, tenantID, owner, userCode string) (store.DeviceAuth, error) {
	g.pairMu.Lock()
	defer g.pairMu.Unlock()
	key := failKey(tenantID, owner)
	if !g.allowAttemptLocked(key) {
		return store.DeviceAuth{}, ErrRateLimited
	}
	d, err := g.cfg.Store.DeviceAuthByUserCode(ctx, tenantID, normCode(userCode))
	if err != nil || d.Status != "pending" || time.Now().After(d.ExpiresAt) {
		g.recordFailureLocked(key)
		return store.DeviceAuth{}, ErrCodeInvalid
	}
	return d, nil
}

// Decide approves (binding the new device to owner) or denies the pairing
// identified by userCode. jkt, when set, must match the device key.
//
// Failure counting and lockout live here, in the shared business layer, so
// the HTTP API and in-process callers (SDK Pairing.Approve/Deny) are limited
// alike: after 10 failed codes per end user (tenant + X-End-User) within a
// minute, Decide returns ErrRateLimited without looking the code up. One
// lock covers the limit check, the decision and the failure record, so a
// code is decided at most once (one device per code) and concurrent
// failures cannot overrun the limit.
func (g *Gateway) Decide(ctx context.Context, tenantID, owner, userCode, jkt string, deny bool) (store.DeviceAuth, error) {
	g.pairMu.Lock()
	defer g.pairMu.Unlock()
	key := failKey(tenantID, owner)
	if !g.allowAttemptLocked(key) {
		return store.DeviceAuth{}, ErrRateLimited
	}
	d, err := g.decide(ctx, tenantID, owner, userCode, jkt, deny)
	if errors.Is(err, ErrCodeDenied) || errors.Is(err, ErrCodeInvalid) || errors.Is(err, ErrJKTMismatch) {
		g.recordFailureLocked(key)
	}
	return d, err
}

func (g *Gateway) decide(ctx context.Context, tenantID, owner, userCode, jkt string, deny bool) (store.DeviceAuth, error) {
	d, err := g.cfg.Store.DeviceAuthByUserCode(ctx, tenantID, normCode(userCode))
	if err == nil && d.Status == "denied" && !time.Now().After(d.ExpiresAt) {
		return d, ErrCodeDenied
	}
	if err != nil || d.Status != "pending" || time.Now().After(d.ExpiresAt) {
		return d, ErrCodeInvalid
	}
	if jkt != "" && jkt != lmbp.Thumbprint(d.PublicKey) {
		return d, ErrJKTMismatch
	}
	if deny {
		d.Status = "denied"
	} else {
		d.Status, d.OwnerID, d.DeviceID = "approved", owner, lmbp.RandomID("dev_")
		if err := g.cfg.Store.CreateDevice(ctx, store.Device{ID: d.DeviceID, TenantID: tenantID, OwnerID: owner, Name: d.DeviceName, PublicKey: d.PublicKey, Status: "active", CreatedAt: time.Now()}); err != nil {
			return d, err
		}
	}
	g.releasePending(tenantID, d.DeviceCodeHash)
	return d, g.cfg.Store.UpdateDeviceAuth(ctx, d)
}

// RevokeDevice revokes owner's device: the session ends and refresh is refused.
func (g *Gateway) RevokeDevice(ctx context.Context, tenantID, owner, id string) error {
	d, err := g.cfg.Store.GetDevice(ctx, id)
	if err != nil || d.TenantID != tenantID || d.OwnerID != owner {
		return ErrDeviceUnknown
	}
	if err := g.cfg.Store.SetDeviceStatus(ctx, id, "revoked"); err != nil {
		return err
	}
	g.dropDevice(id, lmbp.ErrDeviceOffline, "device revoked")
	return nil
}

// LiveDevice reports whether a device is connected and what it serves.
type LiveDevice struct {
	Online            bool
	Models            []string
	ModelCapabilities map[string][]string
	ModelNames        map[string]string
	Capabilities      []string
}

// Live returns the live session state of a device.
func (g *Gateway) Live(id string) LiveDevice {
	ds := g.online(id)
	if ds == nil {
		return LiveDevice{}
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()
	caps := map[string][]string{}
	for k, v := range ds.modelCapMap {
		caps[k] = slices.Clone(v)
	}
	names := map[string]string{}
	for k, v := range ds.modelNames {
		names[k] = v
	}
	return LiveDevice{Online: true, Models: slices.Clone(ds.models), ModelCapabilities: caps, ModelNames: names, Capabilities: slices.Clone(ds.caps)}
}

// Owns reports whether the gateway serves path (frameworks fall through otherwise).
func Owns(path string) bool {
	switch path {
	case "/healthz", "/.well-known/jwks.json", "/.well-known/lmbp", "/lmbp/v1/device/authorize", "/lmbp/v1/token", "/lmbp/v1/connect",
		"/lmbp/v1/tenant/devices/approvals", "/lmbp/v1/tenant/devices", "/v1/models", "/v1/chat/completions", "/v1/messages":
		return true
	}
	return strings.HasPrefix(path, "/lmbp/v1/tenant/devices/") || strings.HasPrefix(path, "/lmbp/v1/tenant/tasks/")
}
