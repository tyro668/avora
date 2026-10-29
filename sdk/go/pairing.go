package lmbpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/gateway"
)

// Pairing errors returned by Approve / Deny / RevokeDevice.
var (
	ErrCodeInvalid   = gateway.ErrCodeInvalid
	ErrCodeDenied    = gateway.ErrCodeDenied
	ErrJKTMismatch   = gateway.ErrJKTMismatch
	ErrDeviceUnknown = gateway.ErrDeviceUnknown
	ErrRateLimited   = gateway.ErrRateLimited
	ErrUnknownTenant = errors.New("unknown tenant")
)

// Pairing is the pairing and device-management API.
type Pairing struct{ s *Server }

// PairingInfo is what you show the user to start pairing.
type PairingInfo struct {
	Link  string // lmbp://pair?... deep link (§19.4)
	QRSVG string // QR code of Link as an SVG document
	QRPNG []byte // QR code of Link as PNG
}

// PendingPairing describes a device waiting for approval.
type PendingPairing struct {
	UserCode   string
	DeviceName string
	JKT        string
	Status     string
	ExpiresAt  time.Time
}

// ApproveResult is the outcome of Approve / Deny.
type ApproveResult struct {
	Status     string // approved | denied
	DeviceID   string
	DeviceName string
	JKT        string
}

// DeviceInfo is one paired device with its live state.
type DeviceInfo struct {
	DeviceID          string
	Name              string
	Status            string // active | revoked
	CreatedAt         time.Time
	JKT               string
	Online            bool
	Models            []string
	ModelCapabilities map[string][]string
	ModelNames        map[string]string // optional display name per model id
	PublicKey         []byte            // Ed25519 identity key (verify against your pinned JKT)
	E2EEKey           string            // device-signed X25519 key statement; "" if none
}

// Link returns the §19.4 deep link for tenant on this gateway (Options.Issuer).
func (p *Pairing) Link(tenant string) (string, error) {
	return lmbp.PairLink{Gateway: p.s.gw.Issuer(), Tenant: tenant}.String(), nil
}

// Create returns the pair link with its QR code (SVG and PNG).
func (p *Pairing) Create(tenant string) (PairingInfo, error) {
	link, err := p.Link(tenant)
	if err != nil {
		return PairingInfo{}, err
	}
	c, err := qr.Encode(link, qr.M)
	if err != nil {
		return PairingInfo{}, err
	}
	return PairingInfo{Link: link, QRSVG: qrSVG(c, 4, 2), QRPNG: c.PNG()}, nil
}

func qrSVG(c *qr.Code, cell, margin int) string {
	n := c.Size + 2*margin
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="`, n, n, n*cell, n*cell)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+margin, y+margin)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// Lookup returns the pending pairing for a user code that endUser typed (to
// show the device before approving). DeviceName is chosen by the device:
// render it as untrusted plain text. A code that is not pending counts as a
// failed attempt of endUser (ErrRateLimited after 10 per minute), exactly
// like Approve and Deny.
func (p *Pairing) Lookup(ctx context.Context, tenant, endUser, userCode string) (PendingPairing, error) {
	d, err := p.s.gw.PendingPairing(ctx, tenant, endUser, userCode)
	if errors.Is(err, gateway.ErrRateLimited) {
		return PendingPairing{}, ErrRateLimited
	}
	if err != nil {
		return PendingPairing{}, ErrCodeInvalid
	}
	return PendingPairing{UserCode: d.UserCode, DeviceName: d.DeviceName, JKT: lmbp.Thumbprint(d.PublicKey), Status: d.Status, ExpiresAt: d.ExpiresAt}, nil
}

// Approve binds the device that shows userCode to endUser. jkt (optional)
// pins the device key thumbprint. The desktop app completes on its next poll.
func (p *Pairing) Approve(ctx context.Context, tenant, endUser, userCode, jkt string) (ApproveResult, error) {
	return p.decide(ctx, tenant, endUser, userCode, jkt, false)
}

// Deny declines the pairing for userCode.
func (p *Pairing) Deny(ctx context.Context, tenant, endUser, userCode string) (ApproveResult, error) {
	return p.decide(ctx, tenant, endUser, userCode, "", true)
}

func (p *Pairing) decide(ctx context.Context, tenant, endUser, userCode, jkt string, deny bool) (ApproveResult, error) {
	if _, ok := p.s.keys[tenant]; !ok {
		return ApproveResult{}, ErrUnknownTenant
	}
	if !lmbp.ValidHeaderValue(endUser, 128) {
		return ApproveResult{}, errors.New("endUser must be 1-128 printable ASCII characters (it travels as X-End-User)")
	}
	d, err := p.s.gw.Decide(ctx, tenant, endUser, userCode, jkt, deny)
	if err != nil {
		return ApproveResult{}, err
	}
	return ApproveResult{Status: d.Status, DeviceID: d.DeviceID, DeviceName: d.DeviceName, JKT: lmbp.Thumbprint(d.PublicKey)}, nil
}

// ListDevices returns endUser's devices with live status.
func (p *Pairing) ListDevices(ctx context.Context, tenant, endUser string) ([]DeviceInfo, error) {
	ds, err := p.s.store.ListDevices(ctx, tenant, endUser)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceInfo, 0, len(ds))
	for _, d := range ds {
		l := p.s.gw.Live(d.ID)
		out = append(out, DeviceInfo{DeviceID: d.ID, Name: d.Name, Status: d.Status, CreatedAt: d.CreatedAt, JKT: lmbp.Thumbprint(d.PublicKey),
			Online: l.Online, Models: l.Models, ModelCapabilities: l.ModelCapabilities, ModelNames: l.ModelNames, PublicKey: d.PublicKey, E2EEKey: d.E2EEKey})
	}
	return out, nil
}

// RevokeDevice revokes a device: its session ends and refresh is refused.
func (p *Pairing) RevokeDevice(ctx context.Context, tenant, endUser, deviceID string) error {
	return p.s.gw.RevokeDevice(ctx, tenant, endUser, deviceID)
}
