// Package customstore shows a third-party Store implementation written
// against the public lmbpserver contract only (audit finding 10): it does
// not import any internal package, so it compiles from another module too.
package customstore_test

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	lmbpserver "github.com/tyro668/avora/sdk/go"
)

// countingStore wraps another Store and counts writes; every method is
// spelled out with public types.
type countingStore struct {
	in     lmbpserver.Store
	writes int
}

var _ lmbpserver.Store = (*countingStore)(nil)

func (s *countingStore) PutTenant(ctx context.Context, t lmbpserver.StoreTenant) error {
	s.writes++
	return s.in.PutTenant(ctx, t)
}
func (s *countingStore) TenantByAPIKeyHash(ctx context.Context, h string) (lmbpserver.StoreTenant, error) {
	return s.in.TenantByAPIKeyHash(ctx, h)
}
func (s *countingStore) GetTenant(ctx context.Context, id string) (lmbpserver.StoreTenant, error) {
	return s.in.GetTenant(ctx, id)
}
func (s *countingStore) CreateDeviceAuth(ctx context.Context, d lmbpserver.DeviceAuth) error {
	s.writes++
	return s.in.CreateDeviceAuth(ctx, d)
}
func (s *countingStore) DeviceAuthByCodeHash(ctx context.Context, h string) (lmbpserver.DeviceAuth, error) {
	return s.in.DeviceAuthByCodeHash(ctx, h)
}
func (s *countingStore) DeviceAuthByUserCode(ctx context.Context, t, c string) (lmbpserver.DeviceAuth, error) {
	return s.in.DeviceAuthByUserCode(ctx, t, c)
}
func (s *countingStore) UpdateDeviceAuth(ctx context.Context, d lmbpserver.DeviceAuth) error {
	s.writes++
	return s.in.UpdateDeviceAuth(ctx, d)
}
func (s *countingStore) CreateDevice(ctx context.Context, d lmbpserver.Device) error {
	s.writes++
	return s.in.CreateDevice(ctx, d)
}
func (s *countingStore) GetDevice(ctx context.Context, id string) (lmbpserver.Device, error) {
	return s.in.GetDevice(ctx, id)
}
func (s *countingStore) ListDevices(ctx context.Context, t, o string) ([]lmbpserver.Device, error) {
	return s.in.ListDevices(ctx, t, o)
}
func (s *countingStore) SetDeviceStatus(ctx context.Context, id, st string) error {
	s.writes++
	return s.in.SetDeviceStatus(ctx, id, st)
}
func (s *countingStore) SetDeviceE2EEKey(ctx context.Context, id, stmt string) error {
	s.writes++
	return s.in.SetDeviceE2EEKey(ctx, id, stmt)
}
func (s *countingStore) GetIdempotency(ctx context.Context, t, o, k string) (lmbpserver.Idempotency, error) {
	return s.in.GetIdempotency(ctx, t, o, k)
}
func (s *countingStore) CreateTask(ctx context.Context, t lmbpserver.Task, i *lmbpserver.Idempotency) error {
	s.writes++
	return s.in.CreateTask(ctx, t, i)
}
func (s *countingStore) SetTaskState(ctx context.Context, id, st string) error {
	s.writes++
	return s.in.SetTaskState(ctx, id, st)
}
func (s *countingStore) GetTask(ctx context.Context, id string) (lmbpserver.Task, error) {
	return s.in.GetTask(ctx, id)
}
func (s *countingStore) AppendEvent(ctx context.Context, e lmbpserver.Event) error {
	s.writes++
	return s.in.AppendEvent(ctx, e)
}

// FinishTask must store the terminal event and the terminal state in one
// transaction (both or neither); a wrapper simply delegates.
func (s *countingStore) FinishTask(ctx context.Context, e lmbpserver.Event, state string) error {
	s.writes++
	return s.in.FinishTask(ctx, e, state)
}
func (s *countingStore) ListEvents(ctx context.Context, id string) ([]lmbpserver.Event, error) {
	return s.in.ListEvents(ctx, id)
}
func (s *countingStore) Purge(ctx context.Context, cut time.Time) (int, error) {
	return s.in.Purge(ctx, cut)
}
func (s *countingStore) Close() error { return s.in.Close() }

func TestCustomStore(t *testing.T) {
	st := &countingStore{in: lmbpserver.NewMemoryStore()}
	srv, err := lmbpserver.New(context.Background(), lmbpserver.Options{Issuer: "http://127.0.0.1", Store: st, Logger: log.New(io.Discard, "", 0),
		Tenants: []lmbpserver.Tenant{{ID: "acme", APIKey: "tk_ssssssssssssssssssssssssssssssssssssssss"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := st.GetTask(context.Background(), "nope"); err != lmbpserver.ErrNotFound {
		t.Fatalf("not-found sentinel not exported: %v", err)
	}
	if st.writes == 0 {
		t.Fatal("custom store not used")
	}
}
