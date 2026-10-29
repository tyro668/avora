package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tyro668/avora/internal/lmbp"
	"github.com/tyro668/avora/internal/lmbp/store"
)

// event is one device→gateway data frame (or a synthetic gateway terminal
// event) as exposed to SSE subscribers; Seq doubles as the SSE event id.
type event struct {
	Seq  int64
	Type string
	Data json.RawMessage
}

// raceHook, when set by a test, is called at named points of the terminal
// paths so races can be reproduced deterministically. Nil in production.
var raceHook func(t *gtask, point string)

func hook(t *gtask, point string) {
	if raceHook != nil {
		raceHook(t, point)
	}
}

// gtask is the gateway-side hub of one task: it buffers the device's frames,
// fans them out to (re-)attached HTTP subscribers and paces task.ack so a
// slow subscriber exerts backpressure on the device (docs/lmbp-spec.md §8).
type gtask struct {
	g                 *Gateway
	id, tenant, owner string
	reqModel          string
	created           int64
	e2ee, idempotent  bool
	ds                *dstate
	sentRun           atomic.Bool
	devTerminal       atomic.Bool // the device sent its terminal frame
	aggBytes          int         // output bytes received so far (under mu)
	storeFailed       atomic.Bool // ended because output could not be persisted: never ACK unpersisted frames
	ctx               context.Context
	stop              context.CancelFunc
	mu                sync.Mutex
	events            []event
	notify            chan struct{}
	done              bool
	finishedAt        time.Time     // when the task ended (retention drops the in-memory hub with the stored task)
	decided           bool          // a terminal outcome was chosen (decide); only its holder commits and publishes
	seen              int64         // highest device seq onDeviceFrame started to handle
	subs              map[int]int64 // subscriber → delivered seq
	nextSub           int
	acked             int64
	persisted         int64 // highest device seq durably stored; never ACK beyond it
	ackAt             time.Time
	grace             *time.Timer
	slot              bool
}

func (g *Gateway) newTask(ds *dstate, id, tenant, owner, reqModel string, e2ee, idem bool) *gtask {
	ctx, stop := context.WithCancel(context.Background())
	t := &gtask{g: g, id: id, tenant: tenant, owner: owner, reqModel: reqModel, created: time.Now().Unix(), e2ee: e2ee, idempotent: idem,
		ds: ds, ctx: ctx, stop: stop, notify: make(chan struct{}), subs: map[int]int64{}, ackAt: time.Now()}
	g.mu.Lock()
	g.tasks[id] = t
	g.mu.Unlock()
	if ds != nil {
		ds.mu.Lock()
		ds.tasks[id] = t
		ds.mu.Unlock()
		time.AfterFunc(g.cfg.TaskTimeout, func() {
			if t.cancel("timeout") {
				t.failLocal(lmbp.ErrTimeout, "task timed out", false)
			}
		})
		go t.watchdog()
	}
	return t
}

// abandon drops a hub that never became a task (lost the idempotency race
// or the record could not be written); nobody can be attached to it yet.
func (t *gtask) abandon() {
	t.mu.Lock()
	t.done = true
	t.mu.Unlock()
	t.g.mu.Lock()
	if t.g.tasks[t.id] == t {
		delete(t.g.tasks, t.id)
	}
	t.g.mu.Unlock()
	if t.ds != nil {
		t.ds.mu.Lock()
		delete(t.ds.tasks, t.id)
		t.ds.mu.Unlock()
	}
	t.stop()
}

// terminal reports whether the task's event log ends with its terminal event.
func (t *gtask) terminal() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events) > 0 && isTerminal(t.events[len(t.events)-1].Type)
}

// decide claims the task's single terminal decision. Exactly one terminal
// path (device task.done/task.error, timeout, cancel, slow consumer, local
// error) wins; it alone commits the terminal event+state (FinishTask) and
// then publishes that same outcome. Losers do nothing: nothing is published
// before the decision, so callers and storage can never disagree.
func (t *gtask) decide() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done || t.decided {
		return false
	}
	t.decided = true
	return true
}

func (t *gtask) isDone() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.done
}

// finishedTask rebuilds a read-only finished task from storage (re-attach
// after the in-memory hub was dropped).
func (g *Gateway) finishedTask(st store.Task, reqModel string) (*gtask, error) {
	evs, err := g.cfg.Store.ListEvents(context.Background(), st.ID)
	if err != nil {
		return nil, err
	}
	t := &gtask{g: g, id: st.ID, tenant: st.TenantID, owner: st.OwnerID, reqModel: reqModel, created: st.CreatedAt.Unix(), notify: make(chan struct{}), subs: map[int]int64{}, done: true,
		e2ee: storedE2EE(st.Request)}
	for _, e := range evs {
		t.events = append(t.events, event{Seq: e.Seq, Type: e.Kind, Data: e.Data})
	}
	// Recovery decides from a consistent terminal state: the last event is
	// terminal AND the stored state agrees with it (FinishTask writes both
	// atomically). Anything else (no terminal event, or a legacy row whose
	// event and state disagree) is reported as OUTCOME_UNKNOWN. That event is
	// synthetic, only served, never stored, and takes the next unused seq.
	var lastSeq int64
	if n := len(t.events); n > 0 {
		lastSeq = t.events[n-1].Seq
	}
	consistent := false
	if n := len(t.events); n > 0 {
		switch t.events[n-1].Type {
		case lmbp.TypeTaskDone:
			consistent = st.State == "SUCCEEDED"
		case lmbp.TypeTaskError:
			consistent = st.State == "FAILED" || st.State == "CANCELLED"
		}
		if !consistent && isTerminal(t.events[n-1].Type) {
			g.cfg.Logger.Printf("lmbp: task %s: stored terminal %s disagrees with state %s; reporting %s", st.ID, t.events[n-1].Type, st.State, lmbp.ErrOutcomeUnknown)
			t.events = t.events[:n-1]
		}
	}
	if !consistent {
		b, _ := json.Marshal(lmbp.ErrorBody{Code: lmbp.ErrOutcomeUnknown, Message: "task outcome unknown"})
		t.events = append(t.events, event{Seq: lastSeq + 1, Type: lmbp.TypeTaskError, Data: b})
	}
	return t, nil
}

func isTerminal(typ string) bool { return typ == lmbp.TypeTaskDone || typ == lmbp.TypeTaskError }

func (t *gtask) recvSeq() int64 {
	t.ds.mu.Lock()
	in := t.ds.in
	t.ds.mu.Unlock()
	if in == nil {
		return 0
	}
	return in.Recv(t.id)
}

func (t *gtask) broadcastLocked() {
	close(t.notify)
	t.notify = make(chan struct{})
}

// onDeviceFrame records an accepted, in-order device data frame.
func (t *gtask) onDeviceFrame(in lmbp.Envelope) {
	hook(t, "device-frame")
	if isTerminal(in.Type) {
		t.devTerminal.Store(true)
	}
	t.mu.Lock()
	if t.done || t.decided {
		t.mu.Unlock()
		t.maybeAck()
		return
	}
	if in.Seq > t.seen {
		t.seen = in.Seq
	}
	data := in.Data
	if in.Type == lmbp.TypeTaskDelta {
		why := ""
		if t.e2ee {
			why = t.checkSealedLocked(data)
		} else {
			why = t.checkDeltaLocked(data)
		}
		if why != "" {
			t.mu.Unlock()
			t.g.cfg.Logger.Printf("lmbp: task %s: %s", t.id, why)
			t.abort("protocol_error", lmbp.ErrInternal, "device sent an invalid delta: "+why)
			return
		}
	}
	if in.Type == lmbp.TypeTaskDelta && !t.e2ee {
		// Drop any e2ee field the device must not send for a cleartext task.
		var d lmbp.TaskDelta
		if json.Unmarshal(data, &d) == nil && d.E2EE != "" {
			d.E2EE = ""
			data, _ = json.Marshal(d)
		}
	}
	t.mu.Unlock()
	// Persist before publishing or ACKing: an ACK tells the device it may
	// drop the frame from its resume buffer, so it must only cover frames the
	// gateway can still serve after a restart (re-attach / replay).
	ctx := context.Background()
	ev := store.Event{TaskID: t.id, Seq: in.Seq, Kind: in.Type, Data: data, At: time.Now()}
	state := ""
	if isTerminal(in.Type) {
		state = "SUCCEEDED"
		if in.Type == lmbp.TypeTaskError {
			state = "FAILED"
			var eb lmbp.ErrorBody
			if json.Unmarshal(data, &eb) == nil && eb.Code == lmbp.ErrCancelled {
				state = "CANCELLED"
			}
		}
		// The device's terminal frame competes for the single decision.
		if !t.decide() {
			t.maybeAck()
			return
		}
		hook(t, "device-terminal-decided")
		// Terminal event + terminal state in one transaction: if it fails,
		// neither is stored, and the decision holder (us) turns the outcome
		// into a local INTERNAL error at the same seq instead.
		if err := t.g.cfg.Store.FinishTask(ctx, ev, state); err != nil {
			t.g.cfg.Logger.Printf("lmbp: task %s: persisting terminal event and state for seq %d failed: %v (not acknowledged)", t.id, in.Seq, err)
			t.sendCancel("internal_error")
			t.storeFailed.Store(true)
			t.commitLocal(lmbp.ErrInternal, "gateway could not persist task output", false)
			return
		}
		hook(t, "device-terminal-committed")
	} else if err := t.g.cfg.Store.AppendEvent(ctx, ev); err != nil {
		t.persistFailed(in.Seq, "event", err)
		return
	}
	t.mu.Lock()
	if t.done || (t.decided && state == "") { // another path decided while we were writing
		t.mu.Unlock()
		return
	}
	t.events = append(t.events, event{Seq: in.Seq, Type: in.Type, Data: data})
	t.persisted = in.Seq
	t.broadcastLocked()
	t.mu.Unlock()
	if state != "" {
		t.finishWith(state, true, false)
		return
	}
	t.maybeAck()
}

// persistFailed handles a failed write of device output: the frame is not
// ACKed (the device keeps it), the device is told to stop, and every caller
// gets INTERNAL instead of a result the gateway could not make durable.
func (t *gtask) persistFailed(seq int64, what string, err error) {
	t.g.cfg.Logger.Printf("lmbp: task %s: persisting %s for seq %d failed: %v (not acknowledged)", t.id, what, seq, err)
	t.storeFailed.Store(true)
	t.abort("internal_error", lmbp.ErrInternal, "gateway could not persist task output")
}

// maybeAck acknowledges what every attached subscriber has consumed (or all
// received frames when nobody is attached; they are buffered for re-attach).
func (t *gtask) maybeAck() {
	if t.ds == nil {
		return
	}
	recv := t.recvSeq()
	t.mu.Lock()
	target := min(recv, t.persisted)
	if !t.done {
		for _, d := range t.subs {
			if d < target {
				target = d
			}
		}
	}
	if target <= t.acked {
		t.mu.Unlock()
		return
	}
	t.acked, t.ackAt = target, time.Now()
	t.mu.Unlock()
	t.ds.mu.Lock()
	in := t.ds.in
	t.ds.mu.Unlock()
	if in != nil {
		in.Acked(t.id, target)
	}
	t.ds.sendAck(t.id, target)
}

// watchdog fails the task when subscribers stop consuming for too long.
func (t *gtask) watchdog() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tick.C:
			recv := t.recvSeq()
			t.mu.Lock()
			stalled := len(t.subs) > 0 && recv > t.acked && time.Since(t.ackAt) > t.g.cfg.SlowConsumer
			t.mu.Unlock()
			if stalled && t.cancel("slow_consumer") {
				t.failLocal(lmbp.ErrSlowConsumer, "client did not consume the stream in time", false)
			}
		}
	}
}

// cancel tells the device to stop; false if the task already finished or
// its terminal outcome is already decided (then there is nothing to stop).
func (t *gtask) cancel(reason string) bool {
	t.mu.Lock()
	over := t.done || t.decided
	t.mu.Unlock()
	if over {
		return false
	}
	t.sendCancel(reason)
	return true
}

func (t *gtask) sendCancel(reason string) {
	if t.ds != nil && t.sentRun.Load() {
		b, _ := json.Marshal(lmbp.TaskCancel{Reason: reason})
		_ = t.ds.control(lmbp.Envelope{Type: lmbp.TypeTaskCancel, TaskID: t.id, Data: b})
	}
}

// abort ends the task with a gateway-local error (protocol violation,
// storage failure) and tells the device to stop. The outcome is decided
// BEFORE task.cancel goes out: otherwise the device's reply to the cancel
// (task.error CANCELLED) could win the decision and the task would end as
// a device cancellation instead of INTERNAL (seen on the Windows runner).
func (t *gtask) abort(reason, code, msg string) {
	if !t.decide() {
		return
	}
	t.sendCancel(reason)
	hook(t, "abort-cancel-sent")
	t.commitLocal(code, msg, false)
}

// failLocal ends the task with a gateway-local terminal error, if it wins
// the terminal decision (see decide); otherwise it does nothing.
// failLocal reports whether this call decided the terminal outcome; false
// means another path (device frame, timeout, cancel) already won.
func (t *gtask) failLocal(code, msg string, retryable bool) bool {
	if !t.decide() {
		return false
	}
	t.commitLocal(code, msg, retryable)
	return true
}

// commitLocal stores and then publishes a local terminal error. The caller
// holds the decision. The seq follows every device seq seen so far, so it
// never collides with a device frame still being written.
func (t *gtask) commitLocal(code, msg string, retryable bool) {
	t.mu.Lock()
	seq := t.seen
	if n := len(t.events); n > 0 && t.events[n-1].Seq > seq {
		seq = t.events[n-1].Seq
	}
	seq++
	t.mu.Unlock()
	hook(t, "local-terminal-decided")
	b, _ := json.Marshal(lmbp.ErrorBody{Code: code, Message: msg, Retryable: retryable})
	state := "FAILED"
	if code == lmbp.ErrCancelled {
		state = "CANCELLED"
	}
	// A gateway-local terminal event is not a device frame (nothing to ACK).
	// It is stored atomically with the terminal state; if that fails nothing
	// is stored and a later re-attach reports OUTCOME_UNKNOWN (an error, as
	// this one is: never a success).
	if err := t.g.cfg.Store.FinishTask(context.Background(), store.Event{TaskID: t.id, Seq: seq, Kind: lmbp.TypeTaskError, Data: b, At: time.Now()}, state); err != nil && err != store.ErrNotFound {
		t.g.cfg.Logger.Printf("lmbp: task %s: persisting local %s failed: %v", t.id, code, err)
	}
	t.mu.Lock()
	t.events = append(t.events, event{Seq: seq, Type: lmbp.TypeTaskError, Data: b})
	t.broadcastLocked()
	t.mu.Unlock()
	t.finishWith(state, false, false)
}

// failOffline ends a task whose device session is gone, whatever ended it
// (disconnect, revocation, replacement): once task.run was written the
// device may have run it, so the outcome is OUTCOME_UNKNOWN (§7.5); before
// that, DEVICE_OFFLINE, which is retryable (at-most-once execution).
func (t *gtask) failOffline(code, msg string) {
	if t.sentRun.Load() {
		if code != lmbp.ErrOutcomeUnknown {
			msg += "; outcome unknown"
		}
		code = lmbp.ErrOutcomeUnknown
	} else {
		code = lmbp.ErrDeviceOffline
	}
	t.failLocal(code, msg, code == lmbp.ErrDeviceOffline)
}

// finishWith ends the in-memory task. The terminal state is always stored by
// the caller together with its terminal event (Store.FinishTask).
func (t *gtask) finishWith(state string, fromDevice, _ bool) {
	t.mu.Lock()
	if t.done {
		t.mu.Unlock()
		return
	}
	t.done = true
	slot := t.slot
	t.slot = false
	if t.grace != nil {
		t.grace.Stop()
	}
	t.broadcastLocked()
	t.mu.Unlock()
	if ds := t.ds; ds != nil {
		var late, ackNow int64 // late: seq ACKed so far; ackNow: ACK to send now
		var in *lmbp.Inbound
		if fromDevice {
			t.maybeAck() // release the device's resume buffer
			ds.mu.Lock()
			delete(ds.tasks, t.id)
			in = ds.in
			ds.mu.Unlock()
		} else {
			hook(t, "finish-transition")
			// Ended here (cancel, timeout, slow consumer, ...): the device
			// may still be sending. Reading the received seq, removing the
			// task and registering late-frame cleanup happen under ds.mu,
			// which onDeviceData also holds from task lookup through
			// Accept. So every device frame is either counted in late (and
			// ACKed below) or meets the cleanup record (and is ACKed
			// there); none falls in between. Review8 P2-a.
			ds.mu.Lock()
			in = ds.in
			if in != nil && !t.storeFailed.Load() {
				late = in.Recv(t.id)
			}
			delete(ds.tasks, t.id)
			if !t.storeFailed.Load() && !t.devTerminal.Load() {
				ds.reclaimLocked(t.id, late)
			}
			ds.mu.Unlock()
			t.mu.Lock()
			if late > t.acked {
				t.acked, ackNow = late, late
			}
			t.mu.Unlock()
		}
		ds.out.Forget(t.id)
		if in != nil {
			in.Forget(t.id)
		}
		if ackNow > 0 {
			hook(t, "finish-ack")
			ds.sendAck(t.id, ackNow)
		}
		if slot {
			ds.release()
		}
	}
	t.stop()
	t.mu.Lock()
	t.finishedAt = time.Now()
	t.mu.Unlock()
	time.AfterFunc(t.g.cfg.AttachGrace+10*time.Minute, func() {
		t.g.mu.Lock()
		if t.g.tasks[t.id] == t {
			delete(t.g.tasks, t.id)
		}
		t.g.mu.Unlock()
		if t.ds != nil {
			t.ds.forgetAck(t.id)
		}
	})
}

// attach registers a subscriber that has already seen events <= after.
func (t *gtask) attach(after int64) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextSub++
	t.subs[t.nextSub] = after
	if t.grace != nil {
		t.grace.Stop()
		t.grace = nil
	}
	return t.nextSub
}

// detach removes a subscriber. When the last one leaves an unfinished task,
// an idempotent task gets AttachGrace to be re-attached; others are cancelled.
func (t *gtask) detach(id int) {
	t.mu.Lock()
	delete(t.subs, id)
	left := len(t.subs) == 0 && !t.done
	if left && t.idempotent {
		t.grace = time.AfterFunc(t.g.cfg.AttachGrace, func() {
			t.mu.Lock()
			still := len(t.subs) == 0
			t.mu.Unlock()
			if still && t.cancel("client_disconnected") {
				t.failLocal(lmbp.ErrCancelled, "client did not re-attach", false)
			}
		})
	}
	t.mu.Unlock()
	if left && !t.idempotent {
		if t.cancel("client_disconnected") {
			t.failLocal(lmbp.ErrCancelled, "client disconnected", false)
		}
		return
	}
	t.maybeAck()
}

// stream delivers events with seq > after to fn, in order, until the
// terminal event or ctx ends. Each delivered event advances the ack point.
func (t *gtask) stream(ctx context.Context, after int64, keepalive func() error, fn func(event) error) error {
	sub := t.attach(after)
	defer t.detach(sub)
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		t.mu.Lock()
		// events are kept in strictly increasing seq order: find the cursor
		// by binary search instead of rescanning the whole history on every
		// wake-up (that made a long stream O(n²)).
		i := sort.Search(len(t.events), func(i int) bool { return t.events[i].Seq > after })
		batch := append([]event(nil), t.events[i:]...)
		wait := t.notify
		// Finished task and nothing after the cursor (Last-Event-ID equal to
		// or beyond the terminal seq): end instead of waiting forever.
		ended := len(batch) == 0 && len(t.events) > 0 && isTerminal(t.events[len(t.events)-1].Type)
		t.mu.Unlock()
		if ended {
			return nil
		}
		for _, e := range batch {
			if err := fn(e); err != nil {
				return err
			}
			after = e.Seq
			t.mu.Lock()
			t.subs[sub] = after
			t.mu.Unlock()
			if isTerminal(e.Type) {
				return nil
			}
		}
		t.maybeAck()
		if len(batch) > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait:
		case <-keep.C:
			if keepalive != nil {
				if err := keepalive(); err != nil {
					return err
				}
			}
		}
	}
}

// checkDeltaLocked validates a device delta before it is stored or
// aggregated: tool-call index range (§16.1) and the task's output budget.
func (t *gtask) checkDeltaLocked(data []byte) string {
	var d lmbp.TaskDelta
	if json.Unmarshal(data, &d) != nil {
		return "malformed task.delta"
	}
	for _, c := range d.ToolCalls {
		if c.Index != nil && (*c.Index < 0 || *c.Index > lmbp.MaxToolCallIndex) {
			return fmt.Sprintf("tool call index %d out of range [0,%d]", *c.Index, lmbp.MaxToolCallIndex)
		}
	}
	return t.chargeLocked(len(data))
}

// checkSealedLocked bounds what an end-to-end encrypted task buffers: the
// gateway cannot read sealed deltas, so they are charged like cleartext.
func (t *gtask) checkSealedLocked(data []byte) string { return t.chargeLocked(len(data)) }

// chargeLocked adds an encoded task.delta body to the task's output budget
// (§10: MaxTaskOutputBytes per task, cleartext and sealed alike). Every
// delta is buffered for replay and aggregation, so the budget is what bounds
// a task's memory.
func (t *gtask) chargeLocked(n int) string {
	t.aggBytes += n
	if t.aggBytes > lmbp.MaxTaskOutputBytes {
		return "task output exceeds the per-task limit"
	}
	return ""
}

// storedE2EE restores a task's E2EE mode from its stored request (the
// request row records {"e2ee": true} for sealed tasks; a cleartext TaskRun
// has no e2ee member), so a replay after a restart keeps rendering sealed
// frames as sealed.
func storedE2EE(req []byte) bool {
	var p struct {
		E2EE json.RawMessage `json:"e2ee"`
	}
	if json.Unmarshal(req, &p) != nil {
		return false
	}
	v := strings.TrimSpace(string(p.E2EE))
	return v != "" && v != "null" && v != "false"
}
