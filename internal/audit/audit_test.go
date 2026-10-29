package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRecordStatsPurge(t *testing.T) {
	l, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx := context.Background()
	day1 := time.Date(2026, 10, 12, 9, 15, 0, 0, time.UTC)
	day2 := time.Date(2026, 10, 13, 14, 5, 0, 0, time.UTC)
	rec := func(at time.Time, tenant, model, status string, p, c int, lat int64) {
		adapter, _, _ := strings.Cut(model, "/")
		r := Record{At: at, ConnectionID: "dev_" + tenant, Gateway: "https://gw.example", Tenant: tenant, SaaSName: tenant + " Inc", TaskID: "t", Model: model,
			Adapter: adapter, Status: status, PromptTokens: p, CompletionTokens: c, UsageReported: p+c > 0, LatencyMS: lat}
		if status == StatusError {
			r.ErrorCode = "UPSTREAM_ERROR"
		}
		if err := l.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rec(day1, "acme", "ollama/qwen3", StatusOK, 100, 50, 1000)
	rec(day1.Add(time.Hour), "acme", "ollama/qwen3", StatusOK, 10, 5, 3000)
	rec(day2, "acme", "codex/gpt-5", StatusOK, 0, 0, 500)
	rec(day2, "beta", "ollama/qwen3", StatusError, 0, 0, 20)
	if err := l.Record(ctx, Record{Status: "weird"}); err == nil {
		t.Fatal("bad status accepted")
	}

	all, _ := l.Stats(ctx, Filter{}, nil, false)
	if len(all) != 1 || all[0].Requests != 4 || all[0].Errors != 1 || all[0].TotalTokens != 165 || all[0].Unmetered != 2 || all[0].MaxLatencyMS != 3000 {
		t.Fatalf("totals %+v", all)
	}
	bySaaS, _ := l.Stats(ctx, Filter{}, []string{BySaaS}, false)
	if len(bySaaS) != 2 || bySaaS[0].SaaS != "acme" || bySaaS[0].SaaSName != "acme Inc" || bySaaS[0].Requests != 3 || bySaaS[0].PromptTokens != 110 || bySaaS[1].Errors != 1 {
		t.Fatalf("by saas %+v", bySaaS)
	}
	byDayModel, _ := l.Stats(ctx, Filter{Tenant: "acme"}, []string{ByDay, ByModel}, false)
	if len(byDayModel) != 2 || byDayModel[0].Day != "2026-10-12" || byDayModel[0].Model != "ollama/qwen3" || byDayModel[0].AvgLatencyMS != 2000 || byDayModel[1].Day != "2026-10-13" {
		t.Fatalf("by day/model %+v", byDayModel)
	}
	byAdapter, _ := l.Stats(ctx, Filter{}, []string{ByAdapter}, false)
	if len(byAdapter) != 2 || byAdapter[0].Adapter != "codex" || byAdapter[1].Adapter != "ollama" || byAdapter[1].Requests != 3 || byAdapter[1].TotalTokens != 165 {
		t.Fatalf("by adapter %+v", byAdapter)
	}
	byHour, _ := l.Stats(ctx, Filter{Since: day1, Until: day2}, []string{ByHour}, false)
	if len(byHour) != 2 || byHour[0].Hour != "2026-10-12T09:00" || byHour[1].Hour != "2026-10-12T10:00" {
		t.Fatalf("by hour %+v", byHour)
	}
	if _, err := l.Stats(ctx, Filter{}, []string{"prompt; DROP TABLE requests"}, false); err == nil {
		t.Fatal("unknown group accepted")
	}
	rows, _ := l.List(ctx, Filter{Status: StatusError})
	if len(rows) != 1 || rows[0].Tenant != "beta" || rows[0].ErrorCode != "UPSTREAM_ERROR" {
		t.Fatalf("list %+v", rows)
	}
	n, _ := l.Purge(ctx, day2)
	if n != 2 {
		t.Fatalf("purged %d", n)
	}
	rows, _ = l.List(ctx, Filter{})
	if len(rows) != 2 {
		t.Fatalf("after purge %d", len(rows))
	}
}

// Review4 F: the same device id on two gateways must not merge stats.
func TestStatsByConnectionSeparatesGateways(t *testing.T) {
	ctx := context.Background()
	l, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, gw := range []string{"https://gw.a", "https://gw.b", "https://gw.b"} {
		if err := l.Record(ctx, Record{At: time.Now(), ConnectionID: "dev_same", Gateway: gw, Tenant: "t", TaskID: "x", Model: "m", Status: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	bs, err := l.Stats(ctx, Filter{}, []string{ByConn}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs[0].ConnectionGateway != "https://gw.a" || bs[0].Requests != 1 || bs[1].ConnectionGateway != "https://gw.b" || bs[1].Requests != 2 {
		t.Fatalf("buckets %+v", bs)
	}
}
