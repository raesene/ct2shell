package monitor

import (
	"testing"
	"time"

	"ct2shell/internal/state"
)

func TestBulkCheck(t *testing.T) {
	now := time.Now()
	cfg := BulkConfig{Window: 30 * time.Minute, Min: 3}
	p := func(d, reg, verdict string) state.Peer {
		return state.Peer{Domain: d, FirstSeen: now, Registrar: reg, Verdict: verdict}
	}

	// Today's real burst: same registrar, seconds apart.
	b := bulkCheck("Name.com, Inc.", []state.Peer{
		p("express2root.com", "Name.com, Inc.", ""),
		p("flask2root.com", "name.com, inc.", "bulk"),
		p("esxi2shell.com", "", ""), // not yet enriched: still counts
	}, cfg)
	if !b.IsBulk || b.GroupSize != 4 || len(b.Peers) != 3 || b.Registrar != "" {
		t.Errorf("burst: %+v", b) // registrar not asserted: one peer unknown
	}

	// Different registrars and established renewals don't form a group.
	b = bulkCheck("Spaceship, Inc.", []state.Peer{
		p("a2shell.com", "Name.com, Inc.", ""),
		p("b2shell.com", "", "existing"),
	}, cfg)
	if b.IsBulk || b.GroupSize != 1 || b.Peers != nil {
		t.Errorf("unrelated: %+v", b)
	}

	// All peers share a known registrar -> group registrar reported.
	b = bulkCheck("Name.com, Inc.", []state.Peer{p("x2root.com", "Name.com, Inc.", ""), p("y2root.com", "Name.com, Inc.", "")}, cfg)
	if !b.IsBulk || b.Registrar != "Name.com, Inc." {
		t.Errorf("shared registrar: %+v", b)
	}

	// A lone genuine disclosure site.
	if b := bulkCheck("Cloudflare, Inc.", nil, cfg); b.IsBulk || b.GroupSize != 1 {
		t.Errorf("lone: %+v", b)
	}
}

func TestApplyBulk(t *testing.T) {
	yes := Bulk{IsBulk: true}
	cases := []struct {
		base string
		b    Bulk
		want string
	}{
		{"new", yes, "bulk"},
		{"likely_new", yes, "bulk"},
		{"existing", yes, "existing"},
		{"new", Bulk{}, "new"},
	}
	for _, c := range cases {
		if got := applyBulk(c.base, c.b); got != c.want {
			t.Errorf("applyBulk(%q,%v)=%q want %q", c.base, c.b.IsBulk, got, c.want)
		}
	}
}
