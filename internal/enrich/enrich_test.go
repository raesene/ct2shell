package enrich

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerdict(t *testing.T) {
	seen := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	ptrT := func(d time.Duration) *time.Time { x := seen.Add(-d); return &x }
	ptrF := func(f float64) *float64 { return &f }
	ptrI := func(i int) *int { return &i }
	day := 24 * time.Hour
	cases := []struct {
		name string
		r    Result
		want string
	}{
		{"fresh registration", Result{RegisteredAt: ptrT(2 * day), RegistrationAgeDays: ptrF(2), CrtshCertCount: ptrI(0)}, "new"},
		{"re-registered with old history", Result{RegisteredAt: ptrT(5 * day), RegistrationAgeDays: ptrF(5), CrtshCertCount: ptrI(9), CrtshEarliest: ptrT(900 * day)}, "new"},
		{"old with history", Result{RegisteredAt: ptrT(800 * day), RegistrationAgeDays: ptrF(800), CrtshCertCount: ptrI(9), CrtshEarliest: ptrT(700 * day)}, "existing"},
		{"old, no certs ever", Result{RegisteredAt: ptrT(800 * day), RegistrationAgeDays: ptrF(800), CrtshCertCount: ptrI(0)}, "dormant"},
		{"old, only today's cert", Result{RegisteredAt: ptrT(800 * day), RegistrationAgeDays: ptrF(800), CrtshCertCount: ptrI(1), CrtshEarliest: ptrT(time.Hour)}, "dormant"},
		{"hosted, no history", Result{CrtshCertCount: ptrI(0)}, "likely_new"},
		{"hosted, history", Result{CrtshCertCount: ptrI(3), CrtshEarliest: ptrT(30 * day)}, "existing"},
		{"nothing", Result{}, "unknown"},
	}
	for _, c := range cases {
		if got := Verdict(c.r, seen, 30); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestVcardFN(t *testing.T) {
	raw := json.RawMessage(`["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]`)
	if got := vcardFN(raw); got != "Example Registrar, Inc." {
		t.Fatalf("got %q", got)
	}
}
