package publish

import (
	"testing"
	"time"
)

func TestIssuerCN(t *testing.T) {
	cases := map[string]string{
		"CN=YR1,O=Let's Encrypt,C=US":    "Let's Encrypt YR1",
		"CN=WE1,O=Google Trust Services": "Google Trust Services WE1",
		"CN=Only":                        "Only",
	}
	for in, want := range cases {
		if got := issuerCN(in); got != want {
			t.Errorf("issuerCN(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGroups(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	r := func(d, reg, v string, min int) Record {
		return Record{Domain: d, Registrar: reg, Verdict: v, FirstSeen: t0.Add(time.Duration(min) * time.Minute)}
	}
	recs := []Record{
		r("a2root.com", "Name.com, Inc.", "bulk", 0),
		r("b2root.com", "Name.com, Inc.", "bulk", 1),
		r("solo2shell.com", "GoDaddy.com, LLC", "new", 2),
		r("c2root.com", "name.com, inc.", "bulk", 20),  // chained: within 30m of previous member
		r("d2root.com", "Name.com, Inc.", "bulk", 120), // new burst later
	}
	gs := Groups(recs, 30*time.Minute)
	if len(gs) != 2 {
		t.Fatalf("got %d groups: %+v", len(gs), gs)
	}
	// newest first
	if len(gs[0].Domains) != 1 || gs[0].Domains[0].Domain != "d2root.com" {
		t.Errorf("latest group: %+v", gs[0])
	}
	if len(gs[1].Domains) != 3 || gs[1].End.Sub(gs[1].Start) != 20*time.Minute {
		t.Errorf("first group: %+v", gs[1])
	}
}

func TestSameContent(t *testing.T) {
	a := &Data{GeneratedAt: time.Now(), Suffixes: []string{"2shell"}, Records: []Record{{Domain: "x2shell.com"}}}
	b := *a
	b.GeneratedAt = a.GeneratedAt.Add(time.Hour)
	b.Monitor.TotalLag = 99
	if !SameContent(a, &b) {
		t.Error("timestamps/monitor should not count as a content change")
	}
	b.Records = append(b.Records, Record{Domain: "y2shell.com"})
	if SameContent(a, &b) {
		t.Error("new record should count as a change")
	}
}
