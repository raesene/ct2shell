package main

import (
	"testing"
	"time"

	"ct2shell/internal/publish"
)

func TestNewestFirst(t *testing.T) {
	t0 := time.Now()
	var recs []publish.Record // oldest first, as ReadMatches returns them
	for i, d := range []string{"a", "b", "c", "d"} {
		recs = append(recs, publish.Record{Domain: d, FirstSeen: t0.Add(time.Duration(i) * time.Minute)})
	}
	got := newestFirst(recs, 3)
	if len(got) != 3 || got[0].Domain != "d" || got[1].Domain != "c" || got[2].Domain != "b" {
		t.Fatalf("got %v", got)
	}
	if got := newestFirst(recs[:1], 3); len(got) != 1 || got[0].Domain != "a" {
		t.Fatalf("short input: %v", got)
	}
	if got := newestFirst(nil, 3); len(got) != 0 {
		t.Fatalf("empty input: %v", got)
	}
}
