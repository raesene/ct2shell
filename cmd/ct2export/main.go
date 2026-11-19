// Command ct2export converts the monitor's private files into the public
// data.json consumed by the GitHub Pages site. It leaves the output file
// untouched (exit 0, "unchanged") when the records are the same and the
// existing file is younger than -heartbeat, so the publisher can skip a commit.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ct2shell/internal/publish"
	"ct2shell/internal/state"
)

func main() {
	matches := flag.String("matches", "matches.jsonl", "monitor JSONL output")
	statePath := flag.String("state", "state.json", "monitor state file")
	out := flag.String("out", "data.json", "public data file to write")
	suffixes := flag.String("suffixes", "4shell,2shell,2root,4root", "suffixes being monitored (for display)")
	heartbeat := flag.Duration("heartbeat", 6*time.Hour, "rewrite even if unchanged once the existing file is this old")
	flag.Parse()

	recs, err := publish.ReadMatches(*matches)
	if err != nil {
		fail(err)
	}
	st, err := state.Load(*statePath)
	if err != nil {
		fail(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	d := &publish.Data{
		GeneratedAt: now,
		Suffixes:    strings.Split(*suffixes, ","),
		Monitor:     publish.MonitorStatus(st, now),
		Records:     recs,
	}
	if d.Records == nil {
		d.Records = []publish.Record{}
	}
	if len(recs) > 0 {
		d.Monitor.Since = recs[0].FirstSeen
	}

	if b, err := os.ReadFile(*out); err == nil {
		var old publish.Data
		if json.Unmarshal(b, &old) == nil && publish.SameContent(&old, d) && now.Sub(old.GeneratedAt) < *heartbeat {
			fmt.Println("unchanged")
			return
		}
	}
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		fail(err)
	}
	tmp := *out + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		fail(err)
	}
	if err := os.Rename(tmp, *out); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %d records\n", len(recs))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ct2export:", err)
	os.Exit(1)
}
