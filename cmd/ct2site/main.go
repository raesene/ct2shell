// Command ct2site renders the static GitHub Pages site from data.json.
// The page is complete without JavaScript; site/app.js only moves the lamp,
// filters the table, and reloads when newer data has been published.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ct2shell/internal/publish"
)

type marker struct{ Word, Class string }

var markers = map[string]marker{
	"new":        {"NEW", "ok"},
	"likely_new": {"LIKELY", "info"},
	"dormant":    {"DORMANT", "info"},
	"bulk":       {"BULK", "warn"},
	"existing":   {"KNOWN", "muted"},
	"unknown":    {"UNKN", "muted"},
}

// Order and wording for the marker list.
var markerDefs = []struct{ Verdict, Text string }{
	{"new", "Registered within the last 30 days and not part of a burst. These are the ones to look at."},
	{"likely_new", "No registration record (a hosting-platform subdomain or a TLD without RDAP) and no earlier certificates."},
	{"dormant", "Registered long ago but never had a certificate before now."},
	{"bulk", "Freshly registered as part of a burst: three or more matches from one registrar within 30 minutes. Usually speculative squatting."},
	{"existing", "An established domain renewing its certificate."},
	{"unknown", "Enrichment failed; judge it by hand."},
}

type view struct {
	D         *publish.Data
	Counts    map[string]int
	Total     int
	Log       []publish.Record // last entries, oldest first
	Corner    []publish.Record // last three
	Fresh     []publish.Record // new / likely_new / dormant, newest first
	Groups    []publish.Group
	All       []publish.Record // newest first
	Defs      []struct{ Verdict, Text string }
	Generated string
}

func main() {
	dataPath := flag.String("data", "data/data.json", "published data file")
	siteDir := flag.String("site", "site", "site sources (templates, css, js, assets)")
	outDir := flag.String("out", "_site", "output directory")
	flag.Parse()

	d := &publish.Data{GeneratedAt: time.Now().UTC(), Records: []publish.Record{}}
	if b, err := os.ReadFile(*dataPath); err == nil {
		if err := json.Unmarshal(b, d); err != nil {
			fail(fmt.Errorf("parse %s: %w", *dataPath, err))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fail(err)
	}

	v := view{D: d, Counts: map[string]int{}, Total: len(d.Records), Defs: markerDefs,
		Generated: d.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")}
	for _, r := range d.Records {
		v.Counts[r.Verdict]++
	}
	recs := d.Records // oldest first
	v.Log = recs[max(0, len(recs)-11):]
	v.Corner = recs[max(0, len(recs)-3):]
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		v.All = append(v.All, r)
		switch r.Verdict {
		case "new", "likely_new", "dormant":
			v.Fresh = append(v.Fresh, r)
		}
	}
	v.Groups = publish.Groups(recs, 30*time.Minute)

	funcs := template.FuncMap{
		"marker": func(verdict string) marker {
			if m, ok := markers[verdict]; ok {
				return m
			}
			return marker{strings.ToUpper(verdict), "muted"}
		},
		"ts": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"hm": func(t time.Time) string { return t.UTC().Format("15:04") },
		"day": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.UTC().Format("2006-01-02")
		},
		"iso": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"isop": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.UTC().Format(time.RFC3339)
		},
		"sentence": sentence,
		"join":     strings.Join,
		"names":    func(g publish.Group) []string { return groupNames(g, 8) },
		"more":     func(g publish.Group) int { return max(0, len(g.Domains)-8) },
		"span": func(g publish.Group) string {
			d := g.End.Sub(g.Start).Round(time.Second)
			if d < time.Minute {
				return fmt.Sprintf("%ds", int(d.Seconds()))
			}
			return d.Round(time.Minute).String()
		},
		"add": func(a, b int) int { return a + b },
		"suffixes": func(s []string) string {
			var out []string
			for _, x := range s {
				out = append(out, "*"+x)
			}
			return strings.Join(out, " ")
		},
		"delay": func(s float64) string { return fmt.Sprintf("%.0fs", s) },
		"comma": func(n uint64) string {
			s := fmt.Sprint(n)
			for i := len(s) - 3; i > 0; i -= 3 {
				s = s[:i] + "," + s[i:]
			}
			return s
		},
	}
	tmpl, err := template.New("index.html.tmpl").Funcs(funcs).ParseFiles(filepath.Join(*siteDir, "templates", "index.html.tmpl"))
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Join(*outDir, "assets"), 0o755); err != nil {
		fail(err)
	}
	f, err := os.Create(filepath.Join(*outDir, "index.html"))
	if err != nil {
		fail(err)
	}
	if err := tmpl.Execute(f, v); err != nil {
		fail(err)
	}
	f.Close()

	// Static files and a copy of the data for the refresh check / reuse.
	for _, p := range []string{"style.css", "app.js", "assets/hero.webp"} {
		if err := copyFile(filepath.Join(*siteDir, p), filepath.Join(*outDir, p)); err != nil {
			fail(err)
		}
	}
	b, _ := json.Marshal(d)
	if err := os.WriteFile(filepath.Join(*outDir, "data.json"), b, 0o644); err != nil {
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, ".nojekyll"), nil, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("rendered %d records, %d groups -> %s\n", len(d.Records), len(v.Groups), *outDir)
}

func sentence(r publish.Record) string {
	var b strings.Builder
	b.WriteString(r.Domain)
	b.WriteString(" got its first cert from ")
	b.WriteString(r.Issuer)
	switch {
	case r.Hosted:
		fmt.Fprintf(&b, ", hosted on %s", r.PublicSuffix)
	case r.RegisteredAt != nil && r.Registrar != "":
		fmt.Fprintf(&b, ", registered %s at %s", r.RegisteredAt.UTC().Format("Jan 2 15:04"), r.Registrar)
	case r.RegisteredAt != nil:
		fmt.Fprintf(&b, ", registered %s", r.RegisteredAt.UTC().Format("Jan 2 15:04"))
	}
	if r.BulkGroupSize > 0 {
		fmt.Fprintf(&b, ", one of a %d-domain burst", r.BulkGroupSize)
	}
	b.WriteString(".")
	return b.String()
}

func groupNames(g publish.Group, n int) []string {
	var out []string
	for _, r := range g.Domains {
		out = append(out, r.Domain)
	}
	sort.Strings(out)
	return out[:min(n, len(out))]
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ct2site:", err)
	os.Exit(1)
}
