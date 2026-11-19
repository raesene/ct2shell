// Package publish defines the public data.json format and converts the
// monitor's private files (matches.jsonl, state.json) into it. Only fields
// that are already public via CT, RDAP and crt.sh are published.
package publish

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"ct2shell/internal/monitor"
	"ct2shell/internal/state"
)

type Data struct {
	GeneratedAt time.Time `json:"generated_at"`
	Suffixes    []string  `json:"suffixes"`
	Monitor     Monitor   `json:"monitor"`
	Records     []Record  `json:"records"`
}

type Monitor struct {
	ActiveLogs    int       `json:"active_logs"`     // logs updated in the last 10 minutes
	TotalLag      uint64    `json:"total_lag"`       // entries behind across active logs
	LastLogUpdate time.Time `json:"last_log_update"` // most recent position save
	Since         time.Time `json:"since,omitzero"`  // first record ever seen
}

type Record struct {
	Domain         string     `json:"domain"`
	Label          string     `json:"label"`
	MatchedSuffix  string     `json:"matched_suffix"`
	PublicSuffix   string     `json:"public_suffix"`
	Hosted         bool       `json:"hosted"` // private public suffix, e.g. github.io
	FirstSeen      time.Time  `json:"first_seen"`
	Names          []string   `json:"names"`
	Log            string     `json:"log"`
	Issuer         string     `json:"issuer"`
	DelaySec       float64    `json:"detection_delay_sec"`
	RegisteredAt   *time.Time `json:"registered_at,omitempty"`
	Registrar      string     `json:"registrar,omitempty"`
	CrtshCertCount *int       `json:"crtsh_cert_count,omitempty"`
	CrtshEarliest  *time.Time `json:"crtsh_earliest_not_before,omitempty"`
	Verdict        string     `json:"verdict"`
	BaseVerdict    string     `json:"base_verdict,omitempty"`
	BulkGroupSize  int        `json:"bulk_group_size,omitempty"`
	BulkRegistrar  string     `json:"bulk_registrar,omitempty"`
	Reclassified   bool       `json:"reclassified,omitempty"`
}

// issuerCN reduces "CN=YR1,O=Let's Encrypt,C=US" to "Let's Encrypt YR1".
func issuerCN(dn string) string {
	var cn, o string
	for _, part := range strings.Split(dn, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "CN":
			cn = v
		case "O":
			o = v
		}
	}
	switch {
	case o != "" && cn != "":
		return o + " " + cn
	case cn != "":
		return cn
	}
	return dn
}

// ReadMatches parses matches.jsonl, skipping a partially written last line.
func ReadMatches(path string) ([]Record, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m struct {
			monitor.Record
			ReclassifiedAt string `json:"reclassified_at"`
		}
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		r := Record{
			Domain: m.Domain, Label: m.Label, MatchedSuffix: m.Suffix, PublicSuffix: m.PublicSuffix,
			Hosted: !m.ICANN, FirstSeen: m.FirstSeen, Names: m.Names, Log: m.Cert.Log,
			Issuer: issuerCN(m.Cert.Issuer), DelaySec: m.DetectionDelaySec,
			Verdict: m.Verdict, BaseVerdict: m.BaseVerdict, Reclassified: m.ReclassifiedAt != "",
		}
		if e := m.Enrichment; e != nil {
			r.RegisteredAt, r.Registrar = e.RegisteredAt, e.Registrar
			r.CrtshCertCount, r.CrtshEarliest = e.CrtshCertCount, e.CrtshEarliest
		}
		if b := m.Bulk; b != nil && b.IsBulk {
			r.BulkGroupSize, r.BulkRegistrar = b.GroupSize, b.Registrar
		}
		if r.Verdict == "" {
			r.Verdict = "unknown"
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.Before(out[j].FirstSeen) })
	return out, sc.Err()
}

func MonitorStatus(st *state.Store, now time.Time) Monitor {
	var m Monitor
	for _, l := range st.Logs {
		if l.UpdatedAt.After(m.LastLogUpdate) {
			m.LastLogUpdate = l.UpdatedAt
		}
		if now.Sub(l.UpdatedAt) < 10*time.Minute {
			m.ActiveLogs++
			if l.Size > l.Next {
				m.TotalLag += l.Size - l.Next
			}
		}
	}
	return m
}

// Group is a cluster of bulk registrations.
type Group struct {
	Registrar string
	Start     time.Time
	End       time.Time
	Domains   []Record
}

// Groups clusters bulk records: same registrar, each first seen within
// window of the previous member.
func Groups(records []Record, window time.Duration) []Group {
	var gs []Group
	open := map[string]int{}    // registrar -> index of latest group
	for _, r := range records { // records are sorted by first_seen
		if r.Verdict != "bulk" {
			continue
		}
		key := strings.ToLower(r.Registrar)
		if i, ok := open[key]; ok && r.FirstSeen.Sub(gs[i].End) <= window {
			gs[i].Domains = append(gs[i].Domains, r)
			gs[i].End = r.FirstSeen
			continue
		}
		gs = append(gs, Group{Registrar: r.Registrar, Start: r.FirstSeen, End: r.FirstSeen, Domains: []Record{r}})
		open[key] = len(gs) - 1
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].Start.After(gs[j].Start) })
	return gs
}

// SameContent reports whether two Data differ only in timestamps/monitor
// figures, so the publisher can skip a commit.
func SameContent(a, b *Data) bool {
	ja, _ := json.Marshal(struct {
		S []string
		R []Record
	}{a.Suffixes, a.Records})
	jb, _ := json.Marshal(struct {
		S []string
		R []Record
	}{b.Suffixes, b.Records})
	return bytes.Equal(ja, jb)
}
