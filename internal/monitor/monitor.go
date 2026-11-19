// Package monitor ties the pieces together: prefilter raw entries, extract
// names, match, dedupe, enrich, and write JSONL.
package monitor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ct2shell/internal/ctlog"
	"ct2shell/internal/enrich"
	"ct2shell/internal/match"
	"ct2shell/internal/state"
)

type CertInfo struct {
	Log          string    `json:"log"`
	LogIndex     uint64    `json:"log_index"`
	LogTimestamp time.Time `json:"log_timestamp"`
	Precert      bool      `json:"precert"`
	Issuer       string    `json:"issuer,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	NotBefore    time.Time `json:"not_before,omitzero"`
	NotAfter     time.Time `json:"not_after,omitzero"`
	ParseError   string    `json:"parse_error,omitempty"`
}

type Record struct {
	match.Hit
	FirstSeen   time.Time      `json:"first_seen"`
	Names       []string       `json:"names"` // all names on the cert under this domain
	AllNames    int            `json:"cert_name_count"`
	Cert        CertInfo       `json:"cert"`
	Enrichment  *enrich.Result `json:"enrichment,omitempty"`
	Bulk        *Bulk          `json:"bulk,omitempty"`
	Verdict     string         `json:"verdict,omitempty"`
	BaseVerdict string         `json:"base_verdict,omitempty"` // verdict before bulk override
	// Lead indicators for later analysis.
	DetectionDelaySec float64 `json:"detection_delay_sec"` // first_seen - log_timestamp
}

type Stats struct {
	Entries    atomic.Uint64
	Candidates atomic.Uint64 // prefilter hits
	Matches    atomic.Uint64 // matched names (incl. duplicates)
	NewDomains atomic.Uint64
	ParseFails atomic.Uint64
}

type Monitor struct {
	m        *match.Matcher
	st       *state.Store
	enr      *enrich.Enricher // nil => no enrichment
	newDays  int
	bulk     BulkConfig
	log      *slog.Logger
	Stats    Stats
	needles  [][]byte
	fallback *regexp.Regexp
	queue    chan string

	outMu sync.Mutex
	out   *os.File
}

func New(m *match.Matcher, st *state.Store, enr *enrich.Enricher, outPath string, newDays int, bulk BulkConfig, log *slog.Logger) (*Monitor, error) {
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	mo := &Monitor{m: m, st: st, enr: enr, newDays: newDays, bulk: bulk, log: log, out: f, queue: make(chan string, 4096)}
	var alt []string
	for _, s := range m.Suffixes() {
		mo.needles = append(mo.needles, []byte(s))
		alt = append(alt, regexp.QuoteMeta(s))
	}
	// Used only when a matching cert can't be parsed: pull hostnames out of raw DER.
	mo.fallback = regexp.MustCompile(`[a-z0-9*_-][a-z0-9._*-]*(?:` + joinAlt(alt) + `)\.[a-z0-9.-]*[a-z0-9]`)
	return mo, nil
}

func joinAlt(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += "|"
		}
		s += x
	}
	return s
}

func (mo *Monitor) Close() error { return mo.out.Close() }

// Handle is called by log runners, concurrently across logs.
func (mo *Monitor) Handle(logName string, es []ctlog.Entry) {
	var buf []byte
	for i := range es {
		e := &es[i]
		buf = asciiLower(buf[:0], e.Signed)
		hit := false
		for _, n := range mo.needles {
			if bytes.Contains(buf, n) {
				hit = true
				break
			}
		}
		if hit {
			mo.Stats.Candidates.Add(1)
			mo.candidate(logName, e, buf)
		}
	}
	mo.Stats.Entries.Add(uint64(len(es)))
}

func asciiLower(dst, src []byte) []byte {
	dst = append(dst, src...)
	for i, c := range dst {
		if c >= 'A' && c <= 'Z' {
			dst[i] = c + 32
		}
	}
	return dst
}

func (mo *Monitor) candidate(logName string, e *ctlog.Entry, lowered []byte) {
	ci := CertInfo{Log: logName, LogIndex: e.Index, LogTimestamp: time.UnixMilli(int64(e.Timestamp)).UTC(), Precert: e.Precert}
	var names []string
	var cert *x509.Certificate
	var err error
	if e.Cert != nil {
		cert, err = x509.ParseCertificate(e.Cert)
	}
	if cert != nil {
		names = append(names, cert.DNSNames...)
		if cert.Subject.CommonName != "" {
			names = append(names, cert.Subject.CommonName)
		}
		ci.Issuer = cert.Issuer.String()
		ci.Serial = hex.EncodeToString(cert.SerialNumber.Bytes())
		ci.NotBefore, ci.NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
	} else {
		mo.Stats.ParseFails.Add(1)
		if err != nil {
			ci.ParseError = err.Error()
		} else {
			ci.ParseError = "no full certificate in entry"
		}
		for _, b := range mo.fallback.FindAll(lowered, -1) {
			names = append(names, string(b))
		}
	}

	byDomain := map[string]*Record{}
	for _, n := range names {
		h, ok := mo.m.Match(n)
		if !ok {
			continue
		}
		mo.Stats.Matches.Add(1)
		r := byDomain[h.Domain]
		if r == nil {
			r = &Record{Hit: h, Cert: ci, AllNames: len(names)}
			byDomain[h.Domain] = r
		}
		if ln := strings.ToLower(n); !contains(r.Names, ln) {
			r.Names = append(r.Names, ln)
		}
	}
	for d, r := range byDomain {
		r.FirstSeen = time.Now().UTC()
		r.DetectionDelaySec = r.FirstSeen.Sub(ci.LogTimestamp).Seconds()
		sort.Strings(r.Names)
		b, _ := json.Marshal(r)
		if mo.st.MarkSeen(d, b) {
			mo.Stats.NewDomains.Add(1)
			mo.log.Info("NEW MATCH", "domain", d, "names", r.Names, "log", logName, "index", e.Index,
				"issuer", ci.Issuer, "delay_s", int(r.DetectionDelaySec))
			mo.enqueue(d)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func (mo *Monitor) enqueue(d string) {
	select {
	case mo.queue <- d:
	default:
		go func() { mo.queue <- d }()
	}
}

// Requeue re-submits domains that were seen but never written (crash recovery).
func (mo *Monitor) Requeue() {
	for _, d := range mo.st.Unemitted() {
		mo.enqueue(d)
	}
}

func (mo *Monitor) loadPending(d string) (*Record, bool) {
	raw := mo.st.PendingRecord(d)
	if raw == nil {
		return nil, false
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		mo.log.Error("bad pending record", "domain", d, "err", err)
		mo.st.MarkEmitted(d, "")
		return nil, false
	}
	return &r, true
}

func (mo *Monitor) savePending(r *Record) {
	if b, err := json.Marshal(r); err == nil {
		mo.st.UpdatePending(r.Domain, b)
	}
}

// RunEnricher runs the two enrichment stages until ctx ends:
//
//  1. RDAP, immediately on detection (fast), so every member of a burst has
//     its registrar recorded before any of them is judged.
//  2. After the bulk hold has elapsed since first sighting: bulk grouping,
//     crt.sh history if still needed, verdict, write.
func (mo *Monitor) RunEnricher(ctx context.Context) {
	finalize := make(chan string, 4096)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case d := <-mo.queue:
				r, ok := mo.loadPending(d)
				if !ok {
					continue
				}
				if mo.enr != nil && r.Enrichment == nil {
					var res enrich.Result
					ectx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					mo.enr.RDAP(ectx, r.Domain, r.ICANN, r.FirstSeen, &res)
					cancel()
					if ctx.Err() != nil {
						return
					}
					r.Enrichment = &res
					mo.savePending(r)
					mo.st.SetRegistrar(d, res.Registrar)
				}
				select {
				case finalize <- d:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case d := <-finalize:
			r, ok := mo.loadPending(d)
			if !ok {
				continue
			}
			// Let the rest of a burst arrive (and be RDAP'd) before judging.
			if wait := time.Until(r.FirstSeen.Add(mo.bulk.Hold)); wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			registrar := ""
			if r.Enrichment != nil {
				registrar = r.Enrichment.Registrar
			}
			b := bulkCheck(registrar, mo.st.Peers(d, r.FirstSeen, mo.bulk.Window), mo.bulk)
			r.Bulk = &b

			base := ""
			if mo.enr != nil && r.Enrichment != nil {
				// Bulk members are squatting; their crt.sh history adds little
				// and each lookup takes ~30s+, so don't let a burst of 50
				// delay a real disclosure site queued behind it.
				if b.IsBulk {
					r.Enrichment.CrtshSkipped = "bulk registration"
				} else {
					ectx, cancel := context.WithTimeout(ctx, 5*time.Minute)
					mo.enr.Crtsh(ectx, r.Domain, mo.newDays, r.Enrichment)
					cancel()
					if ctx.Err() != nil {
						return // stays pending for next run
					}
				}
				base = enrich.Verdict(*r.Enrichment, r.FirstSeen, mo.newDays)
			}
			r.Verdict = applyBulk(base, b)
			if r.Verdict != base {
				r.BaseVerdict = base
			}
			if err := mo.write(r); err != nil {
				mo.log.Error("write output", "err", err)
				continue
			}
			mo.st.MarkEmitted(d, r.Verdict)
			mo.log.Info("recorded", "domain", d, "verdict", r.Verdict, "bulk_group", b.GroupSize)
		}
	}
}

func (mo *Monitor) write(r *Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	mo.outMu.Lock()
	defer mo.outMu.Unlock()
	if _, err := mo.out.Write(b); err != nil {
		return err
	}
	return mo.out.Sync()
}
