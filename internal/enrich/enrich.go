// Package enrich adds registration date (RDAP) and prior-certificate history
// (crt.sh) to a matched domain, and classifies it as new or existing.
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"
	crtshURL         = "https://crt.sh/"
	// A cert older than this before our sighting counts as prior history.
	historyGrace = 72 * time.Hour
)

type Result struct {
	RDAPDomain          string     `json:"rdap_domain,omitempty"`
	RegisteredAt        *time.Time `json:"registered_at,omitempty"`
	RegistrationAgeDays *float64   `json:"registration_age_days,omitempty"`
	Registrar           string     `json:"registrar,omitempty"`
	RDAPError           string     `json:"rdap_error,omitempty"`
	CrtshCertCount      *int       `json:"crtsh_cert_count,omitempty"`
	CrtshEarliest       *time.Time `json:"crtsh_earliest_not_before,omitempty"`
	CrtshError          string     `json:"crtsh_error,omitempty"`
	CrtshSkipped        string     `json:"crtsh_skipped,omitempty"`
}

type Enricher struct {
	c         *http.Client
	ua        string
	bootOnce  sync.Mutex
	boot      map[string]string // tld -> RDAP base URL
	bootAt    time.Time
	crtshMu   sync.Mutex
	crtshLast time.Time
}

func New(c *http.Client, ua string) *Enricher { return &Enricher{c: c, ua: ua} }

// RDAP fills registration data. Hosting-platform subdomains (private public
// suffixes such as github.io) have no registration of their own.
func (e *Enricher) RDAP(ctx context.Context, domain string, icann bool, firstSeen time.Time, r *Result) {
	if !icann {
		r.RDAPError = "private public suffix (hosting platform subdomain); RDAP not applicable"
		return
	}
	e.rdap(ctx, domain, firstSeen, r)
}

// Crtsh fills prior-certificate history. It is slow (crt.sh is a shared,
// overloaded service), so it is skipped when RDAP has already shown the
// domain was registered within newDays: crt.sh lags CT by hours and would
// have nothing to add.
func (e *Enricher) Crtsh(ctx context.Context, domain string, newDays int, r *Result) {
	if r.RegistrationAgeDays != nil && *r.RegistrationAgeDays <= float64(newDays) {
		r.CrtshSkipped = "recently registered per RDAP"
		return
	}
	e.crtsh(ctx, domain, r)
}

// Verdict classifies a domain from its enrichment data.
//
//	new        registered within newDays of first sighting
//	dormant    registered long ago but no cert history in CT
//	existing   old registration, or cert history before this sighting
//	likely_new no registration data, but no prior certs either
//	unknown    no usable data
func Verdict(r Result, firstSeen time.Time, newDays int) string {
	crtKnown := r.CrtshCertCount != nil
	history := r.CrtshEarliest != nil && r.CrtshEarliest.Before(firstSeen.Add(-historyGrace))
	switch {
	case r.RegistrationAgeDays != nil && *r.RegistrationAgeDays <= float64(newDays):
		return "new"
	case r.RegisteredAt != nil:
		if crtKnown && !history {
			return "dormant"
		}
		return "existing"
	case crtKnown && history:
		return "existing"
	case crtKnown:
		return "likely_new"
	default:
		return "unknown"
	}
}

func (e *Enricher) getJSON(ctx context.Context, u string, accept string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", e.ua)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := e.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &statusErr{resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

type statusErr struct{ code int }

func (s *statusErr) Error() string { return fmt.Sprintf("HTTP %d", s.code) }

// ---- RDAP ----

func (e *Enricher) rdapBase(ctx context.Context, tld string) (string, error) {
	e.bootOnce.Lock()
	defer e.bootOnce.Unlock()
	if e.boot == nil || time.Since(e.bootAt) > 24*time.Hour {
		var bs struct {
			Services [][][]string `json:"services"`
		}
		if err := e.getJSON(ctx, rdapBootstrapURL, "", &bs); err != nil {
			if e.boot == nil {
				return "", fmt.Errorf("rdap bootstrap: %w", err)
			}
		} else {
			m := map[string]string{}
			for _, svc := range bs.Services {
				if len(svc) < 2 || len(svc[1]) == 0 {
					continue
				}
				base := svc[1][0]
				for _, u := range svc[1] { // prefer https
					if strings.HasPrefix(u, "https://") {
						base = u
						break
					}
				}
				for _, t := range svc[0] {
					m[strings.ToLower(t)] = base
				}
			}
			e.boot, e.bootAt = m, time.Now()
		}
	}
	base, ok := e.boot[tld]
	if !ok {
		return "", fmt.Errorf("no RDAP service for .%s", tld)
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base, nil
}

func (e *Enricher) rdap(ctx context.Context, domain string, firstSeen time.Time, r *Result) {
	r.RDAPDomain = domain
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	base, err := e.rdapBase(ctx, tld)
	if err != nil {
		r.RDAPError = err.Error()
		return
	}
	var resp struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles []string        `json:"roles"`
			Vcard json.RawMessage `json:"vcardArray"`
		} `json:"entities"`
	}
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			if !sleepCtx(ctx, time.Duration(attempt)*5*time.Second) {
				break
			}
		}
		lastErr = e.getJSON(ctx, base+"domain/"+url.PathEscape(domain), "application/rdap+json", &resp)
		var se *statusErr
		if lastErr == nil || (errors.As(lastErr, &se) && se.code == http.StatusNotFound) {
			break
		}
	}
	if lastErr != nil {
		r.RDAPError = lastErr.Error()
		return
	}
	for _, ev := range resp.Events {
		if ev.Action != "registration" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, ev.Date); err == nil {
			t = t.UTC()
			age := firstSeen.Sub(t).Hours() / 24
			r.RegisteredAt, r.RegistrationAgeDays = &t, &age
		}
	}
	for _, ent := range resp.Entities {
		for _, role := range ent.Roles {
			if role == "registrar" {
				r.Registrar = vcardFN(ent.Vcard)
			}
		}
	}
	if r.RegisteredAt == nil {
		r.RDAPError = "no registration event in RDAP response"
	}
}

// vcardFN extracts the "fn" property from a jCard: ["vcard", [[name, params, type, value], ...]].
func vcardFN(raw json.RawMessage) string {
	var v []json.RawMessage
	if json.Unmarshal(raw, &v) != nil || len(v) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(v[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		var name, val string
		if len(p) >= 4 && json.Unmarshal(p[0], &name) == nil && name == "fn" && json.Unmarshal(p[3], &val) == nil {
			return val
		}
	}
	return ""
}

// ---- crt.sh ----

type crtshEntry struct {
	ID        int64  `json:"id"`
	NotBefore string `json:"not_before"`
}

func (e *Enricher) crtshQuery(ctx context.Context, q string) ([]crtshEntry, error) {
	// crt.sh is a shared free service: serialise and space out requests.
	e.crtshMu.Lock()
	defer e.crtshMu.Unlock()
	var out []crtshEntry
	var err error
	for attempt := range 4 {
		if wait := 3*time.Second - time.Since(e.crtshLast); wait > 0 {
			sleepCtx(ctx, wait)
		}
		if attempt > 0 && !sleepCtx(ctx, time.Duration(attempt*attempt)*10*time.Second) {
			break
		}
		e.crtshLast = time.Now()
		out = nil
		err = e.getJSON(ctx, crtshURL+"?output=json&deduplicate=Y&q="+url.QueryEscape(q), "", &out)
		if err == nil {
			return out, nil
		}
	}
	return nil, err
}

func (e *Enricher) crtsh(ctx context.Context, domain string, r *Result) {
	seen := map[int64]bool{}
	var earliest *time.Time
	for _, q := range []string{domain, "%." + domain} {
		es, err := e.crtshQuery(ctx, q)
		if err != nil {
			r.CrtshError = fmt.Sprintf("crt.sh q=%s: %v", q, err)
			return
		}
		for _, x := range es {
			if seen[x.ID] {
				continue
			}
			seen[x.ID] = true
			if t, err := time.Parse("2006-01-02T15:04:05", x.NotBefore); err == nil {
				if earliest == nil || t.Before(*earliest) {
					earliest = &t
				}
			}
		}
	}
	n := len(seen)
	r.CrtshCertCount, r.CrtshEarliest = &n, earliest
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
