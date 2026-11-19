package monitor

import (
	"sort"
	"strings"
	"time"

	"ct2shell/internal/state"
)

// Bulk describes whether a domain arrived as part of a burst of matching
// registrations, the signature of speculative squatting (e.g. someone
// registering fortinet2root, flask2root, envoy2shell ... within a minute),
// as opposed to a one-off disclosure site.
type Bulk struct {
	IsBulk    bool     `json:"is_bulk"`
	GroupSize int      `json:"group_size"` // including this domain
	Peers     []string `json:"peers,omitempty"`
	WindowSec int      `json:"window_sec"`
	// Registrar the group shares, when known.
	Registrar string `json:"registrar,omitempty"`
}

type BulkConfig struct {
	Window time.Duration // peers must be first seen within ±Window
	Min    int           // group size (incl. self) at which a domain is bulk
	Hold   time.Duration // wait this long after first sighting before deciding
}

const maxPeersListed = 25

// bulkCheck groups a domain with peers first seen nearby. A peer is excluded
// if it is already known to be an established domain (verdict "existing";
// renewals cluster by chance), or if both registrars are known and differ.
// Peers whose registrar is not yet known still count: timing alone is a
// strong signal within a short window.
func bulkCheck(registrar string, peers []state.Peer, cfg BulkConfig) Bulk {
	b := Bulk{WindowSec: int(cfg.Window.Seconds())}
	sort.Slice(peers, func(i, j int) bool { return peers[i].FirstSeen.Before(peers[j].FirstSeen) })
	sameRegistrar := registrar != ""
	for _, p := range peers {
		if p.Verdict == "existing" {
			continue
		}
		if registrar != "" && p.Registrar != "" && !strings.EqualFold(registrar, p.Registrar) {
			continue
		}
		if p.Registrar == "" {
			sameRegistrar = false
		}
		b.GroupSize++
		if len(b.Peers) < maxPeersListed {
			b.Peers = append(b.Peers, p.Domain)
		}
	}
	b.GroupSize++ // self
	b.IsBulk = cfg.Min > 0 && b.GroupSize >= cfg.Min
	if b.IsBulk && sameRegistrar {
		b.Registrar = registrar
	}
	if !b.IsBulk {
		b.Peers = nil
	}
	return b
}

// applyBulk overrides "new-ish" verdicts with "bulk". Established domains
// keep "existing": bulk is a statement about fresh registrations.
func applyBulk(base string, b Bulk) string {
	if !b.IsBulk {
		return base
	}
	switch base {
	case "new", "likely_new", "dormant", "unknown", "":
		return "bulk"
	}
	return base
}
