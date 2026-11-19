// Package state persists log positions and seen domains as a JSON file.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogState struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Next      uint64    `json:"next"`
	Size      uint64    `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DomainState struct {
	FirstSeen time.Time       `json:"first_seen"`
	Emitted   bool            `json:"emitted"`
	Pending   json.RawMessage `json:"pending,omitempty"` // record awaiting enrichment/output
	Registrar string          `json:"registrar,omitempty"`
	Verdict   string          `json:"verdict,omitempty"`
}

// Peer is a summary of another seen domain, used for bulk detection.
type Peer struct {
	Domain    string
	FirstSeen time.Time
	Registrar string // empty if unknown / not yet enriched
	Verdict   string // empty if not yet emitted
}

type Store struct {
	path    string
	mu      sync.Mutex
	dirty   bool
	Logs    map[string]*LogState    `json:"logs"`
	Domains map[string]*DomainState `json:"domains"`
}

func Load(path string) (*Store, error) {
	s := &Store{path: path, Logs: map[string]*LogState{}, Domains: map[string]*DomainState{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Logs == nil {
		s.Logs = map[string]*LogState{}
	}
	if s.Domains == nil {
		s.Domains = map[string]*DomainState{}
	}
	return s, nil
}

// HasLogs reports whether this is an existing state file with log positions.
func (s *Store) HasLogs() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Logs) > 0
}

func (s *Store) LogPos(id string) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.Logs[id]
	if !ok {
		return 0, false
	}
	return l.Next, true
}

func (s *Store) SetLogPos(id, name, url string, next, size uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.Logs[id]
	if l == nil {
		l = &LogState{}
		s.Logs[id] = l
	}
	l.Name, l.URL, l.Next, l.Size, l.UpdatedAt = name, url, next, size, time.Now().UTC()
	s.dirty = true
}

// Lag returns size-next per log name.
func (s *Store) Lag() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]uint64, len(s.Logs))
	for _, l := range s.Logs {
		if l.Size > l.Next {
			m[l.Name] = l.Size - l.Next
		} else {
			m[l.Name] = 0
		}
	}
	return m
}

// MarkSeen records a domain; returns true if it had not been seen before.
func (s *Store) MarkSeen(domain string, pending json.RawMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Domains[domain]; ok {
		return false
	}
	s.Domains[domain] = &DomainState{FirstSeen: time.Now().UTC(), Pending: pending}
	s.dirty = true
	return true
}

func (s *Store) PendingRecord(domain string) json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.Domains[domain]; ok {
		return d.Pending
	}
	return nil
}

// UpdatePending replaces a not-yet-emitted domain's pending record.
func (s *Store) UpdatePending(domain string, raw json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.Domains[domain]; ok && !d.Emitted {
		d.Pending = raw
		s.dirty = true
	}
}

// SetRegistrar records a domain's registrar as soon as it is known, so peers
// being evaluated for bulk can compare against it.
func (s *Store) SetRegistrar(domain, registrar string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.Domains[domain]; ok && registrar != "" {
		d.Registrar = registrar
		s.dirty = true
	}
}

func (s *Store) MarkEmitted(domain, verdict string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.Domains[domain]; ok {
		d.Emitted, d.Pending, d.Verdict = true, nil, verdict
		s.dirty = true
	}
}

// Peers returns other domains first seen within window of t.
func (s *Store) Peers(self string, t time.Time, window time.Duration) []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Peer
	for d, ds := range s.Domains {
		if d == self {
			continue
		}
		if diff := ds.FirstSeen.Sub(t); diff <= window && diff >= -window {
			out = append(out, Peer{Domain: d, FirstSeen: ds.FirstSeen, Registrar: ds.Registrar, Verdict: ds.Verdict})
		}
	}
	return out
}

// Unemitted lists domains seen but not yet written out (e.g. after a crash).
func (s *Store) Unemitted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for d, ds := range s.Domains {
		if !ds.Emitted {
			out = append(out, d)
		}
	}
	return out
}

// Save writes the state atomically if it changed.
func (s *Store) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.MarshalIndent(s, "", " ")
	s.dirty = false
	s.mu.Unlock()
	if err == nil {
		err = s.write(b)
	}
	if err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
	}
	return err
}

func (s *Store) write(b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	return os.Rename(tmp.Name(), s.path)
}
