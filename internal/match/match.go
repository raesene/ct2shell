// Package match decides whether a DNS name's registrable label ends in one of
// the target suffixes (e.g. "react2shell.com" -> label "react2shell").
package match

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Matcher struct {
	suffixes []string
}

func New(suffixes []string) *Matcher {
	m := &Matcher{}
	for _, s := range suffixes {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			m.suffixes = append(m.suffixes, s)
		}
	}
	return m
}

func (m *Matcher) Suffixes() []string { return m.suffixes }

type Hit struct {
	Domain       string `json:"domain"`        // registrable domain (eTLD+1)
	Label        string `json:"label"`         // label before the public suffix
	PublicSuffix string `json:"public_suffix"` // e.g. "com", "co.uk", "github.io"
	ICANN        bool   `json:"icann"`         // false => private suffix (hosting platform)
	Suffix       string `json:"matched_suffix"`
}

// Normalize lowercases, strips a leading wildcard and trailing dot, and
// rejects anything that is not a plausible hostname.
func Normalize(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	n = strings.TrimPrefix(n, "*.")
	if n == "" || len(n) > 253 || !strings.Contains(n, ".") {
		return "", false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return "", false
		}
	}
	return n, true
}

func (m *Matcher) Match(name string) (Hit, bool) {
	n, ok := Normalize(name)
	if !ok {
		return Hit{}, false
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return Hit{}, false
	}
	label, ps, _ := strings.Cut(etld1, ".")
	for _, s := range m.suffixes {
		if strings.HasSuffix(label, s) {
			_, icann := publicsuffix.PublicSuffix(n)
			return Hit{Domain: etld1, Label: label, PublicSuffix: ps, ICANN: icann, Suffix: s}, true
		}
	}
	return Hit{}, false
}
