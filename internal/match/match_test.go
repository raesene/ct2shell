package match

import "testing"

func TestMatch(t *testing.T) {
	m := New([]string{"4shell", "2shell", "2root", "4root"})
	cases := []struct {
		name   string
		domain string
		icann  bool
		ok     bool
	}{
		{"react2shell.com", "react2shell.com", true, true},
		{"*.react2shell.com", "react2shell.com", true, true},
		{"www.Log4Shell.com.", "log4shell.com", true, true},
		{"text4shell.co.uk", "text4shell.co.uk", true, true},
		{"sudo2root.github.io", "sudo2root.github.io", false, true},
		{"api.kernel4root.io", "kernel4root.io", true, true},
		{"4root.net", "4root.net", true, true},
		// pattern only in a subdomain label -> not matched (registrable label only)
		{"react2shell.example.com", "", false, false},
		// pattern not at the end of the label
		{"react2shellfan.com", "", false, false},
		{"2shell-blog.com", "", false, false},
		// bare public suffix / junk
		{"com", "", false, false},
		{"github.io", "", false, false},
		{"foo bar.com", "", false, false},
	}
	for _, c := range cases {
		h, ok := m.Match(c.name)
		if ok != c.ok || h.Domain != c.domain || (ok && h.ICANN != c.icann) {
			t.Errorf("Match(%q) = %+v,%v; want domain=%q icann=%v ok=%v", c.name, h, ok, c.domain, c.icann, c.ok)
		}
	}
}
