package ctlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// RFC6962 reads a classic CT log via get-sth / get-entries.
type RFC6962 struct {
	base  string
	c     *http.Client
	batch uint64
}

func NewRFC6962(url string, c *http.Client, batch uint64) *RFC6962 {
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	return &RFC6962{base: url, c: c, batch: batch}
}

func (l *RFC6962) Size(ctx context.Context) (uint64, error) {
	b, err := get(ctx, l.c, l.base+"ct/v1/get-sth", 1<<16)
	if err != nil {
		return 0, err
	}
	var sth struct {
		TreeSize uint64 `json:"tree_size"`
	}
	if err := json.Unmarshal(b, &sth); err != nil {
		return 0, err
	}
	return sth.TreeSize, nil
}

// Plan splits [pos,size) into batch-aligned ranges (alignment helps logs that
// cap responses at internal boundaries).
func (l *RFC6962) Plan(pos, size uint64, _ bool, k int) []Range {
	var rs []Range
	for len(rs) < k && pos < size {
		end := min((pos/l.batch+1)*l.batch, size)
		rs = append(rs, Range{pos, end})
		pos = end
	}
	return rs
}

func (l *RFC6962) Fetch(ctx context.Context, r Range) ([]Entry, error) {
	out := make([]Entry, 0, r.End-r.Start)
	for start := r.Start; start < r.End; {
		url := fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", l.base, start, r.End-1)
		b, err := get(ctx, l.c, url, 128<<20)
		var he *HTTPError
		if errors.As(err, &he) && he.Status == http.StatusBadRequest {
			// Some frontends advertise an STH ahead of what they will serve.
			return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
		}
		if err != nil {
			return nil, err
		}
		var resp struct {
			Entries []struct {
				LeafInput []byte `json:"leaf_input"`
				ExtraData []byte `json:"extra_data"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(b, &resp); err != nil {
			return nil, err
		}
		if len(resp.Entries) == 0 {
			return nil, fmt.Errorf("%w: get-entries %d-%d returned no entries", ErrNotReady, start, r.End-1)
		}
		for _, je := range resp.Entries {
			if start >= r.End {
				break
			}
			e := Entry{Index: start}
			if err := ParseMerkleTreeLeaf(je.LeafInput, je.ExtraData, &e); err != nil {
				return nil, fmt.Errorf("entry %d: %w", start, err)
			}
			out = append(out, e)
			start++
		}
	}
	return out, nil
}
