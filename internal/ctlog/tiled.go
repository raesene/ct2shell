package ctlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const tileWidth = 256

// Tiled reads a static-ct-api (C2SP) log via its monitoring prefix.
type Tiled struct {
	base string
	c    *http.Client
}

func NewTiled(monitoringURL string, c *http.Client) *Tiled {
	if !strings.HasSuffix(monitoringURL, "/") {
		monitoringURL += "/"
	}
	return &Tiled{base: monitoringURL, c: c}
}

// Size reads the tree size from the checkpoint. Signatures are not verified:
// we are a name monitor, not an auditor.
func (t *Tiled) Size(ctx context.Context) (uint64, error) {
	b, err := get(ctx, t.c, t.base+"checkpoint", 1<<16)
	if err != nil {
		return 0, err
	}
	lines := strings.SplitN(string(b), "\n", 3)
	if len(lines) < 2 {
		return 0, fmt.Errorf("malformed checkpoint")
	}
	return strconv.ParseUint(lines[1], 10, 64)
}

// Plan splits [pos,size) into tile-aligned ranges. The trailing partial tile
// is only included when allowPartial is set, since it will be re-downloaded
// once the full tile exists.
func (t *Tiled) Plan(pos, size uint64, allowPartial bool, k int) []Range {
	var rs []Range
	for len(rs) < k && pos < size {
		end := (pos/tileWidth + 1) * tileWidth
		if end > size {
			if !allowPartial {
				break
			}
			end = size
		}
		rs = append(rs, Range{pos, end})
		pos = end
	}
	return rs
}

// TilePath encodes a data tile path per C2SP tlog-tiles.
func TilePath(n uint64, width uint64) string {
	p := fmt.Sprintf("%03d", n%1000)
	for n /= 1000; n > 0; n /= 1000 {
		p = fmt.Sprintf("x%03d/", n%1000) + p
	}
	p = "tile/data/" + p
	if width > 0 && width < tileWidth {
		p += fmt.Sprintf(".p/%d", width)
	}
	return p
}

func (t *Tiled) Fetch(ctx context.Context, r Range) ([]Entry, error) {
	n := r.Start / tileWidth
	width := r.End - n*tileWidth
	b, err := get(ctx, t.c, t.base+TilePath(n, width), 64<<20)
	var he *HTTPError
	if width < tileWidth && errors.As(err, &he) && he.Status == http.StatusNotFound {
		// Partial tile may have been replaced by the full tile.
		b, err = get(ctx, t.c, t.base+TilePath(n, tileWidth), 64<<20)
	}
	if errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusForbidden) {
		// Checkpoint published before the tile reached the CDN (seen on
		// TrustAsia, where the 404 is briefly cached, and on HARICA's
		// BunnyCDN, which answers 403 for missing objects).
		return nil, fmt.Errorf("%w: %v", ErrNotReady, err)
	}
	if err != nil {
		return nil, err
	}
	s := cryptobyte.String(b)
	out := make([]Entry, 0, r.End-r.Start)
	for i := uint64(0); i < width; i++ {
		var e Entry
		if err := ReadTileLeaf(&s, &e); err != nil {
			return nil, fmt.Errorf("tile %d entry %d: %w", n, i, err)
		}
		e.Index = n*tileWidth + i
		if e.Index >= r.Start {
			out = append(out, e)
		}
	}
	return out, nil
}
