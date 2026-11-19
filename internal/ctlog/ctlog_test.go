package ctlog

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func TestTilePath(t *testing.T) {
	cases := map[[2]uint64]string{
		{0, 256}:       "tile/data/000",
		{5, 256}:       "tile/data/005",
		{1234067, 256}: "tile/data/x001/x234/067",
		{1000, 17}:     "tile/data/x001/000.p/17",
	}
	for in, want := range cases {
		if got := TilePath(in[0], in[1]); got != want {
			t.Errorf("TilePath(%d,%d)=%s want %s", in[0], in[1], got, want)
		}
	}
}

func TestPlanTiled(t *testing.T) {
	tl := &Tiled{}
	got := tl.Plan(250, 700, false, 10)
	want := []Range{{250, 256}, {256, 512}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("no partial: %v", got)
	}
	got = tl.Plan(250, 700, true, 10)
	if len(got) != 3 || got[2] != (Range{512, 700}) {
		t.Fatalf("partial: %v", got)
	}
}

func buildTileLeaf(precert bool, signed, pre []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint64(1_700_000_000_000)
	if precert {
		b.AddUint16(entryTypePrecert)
		b.AddBytes(make([]byte, 32))
	} else {
		b.AddUint16(entryTypeX509)
	}
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(signed) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {}) // extensions
	if precert {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pre) })
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 64)) }) // 2 fingerprints
	return b.BytesOrPanic()
}

func TestReadTileLeaf(t *testing.T) {
	data := append(buildTileLeaf(false, []byte("CERT"), nil), buildTileLeaf(true, []byte("TBS"), []byte("PRECERT"))...)
	s := cryptobyte.String(data)
	var a, b Entry
	if err := ReadTileLeaf(&s, &a); err != nil {
		t.Fatal(err)
	}
	if err := ReadTileLeaf(&s, &b); err != nil {
		t.Fatal(err)
	}
	if !s.Empty() {
		t.Fatalf("%d trailing bytes", len(s))
	}
	if a.Precert || !bytes.Equal(a.Cert, []byte("CERT")) || a.Timestamp != 1_700_000_000_000 {
		t.Errorf("x509 entry: %+v", a)
	}
	if !b.Precert || !bytes.Equal(b.Signed, []byte("TBS")) || !bytes.Equal(b.Cert, []byte("PRECERT")) {
		t.Errorf("precert entry: %+v", b)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("7"); d != 7*time.Second {
		t.Errorf("seconds: %v", d)
	}
	future := time.Now().Add(3 * time.Second).UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC")
	if d := parseRetryAfter(future); d <= 0 || d > 4*time.Second {
		t.Errorf("http-date %q: %v", future, d)
	}
}
