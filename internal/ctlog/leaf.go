// Package ctlog reads entries from Certificate Transparency logs, supporting
// both the classic RFC 6962 JSON API and the C2SP static-ct-api (tiled) format.
package ctlog

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Entry is a single log entry, reduced to the parts needed for name matching.
// Byte slices may alias the fetch buffer and are only valid during Handle.
type Entry struct {
	Index     uint64
	Timestamp uint64 // milliseconds since epoch (SCT timestamp)
	Precert   bool
	// Signed is the signed_entry payload: the DER certificate for x509
	// entries, or the DER TBSCertificate for precert entries. Every name in the
	// certificate appears inside it, so it is what we prefilter on.
	Signed []byte
	// Cert is a full, parseable DER certificate (the final certificate or the
	// precertificate). May be nil if the log did not supply one.
	Cert []byte
}

const (
	entryTypeX509    = 0
	entryTypePrecert = 1
)

var errTruncated = errors.New("truncated or malformed entry")

// readTimestampedEntry parses an RFC 6962 TimestampedEntry.
func readTimestampedEntry(s *cryptobyte.String, e *Entry) error {
	var et uint16
	if !s.ReadUint64(&e.Timestamp) || !s.ReadUint16(&et) {
		return errTruncated
	}
	switch et {
	case entryTypeX509:
		var cert cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&cert) {
			return errTruncated
		}
		e.Signed, e.Cert = cert, cert
	case entryTypePrecert:
		var tbs cryptobyte.String
		if !s.Skip(32) || !s.ReadUint24LengthPrefixed(&tbs) {
			return errTruncated
		}
		e.Signed, e.Precert = tbs, true
	default:
		return fmt.Errorf("unknown entry type %d", et)
	}
	var ext cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ext) {
		return errTruncated
	}
	return nil
}

// ParseMerkleTreeLeaf parses an RFC 6962 leaf_input plus extra_data.
func ParseMerkleTreeLeaf(leaf, extra []byte, e *Entry) error {
	s := cryptobyte.String(leaf)
	var version, leafType uint8
	if !s.ReadUint8(&version) || !s.ReadUint8(&leafType) {
		return errTruncated
	}
	if version != 0 || leafType != 0 {
		return fmt.Errorf("unsupported leaf version=%d type=%d", version, leafType)
	}
	if err := readTimestampedEntry(&s, e); err != nil {
		return err
	}
	if e.Precert {
		// extra_data is a PrecertChainEntry; first field is the precertificate.
		x := cryptobyte.String(extra)
		var pre cryptobyte.String
		if x.ReadUint24LengthPrefixed(&pre) {
			e.Cert = pre
		}
	}
	return nil
}

// ReadTileLeaf parses one static-ct-api TileLeaf from s.
func ReadTileLeaf(s *cryptobyte.String, e *Entry) error {
	if err := readTimestampedEntry(s, e); err != nil {
		return err
	}
	if e.Precert {
		var pre cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&pre) {
			return errTruncated
		}
		e.Cert = pre
	}
	var chain cryptobyte.String // fingerprints of the chain
	if !s.ReadUint16LengthPrefixed(&chain) {
		return errTruncated
	}
	return nil
}
