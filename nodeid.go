package udp_discover

import (
	"encoding/hex"
	"fmt"
)

const NodeIDBits = 512

type NodeID [NodeIDBits / 16]byte

// Bytes returns a byte slice representation of the NodeID
func (id NodeID) Bytes() []byte {
	return id[:]
}

// NodeID prints as a long hexadecimal number.
func (id NodeID) String() string {
	return fmt.Sprintf("%x", id[:])
}

// The Go syntax representation of a NodeID is a call to HexID.
func (id NodeID) GoString() string {
	return fmt.Sprintf("discover.HexID(\"%x\")", id[:])
}

// TerminalString returns a shortened hex string for terminal logging.
func (id NodeID) TerminalString() string {
	return hex.EncodeToString(id[:8])
}

// MarshalText implements the encoding.TextMarshaler interface.
func (id NodeID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(id[:])), nil
}
