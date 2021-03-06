package udp_discover

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

const NodeIDBits = 512

type NodeID [NodeIDBits / 8]byte

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

// Pubkey returns the public key represented by the node ID.
// It returns an error if the ID is not a point on the curve.
func (id NodeID) Pubkey() (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(id) / 2
	p.X.SetBytes(id[:half])
	p.Y.SetBytes(id[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("id is invalid secp256k1 curve point")
	}
	return p, nil
}
