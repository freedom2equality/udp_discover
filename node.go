package udp_discover

import (
	"errors"
	"net"
	"time"

	"github.com/blockchainservice/common"
	"github.com/blockchainservice/common/crypto"
	"github.com/blockchainservice/common/crypto/ed25519"
)

type Node struct {
	IP       net.IP // len 4 for IPv4 or 16 for IPv6
	UDP, TCP uint16 // port numbers
	ID       NodeID // the node's public key
	sha      common.Hash
	// Time when the node was added to the table.
	addedAt time.Time
}

func NewNode(id NodeID, ip net.IP, udpPort, tcpPort uint16) *Node {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	return &Node{
		IP:  ip,
		UDP: udpPort,
		TCP: tcpPort,
		ID:  id,
		sha: crypto.Sha256Hash(id[:]),
	}
}

func PubkeyID(pub *ed25519.PublicKey) NodeID {
	var id NodeID
	/*
		pbytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		if len(pbytes)-1 != len(id) {
			panic(fmt.Errorf("need %d bit pubkey, got %d bits", (len(id)+1)*8, len(pbytes)))
		}
		copy(id[:], pbytes[1:])
	*/
	return id
}

func (n *Node) addr() *net.UDPAddr {
	return &net.UDPAddr{IP: n.IP, Port: int(n.UDP)}
}

// Incomplete returns true for nodes with no IP address.
func (n *Node) Incomplete() bool {
	return n.IP == nil
}

// checks whether n is a valid complete node.
func (n *Node) validateComplete() error {
	if n.Incomplete() {
		return errors.New("incomplete node")
	}
	if n.UDP == 0 {
		return errors.New("missing UDP port")
	}
	if n.TCP == 0 {
		return errors.New("missing TCP port")
	}
	if n.IP.IsMulticast() || n.IP.IsUnspecified() {
		return errors.New("invalid IP (multicast/unspecified)")
	}
	return nil
}
