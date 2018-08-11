package udp_discover

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
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
	copy(id[:], *pub)
	return id
}

func HexStr2NodeID(in string) (NodeID, error) {
	var id NodeID
	b, err := hex.DecodeString(strings.TrimPrefix(in, "0x"))
	if err != nil {
		return id, err
	} else if len(b) != len(id) {
		return id, fmt.Errorf("wrong length, want %d hex chars", len(id)*2)
	}
	copy(id[:], b)
	return id, nil
}

func ParseNode(rawurl string) (*Node, error) {
	var (
		id               NodeID
		ip               net.IP
		tcpPort, udpPort uint64
	)
	nodeURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if nodeURL.Scheme != NodeURLScheme {
		return nil, errors.New("invalid URL scheme, want \"enode\"")
	}
	// Parse the Node ID from the user portion.
	if nodeURL.User == nil {
		return nil, errors.New("does not contain node ID")
	}
	if id, err = HexStr2NodeID(nodeURL.User.String()); err != nil {
		return nil, fmt.Errorf("invalid node ID (%v)", err)
	}
	// Parse the IP address.
	host, port, err := net.SplitHostPort(nodeURL.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host: %v", err)
	}
	if ip = net.ParseIP(host); ip == nil {
		return nil, errors.New("invalid IP address")
	}
	// Ensure the IP is 4 bytes long for IPv4 addresses.
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	// Parse the port numbers.
	if tcpPort, err = strconv.ParseUint(port, 10, 16); err != nil {
		return nil, errors.New("invalid port")
	}
	udpPort = tcpPort
	return NewNode(id, ip, uint16(udpPort), uint16(tcpPort)), nil
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

func (n *Node) String() string {
	nodeURL := url.URL{
		Scheme: NodeURLScheme,
	}

	err := n.validateComplete()
	if err == nil {
		addr := net.TCPAddr{
			IP:   n.IP,
			Port: int(n.TCP),
		}
		nodeURL.User = url.User(n.ID.String())
		nodeURL.Host = addr.String()
	} else {
		nodeURL.Host = n.ID.String()
	}
	return nodeURL.String()
}
