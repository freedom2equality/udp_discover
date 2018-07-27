package udp_discover

import (
	"net"
	"time"
)

// discovery protocol packet types
const (
	pingPacket = iota + 1
	pongPacket
	findnodePacket
	neighborsPacket
)

func expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}

type rpcNode struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for tcp protocol
	ID  NodeID
}

type rpcEndpoint struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for tcp protocol
}

type packet interface {
	handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error
	name() string
}

// discovery request structures
type ping struct {
	Version    uint
	From, To   rpcEndpoint
	Expiration uint64
}

func (req *ping) name() string { return "PING/v4" }

func (req *ping) handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//收到ping的消息收，发送pong
	return nil
}

// pong is the reply to ping.
type pong struct {
	To rpcEndpoint

	ReplyTok   []byte // This contains the hash of the ping packet.
	Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
}

func (req *pong) name() string { return "PONG/v4" }

func (req *pong) handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error {

	return nil
}

func (req *findnode) name() string { return "FINDNODE/v4" }

// findnode is a query for nodes close to the given target.
type findnode struct {
	Target     NodeID // doesn't need to be an actual public key
	Expiration uint64
}

func (req *findnode) handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//收到findnode消息后，发送neighbors
	return nil
}

// reply to findnode
type neighbors struct {
	Nodes      []rpcNode
	Expiration uint64
}

func (req *neighbors) name() string { return "NEIGHBORS/v4" }

func (req *neighbors) handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	return nil
}
