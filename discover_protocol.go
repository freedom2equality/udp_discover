package udp_discover

import (
	"net"
	"time"

	"github.com/blockchainservice/common/crypto"
	"github.com/bytom/p2p/netutil"
	"github.com/ethereum/go-ethereum/rlp"
)

// discovery protocol packet types
const (
	pingPacket = iota + 1
	pongPacket
	findnodePacket
	neighborsPacket
)

const (
	macSize  = 256 / 8
	sigSize  = 520 / 8
	headSize = macSize + sigSize // space of packet frame data
)

var (
	headSpace = make([]byte, headSize)

	// Neighbors replies are sent across multiple packets to
	// stay below the 1280 byte limit. We compute the maximum number
	// of entries by stuffing a packet until it grows too large.
	maxNeighbors int
)

func init() {
	p := neighbors{Expiration: ^uint64(0)}
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
	for n := 0; ; n++ {
		p.Nodes = append(p.Nodes, maxSizeNode)
		size, _, err := rlp.EncodeToReader(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		if headSize+size+1 >= 1280 {
			maxNeighbors = n
			break
		}
	}
}

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

func nodeToRPC(n *Node) rpcNode {
	return rpcNode{ID: n.ID, IP: n.IP, UDP: n.UDP, TCP: n.TCP}
}

func (req *ping) name() string { return "PING/v4" }

//收到ping的消息收，发送pong
func (req *ping) handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error {

	if expired(req.Expiration) {
		return errExpired
	}
	t.send(from, pongPacket, &pong{
		To:         makeEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	t.handleReply(fromID, pingPacket, req)
	n := NewNode(fromID, from.IP, uint16(from.Port), req.From.TCP)
	if time.Since(t.discv.db.lastPongReceived(fromID)) > nodeDBNodeExpiration {
		t.sendPing(fromID, from, func() { t.discv.tab.add(n) })
	} else {
		t.discv.tab.add(n)
	}
	t.discv.db.updateLastPingReceived(fromID, time.Now())
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
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, pongPacket, req) {
		return errUnsolicitedReply
	}
	t.discv.db.updateLastPongReceived(fromID, time.Now())
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

	if expired(req.Expiration) {
		return errExpired
	}
	if !t.discv.db.hasBond(fromID) {
		// No endpoint proof pong exists, we don't process the packet. This prevents an
		// attack vector where the discovery protocol could be used to amplify traffic in a
		// DDOS attack. A malicious actor would send a findnode request with the IP address
		// and UDP port of the target as the source address. The recipient of the findnode
		// packet would then send a neighbors packet (which is a much bigger packet than
		// findnode) to the victim.
		return errUnknownNode
	}
	target := crypto.Sha256Hash(req.Target[:])
	t.discv.mutex.Lock()
	closest := t.discv.tab.closest(target, bucketSize).entries
	t.discv.mutex.Unlock()

	p := neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	var sent bool
	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the 1280 byte limit.
	for _, n := range closest {
		if netutil.CheckRelayIP(from.IP, n.IP) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(n))
		}
		if len(p.Nodes) == maxNeighbors {
			t.send(from, neighborsPacket, &p)
			p.Nodes = p.Nodes[:0]
			sent = true
		}
	}
	if len(p.Nodes) > 0 || !sent {
		t.send(from, neighborsPacket, &p)
	}

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
	if !t.handleReply(fromID, neighborsPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}
