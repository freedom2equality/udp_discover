package udp_discover

import (
	"net"
	"time"

	"github.com/blockchainservice/common/crypto"
	"github.com/bytom/p2p/netutil"
	"github.com/gogo/protobuf/proto"
	"github.com/udp_discover/protos"
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
	maxSizeNode := Peer{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
	for n := 0; ; n++ {
		p.Peers = append(p.Peers, maxSizeNode)
		tmp, err := p.Serialize()
		size := len(tmp)
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

type Peer struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for tcp protocol
	ID  NodeID
}

func (p *Peer) toProto() *protos.Peer {
	nodepb := &protos.Peer{
		ID:  p.ID[:],
		IP:  p.IP.String(),
		UDP: uint32(p.UDP),
		TCP: uint32(p.TCP),
	}
	return nodepb
}

func protoToNode(peerpb *protos.Peer) *Peer {
	peer := new(Peer)
	copy(peer.ID[:], peerpb.ID)
	peer.IP = net.ParseIP(peerpb.IP)
	peer.UDP = uint16(peerpb.UDP)
	peer.TCP = uint16(peerpb.TCP)
	return peer
}

type Endpoint struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6
	UDP uint16 // for discovery protocol
	TCP uint16 // for tcp protocol
}

type packet interface {
	handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error
	name() string
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}

// discovery request structures
type ping struct {
	Version    uint32
	From, To   Endpoint
	Expiration uint64
}

func nodeToRPC(n *Node) Peer {
	return Peer{ID: n.ID, IP: n.IP, UDP: n.UDP, TCP: n.TCP}
}

func (req *ping) name() string { return "PING/v4" }

func (req *ping) Serialize() ([]byte, error) {
	from := &protos.Endpoint{
		IP:  req.From.IP.String(),
		UDP: uint32(req.From.UDP),
		TCP: uint32(req.From.TCP),
	}
	to := &protos.Endpoint{
		IP:  req.To.IP.String(),
		UDP: uint32(req.To.UDP),
		TCP: uint32(req.To.TCP),
	}
	pingpb := &protos.Ping{
		Version:    uint32(req.Version),
		From:       from,
		To:         to,
		Expiration: req.Expiration,
	}
	return proto.Marshal(pingpb)
}

func (req *ping) Deserialize(buf []byte) error {
	pingpb := &protos.Ping{}
	err := proto.Unmarshal(buf, pingpb)
	if err != nil {
		return err
	}
	req.Version = pingpb.Version
	from := Endpoint{
		IP:  net.ParseIP(pingpb.From.IP),
		UDP: uint16(pingpb.From.UDP),
		TCP: uint16(pingpb.From.TCP),
	}
	to := Endpoint{
		IP:  net.ParseIP(pingpb.To.IP),
		UDP: uint16(pingpb.To.UDP),
		TCP: uint16(pingpb.To.TCP),
	}
	req.From = from
	req.To = to
	req.Expiration = pingpb.Expiration
	return nil
}

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
	To         Endpoint
	ReplyTok   []byte // This contains the hash of the ping packet.
	Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
}

func (req *pong) name() string { return "PONG/v4" }

func (req *pong) Serialize() ([]byte, error) {
	to := &protos.Endpoint{
		IP:  req.To.IP.String(),
		UDP: uint32(req.To.UDP),
		TCP: uint32(req.To.TCP),
	}
	pongpb := &protos.Pong{
		To:         to,
		ReplyTok:   req.ReplyTok[:],
		Expiration: req.Expiration,
	}

	return proto.Marshal(pongpb)
}
func (req *pong) Deserialize(buf []byte) error {
	pongpb := &protos.Pong{}
	err := proto.Unmarshal(buf, pongpb)
	if err != nil {
		return err
	}

	to := Endpoint{
		IP:  net.ParseIP(pongpb.To.IP),
		UDP: uint16(pongpb.To.UDP),
		TCP: uint16(pongpb.To.TCP),
	}
	req.To = to
	req.ReplyTok = pongpb.ReplyTok
	req.Expiration = pongpb.Expiration
	return nil
}

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

// findnode is a query for nodes close to the given target.
type findnode struct {
	Target     NodeID // doesn't need to be an actual public key
	Expiration uint64
}

func (req *findnode) name() string { return "FINDNODE/v4" }

func (req *findnode) Serialize() ([]byte, error) {
	findnodepb := &protos.Findnode{
		Target:     req.Target[:],
		Expiration: req.Expiration,
	}
	return proto.Marshal(findnodepb)
}
func (req *findnode) Deserialize(buf []byte) error {
	findnodepb := &protos.Findnode{}
	err := proto.Unmarshal(buf, findnodepb)
	if err != nil {
		return err
	}
	copy(req.Target[:], findnodepb.Target)
	req.Expiration = findnodepb.Expiration
	return nil
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
			p.Peers = append(p.Peers, nodeToRPC(n))
		}
		if len(p.Peers) == maxNeighbors {
			t.send(from, neighborsPacket, &p)
			p.Peers = p.Peers[:0]
			sent = true
		}
	}
	if len(p.Peers) > 0 || !sent {
		t.send(from, neighborsPacket, &p)
	}

	return nil
}

// reply to findnode
type neighbors struct {
	Peers      []Peer
	Expiration uint64
}

func (req *neighbors) name() string { return "NEIGHBORS/v4" }

func (req *neighbors) Serialize() ([]byte, error) {
	peerpbs := make([]*protos.Peer, 0, len(req.Peers))
	for _, peer := range req.Peers {
		peerpbs = append(peerpbs, peer.toProto())
	}

	neighborspb := &protos.Neighbors{
		Peers:      peerpbs,
		Expiration: req.Expiration,
	}
	return proto.Marshal(neighborspb)
}
func (req *neighbors) Deserialize(buf []byte) error {
	neighborspb := &protos.Neighbors{}
	err := proto.Unmarshal(buf, neighborspb)
	if err != nil {
		return err
	}
	//peers := make([]*Peer, 0, len(neighborspb.Peers))
	for _, peerpb := range neighborspb.Peers {
		req.Peers = append(req.Peers, *protoToNode(peerpb))
	}
	req.Expiration = neighborspb.Expiration
	return nil
}

func (req *neighbors) handle(t *discoverUdp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, neighborsPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}
