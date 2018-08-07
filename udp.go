package udp_discover

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/blockchainservice/common/crypto"
	"github.com/blockchainservice/common/crypto/ed25519"
	"github.com/udp_discover/util"
)

const (
	Version = 5

	respTimeout = 500 * time.Millisecond
	expiration  = 20 * time.Second

	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user
)

type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

type DiscvConfig struct {
	Priv       ed25519.PrivateKey
	DBPath     string
	BootNodes  []*Node
	Addr       *net.UDPAddr
	ExternalIP net.IP
}

type pending struct {
	from     NodeID
	ptype    byte
	deadline time.Time
	callback func(resp interface{}) (done bool)
	errc     chan<- error
}

type reply struct {
	from    NodeID
	ptype   byte
	data    interface{}
	matched chan<- bool
}

type discoverUdp struct {
	conn        net.UDPConn
	priv        ed25519.PrivateKey
	ourEndpoint Endpoint
	addpending  chan *pending
	gotreply    chan reply
	stopped     chan struct{}
	discv       *DiscoverTab
}

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) Endpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return Endpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func newDiscoverUdp(cfg *DiscvConfig) (*Table, error) {
	laddr := cfg.Addr
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	discvUdp := discoverUdp{
		conn:       *conn,
		priv:       cfg.Priv,
		stopped:    make(chan struct{}),
		gotreply:   make(chan reply),
		addpending: make(chan *pending),
	}
	exIp := cfg.ExternalIP
	if exIp == nil {
		exIp = laddr.IP
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	discvUdp.ourEndpoint = makeEndpoint(realaddr, uint16(realaddr.Port))
	netrestrict := Netlist{}
	discv, err := newDiscover(&discvUdp, cfg.Priv.Public().(ed25519.PublicKey), cfg.DBPath, &netrestrict, cfg.BootNodes)
	if err != nil {
		return nil, err
	}
	discvUdp.discv = discv
	return discv.tab, nil
}

func encodePacket(priv *ed25519.PrivateKey, ptype byte, req packet) (data, hash []byte, err error) {
	pack := new(bytes.Buffer)
	buf, err := req.Serialize()
	if err != nil {
		return nil, nil, err
	}
	// 改成私钥签名
	sig := ed25519.Sign(*priv, buf)
	pack.Write(versionPrefix)
	pack.Write(sig)
	pack.WriteByte(ptype)
	pack.Write(buf)
	data = pack.Bytes()
	hash = crypto.Sha3(data[versionPrefixSize:])
	return data, hash, nil
}

func decodePacket(buf []byte) (packet, NodeID, []byte, error) {
	if len(buf) < headSize+1 {
		return nil, NodeID{}, nil, errPacketTooSmall
	}
	prefix, sig, sigdata := buf[:versionPrefixSize], buf[versionPrefixSize:headSize], buf[headSize:]
	if !bytes.Equal(prefix, versionPrefix) {
		return nil, NodeID{}, nil, errBadPrefix
	}
	fmt.Println(sig)
	hash := make([]byte, sigSize)
	var fromID NodeID
	var req packet
	switch ptype := sigdata[0]; ptype {
	case pingPacket:
		req = new(ping)
	case pongPacket:
		req = new(pong)
	case findnodePacket:
		req = new(findnode)
	case neighborsPacket:
		req = new(neighbors)
	default:
		return nil, fromID, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	err := req.Deserialize(sigdata[1:])
	return req, fromID, hash, err
}

func (t *discoverUdp) loop() {

	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *pending // head of plist when timeout was last reset
		contTimeouts = 0      // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*pending)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.stopped:
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*pending).errc <- errClosed
			}
			return
		case p := <-t.addpending:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if p.from == r.from && p.ptype == r.ptype {
					matched = true
					// Remove the matcher if its callback indicates
					// that all replies have been received. This is
					// required for packet types that expect multiple
					// reply packets.
					if p.callback(r.data) {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					//go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

func (t *discoverUdp) readLoop() {
	defer t.conn.Close()
	buf := make([]byte, 1280)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if util.IsTemporaryError(err) {
			log.Debug(fmt.Sprintf("Temporary read error: %v", err))
			continue
		} else if err != nil {
			log.Debug(fmt.Sprintf("Read error: %v", err))
			return
		}
		t.handlePacket(from, buf[:nbytes])
	}
}

func (t *discoverUdp) Start() {
	// 循环发送findnode消息,以及根据pong更新table
	go t.discv.start()
	// 定时发送ping，根据pong处理更新table
	go t.loop()
	// 作为udp服务，接受其他client的连接，处理收到的findnode、ping、pong、neighbors消息
	go t.readLoop()
}

func (t *discoverUdp) close() {
	close(t.stopped)
	t.conn.Close()
	// TODO: wait for the loops to end.
}

func (t *discoverUdp) localAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

// ping sends a ping message to the given node and waits for a reply.
func (t *discoverUdp) ping(toid NodeID, toaddr *net.UDPAddr) error {
	return <-t.sendPing(toid, toaddr, nil)
}

func (t *discoverUdp) sendPing(toid NodeID, toaddr *net.UDPAddr, callback func()) <-chan error {
	req := &ping{
		Version:    4,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, 0), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	packet, hash, err := encodePacket(&t.priv, pingPacket, req)
	if err != nil {
		errc := make(chan error, 1)
		errc <- err
		return errc
	}
	errc := t.pending(toid, pongPacket, func(p interface{}) bool {
		ok := bytes.Equal(p.(*pong).ReplyTok, hash)
		if ok && callback != nil {
			callback()
		}
		return ok
	})
	log.Debug(req)
	t.write(toaddr, req.name(), packet)
	return errc
}

func (t *discoverUdp) waitping(from NodeID) error {
	return <-t.pending(from, pingPacket, func(interface{}) bool { return true })
}

func (t *discoverUdp) findnode(toid NodeID, toaddr *net.UDPAddr, target NodeID) ([]*Node, error) {
	if time.Since(t.discv.db.lastPingReceived(toid)) > nodeDBNodeExpiration {
		t.ping(toid, toaddr)
		t.waitping(toid)
	}

	// 发送findnode消息，并等待neighbors返回
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	errc := t.pending(toid, neighborsPacket, func(r interface{}) bool {
		reply := r.(*neighbors)
		for _, rn := range reply.Peers {
			nreceived++
			//检查找到的ip、port的合法性，生成一个node节点
			n, err := t.checkneighbor(toaddr, rn)
			if err != nil {
				log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		return nreceived >= bucketSize
	})
	t.send(toaddr, findnodePacket, &findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})

	return nodes, <-errc
}

func (t *discoverUdp) checkneighbor(sender *net.UDPAddr, rn Peer) (*Node, error) {
	if rn.UDP <= 1024 {
		return nil, errors.New("low port")
	}
	if err := CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.discv.netrestrict != nil && !t.discv.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict whitelist")
	}
	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
	err := n.validateComplete()
	return n, err
}

func (t *discoverUdp) pending(id NodeID, ptype byte, callback func(interface{}) bool) <-chan error {
	ch := make(chan error, 1)
	p := &pending{from: id, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addpending <- p:
	// loop will handle it
	case <-t.stopped:
		ch <- errClosed
	}
	return ch
}

func (t *discoverUdp) handleReply(from NodeID, ptype byte, req packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, ptype, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.stopped:
		return false
	}
}

func (t *discoverUdp) send(toaddr *net.UDPAddr, ptype byte, req packet) ([]byte, error) {
	packet, hash, err := encodePacket(&t.priv, ptype, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, req.name(), packet)
}

func (t *discoverUdp) write(toaddr *net.UDPAddr, what string, packet []byte) error {
	_, err := t.conn.WriteToUDP(packet, toaddr)
	log.Trace(">> "+what, "addr", toaddr, "err", err)
	return err
}

func (t *discoverUdp) handlePacket(from *net.UDPAddr, buf []byte) error {
	packet, fromID, hash, err := decodePacket(buf)
	if err != nil {
		log.Debug("Bad packet", "addr", from, "err", err)
		return err
	}
	err = packet.handle(t, from, fromID, hash)
	log.Trace("<< "+packet.name(), "addr", from, "err", err)
	return err
}
