package udp_discover

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

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
	Priv       ecdsa.PrivateKey
	DBPath     string
	BootNodes  []*Node
	Addr       *net.UDPAddr
	ExternalIP net.IP
}

type discoverUdp struct {
	conn        net.UDPConn
	priv        ecdsa.PrivateKey
	ourEndpoint rpcEndpoint
	stopped     chan struct{}
	discv       *DiscoverTab
}

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func newDiscoverUdp(cfg *DiscvConfig) (*Table, error) {
	laddr := cfg.Addr
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	discvUdp := discoverUdp{
		conn:    *conn,
		priv:    cfg.Priv,
		stopped: make(chan struct{}),
	}
	exIp := cfg.ExternalIP
	if exIp == nil {
		exIp = laddr.IP
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	discvUdp.ourEndpoint = makeEndpoint(realaddr, uint16(realaddr.Port))
	netrestrict := Netlist{}
	discv, err := newDiscover(&discvUdp, cfg.Priv.PublicKey, cfg.DBPath, &netrestrict, cfg.BootNodes)
	if err != nil {
		return nil, err
	}
	discvUdp.discv = discv
	return discv.tab, nil
}

func (t *discoverUdp) loop() {
	for {
		select {
		case <-t.stopped:
			return
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

func encodePacket(priv *ecdsa.PrivateKey, ptype byte, req interface{}) (packet, hash []byte, err error) {
	return nil, nil, nil
}

func decodePacket(buf []byte) (packet, NodeID, []byte, error) {
	return nil, NodeID{}, nil, errPacketTooSmall
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
	log.Debug(req)
	return nil
}

func (t *discoverUdp) waitping(from NodeID) error {
	return <-t.pending(from, pingPacket, func(interface{}) bool { return true })
}

func (t *discoverUdp) findnode(toid NodeID, toaddr *net.UDPAddr, target NodeID) ([]*Node, error) {
	return nil, nil
}

func (t *discoverUdp) pending(id NodeID, ptype byte, callback func(interface{}) bool) <-chan error {
	ch := make(chan error, 1)
	//p := &pending{from: id, ptype: ptype, callback: callback, errc: ch}
	select {
	//case t.addpending <- p:
	// loop will handle it
	case <-t.stopped:
		ch <- errClosed
	}
	return ch
}

func (t *discoverUdp) handleReply(from NodeID, ptype byte, req packet) bool {
	return true
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
