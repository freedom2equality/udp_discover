package udp_discover

import (
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/blockchainservice/common/crypto"
)

const (
	alpha      = 3  // Kademlia concurrency factor
	bucketSize = 16 // Kademlia bucket size

	maxFindnodeFailures   = 5 // Nodes exceeding this limit are dropped
	autoNeighborsInterval = 30 * time.Minute
	bucketRefreshInterval = 1 * time.Minute
	walNodesInterval      = 30 * time.Second
	pingPongInterval      = 10 * time.Second
	seedMinTableTime      = 5 * time.Minute
	seedCount             = 30
	seedMaxAge            = 5 * 24 * time.Hour
)

type DiscoverTab struct {
	tab           *Table
	db            *nodeDB
	conn          *discoverUdp
	netrestrict   *Netlist
	nursery       []*Node
	closed        chan struct{}
	closeReq      chan struct{}
	neighborsReq  chan struct{}
	neighborsResp chan (<-chan struct{})
	mutex         sync.Mutex
	rand          *rand.Rand // source of randomness, periodically reseeded
}

func newDiscover(conn *discoverUdp, ourPubkey ecdsa.PublicKey, dbPath string, netrestrict *Netlist, bootnodes []*Node) (*DiscoverTab, error) {
	ourID := PubkeyID(&ourPubkey)
	var db *nodeDB
	if dbPath != "<no database>" {
		var err error
		if db, err = newNodeDB(dbPath, Version, ourID); err != nil {
			return nil, err
		}
	}
	tab := newTable(ourID, conn.localAddr())
	discv := &DiscoverTab{
		tab:           tab,
		db:            db,
		conn:          conn,
		netrestrict:   netrestrict,
		closed:        make(chan struct{}),
		closeReq:      make(chan struct{}),
		neighborsReq:  make(chan struct{}),
		neighborsResp: make(chan (<-chan struct{})),
		rand:          rand.New(rand.NewSource(0)),
	}

	discv.setFallbackNodes(bootnodes)
	return discv, nil
}

func (discv *DiscoverTab) start() {
	var (
		pingPongTimer      = time.NewTimer(discv.nextPingPongTime())
		bucketRefreshTimer = time.NewTimer(bucketRefreshInterval)
		neighborsTimer     = time.NewTicker(autoNeighborsInterval)
		walNodesTimer      = time.NewTicker(walNodesInterval)
		neighborsDone      = make(chan struct{})
	)
	discv.db.ensureExpirer()
loop:
	for {
		select {
		case <-neighborsTimer.C:
			if neighborsDone == nil {
				neighborsDone = make(chan struct{})
			}
			discv.getNeighbors(neighborsDone)

		case <-bucketRefreshTimer.C:
			target := discv.tab.chooseBucketRefreshTarget()
			go func() {
				discv.findnode(target)
				bucketRefreshTimer.Reset(bucketRefreshInterval)
			}()

		case <-discv.neighborsReq:
			discv.getNeighbors(neighborsDone)
			discv.neighborsResp <- neighborsDone

		case <-neighborsDone:
			log.Debug("refreshDone")
			if discv.tab.count != 0 {
				neighborsDone = nil
			} else {
				neighborsDone = make(chan struct{})
				discv.getNeighbors(neighborsDone)
			}
		case <-pingPongTimer.C:
			go func() {
				discv.pingPong()
				pingPongTimer.Reset(discv.nextPingPongTime())
			}()
		case <-walNodesTimer.C:
			go discv.walNodes()
		case <-discv.closeReq:
			break loop
		}
	}
}

// 节点发现触发
func (discv *DiscoverTab) setFallbackNodes(nodes []*Node) error {
	nursery := make([]*Node, 0, len(nodes))
	for _, n := range nodes {

		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}

		// Recompute cpy.sha because the node might not have been created by NewNode or ParseNode.
		cpy := *n
		cpy.sha = crypto.Sha256Hash(n.ID[:])
		nursery = append(nursery, &cpy)
	}
	discv.nursery = nursery
	// 发送消息，告诉其他start routine可以从加载种子节点，以及findnode
	select {
	case discv.neighborsReq <- struct{}{}:
		<-discv.neighborsResp
	case <-discv.closed:
	}

	return nil
}

func (discv *DiscoverTab) nextPingPongTime() time.Duration {
	discv.mutex.Lock()
	defer discv.mutex.Unlock()

	return time.Duration(discv.rand.Int63n(int64(pingPongInterval)))
}

func (discv *DiscoverTab) loadSeedNodes(done chan<- struct{}) {
	var seeds []*Node
	if discv.db != nil {
		seeds = discv.db.querySeeds(seedCount, seedMaxAge)
	}
	if len(seeds) == 0 {
		seeds = append(seeds, discv.nursery...)
	}

	if len(seeds) == 0 {
		log.Trace("no seed nodes found")
		close(done)
		return
	}

	for i := range seeds {
		seed := seeds[i]
		age := time.Since(discv.db.lastPongReceived(seed.ID))
		log.Debug("Found seed node in database", "id", seed.ID, "addr", seed.addr(), "age", age)
		discv.tab.add(seed)
	}
}

// neighborsPacket
func (discv *DiscoverTab) getNeighbors(done chan<- struct{}) {
	discv.loadSeedNodes(done)
	go func() {
		go discv.findnode(discv.tab.self.ID)
		close(done)
	}()
}

func (discv *DiscoverTab) pingPong() {
	last, bi := discv.tab.nodeToRevalidate()
	if last == nil {
		// No non-empty bucket found.
		return
	}
	err := discv.conn.ping(last.ID, last.addr())
	discv.tab.mutex.Lock()
	defer discv.tab.mutex.Unlock()
	b := discv.tab.buckets[bi]
	if err == nil {
		// The node responded, move it to the front.
		log.Trace("Revalidated node", "b", bi, "id", last.ID)
		b.bump(last)
		return
	}
	if r := discv.tab.replace(b, last); r != nil {
		log.Trace("Replaced dead node", "b", bi, "id", last.ID, "ip", last.IP, "r", r.ID, "rip", r.IP)
	} else {
		log.Trace("Removed dead node", "b", bi, "id", last.ID, "ip", last.IP)
	}
}

func (discv *DiscoverTab) walNodes() {
	discv.mutex.Lock()
	defer discv.mutex.Unlock()

	now := time.Now()
	for _, b := range discv.tab.buckets {
		for _, n := range b.entries {
			if now.Sub(n.addedAt) >= seedMinTableTime {
				discv.db.updateNode(n)
			}
		}
	}
}

func (discv *DiscoverTab) findnode(targetID NodeID) {
	var (
		target         = crypto.Sha256Hash(targetID[:])
		asked          = make(map[NodeID]bool)
		seen           = make(map[NodeID]bool)
		reply          = make(chan []*Node, alpha)
		pendingQueries = 0
		result         *nodesByDistance
	)
	// 不能从自己这里findnode
	asked[discv.tab.self.ID] = true

	for {
		discv.mutex.Lock()
		result = discv.tab.closest(target, bucketSize)
		discv.mutex.Unlock()
		if len(result.entries) > 0 {
			break
		}
	}
	for {
		for i := 0; i < len(result.entries) && pendingQueries < alpha; i++ {
			n := result.entries[i]
			if !asked[n.ID] {
				asked[n.ID] = true
				pendingQueries++
				go discv.reqQueryFindnode(n, targetID, reply)
			}
		}
		if pendingQueries == 0 {
			// we have asked all closest nodes, stop the search
			break
		}
		// wait for the next reply
		for _, n := range <-reply {
			if n != nil && !seen[n.ID] {
				seen[n.ID] = true
				result.push(n, bucketSize)
			}
		}
		pendingQueries--
	}
}

func (discv *DiscoverTab) reqQueryFindnode(n *Node, targetID NodeID, reply chan<- []*Node) {
	fails := discv.db.findFails(n.ID)
	r, err := discv.conn.findnode(n.ID, n.addr(), targetID)
	if err != nil || len(r) == 0 {
		fails++
		discv.db.updateFindFails(n.ID, fails)
		log.Trace("Findnode failed", "id", n.ID, "failcount", fails, "err", err)
		if fails >= maxFindnodeFailures {
			log.Trace("Too many findnode failures, dropping", "id", n.ID, "failcount", fails)
			//discv.tab.delete(n)
		}
	} else if fails > 0 {
		discv.db.updateFindFails(n.ID, fails-1)
	}
	for _, n := range r {
		discv.tab.add(n)
	}
	reply <- r
}
