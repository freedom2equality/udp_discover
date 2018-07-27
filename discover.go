package udp_discover

import (
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/blockchainservice/common/crypto"
)

type DiscoverTab struct {
	tab         *Table
	db          *nodeDB
	conn        *discoverUdp
	netrestrict *Netlist
	nursery     []*Node
	closeReq    chan struct{}
	findnodeReq chan struct{}
	mutex       sync.Mutex
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
		tab:         tab,
		db:          db,
		conn:        conn,
		netrestrict: netrestrict,
		closeReq:    make(chan struct{}),
		findnodeReq: make(chan struct{}),
	}
	discv.setFallbackNodes(bootnodes)
	return discv, nil
}

func (discv *DiscoverTab) start() {
	var (
		refreshDone = make(chan struct{})
	)
	discv.db.ensureExpirer()
	// 种子节点的findnode

loop:
	for {
		select {
		case <-discv.findnodeReq:
			discv.refresh(refreshDone)
		case <-refreshDone:
			log.Debug("refreshDone")
		case <-discv.closeReq:
			break loop
		}
	}
}

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
	// 发送消息，告诉其他start routine可以从加载种子节点，以及findnode了
	discv.findnodeReq <- struct{}{}
	return nil
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

func (discv *DiscoverTab) refresh(done chan<- struct{}) {
	discv.loadSeedNodes(done)
	// findnode

	go func() {
		go discv.findnode(discv.tab.self.ID)
		close(done)
	}()
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
