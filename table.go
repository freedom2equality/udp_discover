package udp_discover

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sync"

	"github.com/blockchainservice/common"
)

const (
	// We keep buckets for the upper 1/15 of distances because
	// it's very unlikely we'll ever encounter a node that's closer.
	hashBits          = len(common.Hash{}) * 8
	nBuckets          = hashBits / 15       // Number of buckets
	bucketMinDistance = hashBits - nBuckets // Log distance of closest bucket
)

type Table struct {
	mutex   sync.Mutex        // protects buckets, bucket content, nursery, rand
	buckets [nBuckets]*bucket // index of known nodes by distance
	self    *Node             // metadata of the local node
	rand    *rand.Rand        // source of randomness, periodically reseeded
	count   int               // number of nodes
}

func newTable(ourID NodeID, ourAddr *net.UDPAddr) *Table {
	self := NewNode(ourID, ourAddr.IP, uint16(ourAddr.Port), uint16(ourAddr.Port))
	tab := &Table{self: self}
	for i := range tab.buckets {
		tab.buckets[i] = new(bucket)
	}
	return tab
}

func (tab *Table) add(n *Node) (contested *Node) {
	if n.ID == tab.self.ID {
		return
	}
	b := tab.buckets[calcDistance(tab.self.sha, n.sha)]
	switch {
	case b.bump(n):
		// n exists in b.
		return nil
	case len(b.entries) < bucketSize:
		// b has space available.
		b.addFront(n)
		tab.count++

		return nil
	default:
		// b has no space left, add to replacement cache
		// and revalidate the last entry.
		// TODO: drop previous node
		b.replacements = append(b.replacements, n)
		if len(b.replacements) > bucketSize {
			copy(b.replacements, b.replacements[1:])
			b.replacements = b.replacements[:len(b.replacements)-1]
		}
		return b.entries[len(b.entries)-1]
	}
}

func (tab *Table) delete(node *Node) {
	bucket := tab.buckets[calcDistance(tab.self.sha, node.sha)]
	for i := range bucket.entries {
		if bucket.entries[i].ID == node.ID {
			bucket.entries = append(bucket.entries[:i], bucket.entries[i+1:]...)
			tab.count--
			return
		}
	}
}

func (tab *Table) replace(b *bucket, last *Node) *Node {
	if len(b.entries) == 0 || b.entries[len(b.entries)-1].ID != last.ID {
		// Entry has moved, don't replace it.
		return nil
	}
	// Still the last entry.
	if len(b.replacements) == 0 {
		//tab.deleteInBucket(b, last)
		return nil
	}
	r := b.replacements[tab.rand.Intn(len(b.replacements))]
	//b.replacements = deleteNode(b.replacements, r)
	b.entries[len(b.entries)-1] = r
	//tab.removeIP(b, last.IP)
	return r
}

func (tab *Table) closest(target common.Hash, nresults int) *nodesByDistance {
	close := &nodesByDistance{target: target}
	for _, b := range tab.buckets {
		for _, n := range b.entries {
			close.push(n, nresults)
		}
	}
	return close
}

func (tab *Table) chooseBucketRefreshTarget() NodeID {
	var b [8]byte
	rand.Read(b[:])

	tab.mutex.Lock()
	tab.rand.Seed(int64(binary.BigEndian.Uint64(b[:])))
	tab.mutex.Unlock()
	var target NodeID
	rand.Read(target[:])
	return target
}

func (tab *Table) nodeToRevalidate() (n *Node, bi int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, bi = range tab.rand.Perm(len(tab.buckets)) {
		b := tab.buckets[bi]
		if len(b.entries) > 0 {
			last := b.entries[len(b.entries)-1]
			return last, bi
		}
	}
	return nil, 0
}

// table of leading zero counts for bytes [0..255]
var lzcount = [256]int{
	8, 7, 6, 6, 5, 5, 5, 5,
	4, 4, 4, 4, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

// calcDistance returns the logarithmic distance between a and b, log2(a ^ b).
func calcDistance(a, b common.Hash) int {
	lz := 0
	for i := range a {
		x := a[i] ^ b[i]
		if x == 0 {
			lz += 8
		} else {
			lz += lzcount[x]
			break
		}
	}
	return len(a)*8 - lz
}

// hashAtDistance returns a random hash such that logdist(a, b) == n
func hashAtDistance(a common.Hash, n int) (b common.Hash) {
	if n == 0 {
		return a
	}
	// flip bit at position n, fill the rest with random bits
	b = a
	pos := len(a) - n/8 - 1
	bit := byte(0x01) << (byte(n%8) - 1)
	if bit == 0 {
		pos++
		bit = 0x80
	}
	b[pos] = a[pos]&^bit | ^a[pos]&bit // TODO: randomize end bits
	for i := pos + 1; i < len(a); i++ {
		b[i] = byte(rand.Intn(255))
	}
	return b
}
