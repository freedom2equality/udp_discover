package main

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/blockchainservice/common/crypto/ed25519"
	"github.com/udp_discover"
)

var urls = []string{
	"enode://123@127.0.0.1:9001",
	"enode://456@127.0.0.1:9002",
	"enode://789@127.0.0.1:9003",
}

func main() {
	_, pv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &udp_discover.DiscvConfig{
		Priv:   pv,
		DBPath: "./db",
	}
	cfg.BootNodes = make([]*udp_discover.Node, 0, len(urls))
	for _, url := range urls {
		node, err := udp_discover.ParseNode(url)
		if err != nil {
			fmt.Println("Bootstrap URL invalid", "enode", url, "err", err)
		}
		cfg.BootNodes = append(cfg.BootNodes, node)
	}
	addr, err := net.ResolveUDPAddr("udp", ":9001")
	if err != nil {
		fmt.Println("ResolveUDPAddr err:", err)
		return
	}
	cfg.Addr = addr
	tab, _ := udp_discover.NewDiscoverUdp(cfg)
	needDynDials := 50
	randomCandidates := needDynDials / 2
	randomNodes := make([]*udp_discover.Node, randomCandidates)
	for {
		fmt.Println(tab)
		if randomCandidates > 0 {
			n := tab.ReadRandomNodes(randomNodes)
			for i := 0; i < randomCandidates && i < n; i++ {
				fmt.Println(randomNodes[i])
			}
		}
	}
}
