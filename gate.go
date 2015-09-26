package dashd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hashicorp/golang-lru"
	"net"
	"time"
)

// Packet gate based on MAC address.
type Gate struct {
	cache    *lru.Cache
	debounce float64
}

// Create a new Gate.
func NewGate(size int, debounce float64) (*Gate, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &Gate{cache, debounce}, nil
}

// Extract MAC address from packet.
func (g *Gate) Extract(packet gopacket.Packet) (net.HardwareAddr, bool) {
	ethernet, ok := packet.LinkLayer().(*layers.Ethernet)
	if ok {
		return ethernet.SrcMAC, ok
	}
	return nil, ok
}

// Check whether MAC addresses is allowed.
func (g *Gate) Allow(source net.HardwareAddr) bool {
	allow := true
	now := time.Now()
	if value, ok := g.cache.Get(source.String()); ok {
		last, ok := value.(time.Time)
		if ok {
			delta := now.Sub(last)
			if delta.Seconds() < g.debounce {
				allow = false
			}
		}
	}
	g.cache.Add(source.String(), now)
	return allow
}

// Serve hardware addresses.
func (g *Gate) Serve(packets <-chan gopacket.Packet) <-chan net.HardwareAddr {
	sources := make(chan net.HardwareAddr)
	go func() {
		for packet := range packets {
			source, ok := g.Extract(packet)
			if ok && g.Allow(source) {
				sources <- source
			}
		}
	}()
	return sources
}
