package dashd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

// Extract SrcMAC from packets.
func Source(packets <-chan gopacket.Packet) <-chan net.HardwareAddr {
	sources := make(chan net.HardwareAddr)
	go func() {
		for packet := range packets {
			ethernet, ok := packet.LinkLayer().(*layers.Ethernet)
			if ok {
				sources <- ethernet.SrcMAC
			}
		}
	}()
	return sources
}
