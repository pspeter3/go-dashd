package dashd

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Sniffs packets over the device.
func Sniff(device string, snaplen int32, promisc bool, filter string) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenLive(device, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	return source.Packets(), nil
}
