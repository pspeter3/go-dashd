package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	var device string
	flag.StringVar(&device, "device", "", "Device to listen on")
	flag.Parse()
	handle, err := pcap.OpenLive(device, 1660, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		ethernet, ok := packet.LinkLayer().(*layers.Ethernet)
		if ok {
			log.Println(ethernet.SrcMAC)
		}
	}
}
