package main

import (
	"flag"
	"github.com/google/gopacket/layers"
	"github.com/pspeter3/dashd"
	"log"
)

type flags struct {
	key     string
	device  string
	snaplen int
	promisc bool
	filter  string
	verbose bool
}

func parse() flags {
	var args flags
	flag.StringVar(&args.key, "key", "", "IFTTT Maker Channel key")
	flag.StringVar(&args.device, "device", "en0", "Device to listen on")
	flag.IntVar(&args.snaplen, "snaplen", 1600, "Snaplen for pcap")
	flag.BoolVar(&args.promisc, "promisc", true, "Use promiscuous mode")
	flag.StringVar(&args.filter, "filter", "arp", "Pcap filter")
	flag.BoolVar(&args.verbose, "verbose", false, "Verbose output")
	flag.Parse()
	return args
}

func main() {
	args := parse()
	packets, err := dashd.Sniff(args.device, int32(args.snaplen), args.promisc, args.filter)
	if err != nil {
		log.Fatal(err)
	}
	for packet := range packets {
		ethernet, ok := packet.LinkLayer().(*layers.Ethernet)
		if ok {
			log.Println(ethernet.SrcMAC)
		}
	}
}
