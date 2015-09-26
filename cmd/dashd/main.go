package main

import (
	"flag"
	"github.com/pspeter3/dashd"
	"log"
)

type flags struct {
	key     string
	device  string
	snaplen int
	promisc bool
	filter  string
	size    int
	debouce float64
	verbose bool
}

func parse() flags {
	var args flags
	flag.StringVar(&args.key, "key", "", "IFTTT Maker Channel key")
	flag.StringVar(&args.device, "device", "en0", "Device to listen on")
	flag.IntVar(&args.snaplen, "snaplen", 1600, "Snaplen for pcap")
	flag.BoolVar(&args.promisc, "promisc", true, "Use promiscuous mode")
	flag.StringVar(&args.filter, "filter", "arp", "Pcap filter")
	flag.IntVar(&args.size, "size", 50, "LRU cache size")
	flag.Float64Var(&args.debouce, "debounce", 30, "Seconds to debounce packets")
	flag.Parse()
	return args
}

func main() {
	args := parse()
	packets, err := dashd.Sniff(args.device, int32(args.snaplen), args.promisc, args.filter)
	if err != nil {
		log.Fatal(err)
	}
	gate, err := dashd.NewGate(args.size, args.debouce)
	if err != nil {
		log.Fatal(err)
	}
	for addr := range gate.Serve(packets) {
		log.Println(addr)
	}
}
