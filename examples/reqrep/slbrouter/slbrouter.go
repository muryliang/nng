// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package slbrouter

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf slbrouter.c -- -I./headers

func SlbRouter(ifaceName string) {

	// Look up the network interface by name.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPass,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
    var key uint32 = 10
    var val uint32 = 1
    var valout uint32
    fmt.Printf("map is %d %d\n", objs.Start.KeySize(), objs.Start.ValueSize())
	for range ticker.C {
		s, err := formatMapContents(objs.Start)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
        if val == 1 {
            val = 2
        } else {
            val = 1
        }
        err = objs.Start.Put(&key, &val)
		if err != nil {
			log.Printf("can not put: %s", err)
            break
		}
        fmt.Printf("put val %d\n", val)
        err = objs.Start.Lookup(&key, &valout)
		if err != nil {
			log.Printf("can not get: %s", err)
            break
		}
        fmt.Printf("get val %d\n", valout)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key uint32
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sb.WriteString(fmt.Sprintf("\t%d => %d\n", key, val))
	}
	return sb.String(), iter.Err()
}
