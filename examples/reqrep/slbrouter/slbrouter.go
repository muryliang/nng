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
    "bytes"
    "encoding/binary"
    "errors"

	"github.com/cilium/ebpf/link"
    "google.golang.org/protobuf/proto"

    "slb/slbproto"
    "slb/config"
    "slb/util"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf slbrouter.c -- -I./headers

/*
how to update?
configMap: map[saddr|daddr]struct mac, 
when something change, config or topo in doRouter()
get config with lock
lock map
send map and config into slbrouter.RecalAndInstall(inner, cfg, map)
unlock map

*/
type ipsecInfo struct {
    // use this when delete, because delete may
    // only have spi, we need to know what key 
    // so we can delete
    key []byte
}

type SlbRouter struct {
    InnerIP string
    OuterIP string
    InnerIntf *net.Interface
    OuterIntf *net.Interface

    spiMap map[uint32]ipsecInfo

    // maybe these two should be in alg callback's struct
//    prevOnoffMap map[string]bool
    curMap map[string][]byte
//    innerNewMap map[string][]byte

    xdpobjs bpfObjects
    xdplink link.Link
}

// todo: we may should not lock onoffmap for so long, just copy a duplicate for use
// we may use alg func callback here, but currently only
// rr supported, so every time recalculate
func (r *SlbRouter) recalMap(cfgs []config.VerCfg, onoffMap map[string][]byte) (map[string][]byte, map[string][]byte, error) {
    /* 
        create a index list(string) to onoffstring's key
        copy old map as new map first
        for each config
        parse, get Op and VerCfg
        for add: 
            if from local: combine src|dst as key, hash and get result to hash into key, to select mac addr from macmap, then set in newmap[combined_key]mac, 
        for del:
            how to del: remove from new
    */
    // index list for hash use
    var err error
    var maclist []string
    for key, val := range onoffMap {
        if val != nil {
            maclist = append(maclist, key)
        }
    }
    // copy map first
    newMap := make(map[string][]byte)
    for key, val := range r.curMap {
        newMap[key] = val
    }

    // todo parse req, use seperate class
    for _, vercfg := range cfgs {
        cfg := vercfg.Cfg
        if cfg.Op == config.OP_ADD_SA {
            sareq := &slbproto.AddSaReq{}
            err = proto.Unmarshal(cfg.Data, sareq)
            if err != nil {
                return nil, nil, err
            }
            srctmpl := net.IP(sareq.GetTmplHostSrc())
            dsttmpl := net.IP(sareq.GetTmplHostDst())
            if dsttmpl.String() == r.OuterIP {
                // use hash as index to get onoffmap's key, then reterieve its mac addr
                // key is {spi,0,0,0,0}
                hashkeybytes := make([]byte, 4)
                binary.BigEndian.PutUint32(hashkeybytes, sareq.GetSpi())
                hashkeybytes = append(hashkeybytes, []byte{0, 0, 0, 0}...)
                hashres := util.HashFromBytes(hashkeybytes, len(maclist))
                newMap[string(hashkeybytes)] = onoffMap[maclist[hashres]]
                r.spiMap[sareq.GetSpi()] = ipsecInfo{key:hashkeybytes}
            } else if srctmpl.String() == r.OuterIP {
                // install for egress, so for internal subnet key is internalip
                // key is {innersrcip,innerdstip}
                hashkeybytes := sareq.GetHostSrc()
                hashkeybytes = append(hashkeybytes, sareq.GetHostDst()...)
                hashres := util.HashFromBytes(hashkeybytes, len(maclist))
                // use hash as index to get onoffmap's key, then reterieve its mac addr
                newMap[string(hashkeybytes)] = onoffMap[maclist[hashres]]
                r.spiMap[sareq.GetSpi()] = ipsecInfo{key:hashkeybytes}

            } else {
                return nil, nil, errors.New("addreq's src/dst not us")
            }
        } else if cfg.Op == config.OP_DEL_SA {
            sareq := &slbproto.DelSaReq{}
            err = proto.Unmarshal(cfg.Data, sareq)
            if err != nil {
                return nil, nil, err
            }
            spi := sareq.GetSpi()
            if hashkeybytes, ok := r.spiMap[spi]; ok {
                delete(newMap, string(hashkeybytes.key)) 
                delete(r.spiMap, spi)
            }
        }
    }
    return r.curMap, newMap, nil
}

// macMap [string][]byte as []byte can not be map key, but convert to string vice-verse is possible
func (r *SlbRouter) RecalAndInstall(cfgs []config.VerCfg, onoffMap map[string][]byte) error {
    var err error

    // todo: currently not handle xdp map put error
    // when error, we should clear all map and unload router, only
    // need update curmap !
    curmap, newmap, err := r.recalMap(cfgs, onoffMap)
    if err != nil {
        return err
    }
    // todo:
    // for old not in new: delete
    for k, macaddr := range curmap {
        if _, ok := newmap[k]; !ok {
            fmt.Printf("delete %s:%v\n", k, macaddr)
            delete(curmap, k)
            err = r.xdpobjs.RedirectMap.Delete(&k)
            if err != nil {
                fmt.Printf("delete %s error %v\n", k, err)
            }
        }

    }

    // do new add stuff
    for k, macaddr := range newmap {
        origV, ok := curmap[k]
        if !ok {
            // add new
            fmt.Printf("adding %s:%v\n", k, macaddr)
            err = r.xdpobjs.RedirectMap.Put(&k, &macaddr)
        } else if !bytes.Equal(origV, macaddr) {
            // modify map
            fmt.Printf("modify %s:%v=>%v\n", k, origV, macaddr)
            err = r.xdpobjs.RedirectMap.Put(&k, &macaddr)
        } else {
            // nothing done here
        }
        if err != nil {
            fmt.Printf("put %s error %v\n", k, err)
            return err
        }
        // update curmap
        curmap[k] = macaddr
    }
    return nil
}

func (r *SlbRouter) Init() error {
    var err error
    if r.InnerIP == "" || r.OuterIP == "" {
        return errors.New("no ip specified")
    }
    r.curMap = make(map[string][]byte)
    r.spiMap = make(map[uint32]ipsecInfo)
    r.InnerIntf, err = util.GetIntfFromAddr(r.InnerIP)
    if err != nil {
        return err
    }
    r.OuterIntf, err = util.GetIntfFromAddr(r.OuterIP)
    if err != nil {
        return err
    }
    return nil
}

func (r *SlbRouter) Run() {

    var err error

    // load xdp program
	// Load pre-compiled programs into the kernel.
	if err := loadBpfObjects(&r.xdpobjs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
//	defer objs.Close()

// todo: we only test inner now
	// Attach the program.
	r.xdplink, err = link.AttachXDP(link.XDPOptions{
		Program:   r.xdpobjs.XdpPass,
		Interface: r.InnerIntf.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
//	defer l.Close()

	log.Printf("Attached XDP program to inner iface %q (index %d)", r.InnerIntf.Name, r.InnerIntf.Index)

}

/*
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
*/
