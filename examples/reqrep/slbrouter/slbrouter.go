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
	"net"
    "bytes"
    "encoding/binary"
    "errors"
    "strings"

	"github.com/cilium/ebpf"
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
    key [8]byte
}

type SlbRouter struct {
    InnerIP string
    OuterIP string
    InnerIntf *net.Interface
    OuterIntf *net.Interface

    spiMap map[uint32]ipsecInfo

    // maybe these two should be in alg callback's struct
//    prevOnoffMap map[string]bool
    curMap map[[8]byte][]byte
//    innerNewMap map[string][]byte

    xdpobjs bpfObjects
    xdplink link.Link
}

var MAC_DUMB []byte  = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var INNER_VIP_INDEX uint32 = 0
var OUTER_VIP_INDEX uint32 = 1

// check currently ON maclist, and adjust configured ones
func (r *SlbRouter) adjustTopo(newMap map[[8]byte][]byte, onoffMap map[string][]byte, maclist [][]byte) {
    // topo change, some addr is off
    // if not found that mac in maclist
    for key, val := range r.curMap {
        exist := false
        for _, addr := range maclist {
            if bytes.Equal(val, addr) {
                exist = true
                newMap[key] = val
                break
            }
        }
        if !exist {
            if len(maclist) == 0 {
                newMap[key] = MAC_DUMB
            } else {
                hashres := util.HashFromBytes(key[:], len(maclist))
                newMap[key] = maclist[hashres]
            }
        }
    }
}

// todo: we may should not lock onoffmap for so long, just copy a duplicate for use
// we may use alg func callback here, but currently only
// rr supported, so every time recalculate
func (r *SlbRouter) recalMap(cfgs []config.VerCfg, onoffMap map[string][]byte) (map[[8]byte][]byte, map[[8]byte][]byte, error) {
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
    var maclist [][]byte
    for _, val := range onoffMap {
        if val != nil {
            maclist = append(maclist, val)
        }
    }
    // copy map
    newMap := make(map[[8]byte][]byte)

    // first adjust without cfg changes
    r.adjustTopo(newMap, onoffMap, maclist)

    // apply new vercfgs here
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
                if len(maclist) == 0 {
                    newMap[([8]byte)(hashkeybytes)] = MAC_DUMB
                } else {
                    hashres := util.HashFromBytes(hashkeybytes, len(maclist))
                    newMap[([8]byte)(hashkeybytes)] = maclist[hashres]
                }
                r.spiMap[sareq.GetSpi()] = ipsecInfo{key:([8]byte)(hashkeybytes)}
            } else if srctmpl.String() == r.OuterIP {
                // install for egress, so for internal subnet key is internalip
                // key is {innersrcip,innerdstip}
                hashkeybytes := sareq.GetHostSrc()
                hashkeybytes = append(hashkeybytes, sareq.GetHostDst()...)
                // use hash as index to get onoffmap's key, then reterieve its mac addr
                if len(maclist) == 0 {
                    newMap[([8]byte)(hashkeybytes)] = MAC_DUMB
                } else {
                    hashres := util.HashFromBytes(hashkeybytes, len(maclist))
                    newMap[([8]byte)(hashkeybytes)] = maclist[hashres]
                }
                r.spiMap[sareq.GetSpi()] = ipsecInfo{key:([8]byte)(hashkeybytes)}

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
                delete(newMap, hashkeybytes.key) 
                delete(r.spiMap, spi)
            } else {
                fmt.Printf("spi %x not exist\n", spi)
            }
        }
    }
    fmt.Printf("========= dump map topo ==============\n")
    fmt.Printf("curmap %#v\n", r.curMap)
    fmt.Printf("newmap %#v\n", newMap)
    fmt.Printf("========= dump map topo over ==============\n")
    return r.curMap, newMap, nil
}


func (r *SlbRouter) DeleteAll() error {
    // only do delete here, and not update ver
    var err error
    for k := range r.spiMap {
        delete(r.spiMap, k)
    }
    for k := range r.curMap {
        delete(r.curMap, k)
        err = r.xdpobjs.RedirectMap.Delete(&k)
        if err != nil {
            fmt.Printf("only delete %s error %v\n", k, err)
            return err
        }
    }
    return nil
}

// macMap [string][]byte as []byte can not be map key, but convert to string vice-verse is possible
func (r *SlbRouter) RecalAndInstall(cfgs []config.VerCfg, onoffMap map[string][]byte) error {
    var err error

    // todo: currently not handle xdp map put error
    // when error, we should clear all map and unload router, only
    // need update curmap !
    fmt.Printf("in recal install map is %#v\n", onoffMap)
    curmap, newmap, err := r.recalMap(cfgs, onoffMap)
    if err != nil {
        return err
    }

    // what to do if all is off? 
    // we should set in newmap a special val and test before xdpobjs handle

    // for old not in new: delete
    for k, macaddr := range curmap {
        if _, ok := newmap[k]; !ok {
            fmt.Printf("delete %#v:%#v\n", k, macaddr)
            delete(curmap, k)
            err = r.xdpobjs.RedirectMap.Delete(&k)
            if err != nil {
                fmt.Printf("delete %s error %v\n", k, err)
            }
        }
    }

    // do new add stuff
    for k, macaddr := range newmap {
        if bytes.Equal(macaddr, MAC_DUMB) {
            fmt.Printf("skip adding xdp for key %#v\n", k)
            // may not exist
            _ = r.xdpobjs.RedirectMap.Delete(&k)
        } else {
            origV, ok := curmap[k]
            if !ok {
                // add new
                fmt.Printf("\nadding %#v:%#v\n", k, macaddr)
                err = r.xdpobjs.RedirectMap.Put(&k, &macaddr)
            } else if !bytes.Equal(origV, macaddr) {
                // modify map
                fmt.Printf("\nmodify %#v:%#v=>%#v\n", k, origV, macaddr)
                err = r.xdpobjs.RedirectMap.Put(&k, &macaddr)
            } else {
                // nothing done here
            }
            if err != nil {
                fmt.Printf("put %#v error %v\n", k, err)
                return err
            }
            // update curmap
        }
        curmap[k] = macaddr
    }
    fmt.Printf("\n=========== show map after install\n")
    res, _ := formatMapContents(r.xdpobjs.RedirectMap)
    fmt.Printf("%s\n\n", res)
    return nil
}

func (r *SlbRouter) Init() error {
    var err error
    if r.InnerIP == "" || r.OuterIP == "" {
        return errors.New("no ip specified")
    }
    r.curMap = make(map[[8]byte][]byte)
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

func (r *SlbRouter) Run() error {

    var err error

    // load xdp program
	// Load pre-compiled programs into the kernel.
	if err := loadBpfObjects(&r.xdpobjs, nil); err != nil {
		fmt.Printf("loading objects: %s\n", err)
	}
//	defer objs.Close()

// todo: we only test inner now
// and if internal and outer are the same, we combine two functions
	// Attach the program.
	r.xdplink, err = link.AttachXDP(link.XDPOptions{
		Program:   r.xdpobjs.XdpRedirectInternal,
		Interface: r.InnerIntf.Index,
	})
	if err != nil {
		fmt.Printf("could not attach XDP program: %s\n", err)
        return err
	}
//	defer l.Close()

    err = r.xdpobjs.MacArr.Put(&INNER_VIP_INDEX, &r.InnerIntf.HardwareAddr)
    if err != nil {
        fmt.Printf("failed to set inner hwaddr")
        return err
    }
    err = r.xdpobjs.MacArr.Put(&OUTER_VIP_INDEX, &r.OuterIntf.HardwareAddr)
    if err != nil {
        fmt.Printf("failed to set outer hwaddr")
        return err
    }
	fmt.Printf("Attached XDP program to inner iface %q (index %d)\n", r.InnerIntf.Name, r.InnerIntf.Index)
    return nil

}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key [8]byte
		val [6]byte
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sb.WriteString(fmt.Sprintf("\t%#v => %#v\n", key, val))
	}
	return sb.String(), iter.Err()
}
