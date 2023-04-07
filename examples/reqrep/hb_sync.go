// Copyright 2018 The Mangos Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use file except in compliance with the License.
// You may obtain a copy of the license at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"time"
    "sync"
    "encoding/json"
    "flag"
    "math/rand"
    "strings"
    "sync/atomic"
    "net"
    "encoding/binary"
    "encoding/hex"
    "bytes"
    "os/exec"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/req"
	"go.nanomsg.org/mangos/v3/protocol/rep"
	"go.nanomsg.org/mangos/v3/protocol/surveyor"
	"go.nanomsg.org/mangos/v3/protocol/respondent"

	// register transports
	_ "go.nanomsg.org/mangos/v3/transport/all"

    "google.golang.org/protobuf/proto"

    "slb/slbproto"
    "slb/slbrouter"
    "slb/config"
    "slb/util"
)

const (
    HB_MAX_FAIL = 3
    READ_TIMEOUT = 1
    LOOP_TIMEOUT = 1
    HB_INFO = "hb"
    HB_PORT = "22345"
    SYNC_PORT = "22346"
    CFG_PORT = "22347"
    PROTO = "tcp://"
)

const (
    ST_OK int64 = iota
    ST_FAIL

)


type HbTarget struct {
    sock mangos.Socket
    SyncVer int64
}

type HbResp struct {
    Addr string
    Mac  []byte
}

type SendCfgs struct {
    Id   uint64
    Cfgs []config.VerCfg
}

type VerResp struct {
    SyncVer int64
}

var HB_TIMEOUT = flag.Int("hbtmo", 1000, "heartbeat timeout(ms)")
var localaddr = flag.String("laddr", "", "local addr xx.xx.xx.xx/mask")
var vinnerIP = flag.String("vin", "", "vip of inner subnet xx.xx.xx.xx")
var vouterIP = flag.String("vout", "", "vip of outer egress xx.xx.xx.xx")
//var localaddrmask = flag.String("laddrmask", "24", "netmask")
var sub = flag.Bool("sub", false, "subnet machine or not")
var subIntf = flag.String("subIntf", "", "subnet's tunnel intf")
var remoteaddr = flag.String("raddr", "", "remote addr(s) comma seperated")

// onoffmap, used between sync && lb
var onoffMap map[string][]byte = make(map[string][]byte)
var onoffLock sync.Mutex

// macMap, used between router && sync && lb
//var macMap map[string][]byte = make(map[string][]byte)
//var macLock sync.Mutex

var cfgs []config.VerCfg
var cfgLock sync.Mutex
// used for atomic load/store
var CurSyncVer int64
// used when c side add new cfg to go side
var cfgNotifyCh = make(chan struct{}, 1)
// used when lb or syncCfg decide we need to recalculate
var rtNotifyCh = make(chan struct{}, 1)

func die(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func verifyCfgs(showcfgs []config.VerCfg) error {
    for _, verCfg := range showcfgs {
        cfg := verCfg.Cfg
        op := cfg.Op
        sareq := &slbproto.AddSaReq{}
        if cfg.Op == config.OP_ADD_SA {
            err := proto.Unmarshal(cfg.Data, sareq)
            if err != nil {
                fmt.Printf("can not parse showcfg")
                return err
            }
            srcip := net.IP(sareq.GetHostSrc())
            dstip := net.IP(sareq.GetHostDst())
            srcipmask := sareq.GetHostSrcMask()
            dstipmask := sareq.GetHostDstMask()
            tmplsrcip := net.IP(sareq.GetTmplHostSrc())
            tmpldstip := net.IP(sareq.GetTmplHostDst())
            spi := sareq.GetSpi()
            fmt.Printf("cfg client received ver %d, op %s, src:%s/%d, dst:%s/%d,tmplsrc %s, tmpldst %s, spi:0x%x\n", verCfg.Ver, config.Gmap[op], srcip.String(), srcipmask, dstip.String(), dstipmask, tmplsrcip.String(), tmpldstip.String(), spi)
        }
    }
    return nil
}

func notifyRt() {
    select {
    case rtNotifyCh <- struct{}{}:
        fmt.Printf("notify router done\n")
    default:
        fmt.Printf("notify router block skip\n")
    }
}

func getRtNotify() {
    <- rtNotifyCh
}

func notifyCfg() {
    select {
    case cfgNotifyCh <- struct{}{}:
        fmt.Printf("notify cfg done\n")
    default:
        fmt.Printf("notify cfg block skip\n")
    }
}

func getCfgNotify() {
    <- cfgNotifyCh
}

/*
func testGenCfgs() {
    // this 0 is fixed
    var testInterval int32 = 5
    var i int64
    for i = 1; ; i++ {
        time.Sleep(time.Duration(rand.Int31n(testInterval)) * time.Second)
        cfgLock.Lock()
        cfgs = append(cfgs, config.VerCfg{i, config.Config{Op:uint32(i)}})
        cfgLock.Unlock()
        fmt.Printf("========= CFG ver %d added =======\n", i)
        notifyCfg()
    }
}
*/

// recv cfgs from c side
func recvCfg(laddr string) {
	var sock mangos.Socket
	var err error
	var msg []byte
    cfgUrl, err := util.ConcatString(PROTO, laddr, ":", CFG_PORT)
    if err != nil {
        die("can not get cfgurl %v", err)
    }
    fmt.Printf("recvCfg started with url %s\n", cfgUrl)
	if sock, err = rep.NewSocket(); err != nil {
		die("can't get new rep socket: %s", err)
	}
	if err = sock.Listen(cfgUrl); err != nil {
		die("can't listen on rep socket: %s", err.Error())
	}
    var i int64 = 0
	for {
		// Could also use sock.RecvMsg to get header
		msg, err = sock.Recv()
		if err != nil {
			die("cannot receive on cfg socket: %s", err.Error())
		}
        fmt.Printf("get msg %s\n", hex.EncodeToString(msg))
        msglen := int(binary.BigEndian.Uint32(msg[:4]))
        if msglen != len(msg) {
            die("msg len not correct %x %d", msglen, len(msg))
        }
        op := binary.BigEndian.Uint32(msg[4:8])
        fmt.Printf("op is %s\n", config.Gmap[op])

        // do a test unmarshal here, but store in cfg the protobuf only and op

        // maybe do a test here, but add, del struct not same
        /*
        sareq := &slbproto.AddSaReq{}
        err := proto.Unmarshal(msg[8:], sareq)
        if err != nil {
            fmt.Printf("can not parse received data")
            // what to do at C side when fail??
            // only network recv error may we send FAIL
            // and server will remove that newly created ones
            // update and del should be done first before local netlink
            resp.Status = ST_FAIL
        } else {
            resp.Status = ST_OK
        }
        */
        /*
        srcip := net.IP(sareq.GetHostSrc())
        dstip := net.IP(sareq.GetHostDst())
        tmplsrcip := net.IP(sareq.GetTmplHostSrc())
        tmpldstip := net.IP(sareq.GetTmplHostDst())
        spi := sareq.GetSpi()
        fmt.Printf("cfg server received size %d, src:%s, dst:%s,tmplsrc %s, tmpldst %s, spi:%x\n", len(msg), srcip.String(), dstip.String(), tmplsrcip.String(), tmpldstip.String(), spi)
        */

        resp := &slbproto.StatusResp{}
        buf := new(bytes.Buffer)
        err = binary.Write(buf, binary.BigEndian, int32(proto.Size(resp) + 8))
        if err != nil {
            die("can't binary write1 : %s", err.Error())
        }
        err = binary.Write(buf, binary.BigEndian, int32(config.OP_STATUS))
        if err != nil {
            die("can't binary write2 : %s", err.Error())
        }
        respmsg, err := proto.Marshal(resp)
        if err != nil {
            die("can't marshal : %s", err.Error())
        }
        fmt.Printf("before marshal buffer len is %d, msglen %d, protolen %d\n", buf.Len(), len(respmsg), proto.Size(resp))
        _, err = buf.Write(respmsg)
        if err != nil {
            die("can't buf write : %s", err.Error())
        }
//        fmt.Printf("%d NODE0: SENDING DATE %s\n", i, d)
        err = sock.Send(buf.Bytes())
        if err != nil {
            die("can't send reply: %s", err.Error())
        }

        cfgLock.Lock()
        i++  // first valid msg is 1
        cfgs = append(cfgs, config.VerCfg{Ver:i, Cfg:config.Config{Op:op, Data:msg[8:]}})
        cfgLock.Unlock()
        fmt.Printf("========= CFG ver %d added =======\n", i)
        notifyCfg()
	}
}

// handle maponoff case here
func doRouter(innerIP string, outerIP string) {
    var err error

    router := slbrouter.SlbRouter{InnerIP:innerIP, OuterIP:outerIP} 
    err = router.Init()
    if err != nil {
        die("router Init failed with error %v", err)
    }
    err = router.Run()
    if err != nil {
        die("router Run failed with error %v", err)
    }

    fmt.Printf("router started\n")
    var lastSyncVer int64 = 0
    for {
        getRtNotify()

        // come here from map change or cfg change, so will encounter update cur from 0 to 0 
        curVer := atomic.LoadInt64(&CurSyncVer)
        var installCfgs []config.VerCfg

        if lastSyncVer < curVer {
            cfgLock.Lock()
            installCfgs = cfgs[lastSyncVer+1:curVer+1]
            cfgLock.Unlock()
            fmt.Printf("router: begin update cur from %d to %d\n", lastSyncVer, curVer)
        } else if lastSyncVer == curVer {
            fmt.Printf("router: only map topo changed\n")
        } else {
            die("router failed with error %d > %d", lastSyncVer, curVer)
        }

        // if map changed, we need recalculate, so recal and cal topo change
        // if cfg update, we need recalculate also, so recal also
        
        // create a copy, so we will not block other route who access config and map
        onoffLock.Lock()
        copyOnoffMap := make(map[string][]byte)
        for k, v := range onoffMap {
            copyOnoffMap[k] = v
        }
        onoffLock.Unlock()

        // if all sub down, we should delete all maps
        // if at least on is up, we can recal and install
        fmt.Printf("========== do recal and install \n")
        err := router.RecalAndInstall(installCfgs, copyOnoffMap)
        if err != nil {
            die("router failed with error %v", err)
        }
        lastSyncVer = curVer
    }
}

// do syncCfg, use onoffMap{} and []config.VerCfg
// todo: currently directly modify xfrm here
// later we should do this in a second routin
// and reflect failure in heartbeat, so server
// will choose another mathine to redirect
func syncCfg_lbside(serverId uint64) {
    fmt.Printf("syncCfg_lbside started with id %x\n", serverId)
	var err error
    syncMap := make(map[string]*HbTarget)

    // use func trick to work "defer"
    func() {
        onoffLock.Lock()
        defer onoffLock.Unlock()

        options := map[string]interface{} {
            mangos.OptionDialAsynch: true,
        }

        for key := range onoffMap {
            syncMap[key] = &HbTarget{nil, 0}
            syncMap[key].sock, err = req.NewSocket()
            if err != nil {
                die("can't get new req socket: %s", err.Error())
            }
            err = syncMap[key].sock.SetOption(mangos.OptionBestEffort, true)
            if err != nil {
                die("can't set opt for sock: %s", err.Error())
            }
            err = syncMap[key].sock.SetOption(mangos.OptionRecvDeadline, READ_TIMEOUT * time.Second)
            if err != nil {
                die("can't set opt2 for sock: %s", err.Error())
            }
            syncUrl, err := util.ConcatString(PROTO, key, ":", SYNC_PORT)
            if err != nil {
                die("can't get sync url %v", err)
            }
            if err = syncMap[key].sock.DialOptions(syncUrl, options); err != nil {
                die("can't dial on req socket %s: %s", key, err.Error())
            }
        }
    }()

    fmt.Printf("initialize done\n")

    // loop keep sending req
    // may have bug if hb success but here send fail
	for {
        getCfgNotify()
        fmt.Printf("\nstart send config\n")

        // we only update until current latest
        cfgLock.Lock()
        curCfgs := cfgs[:]
        cfgLock.Unlock()

        var wg sync.WaitGroup
        wg.Add(len(syncMap))
        for addr, target := range syncMap {

            go func(remote string, tgt *HbTarget) {
                defer wg.Done()

                // keep trying until onoff is off or sendin one empty slice with syncver
                i := 0
                for {
                    i++
                    fmt.Printf("sending to %s, repeat %d\n", remote, i)

                    onoffLock.Lock()
                    if onoffMap[remote] == nil {
                        // we keep trying until target not online
                        onoffLock.Unlock()
                        fmt.Printf("%s off, skip\n", remote)
                        return
                    }
                    onoffLock.Unlock()

                    var ver_cfgs []config.VerCfg
                    curLastVer := curCfgs[len(curCfgs)-1].Ver
                    if tgt.SyncVer < curLastVer {
                        // else we send empty ones
                        ver_cfgs = curCfgs[tgt.SyncVer+1:]
                        fmt.Printf("sending to %s from %d to %d\n", remote, tgt.SyncVer+1, curLastVer)
                    } else if tgt.SyncVer > curLastVer {
                        die("some error ver")
                    } else {
                        // already sync
                        // this is needed in case client stop and start quickly
                        fmt.Printf("sending to %s empty for sync rsponse\n", remote)
                    }

                    sendmsg, err := json.Marshal(SendCfgs{Id: serverId, Cfgs: ver_cfgs})
                    if err != nil {
                        die("can not marshal sendcfg")
                    }
                    if err = tgt.sock.Send(sendmsg); err != nil {
                        die("Cannot send to %s: %s", remote, err.Error())
                    }
                    recvmsg, err := tgt.sock.Recv()
                    if err == mangos.ErrRecvTimeout {
                        fmt.Printf("%s timeout\n", remote)
                        continue // keep trying until off
                    }
                    if err != nil {
                        die("Cannot recv: %s", err.Error())
                    }
                    // err == nil, update ver
                    resp := &VerResp{}
                    err = json.Unmarshal(recvmsg, resp)
                    if err != nil {
                        die("can not unmarshal")
                    }
                    // no matter what, we use latest sync ver
                    fmt.Printf("lb update %s ver %d => %d\n", remote, tgt.SyncVer, resp.SyncVer)
                    tgt.SyncVer = resp.SyncVer

                    if tgt.SyncVer == curLastVer {
                    // test equal here, not start of for, because we need at least one cycle to know if submachine is ok or during a quick stop and start
                        break
                    }
                }
            }(addr, target)
        }
        wg.Wait()

        atomic.StoreInt64(&CurSyncVer, curCfgs[len(curCfgs)-1].Ver)
        notifyRt()
        fmt.Printf("loop done\n")
	}
}

func subnet_installroute(icfgs []config.VerCfg) error {
    var err error
    for _, icfg := range icfgs {

        cfg := icfg.Cfg
        op := cfg.Op
        var cmdstr string
        if cfg.Op == config.OP_ADD_SA {
            sareq := &slbproto.AddSaReq{}
            err = proto.Unmarshal(cfg.Data, sareq)
            if err != nil {
                fmt.Printf("can not parse showcfg")
                return err
            }
            srcip := net.IP(sareq.GetHostSrc())
            dstip := net.IP(sareq.GetHostDst())
            srcipmask := sareq.GetHostSrcMask()
            dstipmask := sareq.GetHostDstMask()
            tmplsrcip := net.IP(sareq.GetTmplHostSrc())
            tmpldstip := net.IP(sareq.GetTmplHostDst())
            spi := sareq.GetSpi()
            fmt.Printf("cfg client received add ver %d, op %s, src:%s/%d, dst:%s/%d,tmplsrc %s, tmpldst %s, spi:0x%x\n", icfg.Ver, config.Gmap[op], srcip.String(), srcipmask, dstip.String(), dstipmask, tmplsrcip.String(), tmpldstip.String(), spi)

            cmdstr = fmt.Sprintf("ip xfrm state add src %s dst %s proto esp spi 0x%x mode tunnel auth digest_null \"\" enc cipher_null \"\" ", tmplsrcip.String(), tmpldstip.String(), spi)
            cmd := exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }
            cmdstr = fmt.Sprintf("ip xfrm policy add src %s/%d dst %s/%d dir out ptype main tmpl src %s dst %s proto esp mode tunnel ", srcip.String(), srcipmask, dstip.String(), dstipmask, tmplsrcip.String(), tmpldstip.String())
            cmd = exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }
            cmdstr = fmt.Sprintf("ip xfrm policy add src %s/%d dst %s/%d dir in ptype main tmpl src %s dst %s proto esp mode tunnel ", dstip.String(), dstipmask, srcip.String(), srcipmask, tmpldstip.String(), tmplsrcip.String())
            cmd = exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }
            cmdstr = fmt.Sprintf("ip xfrm policy add src %s/%d dst %s/%d dir fwd ptype main tmpl src %s dst %s proto esp mode tunnel ", dstip.String(), dstipmask, srcip.String(), srcipmask, tmpldstip.String(), tmplsrcip.String())
            cmd = exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }

            // todo: maybe used this for policy add, so we need not add too much policy
            if _, err = util.GetIntfFromAddr(tmplsrcip.String()); err != nil {
                // we are adding for local esp, so add outer route
                cmdstr = fmt.Sprintf("ip rule add to %s/%d table 15", dstip.String(), dstipmask)
                cmd = exec.Command("bash", "-c", cmdstr)
                err = cmd.Run()
                if err != nil {
                    fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
                }
                cmdstr = fmt.Sprintf("ip route add %s/%d dev %s table 15", dstip.String(), dstipmask, *subIntf)
                cmd = exec.Command("bash", "-c", cmdstr)
                err = cmd.Run()
                if err != nil {
                    fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
                }

            }
        } else if cfg.Op == config.OP_DEL_SA {
            sareq := &slbproto.DelSaReq{}
            err := proto.Unmarshal(cfg.Data, sareq)
            if err != nil {
                fmt.Printf("can not parse showcfg")
                return err
            }
            srcip := net.IP(sareq.GetHostSrc())
            dstip := net.IP(sareq.GetHostDst())
            srcipmask := sareq.GetHostSrcMask()
            dstipmask := sareq.GetHostDstMask()
            tmplsrcip := net.IP(sareq.GetTmplHostSrc())
            tmpldstip := net.IP(sareq.GetTmplHostDst())
            spi := sareq.GetSpi()
            fmt.Printf("cfg client received delete ver %d spi:0x%x src %s/%d dst %s/%d\n", icfg, spi, srcip.String(), srcipmask, tmpldstip.String(), dstipmask)
            cmdstr = fmt.Sprintf("ip xfrm state delete spi 0x%x src %s dst %s proto esp", spi, tmplsrcip.String(), tmpldstip.String())
            cmd := exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }

            cmdstr = fmt.Sprintf("ip xfrm policy delete dir out src %s/%d dst %s/%d", srcip.String(), srcipmask, dstip.String(), dstipmask)
            cmd = exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }
            cmdstr = fmt.Sprintf("ip xfrm policy delete dir in src %s/%d dst %s/%d", dstip.String(), dstipmask, srcip.String(), srcipmask)
            cmd = exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }
            cmdstr = fmt.Sprintf("ip xfrm policy delete dir fwd src %s/%d dst %s/%d", dstip.String(), dstipmask, srcip.String(), srcipmask)
            cmd = exec.Command("bash", "-c", cmdstr)
            err = cmd.Run()
            if err != nil {
                fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
            }
            if _, err = util.GetIntfFromAddr(tmplsrcip.String()); err != nil {
                // we are adding for local esp, so add outer route
                cmdstr = fmt.Sprintf("ip rule del to %s/%d table 15", dstip.String(), dstipmask)
                cmd = exec.Command("bash", "-c", cmdstr)
                err = cmd.Run()
                if err != nil {
                    fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
                }
                cmdstr = fmt.Sprintf("ip route del %s/%d dev %s table 15", dstip.String(), dstipmask, *subIntf)
                cmd = exec.Command("bash", "-c", cmdstr)
                err = cmd.Run()
                if err != nil {
                    fmt.Printf("cmd '%s' result %v\n", cmdstr, err)
                }

            }
        }
    }
    return err
}

func syncCfg_subside(laddr string) {
	var sock mangos.Socket
	var err error
	var msg []byte

    syncUrl, err := util.ConcatString(PROTO, laddr, ":", SYNC_PORT)
    if err != nil {
		die("can't get sync url: %v\n", err)
    }
    fmt.Printf("syncCfg_subside started with url %s\n", syncUrl)

	if sock, err = rep.NewSocket(); err != nil {
		die("can't get new rep socket: %s", err)
	}
	if err = sock.Listen(syncUrl); err != nil {
		die("can't listen on rep socket: %s", err.Error())
	}

    localcfgs := []config.VerCfg {
        config.VerCfg{Ver:0, Cfg:config.Config{Op:0}},
    }
    var curServerId uint64 = 0
	for {
        if msg, err = sock.Recv(); err != nil {
            die("Failed recv %s", err.Error())
        }
        var sendCfgs SendCfgs
        err = json.Unmarshal(msg, &sendCfgs)
        if err != nil {
            die("Failed decode json: %s", err.Error())
        }
        if sendCfgs.Id != curServerId {
            fmt.Printf("server restarted, trim config\n")
            curServerId = sendCfgs.Id
            localcfgs = localcfgs[:1] // trim cfgs as server restarted
        }
        cfgs := sendCfgs.Cfgs

        var resp VerResp

        // return updated SyncVer
        resp.SyncVer = localcfgs[len(localcfgs)-1].Ver
        if len(cfgs) != 0 {
            // merge cfg here
            fmt.Printf("len %d, local %d, get [%d,%d]\n",
                len(cfgs), resp.SyncVer, cfgs[0].Ver, cfgs[len(cfgs)-1].Ver)
            startVer := cfgs[0].Ver
            endVer := cfgs[len(cfgs)-1].Ver
            if resp.SyncVer + 1 >= startVer &&
                    resp.SyncVer < endVer {
                localcfgs = append(localcfgs, cfgs[resp.SyncVer + 1 - startVer:]...)
                installcfgs := cfgs[resp.SyncVer + 1 - startVer:]
                err = verifyCfgs(installcfgs)
                if err != nil {
                    die("Failed verify cfgs in client: %s", err.Error())
                }
                fmt.Printf("update ver from %d to %d\n", resp.SyncVer, localcfgs[len(localcfgs)-1].Ver)
                resp.SyncVer = localcfgs[len(localcfgs)-1].Ver
                err = subnet_installroute(installcfgs)
                if err != nil {
                    die("Failed to install cfg %v", err.Error())
                }
            } else {
                fmt.Printf("remain ver as %d\n", resp.SyncVer)
            }
            
            // show cfg here

            // update ver
        } else {
            fmt.Printf("remain ver as %d\n", resp.SyncVer)
        }
        sendmsg, err := json.Marshal(resp)
        if err != nil {
            die("Failed encode json: %s", err.Error())
        }
        if err = sock.Send(sendmsg); err != nil {
            die("Failed sending rep: %s", err.Error())
        }
    }
}

// do hb check, update onoffMap{}
func hb_lbside(laddr string) {
	var sock mangos.Socket
	var err error
	var msg []byte

    url, err := util.ConcatString(PROTO, laddr, ":", HB_PORT)
    if err != nil {
        die("can not construct hb url\n")
    }
    fmt.Printf("hb_lbside started with url %s\n", url)
    failMap := make(map[string]int)

    // initialize fail map
    onoffLock.Lock()
    for key := range onoffMap {
        failMap[key] = 0
    }
    onoffLock.Unlock()
    total_cnt := len(failMap)

	if sock, err = surveyor.NewSocket(); err != nil {
		die("can't get new surveyor socket: %s", err)
	}
	if err = sock.Listen(url); err != nil {
		die("can't listen on surveyor socket: %s", err.Error())
	}
	err = sock.SetOption(mangos.OptionSurveyTime, time.Millisecond * time.Duration(*HB_TIMEOUT))
	if err != nil {
		die("SetOption(): %s", err.Error())
	}
    i := 0
	for {
        if len(failMap) == 0 {
            // quick break out
            break
        }
        recvMap := make(map[string][]byte)
        for key := range failMap {
            recvMap[key] = nil
        }

        i++
        fmt.Printf("\nserver: sending hb %d\n", i)
        if err = sock.Send([]byte(HB_INFO)); err != nil {
            die("Failed sending hb: %s", err.Error())
        }
        // currently use this, or we may use client send
        // pair mode is ok, just client send enough
        recv_cnt := 0
        for {
            if msg, err = sock.Recv(); err != nil {
                fmt.Println("get err ", err);
                break
            }
            hbresp := HbResp{}
            err = json.Unmarshal(msg, &hbresp)
            if err != nil {
                fmt.Printf("get json err %v, retry\n", err)
                break;
            }
            from_addr := hbresp.Addr // client send cfg sync addr here
            // we get mac here, then do what? update map of mac, so recvmap should use ip as key, not protocol whole
            mapval, ok := recvMap[from_addr]
            if !ok {
                fmt.Printf("get wrong key %s\n", string(msg))
            } else {
                if mapval == nil {
                    recvMap[from_addr] = hbresp.Mac
                } else {
                    fmt.Printf("recv dup key for add %s %v => %v\n", from_addr, mapval, hbresp.Mac)
                    recvMap[from_addr] = hbresp.Mac
                }
                recv_cnt ++
                if recv_cnt == total_cnt {
                    break
                }
            }
        }

        changed := false
        onoffLock.Lock()
        for addr, macaddr := range recvMap {
            if macaddr == nil {
                failMap[addr] += 1
                fmt.Printf("%s failed\n", addr)
                if failMap[addr] == HB_MAX_FAIL { // when > MAX, already false, not do it
                    fmt.Printf("%s timeout max, set off\n", addr)
                    onoffMap[addr] = nil
                    changed = true
                }
            } else {
                failMap[addr] = 0
                if onoffMap[addr] == nil {
                    fmt.Printf("%s recovered, set on\n", addr)
                    onoffMap[addr] = macaddr
                    changed = true
                }
            }
        }
        onoffLock.Unlock()
        
        // we recalculate hash only after
        // success sync cfgs, then decide where to route
        // so we need to track lastUpdateRoute, lastUpdateVersion
        // in order to calculate and apply current changes
        // so notify in channel here, also notify in synccfg success with all empty
        // in router module, check cfg update and onoff_update here,
        // according to last ver and current, onoffMap, set new ones
        // what we need: spi for input, ip pair for output
        //      after synccfg success for all onoffMap[on]
        //      trigger recal
        // 1. when notifyRt from lb changed: only concern hash recal
        // 2. when notifyRt from cfgsync: concert map update and hash recal, notify should include a version
        if changed {
            fmt.Printf("we changed, recalculate hash here\n")
            // nonblocking echo
            notifyCfg() // map changed, we need send at least one cfgreq to pushd cfg, and it will do notifyRt() for us
            // client side can control hb response when sync cfg failed some time, retire and warn to hb when needed
            // only update hash when we finish sync, so how
        }
        fmt.Printf("========== dump onoffmap ========\n")
        for k, v := range onoffMap {
            fmt.Printf("%s => %#v\n", k, v)
        }
        fmt.Printf("========== dump onoffmap over ========\n")
        if recv_cnt == total_cnt {
            time.Sleep(time.Millisecond * time.Duration(*HB_TIMEOUT))
        }
	}
}

// respmsg is synccfg's connect url
func hb_subside(laddr string, raddr string) {
	var sock mangos.Socket
	var err error
	var msg []byte

    dialurl, err := util.ConcatString(PROTO, raddr, ":", HB_PORT)
    if err != nil {
        die("sub can not get hb url\n")
    }
    fmt.Printf("hb_subside started\n")

	if sock, err = respondent.NewSocket(); err != nil {
		die("can't get new respondent socket: %s", err.Error())
	}
	err = sock.SetOption(mangos.OptionDialAsynch, true)
	if err != nil {
		die("SetOption(): %s", err.Error())
	}
	if err = sock.Dial(dialurl); err != nil {
		die("can't dial on respondent socket: %s", err.Error())
	}
    i := 0
	for {
        fmt.Println("receiving...")
		if msg, err = sock.Recv(); err != nil {
			die("Cannot recv: %s", err.Error())
		}
		fmt.Printf("client(%s): received \"%s\" \n", laddr, string(msg))
        if string(msg) != HB_INFO {
            die("server hb info not correct")
        }

        i++
		fmt.Printf("client: responding hb %d %s\n", i, laddr)
        mac, err := util.GetMacFromAddr(laddr)
        if err != nil {
            die("client hb can not get mac")
        }
        hbResp := HbResp{Addr: laddr, Mac: mac}
        sendMsg, err := json.Marshal(hbResp)
        if err != nil {
            die("client hb can not marshal")
        }
		if err = sock.Send(sendMsg); err != nil {
			die("Cannot send: %s", err.Error())
		}
	}
}

// BUG: client must start after server, we need define a 
// server random id, and send when sending cfg, so client
// can destroy all cur cfgs when random id not match
func main() {
    // todo: use flag for client server, url specify
    // client need sync's url(bind), hb url(dial)
    // server need hb url(bind), sync's urls for each server(dial)
    // use flag.Var for custom multiple arg, see b.go
    flag.Parse()
    if *localaddr == "" || *remoteaddr == "" {
        die("need specify local/remote ip addr here")
    }
    if !*sub {
        // lb, construct hburl, subservers url here
        subservers := strings.Split(*remoteaddr, ",")
        fmt.Printf("lb mode hb addr %s, subservers %v\n", *localaddr, subservers)

        // initialize onoffmap
        for _, server := range subservers {
            onoffMap[server] = nil
        }
        serverId := rand.Uint64()

        // initialize cfg
        cfgs = append(cfgs, config.VerCfg{Ver:0, Cfg:config.Config{Op:config.OP_DUMB}})

        go syncCfg_lbside(serverId)
        go hb_lbside(*localaddr)
        // todo: outer ip should be set by args
        go doRouter(*vinnerIP, *vouterIP)
//        go testGenCfgs()
        go recvCfg(*localaddr)
        for {
            time.Sleep(1 * time.Second)
        }
    } else {
        if *subIntf == "" {
            die("sub need tunnel intf\n")
        }
        hbUrl, err := util.ConcatString(PROTO, *remoteaddr, ":", HB_PORT)
        if err != nil {
            die("sub can not get hb url\n")
        }
        synUrl, err := util.ConcatString(PROTO, *localaddr, ":", SYNC_PORT)
        if err != nil {
            die("can not get sub syn url\n")
        }
        fmt.Printf("sub mode with hb url %s, cfgurl %s\n", hbUrl, synUrl)
        go hb_subside(*localaddr, *remoteaddr) 
        go syncCfg_subside(*localaddr)
        for {
            time.Sleep(1 * time.Second)
        }
    }

    // todo: construct onoff map according to flag.surl, maybe later we use autoconnect and disconnect
}
