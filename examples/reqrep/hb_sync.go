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
    "strconv"
    "sync"
    "encoding/json"
    "flag"
    "math/rand"
    "strings"
    "sync/atomic"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/req"
	"go.nanomsg.org/mangos/v3/protocol/rep"
	"go.nanomsg.org/mangos/v3/protocol/surveyor"
	"go.nanomsg.org/mangos/v3/protocol/respondent"

	// register transports
	_ "go.nanomsg.org/mangos/v3/transport/all"
)

const (
    HB_MAX_FAIL = 3
    READ_TIMEOUT = 1
    LOOP_TIMEOUT = 1
    HB_INFO = "hb"
)

func die(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func date() string {
	return time.Now().Format(time.ANSIC)
}

type HbTarget struct {
    sock mangos.Socket
    SyncVer int64
}

type Config struct {
    Info string
}

type VerCfg struct {
    Ver int64
    Cfg Config
}

type SendCfgs struct {
    Id   uint64
    Cfgs []VerCfg
}

type VerResp struct {
    SyncVer int64
}

var HB_TIMEOUT = flag.Int("hbtmo", 1000, "heartbeat timeout")
var hbUrl = flag.String("hburl", "ipc:///tmp/hb.ipc", "heartbeat url")
var synUrl = flag.String("synurl", "", "for lb, this is comma-seperated list; for subnet, this is just a url string")
var sub = flag.Bool("sub", false, "subnet machine or not")

var onoffMap map[string]bool = make(map[string]bool)

var cfgs []VerCfg
var onoffLock sync.Mutex
var cfgLock sync.Mutex
// used for atomic load/store
var CurSyncVer int64
// used when c side add new cfg to go side
var cfgNotifyCh = make(chan struct{}, 1)
// used when lb or syncCfg decide we need to recalculate
var rtNotifyCh = make(chan struct{}, 1)

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

func testGenCfgs() {
    // this 0 is fixed
    cfgs = append(cfgs, VerCfg{0, Config{strconv.FormatInt(0, 10)}})
    var i int64
    for i = 1; ; i++ {
        time.Sleep(time.Duration(rand.Int31n(10)) * time.Second)
        cfgLock.Lock()
        cfgs = append(cfgs, VerCfg{i, Config{strconv.FormatInt(i, 10)}})
        cfgLock.Unlock()
        fmt.Printf("========= CFG ver %d added =======\n", i)
        notifyCfg()
    }
}

func router() {
    fmt.Printf("router started\n")
    var lastSyncVer int64 = 0
    for {
        getRtNotify()
        // come here from map change or cfg change, so will encounter update cur from 0 to 0 
        curVer := atomic.LoadInt64(&CurSyncVer)
        if lastSyncVer < curVer {
            fmt.Printf("router: update cur from %d to %d\n", lastSyncVer, curVer)
            lastSyncVer = curVer
        } else {
            fmt.Printf("router: only map topo changed\n")
        }
    }
}

// do syncCfg, use onoffMap{} and []VerCfg
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

        for key, _ := range onoffMap {
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
            if err = syncMap[key].sock.DialOptions(key, options); err != nil {
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
                    if !onoffMap[addr] {
                        // we keep trying until target not online
                        onoffLock.Unlock()
                        fmt.Printf("%s off, skip\n", remote)
                        return
                    }
                    onoffLock.Unlock()

                    var ver_cfgs []VerCfg
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
                    if err = tgt.sock.Send(sendmsg); err != nil {
                        die("Cannot send to %s: %s", remote, err.Error())
                    }
                    recvmsg, err := tgt.sock.Recv()
                    if err == mangos.ErrRecvTimeout {
                        fmt.Printf("%s timeout\n", remote)
                        return
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

func syncCfg_subside(url string) {
    fmt.Printf("syncCfg_subside started\n")
	var sock mangos.Socket
	var err error
	var msg []byte

	if sock, err = rep.NewSocket(); err != nil {
		die("can't get new rep socket: %s", err)
	}
	if err = sock.Listen(url); err != nil {
		die("can't listen on rep socket: %s", err.Error())
	}

    localcfgs := []VerCfg {
        VerCfg{0, Config{strconv.FormatInt(0, 10)}},
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
            }
            fmt.Printf("update ver from %d to %d\n", resp.SyncVer, localcfgs[len(localcfgs)-1].Ver)
            resp.SyncVer = localcfgs[len(localcfgs)-1].Ver
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
func hb_lbside(url string) {
    fmt.Printf("hb_lbside started\n")
	var sock mangos.Socket
	var err error
	var msg []byte
    failMap := make(map[string]int)

    // initialize fail map
    onoffLock.Lock()
    for key, _ := range onoffMap {
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
        recvMap := make(map[string]bool)
        for key, _ := range failMap {
            recvMap[key] = false
        }

        i++
        fmt.Printf("\nserver: sending hb %d\n", i)
        if err = sock.Send([]byte(HB_INFO)); err != nil {
            die("Failed sending hb: %s", err.Error())
        }
        // currently use this, or we may use client send
        // pair mode is ok, just client send enough
        recv_cnt := 0
        changed := false
        for {
            if msg, err = sock.Recv(); err != nil {
                fmt.Println("get err ", err);
                break
            }
            from_addr := string(msg) // client send cfg sync addr here
            mapval, ok := recvMap[from_addr]
            if !ok {
                fmt.Printf("get wrong key %s\n", string(msg))
            } else {
                if !mapval {
                    recvMap[from_addr] = true
                    recv_cnt ++
                    if recv_cnt == total_cnt {
                        break
                    }
                }
            }
        }

        onoffLock.Lock()
        for addr, onoff := range recvMap {
            if !onoff {
                failMap[addr] += 1
                fmt.Printf("%s failed\n", addr)
                if failMap[addr] == HB_MAX_FAIL { // when > MAX, already false, not do it
                    fmt.Printf("%s timeout max, set off\n", addr)
                    onoffMap[addr] = false
                    changed = true
                }
            } else {
                failMap[addr] = 0
                if onoffMap[addr] == false {
                    fmt.Printf("%s recovered, set on\n", addr)
                    onoffMap[addr] = true
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
            notifyRt()
            notifyCfg() // map changed, we need send at least one cfgreq to pushd cfg
            // client side can control hb response when sync cfg failed some time, retire and warn to hb when needed
            // only update hash when we finish sync, so how
        }
        res, err := json.MarshalIndent(onoffMap, "", " ")
        if err != nil {
            fmt.Println("some error json", err)
        }
        fmt.Println(string(res))
        if recv_cnt == total_cnt {
            time.Sleep(time.Millisecond * time.Duration(*HB_TIMEOUT))
        }
	}
}

// respmsg is synccfg's connect url
func hb_subside(dialurl string, hbRespmsg string) {
    fmt.Printf("hb_subside started\n")
	var sock mangos.Socket
	var err error
	var msg []byte

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
	for {
        fmt.Println("receiving...")
		if msg, err = sock.Recv(); err != nil {
			die("Cannot recv: %s", err.Error())
		}
		fmt.Printf("client(%s): received \"%s\" \n", hbRespmsg, string(msg))
        if string(msg) != HB_INFO {
            die("server hb info not correct")
        }

		fmt.Printf("client: responding hb %s\n", hbRespmsg)
		if err = sock.Send([]byte(hbRespmsg)); err != nil {
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
    if !*sub {
        // lb
        subservers := strings.Split(*synUrl, ",")
        fmt.Printf("lb mode hb url %s, subservers %v\n", *hbUrl, subservers)

        // initialize onoffmap
        for _, server := range subservers {
            onoffMap[server] = false
        }
        serverId := rand.Uint64()
        go syncCfg_lbside(serverId)
        go hb_lbside(*hbUrl)
        go router()
        go testGenCfgs()
        for {
        }
    } else {
        fmt.Printf("sub mode with hb url %s, cfgurl %s\n", *hbUrl, *synUrl)
        go hb_subside(*hbUrl, *synUrl) 
        go syncCfg_subside(*synUrl)
        for {
        }
    }

    // todo: construct onoff map according to flag.surl, maybe later we use autoconnect and disconnect
	os.Exit(1)
}
