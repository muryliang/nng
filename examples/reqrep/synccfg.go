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

// req implements a req example.  server is a req listening
// socket, and clients are dialing respondent sockets.
//
// To use:
//
//   $ go build .
//   $ url=tcp://127.0.0.1:40899
//   $ ./req server $url server & server=$!
//   $ ./req client $url client0 & client0=$!
//   $ ./req client $url client1 & client1=$!
//   $ ./req client $url client2 & client2=$!
//   $ sleep 5
//   $ kill $server $client0 $client1 $client2
//
package main

import (
	"fmt"
	"os"
	"time"
    "strconv"
    "sync"
    "encoding/json"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/req"
	"go.nanomsg.org/mangos/v3/protocol/rep"

	// register transports
	_ "go.nanomsg.org/mangos/v3/transport/all"
)

const (
    HB_MAX_FAIL = 3
    HB_TIMEOUT = 1
    READ_TIMEOUT = 1
    LOOP_TIMEOUT = 1
)

func die(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func date() string {
	return time.Now().Format(time.ANSIC)
}

/*
func hash_recalculate():
    pass
*/
/*
// select logic
define map_subnet_onoff(addr_str, bool_on)
define map_subnet_version(addr_str, bool_on) (first valid ver is 1)

func recv_install_xfrm:
    first, all handled local, so no worry unhandled liuliang
    push config into redis hset1(key as sub ip pair?)
    push route config into another map hset2, index by one ip(we only have one, maybe 2?)
    check hset and use ip as index check hset2, if all good, we can do install
    notify puller routine:

func puller routine:
    pop from list
    calculate which one to handle
    send to all
    according to map_subnet_onoff, select which to route, add into xdp
*/
/*
// distribute logic
*/
/*
// heartbeat logic
define map_subnet_onoff(addr_str, bool_on)
define map_subnet_fail(addr_str, fail_cnt)
def total_cnt = len(map_subent_fail)
loop:
    def map_test(addr_str, off)
    def recv_cnt = 0
    send_req
    loop: (set timeout as loop_interval)
        recv with addr_str
        if map_test[addr_str] == off:
            map_test[addr_str] = on
            recv_cnt += 1
            if recv_cnt == total_cnt:
                break_loop
        if recv_cnt == total_cnt:
            sleep(loop_interval)
        else
            map_lock()
            foreach(map_test):
                if map_test[addr_str] == off:
                    map_subnet_fail[addr_str] += 1
                    if map_subnet_fail[addr_str] >= MAX_FAIL:
                        map_subnet_onoff[addr_str] = off
                        changed = 1
                else if map_test[addr_str] == on:
                    map_subnet_fail[addr_str] = 0
                    if map_subnet_onoff[addr_str] == off
                        map_subnet_onoff[addr_str] = on
                        changed = 1
            map_unlock()
            if changed == 1
                trigger hash recalculate()
            // if timeout, we already sleeped that time, continue with out sleep

*/
// server is submachine first recv, then send
/*
func server(url string) {
	var sock mangos.Socket
	var err error
	var msg []byte
    var hb_lock sync.Mutex
    hb_map_fail := map[string]int {
        "c1" : 0,
        "c2" : 0,
        "c3" : 0,
    }
    hb_map_onoff := map[string]bool {
        "c1" : false,
        "c2" : false,
        "c3" : false,
    }

    total_cnt := len(hb_map_onoff)
	if sock, err = rep.NewSocket(); err != nil {
		die("can't get new rep socket: %s", err)
	}
	if err = sock.Listen(url); err != nil {
		die("can't listen on rep socket: %s", err.Error())
	}
	for {
        tmp_map := map[string]bool {
            "c1" : false,
            "c2" : false,
            "c3" : false,
        }
        recv_cnt := 0
        changed := false

        fmt.Println("\nserver: sending hb")
        if err = sock.Send([]byte("hb")); err != nil {
            die("Failed sending rep: %s", err.Error())
        }
        // currently use this, or we may use client send
        // pair mode is ok, just client send enough
        for {
            if msg, err = sock.Recv(); err != nil {
                fmt.Println("get err ", err);
                break
            }
            from_addr := string(msg)
            mapval, ok := tmp_map[from_addr]
            if !ok {
                fmt.Printf("get wrong key %v\n", msg)
            } else {
                if !mapval {
                    tmp_map[from_addr] = true
                    recv_cnt ++
                    if recv_cnt == total_cnt {
                        break
                    }
                }
            }
        }

        hb_lock.Lock()
        for addr, onoff := range tmp_map {
            if !onoff {
                hb_map_fail[addr] += 1
                fmt.Printf("%s failed\n", addr)
                if hb_map_fail[addr] == HB_MAX_FAIL { // when > MAX, already false, not do it
                    fmt.Printf("%s timeout max, set off\n", addr)
                    hb_map_onoff[addr] = false
                    changed = true
                }
            } else {
                hb_map_fail[addr] = 0
                if hb_map_onoff[addr] == false {
                    fmt.Printf("%s recovered, set on\n", addr)
                    hb_map_onoff[addr] = true
                    changed = true
                }
            }
        }
        hb_lock.Unlock()
        
        if changed {
            fmt.Printf("we changed\n")
        }
        res, err := json.MarshalIndent(hb_map_onoff, "", " ")
        if err != nil {
            fmt.Println("some error json", err)
        }
        fmt.Println(string(res))
        if recv_cnt == total_cnt {
            time.Sleep(time.Second * HB_TIMEOUT)
        }
	}
}
*/

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

type VerResp struct {
    SyncVer int64
}

func server(url string) {
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
	for {
        if msg, err = sock.Recv(); err != nil {
            die("Failed recv %s", err.Error())
        }
        var cfgs []VerCfg
        err = json.Unmarshal(msg, &cfgs)
        if err != nil {
            die("Failed decode json: %s", err.Error())
        }
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

// client is lb first send, then recv
func lb() {
	var err error
    hb_map := map[string]*HbTarget{
        "ipc:///tmp/1.ipc": &HbTarget{nil, 0},
        "ipc:///tmp/2.ipc": &HbTarget{nil, 0},
        "ipc:///tmp/3.ipc": &HbTarget{nil, 0},
    }
    onoff_map := map[string]bool {
        "ipc:///tmp/1.ipc": true,
        "ipc:///tmp/2.ipc": true,
        "ipc:///tmp/3.ipc": true,
    }
    var cfgs []VerCfg
    var i int64
    for i = 0; i < 10; i++ {
        cfgs = append(cfgs, VerCfg{i, Config{strconv.FormatInt(i, 10)}})
    }
    fmt.Printf("%v\n", cfgs)

    options := map[string]interface{} {
        mangos.OptionDialAsynch: true,
    }
    for key, _ := range hb_map {
        hb_map[key].sock, err = req.NewSocket()
        if err != nil {
            die("can't get new req socket: %s", err.Error())
        }
        err = hb_map[key].sock.SetOption(mangos.OptionBestEffort, true)
        if err != nil {
            die("can't set opt for sock: %s", err.Error())
        }
        err = hb_map[key].sock.SetOption(mangos.OptionRecvDeadline, READ_TIMEOUT * time.Second)
        if err != nil {
            die("can't set opt2 for sock: %s", err.Error())
        }
        if err = hb_map[key].sock.DialOptions(key, options); err != nil {
            die("can't dial on req socket: %s", err.Error())
        }
    }

    fmt.Printf("config done\n")

    /*
    notifyCh := make(chan struct{})
    go func() {
        tick := time.NewTicker(2 * time.Second)
        for {
            select {
            case <- tick.C:
                notifyCh <- struct{}{}
            // case signal stop
            }
        }
    }()
    */
    // loop keep sending req
    // may have bug if hb success but here send fail
	for {
        time.Sleep(LOOP_TIMEOUT * time.Second)
        fmt.Printf("\nstart send config\n")
        var wg sync.WaitGroup
        wg.Add(len(hb_map))
        for addr, target := range hb_map {

            go func(remote string, tgt *HbTarget) {
                defer wg.Done()
                if !onoff_map[addr] {
                    // we keep trying until target not online
                    return
                }
                var ver_cfgs []VerCfg
                if tgt.SyncVer < cfgs[len(cfgs)-1].Ver {
                    fmt.Printf("sending to %s from %d to %d\n", remote, tgt.SyncVer, cfgs[len(cfgs)-1].Ver)
                    // else we send empty ones
                    ver_cfgs = cfgs[tgt.SyncVer+1:]
                } else if tgt.SyncVer > cfgs[len(cfgs)-1].Ver {
                    die("some error ver")
                } else {
                    // already sync, return
                    // this is needed in case client stop and start quickly
                    fmt.Printf("sending to %s empty for sync rsponse\n", remote)
                }

                sendmsg, err := json.Marshal(ver_cfgs)
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
            }(addr, target)
        }
        wg.Wait()
        fmt.Printf("loop done\n")
	}
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "server" {
		server(os.Args[2])
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "lb" {
		lb()
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "Usage: req server <URL> | lb\n")
	os.Exit(1)
}
